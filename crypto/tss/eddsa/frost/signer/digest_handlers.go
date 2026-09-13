// Copyright © 2022 AMIS Technologies
package signer

import (
	"errors"
	"math/big"
	"sort"

	ecpointgrouplaw "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/tss/ecdsa/cggmp"
	"github.com/getamis/alice/crypto/tss/pairwise"
	"github.com/getamis/alice/types"
	"github.com/getamis/sirius/log"
)

var round1DigestPrepareHook func(*round1DigestHandler) error

func (p *round1) blameSender(id string) {
	if p.onBlame != nil {
		p.onBlame(cggmp.BlameContributionFromConfirmed(map[string]struct{}{id: {}}))
	}
}

func (p *round1) blameSuspect(id string) {
	if p.onBlame != nil {
		p.onBlame(cggmp.BlameContributionFromSuspect(map[string]struct{}{id: {}}))
	}
}

func (p *round1) expectedPeersForSender(sender string) []string {
	out := make([]string, 0, p.peerNum+1)
	self := p.peerManager.SelfID()
	if self != sender {
		out = append(out, self)
	}
	for _, id := range p.peerManager.PeerIDs() {
		if id != sender {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

func (p *round1) digestGatekeeper() *pairwise.Gatekeeper {
	return &pairwise.Gatekeeper{
		DST:   pairwiseDigestDST,
		SSID:  p.ssid,
		Store: p.digestStore,
		Blame: p.blameSender,
	}
}

func (p *round1) acceptDigestTable(round pairwise.Round, sender, tag string, entries []*PeerDigestEntry, root []byte) error {
	return p.digestGatekeeper().AcceptTable(round, tag, sender, p.expectedPeersForSender(sender), frostEntries(entries), root)
}

func (p *round1) gateEdgeDigest(round pairwise.Round, sender, self string, compute func() ([]byte, error)) error {
	return p.digestGatekeeper().GateEdgeDigest(round, sender, self, compute)
}

func (p *round1) blameMissingDigestSenders(msgType types.MessageType) {
	for _, id := range p.peerManager.PeerIDs() {
		if p.nodes[id].Messages[msgType] == nil {
			p.blameSuspect(id) // IA-04: digest timeout → Suspect
		}
	}
}

func (p *round1) broadcastToPeers(msg *Message) {
	for _, id := range p.peerManager.PeerIDs() {
		p.peerManager.MustSend(id, msg)
	}
}

func peerDigestHandled(nodes map[string]*peer, id string, msgType types.MessageType) bool {
	node, ok := nodes[id]
	return ok && node.Messages[msgType] != nil
}

type round1DigestHandler struct {
	*round1
	pendingRound1 map[string]*Message
	digestMsg     *Message
}

func newRound1DigestHandler(r *round1) *round1DigestHandler {
	return &round1DigestHandler{
		round1:        r,
		pendingRound1: make(map[string]*Message, len(r.nodes)),
	}
}

func (p *round1DigestHandler) MessageType() types.MessageType {
	return types.MessageType(Type_Round1Digest)
}

func (p *round1DigestHandler) GetRequiredMessageCount() uint32 { return p.peerNum }

func (p *round1DigestHandler) IsHandled(logger log.Logger, id string) bool {
	_ = logger
	return peerDigestHandled(p.nodes, id, p.MessageType())
}

func (p *round1DigestHandler) HandleMessage(logger log.Logger, message types.Message) error {
	msg := getMessage(message)
	id := msg.GetId()
	node, ok := p.nodes[id]
	if !ok {
		return ErrPeerNotFound
	}
	body := msg.GetRound1Digest()
	if body == nil {
		p.blameSender(id)
		return pairwise.ErrPairwiseDigestTable
	}
	if err := p.acceptDigestTable(pairwise.Round1, id, tagR1, body.GetToPeer(), body.GetTableRoot()); err != nil {
		return err
	}
	d, err := body.GetD().ToPoint()
	if err != nil {
		p.blameSender(id)
		return err
	}
	e, err := body.GetE().ToPoint()
	if err != nil {
		p.blameSender(id)
		return err
	}
	node.digestD = d
	node.digestE = e
	return node.AddMessage(msg)
}

func (p *round1DigestHandler) Finalize(logger log.Logger) (types.Handler, error) {
	if len(p.pendingRound1) != int(p.peerNum) {
		return nil, errors.New("round1 reveal not prepared before digest barrier")
	}
	for id, m := range p.pendingRound1 {
		p.peerManager.MustSend(id, m)
	}
	return p.round1, nil
}

func (p *round1DigestHandler) OnDigestTimeout() {
	p.blameMissingDigestSenders(p.MessageType())
}

func (p *round1DigestHandler) prepareRound1Digest() error {
	if round1DigestPrepareHook != nil {
		return round1DigestPrepareHook(p)
	}
	selfID := p.peerManager.SelfID()
	digests := make(map[string][]byte, len(p.nodes))
	pending := make(map[string]*Message, len(p.nodes))
	msgD, err := p.D.ToEcPointMessage()
	if err != nil {
		return err
	}
	msgE, err := p.E.ToEcPointMessage()
	if err != nil {
		return err
	}
	bkX := p.ownbk.GetX().Bytes()
	for _, id := range p.peerManager.PeerIDs() {
		d, err := Round1PairwiseDigest(p.ssid, selfID, id, bkX, p.D, p.E)
		if err != nil {
			return err
		}
		digests[id] = d
		pending[id] = &Message{
			Id:   selfID,
			Type: Type_Round1,
			Body: &Message_Round1{
				Round1: &BodyRound1{
					D: msgD,
					E: msgE,
				},
			},
		}
	}
	entries, root := commitDigestTable(p.ssid, tagR1, selfID, digests)
	p.pendingRound1 = pending
	p.digestMsg = &Message{
		Id:   selfID,
		Type: Type_Round1Digest,
		Body: &Message_Round1Digest{
			Round1Digest: &Round1DigestMsg{
				D:         msgD,
				E:         msgE,
				ToPeer:    entries,
				TableRoot: root,
			},
		},
	}
	return nil
}

func (p *round1DigestHandler) broadcastRound1Digest() {
	if p.digestMsg == nil {
		return
	}
	p.broadcastToPeers(p.digestMsg)
}

type round2DigestHandler struct {
	*round1
}

func newRound2DigestHandler(r *round1) *round2DigestHandler {
	return &round2DigestHandler{round1: r}
}

func (p *round2DigestHandler) MessageType() types.MessageType {
	return types.MessageType(Type_Round2Digest)
}

func (p *round2DigestHandler) GetRequiredMessageCount() uint32 { return p.peerNum }

func (p *round2DigestHandler) IsHandled(logger log.Logger, id string) bool {
	_ = logger
	return peerDigestHandled(p.nodes, id, p.MessageType())
}

func (p *round2DigestHandler) HandleMessage(logger log.Logger, message types.Message) error {
	msg := getMessage(message)
	id := msg.GetId()
	node, ok := p.nodes[id]
	if !ok {
		return ErrPeerNotFound
	}
	body := msg.GetRound2Digest()
	if body == nil {
		p.blameSender(id)
		return pairwise.ErrPairwiseDigestTable
	}
	if err := p.acceptDigestTable(pairwise.Round2, id, tagR2, body.GetToPeer(), body.GetTableRoot()); err != nil {
		return err
	}
	return node.AddMessage(msg)
}

func (p *round2DigestHandler) Finalize(logger log.Logger) (types.Handler, error) {
	h, err := newRound2(p.round1)
	if err != nil {
		return nil, err
	}
	selfMsg := p.pendingRound2
	if selfMsg == nil {
		return nil, errors.New("missing pending round2 message")
	}
	selfID := p.peerManager.SelfID()
	selfNode := p.nodes[selfID]
	selfNode.zi = new(big.Int).SetBytes(selfMsg.GetRound2().GetZi())
	if err := selfNode.AddMessage(selfMsg); err != nil {
		return nil, err
	}
	for _, id := range p.peerManager.PeerIDs() {
		p.peerManager.MustSend(id, selfMsg)
	}
	return h, nil
}

func (p *round2DigestHandler) OnDigestTimeout() {
	p.blameMissingDigestSenders(p.MessageType())
}

func (p *round1) buildRound2DigestAndBroadcast(round2Msg *Message) error {
	selfID := p.peerManager.SelfID()
	digests := make(map[string][]byte, p.peerNum)
	zi := round2Msg.GetRound2().GetZi()
	for _, id := range p.peerManager.PeerIDs() {
		digests[id] = Round2PairwiseDigest(p.ssid, selfID, id, zi)
	}
	entries, root := commitDigestTable(p.ssid, tagR2, selfID, digests)
	digestMsg := &Message{
		Id:   selfID,
		Type: Type_Round2Digest,
		Body: &Message_Round2Digest{
			Round2Digest: &Round2DigestMsg{
				ToPeer:    entries,
				TableRoot: root,
			},
		},
	}
	p.pendingRound2 = round2Msg
	p.broadcastToPeers(digestMsg)
	return nil
}

func digestPointsEqual(a, b *ecpointgrouplaw.ECPoint) bool {
	if a == nil || b == nil {
		return false
	}
	return a.Equal(b)
}
