// Copyright © 2022 AMIS Technologies
package sign

import (
	"bytes"
	"errors"
	"math/big"
	"sort"

	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/tss"
	paillierzkproof "github.com/getamis/alice/crypto/zkproof/paillier"
	"github.com/getamis/alice/types"
	"github.com/getamis/sirius/log"
)

// round1DigestPrepareHook is set by tests to inject prepareRound1Digest errors.
var round1DigestPrepareHook func(*round1DigestHandler) error

func (p *round1Handler) blameSender(id string) {
	if p.onBlamedPeers != nil {
		p.onBlamedPeers(map[string]struct{}{id: {}})
	}
}

// expectedPeersForSender is the set of remotes from sender's view: all parties except sender.
func (p *round1Handler) expectedPeersForSender(sender string) []string {
	out := make([]string, 0, len(p.peers)+1)
	self := p.peerManager.SelfID()
	if self != sender {
		out = append(out, self)
	}
	for id := range p.peers {
		if id != sender {
			out = append(out, id)
		}
	}
	sort.Strings(out)
	return out
}

func (p *round1Handler) acceptDigestTable(round digestRound, sender, tag string, entries []*PeerDigestEntry, root []byte) error {
	tab, err := ValidateDigestTable(p.ssid, tag, sender, p.expectedPeersForSender(sender), entries, root)
	if err != nil {
		p.blameSender(sender)
		return err
	}
	p.digestStore.SetFinalized(round, sender, tab)
	return nil
}

func (p *round1Handler) gateEdgeDigest(round digestRound, sender, self string, compute func() ([]byte, error)) error {
	want, ok := p.digestStore.Get(round, sender, self)
	if !ok {
		p.blameSender(sender)
		return ErrDigestBarrier
	}
	got, err := compute()
	if err != nil {
		p.blameSender(sender)
		return err
	}
	if !bytes.Equal(got, want) {
		p.blameSender(sender)
		return ErrPairwiseDigestMismatch
	}
	return nil
}

// sessionRound2MatchesDigest re-hashes the accepted Round2 reveal against the
// Echo-finalized digest table (strict Err / accountability binding).
func (p *round1Handler) sessionRound2MatchesDigest(senderID string) bool {
	if p.digestStore == nil || !p.digestStore.hasAny(digestR2) {
		return true
	}
	selfID := p.peerManager.SelfID()
	want, ok := p.digestStore.Get(digestR2, senderID, selfID)
	if !ok {
		return false
	}
	sender, ok := p.peers[senderID]
	if !ok {
		return false
	}
	raw := sender.GetMessage(types.MessageType(Type_Round2))
	if raw == nil {
		return false
	}
	r2 := getMessage(raw).GetRound2()
	got, err := Round2PairwiseDigest(p.ssid, senderID, selfID, r2)
	if err != nil {
		return false
	}
	return bytes.Equal(got, want)
}

func (p *round1Handler) blameMissingDigestSenders(msgType types.MessageType) {
	for id, peer := range p.peers {
		if peer.Messages[msgType] == nil {
			p.blameSender(id)
		}
	}
}

func (p *round1Handler) broadcastToPeers(msg *Message) {
	for id := range p.peers {
		p.peerManager.MustSend(id, msg)
	}
}

func peerDigestHandled(peers map[string]*peer, id string, msgType types.MessageType) bool {
	peer, ok := peers[id]
	return ok && peer.Messages[msgType] != nil
}

// --- Round1Digest ---

type round1DigestHandler struct {
	*round1Handler
	pendingRound1 map[string]*Message
	digestMsg     *Message
}

func newRound1DigestHandler(r *round1Handler) *round1DigestHandler {
	return &round1DigestHandler{
		round1Handler: r,
		pendingRound1: make(map[string]*Message, len(r.peers)),
	}
}

func (p *round1DigestHandler) MessageType() types.MessageType {
	return types.MessageType(Type_Round1Digest)
}
func (p *round1DigestHandler) GetRequiredMessageCount() uint32 { return p.peerNum }
func (p *round1DigestHandler) IsHandled(logger log.Logger, id string) bool {
	_ = logger
	return peerDigestHandled(p.peers, id, p.MessageType())
}

func (p *round1DigestHandler) HandleMessage(logger log.Logger, message types.Message) error {
	msg := getMessage(message)
	id := msg.GetId()
	peer, ok := p.peers[id]
	if !ok {
		return tss.ErrPeerNotFound
	}
	body := msg.GetRound1Digest()
	if body == nil {
		p.blameSender(id)
		return ErrPairwiseDigestTable
	}
	if err := p.acceptDigestTable(digestR1, id, tagR1, body.GetToPeer(), body.GetTableRoot()); err != nil {
		return err
	}
	peer.digestKCiphertext = cloneBytes(body.GetKCiphertext())
	peer.digestGammaCiphertext = cloneBytes(body.GetGammaCiphertext())
	return peer.AddMessage(msg)
}

func (p *round1DigestHandler) Finalize(logger log.Logger) (types.Handler, error) {
	if len(p.pendingRound1) != len(p.peers) {
		return nil, errors.New("round1 reveal not prepared before digest barrier")
	}
	for id, m := range p.pendingRound1 {
		p.peerManager.MustSend(id, m)
	}
	return p.round1Handler, nil
}

func (p *round1DigestHandler) OnDigestTimeout() {
	p.blameMissingDigestSenders(p.MessageType())
}

// prepareRound1Digest builds pending Round1 reveals and the Round1Digest broadcast
// body. Must run before MessageMain.Start so Finalize cannot race with an empty pending map.
func (p *round1DigestHandler) prepareRound1Digest() error {
	if round1DigestPrepareHook != nil {
		return round1DigestPrepareHook(p)
	}
	selfID := p.peerManager.SelfID()
	digests := make(map[string][]byte, len(p.peers))
	n := p.paillierKey.GetN()
	pending := make(map[string]*Message, len(p.peers))
	for id, peer := range p.peers {
		psi, err := paillierzkproof.NewEncryptRangeMessage(parameter, peer.ssidWithBk, p.kCiphertext, n, p.k, p.rho, peer.para)
		if err != nil {
			return err
		}
		d, err := Round1PsiDigest(p.ssid, selfID, id, psi)
		if err != nil {
			return err
		}
		digests[id] = d
		pending[id] = &Message{
			Id:   selfID,
			Type: Type_Round1,
			Body: &Message_Round1{
				Round1: &Round1Msg{
					KCiphertext:     p.kCiphertext.Bytes(),
					GammaCiphertext: p.gammaCiphertext.Bytes(),
					Psi:             psi,
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
				KCiphertext:     p.kCiphertext.Bytes(),
				GammaCiphertext: p.gammaCiphertext.Bytes(),
				ToPeer:          entries,
				TableRoot:       root,
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

// --- Round2Digest ---

type round2DigestHandler struct {
	*round1Handler
}

func newRound2DigestHandler(r *round1Handler) *round2DigestHandler {
	return &round2DigestHandler{round1Handler: r}
}

func (p *round2DigestHandler) MessageType() types.MessageType {
	return types.MessageType(Type_Round2Digest)
}
func (p *round2DigestHandler) GetRequiredMessageCount() uint32 { return p.peerNum }
func (p *round2DigestHandler) IsHandled(logger log.Logger, id string) bool {
	_ = logger
	return peerDigestHandled(p.peers, id, p.MessageType())
}

func (p *round2DigestHandler) HandleMessage(logger log.Logger, message types.Message) error {
	msg := getMessage(message)
	id := msg.GetId()
	peer, ok := p.peers[id]
	if !ok {
		return tss.ErrPeerNotFound
	}
	body := msg.GetRound2Digest()
	if body == nil {
		p.blameSender(id)
		return ErrPairwiseDigestTable
	}
	if err := p.acceptDigestTable(digestR2, id, tagR2, body.GetToPeer(), body.GetTableRoot()); err != nil {
		return err
	}
	// Stash gamma from digest for cross-check in Round2.
	g, err := body.GetGamma().ToPoint()
	if err != nil {
		p.blameSender(id)
		return err
	}
	peer.digestGamma = g
	return peer.AddMessage(msg)
}

func (p *round2DigestHandler) Finalize(logger log.Logger) (types.Handler, error) {
	for id, peer := range p.peers {
		if peer.round1Data == nil || peer.round1Data.round2Msg == nil {
			return nil, errors.New("missing pending round2 message")
		}
		p.peerManager.MustSend(id, peer.round1Data.round2Msg)
	}
	return newRound2Handler(p.round1Handler)
}

func (p *round2DigestHandler) OnDigestTimeout() {
	p.blameMissingDigestSenders(p.MessageType())
}

// --- Round3Digest ---

type round3DigestHandler struct {
	*round2Handler
	pendingRound3 map[string]*Message
	deltaStr      string
	bigDeltaMsg   *pt.EcPointMessage
}

func newRound3DigestHandler(r2 *round2Handler, pending map[string]*Message, deltaStr string, bigDelta *pt.EcPointMessage) *round3DigestHandler {
	return &round3DigestHandler{
		round2Handler: r2,
		pendingRound3: pending,
		deltaStr:      deltaStr,
		bigDeltaMsg:   bigDelta,
	}
}

func (p *round3DigestHandler) MessageType() types.MessageType {
	return types.MessageType(Type_Round3Digest)
}
func (p *round3DigestHandler) GetRequiredMessageCount() uint32 { return p.peerNum }
func (p *round3DigestHandler) IsHandled(logger log.Logger, id string) bool {
	_ = logger
	return peerDigestHandled(p.peers, id, p.MessageType())
}

func (p *round3DigestHandler) HandleMessage(logger log.Logger, message types.Message) error {
	msg := getMessage(message)
	id := msg.GetId()
	peer, ok := p.peers[id]
	if !ok {
		return tss.ErrPeerNotFound
	}
	body := msg.GetRound3Digest()
	if body == nil {
		p.blameSender(id)
		return ErrPairwiseDigestTable
	}
	if err := p.acceptDigestTable(digestR3, id, tagR3, body.GetToPeer(), body.GetTableRoot()); err != nil {
		return err
	}
	peer.digestDelta = body.GetDelta()
	bd, err := body.GetBigDelta().ToPoint()
	if err != nil {
		p.blameSender(id)
		return err
	}
	peer.digestBigDelta = bd
	return peer.AddMessage(msg)
}

func (p *round3DigestHandler) Finalize(logger log.Logger) (types.Handler, error) {
	for id, m := range p.pendingRound3 {
		p.peerManager.MustSend(id, m)
	}
	return newRound3Handler(p.round2Handler)
}

func (p *round3DigestHandler) OnDigestTimeout() {
	p.blameMissingDigestSenders(p.MessageType())
}

// buildRound2DigestAndBroadcast commits Round2 pairwise digests (does not reveal Round2).
func (p *round1Handler) buildRound2DigestAndBroadcast(msgGamma *pt.EcPointMessage) error {
	selfID := p.peerManager.SelfID()
	digests := make(map[string][]byte, len(p.peers))
	for id, peer := range p.peers {
		r2 := getMessage(peer.round1Data.round2Msg).GetRound2()
		d, err := Round2PairwiseDigest(p.ssid, selfID, id, r2)
		if err != nil {
			return err
		}
		digests[id] = d
	}
	entries, root := commitDigestTable(p.ssid, tagR2, selfID, digests)
	digestMsg := &Message{
		Id:   selfID,
		Type: Type_Round2Digest,
		Body: &Message_Round2Digest{
			Round2Digest: &Round2DigestMsg{
				Gamma:     msgGamma,
				ToPeer:    entries,
				TableRoot: root,
			},
		},
	}
	p.broadcastToPeers(digestMsg)
	return nil
}

func (p *round2Handler) buildRound3DigestAndBroadcast(delta *big.Int, msgDelta *pt.EcPointMessage, pending map[string]*Message) error {
	selfID := p.peerManager.SelfID()
	digests := make(map[string][]byte, len(p.peers))
	for id, m := range pending {
		psi := getMessage(m).GetRound3().GetPsidoublepai()
		d, err := Round3PairwiseDigest(p.ssid, selfID, id, psi)
		if err != nil {
			return err
		}
		digests[id] = d
	}
	entries, root := commitDigestTable(p.ssid, tagR3, selfID, digests)
	digestMsg := &Message{
		Id:   selfID,
		Type: Type_Round3Digest,
		Body: &Message_Round3Digest{
			Round3Digest: &Round3DigestMsg{
				Delta:     delta.String(),
				BigDelta:  msgDelta,
				ToPeer:    entries,
				TableRoot: root,
			},
		},
	}
	p.broadcastToPeers(digestMsg)
	return nil
}
