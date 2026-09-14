// Copyright © 2022 AMIS Technologies
package sign

import (
	"bytes"
	"errors"
	"math/big"
	"sort"

	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/tss/ecdsa/cggmp"
	"github.com/getamis/alice/crypto/tss/pairwise"
	paillierzkproof "github.com/getamis/alice/crypto/zkproof/paillier"
	"github.com/getamis/alice/types"
	"github.com/getamis/sirius/log"
)

// round1DigestPrepareHook is set by tests to inject prepareRound1Digest errors.
var round1DigestPrepareHook func(*round1DigestHandler) error

func (p *round1Handler) blameSender(id string) {
	if p.onBlame != nil {
		p.onBlame(cggmp.BlameContributionFromConfirmed(map[string]struct{}{id: {}}))
	}
}

func (p *round1Handler) blameSuspect(id string) {
	if p.onBlame != nil {
		p.onBlame(cggmp.BlameContributionFromSuspect(map[string]struct{}{id: {}}))
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

func (p *round1Handler) digestGatekeeper() *pairwise.Gatekeeper {
	return &pairwise.Gatekeeper{
		DST:   pairwiseDigestDST,
		SSID:  p.ssid,
		Store: p.digestStore,
		Blame: p.blameSender,
	}
}

func (p *round1Handler) acceptDigestTable(round digestRound, sender, tag string, entries []*PeerDigestEntry, root []byte) error {
	return p.digestGatekeeper().AcceptTable(round, tag, sender, p.expectedPeersForSender(sender), cggmpEntries(entries), root)
}

func (p *round1Handler) gateEdgeDigest(round digestRound, sender, self string, compute func() ([]byte, error)) error {
	return p.digestGatekeeper().GateEdgeDigest(round, sender, self, compute)
}

// sessionRound2MatchesDigest re-hashes the accepted Round2 reveal against the
// Echo-finalized digest table (strict Err / accountability binding).
func (p *round1Handler) sessionRound2MatchesDigest(senderID string) bool {
	if p.digestStore == nil || !p.digestStore.HasAny(digestR2) {
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
			p.blameSuspect(id) // IA-04: digest timeout → Suspect
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

// --- CoFlight shared guards (INV-1/2/3) ---

func (p *round1Handler) rejectIfEchoConflict() error {
	if p.coFlight.HasEchoConflict() {
		return ErrEchoConflict
	}
	return nil
}

// coFlightReady reports whether MsgMain may Finalize this CoFlight stage.
// Conflict forces Finalize so EnsureCanNext / Finalize can abort (A8).
func (p *round1Handler) coFlightReady() bool {
	echo, reveal, conflict := p.coFlight.Snapshot()
	return conflict || (echo && reveal)
}

// coFlightComplete is the success Next condition (both done, no conflict).
func (p *round1Handler) coFlightComplete() bool {
	echo, reveal, conflict := p.coFlight.Snapshot()
	return !conflict && echo && reveal
}

func (p *round1Handler) syncCoFlightFromPeers(digestType, revealType Type) {
	if p.coFlight == nil {
		return
	}
	var d, r uint32
	for _, peer := range p.peers {
		if peer.Messages[types.MessageType(digestType)] != nil {
			d++
		}
		if peer.Messages[types.MessageType(revealType)] != nil {
			r++
		}
	}
	p.coFlight.SetEchoDone(d >= p.peerNum)
	p.coFlight.SetRevealDone(r >= p.peerNum)
}

func isEarlyOrStored(early map[string]*Message, peers map[string]*peer, id string, revealType types.MessageType) bool {
	if _, ok := early[id]; ok {
		return true
	}
	return peerDigestHandled(peers, id, revealType)
}

// --- Round1Digest (CoFlight: Digest Echo ‖ Round1 Reveal) ---

type round1DigestHandler struct {
	*round1Handler
	pendingRound1 map[string]*Message // outbound reveals (self → peer)
	earlyRound1   map[string]*Message // inbound reveals before digest
	digestMsg     *Message
}

func newRound1DigestHandler(r *round1Handler) *round1DigestHandler {
	return &round1DigestHandler{
		round1Handler: r,
		pendingRound1: make(map[string]*Message, len(r.peers)),
		earlyRound1:   make(map[string]*Message, len(r.peers)),
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
func (p *round1DigestHandler) CollectMessageTypes() []types.MessageType {
	return []types.MessageType{types.MessageType(Type_Round1)}
}
func (p *round1DigestHandler) IsCollectHandled(logger log.Logger, msgType types.MessageType, id string) bool {
	_ = logger
	if msgType != types.MessageType(Type_Round1) {
		return false
	}
	return isEarlyOrStored(p.earlyRound1, p.peers, id, types.MessageType(Type_Round1))
}
func (p *round1DigestHandler) ReadyToFinalize() bool { return p.coFlightReady() }

func (p *round1DigestHandler) HandleMessage(logger log.Logger, message types.Message) error {
	if err := p.rejectIfEchoConflict(); err != nil {
		return err
	}
	msg := getMessage(message)
	switch msg.Type {
	case Type_Round1Digest:
		return p.handleDigest(logger, msg)
	case Type_Round1:
		return p.handleReveal(logger, msg)
	default:
		return errors.New("unexpected message type in round1 coflight")
	}
}

func (p *round1DigestHandler) handleDigest(logger log.Logger, msg *Message) error {
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
	if err := peer.AddMessage(msg); err != nil {
		return err
	}
	if early, ok := p.earlyRound1[id]; ok {
		delete(p.earlyRound1, id)
		if err := p.round1Handler.HandleMessage(logger, early); err != nil {
			return err
		}
	}
	p.syncCoFlightFromPeers(Type_Round1Digest, Type_Round1)
	return nil
}

func (p *round1DigestHandler) handleReveal(logger log.Logger, msg *Message) error {
	id := msg.GetId()
	if !peerDigestHandled(p.peers, id, types.MessageType(Type_Round1Digest)) {
		p.earlyRound1[id] = msg
		return nil
	}
	if err := p.round1Handler.HandleMessage(logger, msg); err != nil {
		return err
	}
	p.syncCoFlightFromPeers(Type_Round1Digest, Type_Round1)
	return nil
}

func (p *round1DigestHandler) Finalize(logger log.Logger) (types.Handler, error) {
	if p.coFlight.HasEchoConflict() {
		return nil, ErrEchoConflict
	}
	if p.coFlightComplete() {
		// Production CoFlight: Digests+Reveals already collected; Reveal already sent at Start.
		return p.round1Handler.Finalize(logger)
	}
	// N/A INV: serial-legacy / unit-test — Digests only; send Reveals then hand off.
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

// broadcastRound1CoFlight sends Digest and Reveal in the same scheduling point.
func (p *round1DigestHandler) broadcastRound1CoFlight() {
	p.broadcastRound1Digest()
	for id, m := range p.pendingRound1 {
		p.peerManager.MustSend(id, m)
	}
}

// --- Round2Digest (CoFlight) ---

type round2DigestHandler struct {
	*round1Handler
	reveal      *round2Handler
	earlyRound2 map[string]*Message
}

func newRound2DigestHandler(r *round1Handler) *round2DigestHandler {
	reveal, _ := newRound2Handler(r) // constructor never fails
	return &round2DigestHandler{
		round1Handler: r,
		reveal:        reveal,
		earlyRound2:   make(map[string]*Message, len(r.peers)),
	}
}

func (p *round2DigestHandler) MessageType() types.MessageType {
	return types.MessageType(Type_Round2Digest)
}
func (p *round2DigestHandler) GetRequiredMessageCount() uint32 { return p.peerNum }
func (p *round2DigestHandler) IsHandled(logger log.Logger, id string) bool {
	_ = logger
	return peerDigestHandled(p.peers, id, p.MessageType())
}
func (p *round2DigestHandler) CollectMessageTypes() []types.MessageType {
	return []types.MessageType{types.MessageType(Type_Round2)}
}
func (p *round2DigestHandler) IsCollectHandled(logger log.Logger, msgType types.MessageType, id string) bool {
	_ = logger
	if msgType != types.MessageType(Type_Round2) {
		return false
	}
	return isEarlyOrStored(p.earlyRound2, p.peers, id, types.MessageType(Type_Round2))
}
func (p *round2DigestHandler) ReadyToFinalize() bool { return p.coFlightReady() }

func (p *round2DigestHandler) HandleMessage(logger log.Logger, message types.Message) error {
	if err := p.rejectIfEchoConflict(); err != nil {
		return err
	}
	msg := getMessage(message)
	switch msg.Type {
	case Type_Round2Digest:
		return p.handleDigest(logger, msg)
	case Type_Round2:
		return p.handleReveal(logger, msg)
	default:
		return errors.New("unexpected message type in round2 coflight")
	}
}

func (p *round2DigestHandler) handleDigest(logger log.Logger, msg *Message) error {
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
	g, err := body.GetGamma().ToPoint()
	if err != nil {
		p.blameSender(id)
		return err
	}
	peer.digestGamma = g
	if err := peer.AddMessage(msg); err != nil {
		return err
	}
	if early, ok := p.earlyRound2[id]; ok {
		delete(p.earlyRound2, id)
		if err := p.reveal.HandleMessage(logger, early); err != nil {
			return err
		}
	}
	p.syncCoFlightFromPeers(Type_Round2Digest, Type_Round2)
	return nil
}

func (p *round2DigestHandler) handleReveal(logger log.Logger, msg *Message) error {
	id := msg.GetId()
	if !peerDigestHandled(p.peers, id, types.MessageType(Type_Round2Digest)) {
		p.earlyRound2[id] = msg
		return nil
	}
	if err := p.reveal.HandleMessage(logger, msg); err != nil {
		return err
	}
	p.syncCoFlightFromPeers(Type_Round2Digest, Type_Round2)
	return nil
}

func (p *round2DigestHandler) broadcastPendingReveals() {
	for id, peer := range p.peers {
		if peer.round1Data == nil || peer.round1Data.round2Msg == nil {
			continue
		}
		p.peerManager.MustSend(id, peer.round1Data.round2Msg)
	}
}

func (p *round2DigestHandler) Finalize(logger log.Logger) (types.Handler, error) {
	if p.coFlight.HasEchoConflict() {
		return nil, ErrEchoConflict
	}
	if p.coFlightComplete() {
		return p.reveal.Finalize(logger)
	}
	// N/A INV: serial-legacy
	for id, peer := range p.peers {
		if peer.round1Data == nil || peer.round1Data.round2Msg == nil {
			return nil, errors.New("missing pending round2 message")
		}
		p.peerManager.MustSend(id, peer.round1Data.round2Msg)
	}
	return p.reveal, nil
}

func (p *round2DigestHandler) OnDigestTimeout() {
	p.blameMissingDigestSenders(p.MessageType())
}

// --- Round3Digest (CoFlight) ---

type round3DigestHandler struct {
	*round2Handler
	reveal        *round3Handler
	pendingRound3 map[string]*Message
	earlyRound3   map[string]*Message
}

func newRound3DigestHandler(r2 *round2Handler, pending map[string]*Message) *round3DigestHandler {
	reveal, _ := newRound3Handler(r2) // constructor never fails
	return &round3DigestHandler{
		round2Handler: r2,
		reveal:        reveal,
		pendingRound3: pending,
		earlyRound3:   make(map[string]*Message, len(r2.peers)),
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
func (p *round3DigestHandler) CollectMessageTypes() []types.MessageType {
	return []types.MessageType{types.MessageType(Type_Round3)}
}
func (p *round3DigestHandler) IsCollectHandled(logger log.Logger, msgType types.MessageType, id string) bool {
	_ = logger
	if msgType != types.MessageType(Type_Round3) {
		return false
	}
	return isEarlyOrStored(p.earlyRound3, p.peers, id, types.MessageType(Type_Round3))
}
func (p *round3DigestHandler) ReadyToFinalize() bool { return p.coFlightReady() }

func (p *round3DigestHandler) HandleMessage(logger log.Logger, message types.Message) error {
	if err := p.rejectIfEchoConflict(); err != nil {
		return err
	}
	msg := getMessage(message)
	switch msg.Type {
	case Type_Round3Digest:
		return p.handleDigest(logger, msg)
	case Type_Round3:
		return p.handleReveal(logger, msg)
	default:
		return errors.New("unexpected message type in round3 coflight")
	}
}

func (p *round3DigestHandler) handleDigest(logger log.Logger, msg *Message) error {
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
	if err := peer.AddMessage(msg); err != nil {
		return err
	}
	if early, ok := p.earlyRound3[id]; ok {
		delete(p.earlyRound3, id)
		if err := p.reveal.HandleMessage(logger, early); err != nil {
			return err
		}
	}
	p.syncCoFlightFromPeers(Type_Round3Digest, Type_Round3)
	return nil
}

func (p *round3DigestHandler) handleReveal(logger log.Logger, msg *Message) error {
	id := msg.GetId()
	if !peerDigestHandled(p.peers, id, types.MessageType(Type_Round3Digest)) {
		p.earlyRound3[id] = msg
		return nil
	}
	if err := p.reveal.HandleMessage(logger, msg); err != nil {
		return err
	}
	p.syncCoFlightFromPeers(Type_Round3Digest, Type_Round3)
	return nil
}

func (p *round3DigestHandler) broadcastPendingReveals() {
	for id, m := range p.pendingRound3 {
		p.peerManager.MustSend(id, m)
	}
}

func (p *round3DigestHandler) Finalize(logger log.Logger) (types.Handler, error) {
	if p.coFlight.HasEchoConflict() {
		return nil, ErrEchoConflict
	}
	if p.coFlightComplete() {
		return p.reveal.Finalize(logger)
	}
	// N/A INV: serial-legacy
	for id, m := range p.pendingRound3 {
		p.peerManager.MustSend(id, m)
	}
	return p.reveal, nil
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
