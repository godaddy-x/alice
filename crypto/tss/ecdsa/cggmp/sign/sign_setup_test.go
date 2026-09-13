// Copyright © 2022 AMIS Technologies
package sign

import (
	"math/big"
	"sync"
	"time"

	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/elliptic"
	"github.com/getamis/alice/crypto/homo/paillier"
	"github.com/getamis/alice/crypto/polynomial"
	"github.com/getamis/alice/crypto/tss"
	paillierzkproof "github.com/getamis/alice/crypto/zkproof/paillier"
	"github.com/getamis/alice/types"
	"github.com/getamis/alice/types/mocks"
	. "github.com/onsi/gomega"
	"github.com/stretchr/testify/mock"
	"google.golang.org/protobuf/proto"
)

var (
	threshold = uint32(2)
	curve     = elliptic.Secp256k1()
	msg       = []byte("Edwin HaHa")
)

// outboundTamperPM mutates outbound messages to selected peers (mesh fault simulation).
type outboundTamperPM struct {
	*tss.TestPeerManager
	tamperTo map[string]struct{}
	mutate   func(*Message)
}

func newOutboundTamperPM(base *tss.TestPeerManager, victims ...string) *outboundTamperPM {
	tamperTo := make(map[string]struct{}, len(victims))
	for _, id := range victims {
		tamperTo[id] = struct{}{}
	}
	return &outboundTamperPM{TestPeerManager: base, tamperTo: tamperTo}
}

func (p *outboundTamperPM) MustSend(id string, message interface{}) {
	if _, tamper := p.tamperTo[id]; tamper && p.mutate != nil {
		if msg, ok := message.(*Message); ok {
			tampered := proto.Clone(msg).(*Message)
			p.mutate(tampered)
			p.TestPeerManager.MustSend(id, tampered)
			return
		}
	}
	p.TestPeerManager.MustSend(id, message)
}

func xorFirstByte(b []byte) []byte {
	if len(b) == 0 {
		return b
	}
	out := append([]byte(nil), b...)
	out[0] ^= 0xff
	return out
}

func tamperRound2Dhat(msg *Message) {
	if body := msg.GetRound2(); body != nil && len(body.GetD()) > 0 {
		body.D = xorFirstByte(body.GetD())
	}
}

func tamperRound4Sigma(msg *Message) {
	if body := msg.GetRound4(); body != nil && len(body.GetSigmai()) > 0 {
		body.Sigmai = xorFirstByte(body.GetSigmai())
	}
}

// blockMsgTypePM drops outbound messages of one type (digest timeout simulation).
type blockMsgTypePM struct {
	*tss.TestPeerManager
	blockType Type
}

func (p *blockMsgTypePM) MustSend(id string, message interface{}) {
	if msg, ok := message.(*Message); ok && msg.Type == p.blockType {
		return
	}
	p.TestPeerManager.MustSend(id, message)
}

type signBuildOptions struct {
	round2Tamper  map[int]string
	round4Tamper  map[int][]string
	blockSendType map[int]Type
}

var (
	signTestPaillierMu   sync.Mutex
	signTestPaillierKeys []*paillier.Paillier
	signTestPeds         []*paillierzkproof.PederssenOpenParameter
)

func ensureSignTestPailliers(count int) {
	signTestPaillierMu.Lock()
	defer signTestPaillierMu.Unlock()
	if len(signTestPaillierKeys) == 0 {
		p1, _ := new(big.Int).SetString("340366771288285996084147479119611242442614345594997750117006424456709538181213174956531242637348887020939489028407223567703089221775929476782718731241099422906757248077561707495116704707032100273066634958903193593316620328414148810945508298178558199690098617229620146557290778760832502595754641527561508212399", 10)
		q1, _ := new(big.Int).SetString("342210008150736860849172031711164446089742451413085875179968626169110229543810442993722803323695011123398437631091572923680081443255606910343772878832257779626343789749157295053728686888061039308352407604712625787390738281942368398061709210466176074618563526725844303576439528711252290452332401583658026307763", 10)
		p2, _ := new(big.Int).SetString("329524328382249319148628764796320840508305153692559642630478952397584014941151457067313849661756427706541392128829569820164488391545929472029591649023899042666372790978994596974957278845545627776319877812580448938383736549723272736985163607971865240447724733248007543186955586338718161415287240720736660379027", 10)
		q2, _ := new(big.Int).SetString("303257730957335372508990468184467952824893660405502046275411179022975791596082369116018636137081456229414107333744883072972870435672759889937021604516341631483943268195146188840571806143131404069249083788746474292239549553036812654888452038110307817556272081492401956345059506919164252213689045814591109663647", 10)
		paillierKeyA, err := paillier.NewPaillierWithGivenPrimes(p1, q1)
		Expect(err).Should(BeNil())
		paillierKeyB, err := paillier.NewPaillierWithGivenPrimes(p2, q2)
		Expect(err).Should(BeNil())
		for _, pk := range []*paillier.Paillier{paillierKeyA, paillierKeyB} {
			ped, err := pk.NewPedersenParameterByPaillier()
			Expect(err).Should(BeNil())
			signTestPaillierKeys = append(signTestPaillierKeys, pk)
			signTestPeds = append(signTestPeds, paillierzkproof.NewPedersenOpenParameter(
				ped.PedersenOpenParameter.GetN(),
				ped.PedersenOpenParameter.GetS(),
				ped.PedersenOpenParameter.GetT(),
			))
		}
	}
	for len(signTestPaillierKeys) < count {
		pk, err := paillier.NewPaillier(2048)
		Expect(err).Should(BeNil())
		ped, err := pk.NewPedersenParameterByPaillier()
		Expect(err).Should(BeNil())
		signTestPaillierKeys = append(signTestPaillierKeys, pk)
		signTestPeds = append(signTestPeds, paillierzkproof.NewPedersenOpenParameter(
			ped.PedersenOpenParameter.GetN(),
			ped.PedersenOpenParameter.GetS(),
			ped.PedersenOpenParameter.GetT(),
		))
	}
}

func newSigns() (map[string]*Sign, map[string]*birkhoffinterpolation.BkParameter, map[string]*mocks.StateChangedListener) {
	return buildSigns(2, nil)
}

// buildSigns creates an in-process sign mesh. round2Tamper maps attacker party index → victim peer id.
func buildSigns(lens int, round2Tamper map[int]string) (map[string]*Sign, map[string]*birkhoffinterpolation.BkParameter, map[string]*mocks.StateChangedListener) {
	return buildSignsOpts(lens, signBuildOptions{round2Tamper: round2Tamper})
}

// buildSignsWithRound4Tamper creates a mesh where party index i tampers Round4 sigma to victim ids.
func buildSignsWithRound4Tamper(lens int, round4Tamper map[int][]string) (map[string]*Sign, map[string]*birkhoffinterpolation.BkParameter, map[string]*mocks.StateChangedListener) {
	return buildSignsOpts(lens, signBuildOptions{round4Tamper: round4Tamper})
}

func buildSignsOpts(lens int, opts signBuildOptions) (map[string]*Sign, map[string]*birkhoffinterpolation.BkParameter, map[string]*mocks.StateChangedListener) {
	signs := make(map[string]*Sign, lens)
	signsMain := make(map[string]types.MessageMain, lens)
	listeners := make(map[string]*mocks.StateChangedListener, lens)
	ensureSignTestPailliers(lens)
	paillierKeys := signTestPaillierKeys[:lens]
	peds := signTestPeds[:lens]

	ssidInfo := []byte("A")
	bks, shares, partialPubKey, pub, allPed := buildTestCredentials(lens, peds)
	assertTestCredentials(lens, bks, partialPubKey, pub)

	for i := 0; i < lens; i++ {
		id := tss.GetTestID(i)
		basePM := tss.NewTestPeerManager(i, lens)
		var pm types.PeerManager = basePM
		if victim, ok := opts.round2Tamper[i]; ok {
			pmWrap := newOutboundTamperPM(basePM, victim)
			pmWrap.mutate = func(m *Message) {
				if m.GetRound2() != nil {
					tamperRound2Dhat(m)
				}
			}
			pm = pmWrap
		}
		if victims, ok := opts.round4Tamper[i]; ok {
			base := basePM
			if wrapped, ok := pm.(*outboundTamperPM); ok {
				base = wrapped.TestPeerManager
			}
			pmWrap := newOutboundTamperPM(base, victims...)
			pmWrap.mutate = func(m *Message) {
				if m.GetRound4() != nil {
					tamperRound4Sigma(m)
				}
			}
			pm = pmWrap
		}
		if blockType, ok := opts.blockSendType[i]; ok {
			pm = &blockMsgTypePM{TestPeerManager: basePM, blockType: blockType}
		}
		basePM.Set(signsMain)
		listeners[id] = new(mocks.StateChangedListener)
		var err error
		signs[id], err = NewSign(threshold, ssidInfo, shares[i], pub, partialPubKey, paillierKeys[i], allPed, bks, msg, pm, listeners[id])
		Expect(err).Should(BeNil())
		signsMain[id] = signs[id]
		r, err := signs[id].GetResult()
		Expect(r).Should(BeNil())
		Expect(err).Should(Equal(tss.ErrNotReady))
	}
	return signs, bks, listeners
}

func buildTestCredentials(lens int, peds []*paillierzkproof.PederssenOpenParameter) (
	map[string]*birkhoffinterpolation.BkParameter,
	[]*big.Int,
	map[string]*pt.ECPoint,
	*pt.ECPoint,
	map[string]*paillierzkproof.PederssenOpenParameter,
) {
	bks := make(map[string]*birkhoffinterpolation.BkParameter, lens)
	shares := make([]*big.Int, lens)
	partialPubKey := make(map[string]*pt.ECPoint)
	allPed := make(map[string]*paillierzkproof.PederssenOpenParameter)

	bkXs := testBkXs(lens)
	fieldOrder := curve.Params().N
	poly, err := polynomial.NewPolynomial(fieldOrder, []*big.Int{big.NewInt(1), big.NewInt(1)})
	Expect(err).Should(BeNil())
	pub := pt.ScalarBaseMult(curve, poly.Get(0))
	for i := 0; i < lens; i++ {
		id := tss.GetTestID(i)
		x := bkXs[i]
		bks[id] = birkhoffinterpolation.NewBkParameter(x, 0)
		shares[i] = poly.Evaluate(x)
		partialPubKey[id] = pt.ScalarBaseMult(curve, shares[i])
		allPed[id] = peds[i]
	}
	return bks, shares, partialPubKey, pub, allPed
}

func startAllAndWaitDone(signs map[string]*Sign, listeners map[string]*mocks.StateChangedListener) {
	doneChs := make([]chan struct{}, 0, len(listeners))
	for _, l := range listeners {
		ch := make(chan struct{})
		doneChs = append(doneChs, ch)
		l.On("OnStateChanged", types.StateInit, types.StateDone).Run(func(_ mock.Arguments) {
			close(ch)
		}).Once()
	}
	for _, s := range signs {
		s.Start()
	}
	for _, ch := range doneChs {
		<-ch
	}
}

func startAllSignMesh(signs map[string]*Sign, listeners map[string]*mocks.StateChangedListener) {
	for _, l := range listeners {
		l.On("OnStateChanged", mock.Anything, mock.Anything).Return().Maybe()
	}
	for _, s := range signs {
		s.Start()
	}
}

const (
	meshAbortCollectTimeout = 10 * time.Second
	meshAbortTestTimeout    = 60 * time.Second
)

func setMeshAbortCollectTimeout(signs map[string]*Sign) {
	for _, s := range signs {
		s.SetAbortTimeout(meshAbortCollectTimeout)
	}
}

func installErr1AttackerDeltaTamper(detectorID, attackerID string) func() {
	curveN := curve.Params().N
	round3BeforeAggregateVerifyTestHook = func(p *round3Handler) {
		if p.peerManager.SelfID() != detectorID {
			return
		}
		peer := p.peers[attackerID]
		if peer == nil || peer.round3Data == nil || peer.round3Data.delta == nil {
			return
		}
		peer.round3Data.delta = new(big.Int).Add(peer.round3Data.delta, big.NewInt(1))
		peer.round3Data.delta.Mod(peer.round3Data.delta, curveN)
	}
	return func() { round3BeforeAggregateVerifyTestHook = nil }
}

func assertMatchingSignResults(signs map[string]*Sign, lens int) {
	ref, err := signs[tss.GetTestID(0)].GetResult()
	Expect(err).Should(BeNil())
	Expect(ref).NotTo(BeNil())
	for i := 1; i < lens; i++ {
		r, err := signs[tss.GetTestID(i)].GetResult()
		Expect(err).Should(BeNil())
		Expect(r).NotTo(BeNil())
		Expect(r.R.Cmp(ref.R) == 0).Should(BeTrue())
		Expect(r.S.Cmp(ref.S) == 0).Should(BeTrue())
	}
}

func testBkXs(lens int) []*big.Int {
	switch lens {
	case 2:
		return []*big.Int{big.NewInt(1), big.NewInt(2)}
	case 3:
		return []*big.Int{big.NewInt(2), big.NewInt(3), big.NewInt(5)}
	default:
		xs := make([]*big.Int, lens)
		for i := range xs {
			xs[i] = big.NewInt(int64(i + 1))
		}
		return xs
	}
}

// assertTestCredentials mirrors newRound1Handler bk/y ordering per party.
func assertTestCredentials(lens int, bks map[string]*birkhoffinterpolation.BkParameter, partialPubKey map[string]*pt.ECPoint, pub *pt.ECPoint) {
	fieldOrder := curve.Params().N
	for i := 0; i < lens; i++ {
		selfID := tss.GetTestID(i)
		bkss := birkhoffinterpolation.BkParameters{bks[selfID]}
		ids := []string{selfID}
		for id, bk := range bks {
			if id == selfID {
				continue
			}
			bkss = append(bkss, bk)
			ids = append(ids, id)
		}
		ys := make([]*pt.ECPoint, len(bkss))
		for j, id := range ids {
			ys[j] = partialPubKey[id]
		}
		Expect(bkss.CheckValid(threshold, fieldOrder)).Should(Succeed())
		Expect(bkss.ValidatePublicKey(ys, threshold, pub)).Should(Succeed())
	}
}
