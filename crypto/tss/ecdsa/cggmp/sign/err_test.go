// Copyright © 2022 AMIS Technologies
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package sign

import (
	"math/big"

	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/elliptic"
	"github.com/getamis/alice/crypto/homo/paillier"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/tss/ecdsa/cggmp"
	paillierzkproof "github.com/getamis/alice/crypto/zkproof/paillier"
	"github.com/getamis/alice/types"
	"github.com/getamis/alice/types/message"
	"github.com/getamis/sirius/log"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var (
	errTestCurve     = elliptic.Secp256k1()
	errTestPublicKey = pt.ScalarBaseMult(errTestCurve, big.NewInt(1))
	errTestG         = pt.NewBase(errTestCurve)

	errP1, _ = new(big.Int).SetString("340366771288285996084147479119611242442614345594997750117006424456709538181213174956531242637348887020939489028407223567703089221775929476782718731241099422906757248077561707495116704707032100273066634958903193593316620328414148810945508298178558199690098617229620146557290778760832502595754641527561508212399", 10)
	errQ1, _ = new(big.Int).SetString("342210008150736860849172031711164446089742451413085875179968626169110229543810442993722803323695011123398437631091572923680081443255606910343772878832257779626343789749157295053728686888061039308352407604712625787390738281942368398061709210466176074618563526725844303576439528711252290452332401583658026307763", 10)
	errP2, _ = new(big.Int).SetString("329524328382249319148628764796320840508305153692559642630478952397584014941151457067313849661756427706541392128829569820164488391545929472029591649023899042666372790978994596974957278845545627776319877812580448938383736549723272736985163607971865240447724733248007543186955586338718161415287240720736660379027", 10)
	errQ2, _ = new(big.Int).SetString("303257730957335372508990468184467952824893660405502046275411179022975791596082369116018636137081456229414107333744883072972870435672759889937021604516341631483943268195146188840571806143131404069249083788746474292239549553036812654888452038110307817556272081492401956345059506919164252213689045814591109663647", 10)

	errPaillierKeyA, _ = paillier.NewPaillierWithGivenPrimes(errP1, errQ1)
	errPaillierKeyB, _ = paillier.NewPaillierWithGivenPrimes(errP2, errQ2)
	errPedA, _         = errPaillierKeyA.NewPedersenParameterByPaillier()
	errPedB, _         = errPaillierKeyB.NewPedersenParameterByPaillier()
	errPedZKA          = paillierzkproof.NewPedersenOpenParameter(errPedA.PedersenOpenParameter.GetN(), errPedA.PedersenOpenParameter.GetS(), errPedA.PedersenOpenParameter.GetT())
	errPedZKB          = paillierzkproof.NewPedersenOpenParameter(errPedB.PedersenOpenParameter.GetN(), errPedB.PedersenOpenParameter.GetS(), errPedB.PedersenOpenParameter.GetT())
)

var _ = Describe("ProcessErr", func() {
	It("Error1 handle: Should be OK", func() {
		ssidInfoWithBK := []byte("A")
		k1 := big.NewInt(5)
		k2 := big.NewInt(2)
		K1, rho1, err := errPaillierKeyA.EncryptWithOutputSalt(k1)
		Expect(err).Should(BeNil())
		K2, rho2, err := errPaillierKeyB.EncryptWithOutputSalt(k2)
		Expect(err).Should(BeNil())
		gamma1 := big.NewInt(11)
		gamma2 := big.NewInt(10)
		G1, mu1, err := errPaillierKeyA.EncryptWithOutputSalt(gamma1)
		Expect(err).Should(BeNil())
		G2, mu2, err := errPaillierKeyB.EncryptWithOutputSalt(gamma2)
		Expect(err).Should(BeNil())
		Gamma1 := errTestG.ScalarMult(gamma1)
		Gamma2 := errTestG.ScalarMult(gamma2)
		sumGamma := errTestG.ScalarMult(gamma1)
		sumGamma, err = sumGamma.Add(Gamma2)
		Expect(err).Should(BeNil())
		bigDelta1 := sumGamma.ScalarMult(k1)
		bigDelta2 := sumGamma.ScalarMult(k2)
		ID1 := tss.GetTestID(0)
		ID2 := tss.GetTestID(1)

		p1Setup, p2Setup := setupErr1Parties(ssidInfoWithBK, errPaillierKeyA, errPaillierKeyB, k1, k2, K1, K2, G1, G2, gamma1, gamma2, Gamma1, Gamma2, bigDelta1, bigDelta2, ID1, ID2)

		map1 := map[string]*peer{ID2: p1Setup.peer}
		map2 := map[string]*peer{ID1: p2Setup.peer}
		p1Err := newRound3HandlerErr1(k1, gamma1, rho1, mu1, K1, G1, p1Setup.delta, bigDelta1, sumGamma, errPaillierKeyA, map1, 0, p1Setup.own)
		p2Err := newRound3HandlerErr1(k2, gamma2, rho2, mu2, K2, G2, p2Setup.delta, bigDelta2, sumGamma, errPaillierKeyB, map2, 1, p2Setup.own)
		Expect(p1Err.buildDeltaVerifyFailureMsg()).Should(Succeed())
		Expect(p2Err.buildDeltaVerifyFailureMsg()).Should(Succeed())

		errMsg1 := &Message{Id: ID1, Type: Type_Err1, Body: p1Err.err1Msg.Body}
		errMsg2 := &Message{Id: ID2, Type: Type_Err1, Body: p2Err.err1Msg.Body}
		blamed, err := p1Err.ProcessErr1Msg([]*Message{errMsg2})
		Expect(err).Should(BeNil())
		Expect(len(blamed.Union())).Should(BeZero())
		blamed, err = p2Err.ProcessErr1Msg([]*Message{errMsg1})
		Expect(err).Should(BeNil())
		Expect(len(blamed.Union())).Should(BeZero())

		tampered := &Message{Id: ID2, Type: Type_Err1, Body: p2Err.err1Msg.Body}
		peerMsg := tampered.GetErr1().Peers[ID1]
		Expect(peerMsg).NotTo(BeNil())
		Expect(len(peerMsg.ProductCiphertext)).NotTo(BeZero())
		peerMsg.ProductCiphertext[0] ^= 0xff
		blamed, err = p1Err.ProcessErr1Msg([]*Message{tampered})
		Expect(err).Should(BeNil())
		Expect(blamed.Union()).To(HaveKey(ID2))

		noProduct := &Message{Id: ID2, Type: Type_Err1, Body: p2Err.err1Msg.Body}
		noProductPeer := noProduct.GetErr1().Peers[ID1]
		Expect(noProductPeer).NotTo(BeNil())
		noProductPeer.ProductCiphertext = nil
		blamed, err = p1Err.ProcessErr1Msg([]*Message{noProduct})
		Expect(err).Should(BeNil())
		Expect(blamed.Union()).To(HaveKey(ID2))

		mismatchedD := &Message{Id: ID2, Type: Type_Err1, Body: p2Err.err1Msg.Body}
		dPeer := mismatchedD.GetErr1().Peers[ID1]
		Expect(dPeer).NotTo(BeNil())
		Expect(len(dPeer.D)).NotTo(BeZero())
		dPeer.D[0] ^= 0xff
		blamed, err = p1Err.ProcessErr1Msg([]*Message{mismatchedD})
		Expect(err).Should(BeNil())
		Expect(blamed.Union()).To(HaveKey(ID2))

		blamed, err = p1Err.ProcessErr1Msg(nil)
		Expect(err).Should(BeNil())
		Expect(blamed.Union()).To(HaveKey(ID2))

		// Scheme A': δ+1 must fail DecModQ against fixed untranslated product C0.
		wrongDelta := &Message{Id: ID2, Type: Type_Err1, Body: p2Err.err1Msg.Body}
		p1Err.peers[ID2].round3Data.delta = new(big.Int).Add(p1Err.peers[ID2].round3Data.delta, big1)
		p1Err.peers[ID2].round3Data.delta.Mod(p1Err.peers[ID2].round3Data.delta, errTestPublicKey.GetCurve().Params().N)
		blamed, err = p1Err.ProcessErr1Msg([]*Message{wrongDelta})
		Expect(err).Should(BeNil())
		Expect(blamed.Union()).To(HaveKey(ID2))
	})

	It("Error2 handle: Should be OK", func() {
		ssidInfoWithBK := []byte("B")
		k1 := big.NewInt(5)
		k2 := big.NewInt(2)
		b1 := big.NewInt(3)
		b2 := big.NewInt(10)
		K1, rho1, err := errPaillierKeyA.EncryptWithOutputSalt(k1)
		Expect(err).Should(BeNil())
		K2, rho2, err := errPaillierKeyB.EncryptWithOutputSalt(k2)
		Expect(err).Should(BeNil())
		x1 := big.NewInt(2)
		x2 := big.NewInt(3)
		bk1 := big.NewInt(2)
		bk2 := big.NewInt(-1)
		rX := big.NewInt(17)
		R := errTestG.ScalarMult(rX)
		ID1 := tss.GetTestID(0)
		ID2 := tss.GetTestID(1)
		bkMulShare1 := new(big.Int).Mul(x1, bk1)
		bkMulShare2 := new(big.Int).Mul(x2, bk2)
		bkPartial1 := errTestG.ScalarMult(x1).ScalarMult(bk1)
		bkPartial2 := errTestG.ScalarMult(x2).ScalarMult(bk2)

		p1Setup, p2Setup := setupErr2Parties(ssidInfoWithBK, errPaillierKeyA, errPaillierKeyB, K1, K2, k1, k2, x1, x2, bkMulShare1, bkMulShare2, bkPartial1, bkPartial2, rX, ID1, ID2)
		map1 := map[string]*peer{ID2: p1Setup.peer}
		map2 := map[string]*peer{ID1: p2Setup.peer}

		p1Err := newRound4HandlerErr2(b1, k1, rho1, rX, K1, errPaillierKeyA, map1, 0, p1Setup.own)
		p2Err := newRound4HandlerErr2(b2, k2, rho2, rX, K2, errPaillierKeyB, map2, 1, p2Setup.own)
		p1Err.R = R
		p2Err.R = R
		p1Err.chi = p1Setup.chi
		p2Err.chi = p2Setup.chi
		p1Err.sigma = p1Setup.sigma
		p2Err.sigma = p2Setup.sigma
		p1Err.bkMulShare = bkMulShare1
		p2Err.bkMulShare = bkMulShare2
		p1Err.bkpartialPubKey = bkPartial1
		p2Err.bkpartialPubKey = bkPartial2
		Expect(p1Err.buildSigmaVerifyFailureMsg()).Should(Succeed())
		Expect(p2Err.buildSigmaVerifyFailureMsg()).Should(Succeed())
		errMsg1 := &Message{Id: ID1, Type: Type_Err2, Body: p1Err.err2Msg.Body}
		errMsg2 := &Message{Id: ID2, Type: Type_Err2, Body: p2Err.err2Msg.Body}

		blamed, err := p1Err.ProcessErr2Msg([]*Message{errMsg2})
		Expect(err).Should(BeNil())
		Expect(len(blamed.Union())).Should(BeZero())
		blamed, err = p2Err.ProcessErr2Msg([]*Message{errMsg1})
		Expect(err).Should(BeNil())
		Expect(len(blamed.Union())).Should(BeZero())

		tampered := &Message{Id: ID2, Type: Type_Err2, Body: p2Err.err2Msg.Body}
		peerMsg := tampered.GetErr2().Peers[ID1]
		Expect(peerMsg).NotTo(BeNil())
		Expect(len(peerMsg.ProductCiphertext)).NotTo(BeZero())
		peerMsg.ProductCiphertext[0] ^= 0xff
		blamed, err = p1Err.ProcessErr2Msg([]*Message{tampered})
		Expect(err).Should(BeNil())
		Expect(blamed.Union()).To(HaveKey(ID2))

		// Scheme A': σ+1 must fail DecModQ(K^m, σ−r·χ) against fixed Err2 proofs.
		wrongSigma := &Message{Id: ID2, Type: Type_Err2, Body: p2Err.err2Msg.Body}
		p1Err.peers[ID2].round4Data.sigma = new(big.Int).Add(p1Err.peers[ID2].round4Data.sigma, big1)
		p1Err.peers[ID2].round4Data.sigma.Mod(p1Err.peers[ID2].round4Data.sigma, errTestPublicKey.GetCurve().Params().N)
		blamed, err = p1Err.ProcessErr2Msg([]*Message{wrongSigma})
		Expect(err).Should(BeNil())
		Expect(blamed.Union()).To(HaveKey(ID2))
		// restore for later use
		p1Err.peers[ID2].round4Data.sigma = new(big.Int).Set(p2Setup.sigma)

		noKm := &Message{Id: ID2, Type: Type_Err2, Body: p2Err.err2Msg.Body}
		noKm.GetErr2().Peers[ID1].DecModQKm = nil
		blamed, err = p1Err.ProcessErr2Msg([]*Message{noKm})
		Expect(err).Should(BeNil())
		Expect(blamed.Union()).To(HaveKey(ID2))

		Expect(len(p2Err.err2Msg.GetErr2().GetChi())).NotTo(BeZero())

		eh, err := newErr2Handler(p1Err, ErrIncorrectSig)
		Expect(err).Should(BeNil())
		Expect(eh.HandleMessage(log.New(), errMsg2)).Should(Succeed())
		_, finalizeErr := eh.Finalize(log.New())
		Expect(finalizeErr).Should(Equal(ErrIncorrectSig))
	})
})

type err1PartySetup struct {
	own   *peer
	peer  *peer
	delta *big.Int
}

func setupErr1Parties(ssid []byte, paillierA, paillierB *paillier.Paillier, k1, k2, K1, K2, G1, G2, gamma1, gamma2 *big.Int, Gamma1, Gamma2, bigDelta1, bigDelta2 *pt.ECPoint, id1, id2 string) (err1PartySetup, err1PartySetup) {
	curveN := errTestPublicKey.GetCurve().Params().N

	// Party1 MTA toward party2.
	beta12, count12, r12, _, d12Bytes, f12, psi12, err := cggmp.MtaWithProofAff_g(ssid, errPedZKB, paillierA, K2.Bytes(), gamma1, Gamma1)
	Expect(err).Should(BeNil())
	// Party2 MTA toward party1.
	beta21, count21, r21, _, d21Bytes, f21, psi21, err := cggmp.MtaWithProofAff_g(ssid, errPedZKA, paillierB, K1.Bytes(), gamma2, Gamma2)
	Expect(err).Should(BeNil())

	alpha21, err := paillierA.Decrypt(d21Bytes)
	Expect(err).Should(BeNil())
	alpha12, err := paillierB.Decrypt(d12Bytes)
	Expect(err).Should(BeNil())

	delta1 := new(big.Int).Mul(k1, gamma1)
	delta1.Add(delta1, new(big.Int).SetBytes(alpha21))
	delta1.Add(delta1, beta12)
	delta1.Mod(delta1, curveN)
	delta2 := new(big.Int).Mul(k2, gamma2)
	delta2.Add(delta2, new(big.Int).SetBytes(alpha12))
	delta2.Add(delta2, beta21)
	delta2.Mod(delta2, curveN)

	round3Msg1, err := bigDelta1.ToEcPointMessage()
	Expect(err).Should(BeNil())
	round3Msg2, err := bigDelta2.ToEcPointMessage()
	Expect(err).Should(BeNil())

	own1 := newErrTestPeer(id1, ssid, errPedZKA)
	own1.bk = birkhoffinterpolation.NewBkParameter(big.NewInt(2), 0)
	peer2 := newErrTestPeer(id2, ssid, errPedZKB)
	peer2.round1Data = &round1Data{
		countDelta:      count12,
		kCiphertext:     K2,
		gammaCiphertext: G2,
		beta:            beta12,
		r:               r12,
		D:               d12Bytes,
		F:               f12,
	}
	peer2.round2Data = &round2Data{
		d:             new(big.Int).SetBytes(d21Bytes),
		f:             f21,
		alpha:         new(big.Int).SetBytes(alpha21),
		allGammaPoint: Gamma2,
		psiProof:      psi21,
	}
	peer2.round3Data = &round3Data{delta: delta2}
	Expect(peer2.AddMessage(&Message{Id: id2, Type: Type_Round3, Body: &Message_Round3{Round3: &Round3Msg{BigDelta: round3Msg2}}})).Should(Succeed())

	own2 := newErrTestPeer(id2, ssid, errPedZKB)
	own2.bk = birkhoffinterpolation.NewBkParameter(big.NewInt(-1), 0)
	peer1 := newErrTestPeer(id1, ssid, errPedZKA)
	peer1.round1Data = &round1Data{
		countDelta:      count21,
		kCiphertext:     K1,
		gammaCiphertext: G1,
		beta:            beta21,
		r:               r21,
		D:               d21Bytes,
		F:               f21,
	}
	peer1.round2Data = &round2Data{
		d:             new(big.Int).SetBytes(d12Bytes),
		f:             f12,
		alpha:         new(big.Int).SetBytes(alpha12),
		allGammaPoint: Gamma1,
		psiProof:      psi12,
	}
	peer1.round3Data = &round3Data{delta: delta1}
	Expect(peer1.AddMessage(&Message{Id: id1, Type: Type_Round3, Body: &Message_Round3{Round3: &Round3Msg{BigDelta: round3Msg1}}})).Should(Succeed())

	return err1PartySetup{own: own1, peer: peer2, delta: delta1}, err1PartySetup{own: own2, peer: peer1, delta: delta2}
}

type err2PartySetup struct {
	own   *peer
	peer  *peer
	chi   *big.Int
	sigma *big.Int
}

func setupErr2Parties(ssid []byte, paillierA, paillierB *paillier.Paillier, K1, K2, k1, k2, x1, x2, bkMulShare1, bkMulShare2 *big.Int, bkPartial1, bkPartial2 *pt.ECPoint, rX *big.Int, id1, id2 string) (err2PartySetup, err2PartySetup) {
	curveN := errTestPublicKey.GetCurve().Params().N
	msg := []byte("test-msg")

	betahat12, countSigma12, _, _, dhat12, fhat12, psihat12, err := cggmp.MtaWithProofAff_g(ssid, errPedZKB, paillierA, K2.Bytes(), bkMulShare1, bkPartial1)
	Expect(err).Should(BeNil())
	betahat21, countSigma21, _, _, dhat21, fhat21, psihat21, err := cggmp.MtaWithProofAff_g(ssid, errPedZKA, paillierB, K1.Bytes(), bkMulShare2, bkPartial2)
	Expect(err).Should(BeNil())

	alpha12, err := paillierB.Decrypt(dhat12)
	Expect(err).Should(BeNil())
	alpha21, err := paillierA.Decrypt(dhat21)
	Expect(err).Should(BeNil())

	chi1 := new(big.Int).Mul(bkMulShare1, k1)
	chi1.Add(chi1, new(big.Int).SetBytes(alpha21))
	chi1.Add(chi1, betahat12)
	chi1.Mod(chi1, curveN)
	chi2 := new(big.Int).Mul(bkMulShare2, k2)
	chi2.Add(chi2, new(big.Int).SetBytes(alpha12))
	chi2.Add(chi2, betahat21)
	chi2.Mod(chi2, curveN)

	R := errTestG.ScalarMult(rX)
	r := R.GetX()
	sigma1 := new(big.Int).Mul(k1, new(big.Int).SetBytes(msg))
	sigma1.Add(sigma1, new(big.Int).Mul(r, chi1))
	sigma1.Mod(sigma1, curveN)
	sigma2 := new(big.Int).Mul(k2, new(big.Int).SetBytes(msg))
	sigma2.Add(sigma2, new(big.Int).Mul(r, chi2))
	sigma2.Mod(sigma2, curveN)

	peer2OnP1 := &peer{
		Peer:          message.NewPeer(id2),
		ssidWithBk:    ssid,
		para:          errPedZKB,
		bk:            birkhoffinterpolation.NewBkParameter(big.NewInt(-1), 0),
		bkcoefficient: big.NewInt(-1),
		partialPubKey: errTestG.ScalarMult(x2),
		round1Data: &round1Data{
			countSigma:  countSigma12,
			kCiphertext: K2,
			betahat:     betahat12,
			Dhat:        dhat12,
			Fhat:        fhat12,
		},
		round2Data: &round2Data{
			psihatProoof: psihat21,
			dhat:         new(big.Int).SetBytes(dhat21),
			fhat:         fhat21,
			alphahat:     new(big.Int).SetBytes(alpha21),
		},
		round4Data: &round4Data{sigma: sigma2, chi: chi2},
	}
	peer1OnP2 := &peer{
		Peer:          message.NewPeer(id1),
		ssidWithBk:    ssid,
		para:          errPedZKA,
		bk:            birkhoffinterpolation.NewBkParameter(big.NewInt(2), 0),
		bkcoefficient: big.NewInt(2),
		partialPubKey: errTestG.ScalarMult(x1),
		round1Data: &round1Data{
			countSigma:  countSigma21,
			kCiphertext: K1,
			betahat:     betahat21,
			Dhat:        dhat21,
			Fhat:        fhat21,
		},
		round2Data: &round2Data{
			psihatProoof: psihat12,
			dhat:         new(big.Int).SetBytes(dhat12),
			fhat:         fhat12,
			alphahat:     new(big.Int).SetBytes(alpha12),
		},
		round4Data: &round4Data{sigma: sigma1, chi: chi1},
	}

	own1 := newErrTestPeer(id1, ssid, errPedZKA)
	own1.bk = birkhoffinterpolation.NewBkParameter(big.NewInt(2), 0)
	own1.bkcoefficient = big.NewInt(2)
	own1.partialPubKey = errTestG.ScalarMult(x1)
	own1.round4Data = &round4Data{sigma: sigma1}

	own2 := newErrTestPeer(id2, ssid, errPedZKB)
	own2.bk = birkhoffinterpolation.NewBkParameter(big.NewInt(-1), 0)
	own2.bkcoefficient = big.NewInt(-1)
	own2.partialPubKey = errTestG.ScalarMult(x2)
	own2.round4Data = &round4Data{sigma: sigma2}

	return err2PartySetup{own: own1, peer: peer2OnP1, chi: chi1, sigma: sigma1},
		err2PartySetup{own: own2, peer: peer1OnP2, chi: chi2, sigma: sigma2}
}

func newErrTestPeer(id string, ssid []byte, para *paillierzkproof.PederssenOpenParameter) *peer {
	return &peer{
		Peer:       message.NewPeer(id),
		ssidWithBk: ssid,
		para:       para,
	}
}

func newRound3HandlerErr1(k, gamma, rho, mu *big.Int, kCipher, gammaCipher, delta *big.Int, bigDelta, sumGamma *pt.ECPoint, paillierKey *paillier.Paillier, peers map[string]*peer, pmIndex int, ownPeer *peer) *round3Handler {
	pm := tss.NewTestPeerManager(pmIndex, len(peers)+1)
	pm.Set(nil)
	if ownPeer.round1Data == nil {
		ownPeer.round1Data = &round1Data{}
	}
	p := &round1Handler{
		rho:             rho,
		mu:              mu,
		own:             ownPeer,
		paillierKey:     paillierKey,
		k:               k,
		gamma:           gamma,
		peers:           peers,
		pubKey:          errTestPublicKey,
		delta:           delta,
		BigDelta:        bigDelta,
		sumGamma:        sumGamma,
		kCiphertext:     kCipher,
		gammaCiphertext: gammaCipher,
		peerManager:     pm,
		peerNum:         uint32(len(peers)),
	}
	p2, _ := newRound2Handler(p)
	p3, _ := newRound3Handler(p2)
	return p3
}

func newRound4HandlerErr2(bkShare, k, rho, rX, kCipher *big.Int, paillierKey *paillier.Paillier, peers map[string]*peer, pmIndex int, ownPeer *peer) *round4Handler {
	pm := tss.NewTestPeerManager(pmIndex, len(peers)+1)
	pm.Set(nil)
	if ownPeer.round1Data == nil {
		ownPeer.round1Data = &round1Data{}
	}
	p := &round1Handler{
		rho:         rho,
		own:         ownPeer,
		paillierKey: paillierKey,
		k:           k,
		kCiphertext: kCipher,
		peers:       peers,
		pubKey:      errTestPublicKey,
		bkMulShare:  bkShare,
		msg:         []byte("test-msg"),
		peerManager: pm,
		peerNum:     uint32(len(peers)),
	}
	p2, _ := newRound2Handler(p)
	p3, _ := newRound3Handler(p2)
	p4, _ := newRound4Handler(p3)
	p4.R = errTestG.ScalarMult(rX)
	return p4
}

var _ = Describe("Abort e2e / API", func() {
	It("GetBlamedPeers rejects non-Failed state", func() {
		signs, _, listeners := newSigns()
		for _, l := range listeners {
			l.On("OnStateChanged", types.StateInit, types.StateDone).Maybe()
			l.On("OnStateChanged", types.StateInit, types.StateFailed).Maybe()
		}
		_, err := signs[tss.GetTestID(0)].GetBlamedPeers()
		Expect(err).Should(Equal(ErrBlamedPeersNotReady))
	})

	It("err1Handler Finalize writes blamed and reason", func() {
		ssidInfoWithBK := []byte("A")
		k1 := big.NewInt(5)
		k2 := big.NewInt(2)
		K1, rho1, err := errPaillierKeyA.EncryptWithOutputSalt(k1)
		Expect(err).Should(BeNil())
		K2, rho2, err := errPaillierKeyB.EncryptWithOutputSalt(k2)
		Expect(err).Should(BeNil())
		gamma1 := big.NewInt(11)
		gamma2 := big.NewInt(10)
		G1, mu1, err := errPaillierKeyA.EncryptWithOutputSalt(gamma1)
		Expect(err).Should(BeNil())
		G2, mu2, err := errPaillierKeyB.EncryptWithOutputSalt(gamma2)
		Expect(err).Should(BeNil())
		Gamma1 := errTestG.ScalarMult(gamma1)
		Gamma2 := errTestG.ScalarMult(gamma2)
		sumGamma := errTestG.ScalarMult(gamma1)
		sumGamma, err = sumGamma.Add(Gamma2)
		Expect(err).Should(BeNil())
		bigDelta1 := sumGamma.ScalarMult(k1)
		bigDelta2 := sumGamma.ScalarMult(k2)
		ID1 := tss.GetTestID(0)
		ID2 := tss.GetTestID(1)

		p1Setup, p2Setup := setupErr1Parties(ssidInfoWithBK, errPaillierKeyA, errPaillierKeyB, k1, k2, K1, K2, G1, G2, gamma1, gamma2, Gamma1, Gamma2, bigDelta1, bigDelta2, ID1, ID2)
		map1 := map[string]*peer{ID2: p1Setup.peer}
		p1Err := newRound3HandlerErr1(k1, gamma1, rho1, mu1, K1, G1, p1Setup.delta, bigDelta1, sumGamma, errPaillierKeyA, map1, 0, p1Setup.own)
		p2Err := newRound3HandlerErr1(k2, gamma2, rho2, mu2, K2, G2, p2Setup.delta, bigDelta2, sumGamma, errPaillierKeyB, map[string]*peer{ID1: p2Setup.peer}, 1, p2Setup.own)
		Expect(p1Err.buildDeltaVerifyFailureMsg()).Should(Succeed())
		Expect(p2Err.buildDeltaVerifyFailureMsg()).Should(Succeed())

		var stored map[string]struct{}
		p1Err.onBlame = func(c cggmp.BlameContribution) { m := c.Union();  stored = m }

		eh, err := newErr1Handler(p1Err, ErrInvalidDelta)
		Expect(err).Should(BeNil())
		Expect(eh.AbortCollecting()).Should(BeTrue())
		errMsg2 := &Message{Id: ID2, Type: Type_Err1, Body: p2Err.err1Msg.Body}
		blamed, err := p1Err.ProcessErr1Msg([]*Message{errMsg2})
		Expect(err).Should(BeNil())
		Expect(len(blamed.Union())).Should(BeZero())
		Expect(eh.HandleMessage(log.New(), errMsg2)).Should(Succeed())

		_, finalizeErr := eh.Finalize(log.New())
		Expect(finalizeErr).Should(Equal(ErrInvalidDelta))
		Expect(stored).ShouldNot(BeNil())
		Expect(len(stored)).Should(BeZero())

		bad := &Message{Id: ID2, Type: Type_Err1, Body: &Message_Err1{Err1: &Err1Msg{
			KgammaCiphertext: p2Err.err1Msg.GetErr1().KgammaCiphertext,
			MulProof:         p2Err.err1Msg.GetErr1().MulProof,
			Peers:            map[string]*Err1PeerMsg{},
		}}}
		eh2, err := newErr1Handler(p1Err, ErrInvalidDelta)
		Expect(err).Should(BeNil())
		Expect(eh2.HandleMessage(log.New(), bad)).Should(Succeed())
		_, err = eh2.Finalize(log.New())
		Expect(err).Should(Equal(ErrInvalidDelta))
		Expect(stored).To(HaveKey(ID2))
	})

	It("ProcessErr2Msg blames when MulStar is omitted", func() {
		ssidInfoWithBK := []byte("B")
		k1 := big.NewInt(5)
		k2 := big.NewInt(2)
		b1 := big.NewInt(3)
		b2 := big.NewInt(10)
		K1, rho1, err := errPaillierKeyA.EncryptWithOutputSalt(k1)
		Expect(err).Should(BeNil())
		K2, rho2, err := errPaillierKeyB.EncryptWithOutputSalt(k2)
		Expect(err).Should(BeNil())
		x1 := big.NewInt(2)
		x2 := big.NewInt(3)
		bk1 := big.NewInt(2)
		bk2 := big.NewInt(-1)
		rX := big.NewInt(17)
		R := errTestG.ScalarMult(rX)
		ID1 := tss.GetTestID(0)
		ID2 := tss.GetTestID(1)
		bkMulShare1 := new(big.Int).Mul(x1, bk1)
		bkMulShare2 := new(big.Int).Mul(x2, bk2)
		bkPartial1 := errTestG.ScalarMult(x1).ScalarMult(bk1)
		bkPartial2 := errTestG.ScalarMult(x2).ScalarMult(bk2)

		p1Setup, p2Setup := setupErr2Parties(ssidInfoWithBK, errPaillierKeyA, errPaillierKeyB, K1, K2, k1, k2, x1, x2, bkMulShare1, bkMulShare2, bkPartial1, bkPartial2, rX, ID1, ID2)
		p1Err := newRound4HandlerErr2(b1, k1, rho1, rX, K1, errPaillierKeyA, map[string]*peer{ID2: p1Setup.peer}, 0, p1Setup.own)
		p2Err := newRound4HandlerErr2(b2, k2, rho2, rX, K2, errPaillierKeyB, map[string]*peer{ID1: p2Setup.peer}, 1, p2Setup.own)
		p1Err.R = R
		p2Err.R = R
		p1Err.chi = p1Setup.chi
		p2Err.chi = p2Setup.chi
		p1Err.sigma = p1Setup.sigma
		p2Err.sigma = p2Setup.sigma
		p1Err.bkMulShare = bkMulShare1
		p2Err.bkMulShare = bkMulShare2
		p1Err.bkpartialPubKey = bkPartial1
		p2Err.bkpartialPubKey = bkPartial2
		Expect(p1Err.buildSigmaVerifyFailureMsg()).Should(Succeed())
		Expect(p2Err.buildSigmaVerifyFailureMsg()).Should(Succeed())

		for _, peerMsg := range p2Err.err2Msg.GetErr2().Peers {
			peerMsg.MulStarProof = nil
		}
		blamed, err := p1Err.ProcessErr2Msg([]*Message{{Id: ID2, Type: Type_Err2, Body: p2Err.err2Msg.Body}})
		Expect(err).Should(BeNil())
		Expect(blamed.Union()).To(HaveKey(ID2))
	})
})
