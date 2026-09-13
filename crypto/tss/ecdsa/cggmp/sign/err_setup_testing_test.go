package sign

import (
	"math/big"
	"sync"
	"testing"

	"github.com/getamis/alice/crypto/birkhoffinterpolation"
	pt "github.com/getamis/alice/crypto/ecpointgrouplaw"
	"github.com/getamis/alice/crypto/homo/paillier"
	"github.com/getamis/alice/crypto/tss"
	"github.com/getamis/alice/crypto/tss/ecdsa/cggmp"
	paillierzkproof "github.com/getamis/alice/crypto/zkproof/paillier"
	"github.com/getamis/alice/types/message"
)

var (
	err3TestOnce    sync.Once
	errPaillierKey3 *paillier.Paillier
	errPedZK3       *paillierzkproof.PederssenOpenParameter
	err3InitErr     error
)

func ensureErr3PaillierTesting(t *testing.T) (*paillier.Paillier, *paillierzkproof.PederssenOpenParameter) {
	t.Helper()
	err3TestOnce.Do(func() {
		errPaillierKey3, err3InitErr = paillier.NewPaillier(2048)
		if err3InitErr != nil {
			return
		}
		ped, err := errPaillierKey3.NewPedersenParameterByPaillier()
		if err != nil {
			err3InitErr = err
			return
		}
		errPedZK3 = paillierzkproof.NewPedersenOpenParameter(
			ped.PedersenOpenParameter.GetN(),
			ped.PedersenOpenParameter.GetS(),
			ped.PedersenOpenParameter.GetT(),
		)
	})
	if err3InitErr != nil {
		t.Fatal(err3InitErr)
	}
	return errPaillierKey3, errPedZK3
}

// setupErr1ThreePartyTesting builds three honest round3 handlers with matching Err1 payloads.
func setupErr1ThreePartyTesting(t *testing.T) ([]*round3Handler, []*Message) {
	t.Helper()
	keyC, pedC := ensureErr3PaillierTesting(t)
	ssid := []byte("3P-Err1-testing")
	ids := []string{tss.GetTestID(0), tss.GetTestID(1), tss.GetTestID(2)}
	keys := []*paillier.Paillier{errPaillierKeyA, errPaillierKeyB, keyC}
	peds := []*paillierzkproof.PederssenOpenParameter{errPedZKA, errPedZKB, pedC}
	ks := []*big.Int{big.NewInt(5), big.NewInt(2), big.NewInt(7)}
	gammas := []*big.Int{big.NewInt(11), big.NewInt(10), big.NewInt(3)}

	K := make([]*big.Int, 3)
	G := make([]*big.Int, 3)
	rho := make([]*big.Int, 3)
	mu := make([]*big.Int, 3)
	Gamma := make([]*pt.ECPoint, 3)
	for i := 0; i < 3; i++ {
		var err error
		K[i], rho[i], err = keys[i].EncryptWithOutputSalt(ks[i])
		if err != nil {
			t.Fatal(err)
		}
		G[i], mu[i], err = keys[i].EncryptWithOutputSalt(gammas[i])
		if err != nil {
			t.Fatal(err)
		}
		Gamma[i] = errTestG.ScalarMult(gammas[i])
	}

	sumGamma := errTestG.ScalarMult(gammas[0])
	var err error
	sumGamma, err = sumGamma.Add(Gamma[1])
	if err != nil {
		t.Fatal(err)
	}
	sumGamma, err = sumGamma.Add(Gamma[2])
	if err != nil {
		t.Fatal(err)
	}

	curveN := errTestPublicKey.GetCurve().Params().N
	type mtaEdge struct {
		beta, count, r *big.Int
		dBytes, f      *big.Int
		psi            *paillierzkproof.PaillierAffAndGroupRangeMessage
		alpha          *big.Int
	}
	mta := make([][]*mtaEdge, 3)
	for i := 0; i < 3; i++ {
		mta[i] = make([]*mtaEdge, 3)
	}
	for i := 0; i < 3; i++ {
		for j := 0; j < 3; j++ {
			if i == j {
				continue
			}
			beta, count, r, _, dBytes, f, psi, e := cggmp.MtaWithProofAff_g(
				ssid, peds[j], keys[i], K[j].Bytes(), gammas[i], Gamma[i],
			)
			if e != nil {
				t.Fatal(e)
			}
			alpha, e := keys[j].Decrypt(dBytes)
			if e != nil {
				t.Fatal(e)
			}
			mta[i][j] = &mtaEdge{
				beta: beta, count: count, r: r,
				dBytes: new(big.Int).SetBytes(dBytes), f: f, psi: psi,
				alpha: new(big.Int).SetBytes(alpha),
			}
		}
	}

	deltas := make([]*big.Int, 3)
	bigDeltas := make([]*pt.ECPoint, 3)
	for i := 0; i < 3; i++ {
		d := new(big.Int).Mul(ks[i], gammas[i])
		for j := 0; j < 3; j++ {
			if i == j {
				continue
			}
			d.Add(d, mta[j][i].alpha)
			d.Add(d, mta[i][j].beta)
		}
		d.Mod(d, curveN)
		deltas[i] = d
		bigDeltas[i] = sumGamma.ScalarMult(ks[i])
	}

	bks := []*birkhoffinterpolation.BkParameter{
		birkhoffinterpolation.NewBkParameter(big.NewInt(2), 0),
		birkhoffinterpolation.NewBkParameter(big.NewInt(3), 0),
		birkhoffinterpolation.NewBkParameter(big.NewInt(5), 0),
	}

	handlers := make([]*round3Handler, 3)
	errMsgs := make([]*Message, 3)
	for i := 0; i < 3; i++ {
		own := newErrTestPeer(ids[i], ssid, peds[i])
		own.bk = bks[i]
		peers := make(map[string]*peer)
		for j := 0; j < 3; j++ {
			if i == j {
				continue
			}
			pj := &peer{
				Peer:       message.NewPeer(ids[j]),
				ssidWithBk: ssid,
				para:       peds[j],
				bk:         bks[j],
				round1Data: &round1Data{
					countDelta:      mta[i][j].count,
					kCiphertext:     K[j],
					gammaCiphertext: G[j],
					beta:            mta[i][j].beta,
					r:               mta[i][j].r,
					D:               mta[i][j].dBytes.Bytes(),
					F:               mta[i][j].f,
				},
				round2Data: &round2Data{
					d:             mta[j][i].dBytes,
					f:             mta[j][i].f,
					alpha:         mta[j][i].alpha,
					allGammaPoint: Gamma[j],
					psiProof:      mta[j][i].psi,
				},
				round3Data: &round3Data{delta: deltas[j]},
			}
			r3, e := bigDeltas[j].ToEcPointMessage()
			if e != nil {
				t.Fatal(e)
			}
			if err := pj.AddMessage(&Message{
				Id: ids[j], Type: Type_Round3,
				Body: &Message_Round3{Round3: &Round3Msg{BigDelta: r3}},
			}); err != nil {
				t.Fatal(err)
			}
			peers[ids[j]] = pj
		}
		h := newRound3HandlerErr1(ks[i], gammas[i], rho[i], mu[i], K[i], G[i], deltas[i], bigDeltas[i], sumGamma, keys[i], peers, i, own)
		if err := h.buildDeltaVerifyFailureMsg(); err != nil {
			t.Fatal(err)
		}
		handlers[i] = h
		errMsgs[i] = &Message{Id: ids[i], Type: Type_Err1, Body: h.err1Msg.Body}
	}
	return handlers, errMsgs
}

func setupErr1PartiesTesting(t *testing.T, ssid []byte, paillierA, paillierB *paillier.Paillier, k1, k2, K1, K2, G1, G2, gamma1, gamma2 *big.Int, Gamma1, Gamma2, bigDelta1, bigDelta2 *pt.ECPoint, id1, id2 string) (err1PartySetup, err1PartySetup) {
	t.Helper()
	curveN := errTestPublicKey.GetCurve().Params().N

	beta12, count12, r12, _, d12Bytes, f12, psi12, err := cggmp.MtaWithProofAff_g(ssid, errPedZKB, paillierA, K2.Bytes(), gamma1, Gamma1)
	if err != nil {
		t.Fatal(err)
	}
	beta21, count21, r21, _, d21Bytes, f21, psi21, err := cggmp.MtaWithProofAff_g(ssid, errPedZKA, paillierB, K1.Bytes(), gamma2, Gamma2)
	if err != nil {
		t.Fatal(err)
	}

	alpha21, err := paillierA.Decrypt(d21Bytes)
	if err != nil {
		t.Fatal(err)
	}
	alpha12, err := paillierB.Decrypt(d12Bytes)
	if err != nil {
		t.Fatal(err)
	}

	delta1 := new(big.Int).Mul(k1, gamma1)
	delta1.Add(delta1, new(big.Int).SetBytes(alpha21))
	delta1.Add(delta1, beta12)
	delta1.Mod(delta1, curveN)
	delta2 := new(big.Int).Mul(k2, gamma2)
	delta2.Add(delta2, new(big.Int).SetBytes(alpha12))
	delta2.Add(delta2, beta21)
	delta2.Mod(delta2, curveN)

	round3Msg1, err := bigDelta1.ToEcPointMessage()
	if err != nil {
		t.Fatal(err)
	}
	round3Msg2, err := bigDelta2.ToEcPointMessage()
	if err != nil {
		t.Fatal(err)
	}

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
	if err := peer2.AddMessage(&Message{Id: id2, Type: Type_Round3, Body: &Message_Round3{Round3: &Round3Msg{BigDelta: round3Msg2}}}); err != nil {
		t.Fatal(err)
	}

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
	if err := peer1.AddMessage(&Message{Id: id1, Type: Type_Round3, Body: &Message_Round3{Round3: &Round3Msg{BigDelta: round3Msg1}}}); err != nil {
		t.Fatal(err)
	}

	return err1PartySetup{own: own1, peer: peer2, delta: delta1}, err1PartySetup{own: own2, peer: peer1, delta: delta2}
}

func setupErr2PartiesTesting(t *testing.T, ssid []byte, paillierA, paillierB *paillier.Paillier, K1, K2, k1, k2, x1, x2, bkMulShare1, bkMulShare2 *big.Int, bkPartial1, bkPartial2 *pt.ECPoint, rX *big.Int, id1, id2 string) (err2PartySetup, err2PartySetup) {
	t.Helper()
	curveN := errTestPublicKey.GetCurve().Params().N
	msg := []byte("test-msg")

	betahat12, countSigma12, _, _, dhat12, fhat12, psihat12, err := cggmp.MtaWithProofAff_g(ssid, errPedZKB, paillierA, K2.Bytes(), bkMulShare1, bkPartial1)
	if err != nil {
		t.Fatal(err)
	}
	betahat21, countSigma21, _, _, dhat21, fhat21, psihat21, err := cggmp.MtaWithProofAff_g(ssid, errPedZKA, paillierB, K1.Bytes(), bkMulShare2, bkPartial2)
	if err != nil {
		t.Fatal(err)
	}

	alpha12, err := paillierB.Decrypt(dhat12)
	if err != nil {
		t.Fatal(err)
	}
	alpha21, err := paillierA.Decrypt(dhat21)
	if err != nil {
		t.Fatal(err)
	}

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

// setupErr2ThreePartyTesting builds three honest round4 handlers with matching Err2 payloads.
func setupErr2ThreePartyTesting(t *testing.T) ([]*round4Handler, []*Message) {
	t.Helper()
	keyC, pedC := ensureErr3PaillierTesting(t)
	ssid := []byte("3P-Err2-testing")
	ids := []string{tss.GetTestID(0), tss.GetTestID(1), tss.GetTestID(2)}
	keys := []*paillier.Paillier{errPaillierKeyA, errPaillierKeyB, keyC}
	peds := []*paillierzkproof.PederssenOpenParameter{errPedZKA, errPedZKB, pedC}
	ks := []*big.Int{big.NewInt(5), big.NewInt(2), big.NewInt(7)}
	xs := []*big.Int{big.NewInt(2), big.NewInt(3), big.NewInt(4)}
	bkCoeffs := []*big.Int{big.NewInt(2), big.NewInt(3), big.NewInt(5)}

	K := make([]*big.Int, 3)
	rho := make([]*big.Int, 3)
	for i := 0; i < 3; i++ {
		var err error
		K[i], rho[i], err = keys[i].EncryptWithOutputSalt(ks[i])
		if err != nil {
			t.Fatal(err)
		}
	}

	bkMulShare := make([]*big.Int, 3)
	bkPartial := make([]*pt.ECPoint, 3)
	bks := make([]*birkhoffinterpolation.BkParameter, 3)
	for i := 0; i < 3; i++ {
		bks[i] = birkhoffinterpolation.NewBkParameter(bkCoeffs[i], 0)
		bkMulShare[i] = new(big.Int).Mul(xs[i], bkCoeffs[i])
		bkPartial[i] = errTestG.ScalarMult(xs[i]).ScalarMult(bkCoeffs[i])
	}

	curveN := errTestPublicKey.GetCurve().Params().N
	msg := []byte("test-msg")
	rX := big.NewInt(17)
	R := errTestG.ScalarMult(rX)
	r := R.GetX()

	type mtaHatEdge struct {
		betahat, count *big.Int
		dhat           []byte
		fhat           *big.Int
		psihat         *paillierzkproof.PaillierAffAndGroupRangeMessage
		alpha          *big.Int
	}
	mtaHat := make([][]*mtaHatEdge, 3)
	for i := 0; i < 3; i++ {
		mtaHat[i] = make([]*mtaHatEdge, 3)
	}
	for i := 0; i < 3; i++ {
		for j := 0; j < 3; j++ {
			if i == j {
				continue
			}
			betahat, count, _, _, dhat, fhat, psihat, e := cggmp.MtaWithProofAff_g(
				ssid, peds[j], keys[i], K[j].Bytes(), bkMulShare[i], bkPartial[i],
			)
			if e != nil {
				t.Fatal(e)
			}
			alpha, e := keys[j].Decrypt(dhat)
			if e != nil {
				t.Fatal(e)
			}
			mtaHat[i][j] = &mtaHatEdge{
				betahat: betahat, count: count,
				dhat: append([]byte(nil), dhat...), fhat: fhat, psihat: psihat,
				alpha: new(big.Int).SetBytes(alpha),
			}
		}
	}

	chi := make([]*big.Int, 3)
	sigma := make([]*big.Int, 3)
	for i := 0; i < 3; i++ {
		c := new(big.Int).Mul(bkMulShare[i], ks[i])
		for j := 0; j < 3; j++ {
			if i == j {
				continue
			}
			c.Add(c, mtaHat[j][i].alpha)
			c.Add(c, mtaHat[i][j].betahat)
		}
		c.Mod(c, curveN)
		chi[i] = c
		s := new(big.Int).Mul(ks[i], new(big.Int).SetBytes(msg))
		s.Add(s, new(big.Int).Mul(r, chi[i]))
		s.Mod(s, curveN)
		sigma[i] = s
	}

	handlers := make([]*round4Handler, 3)
	errMsgs := make([]*Message, 3)
	for i := 0; i < 3; i++ {
		own := newErrTestPeer(ids[i], ssid, peds[i])
		own.bk = bks[i]
		own.bkcoefficient = bkCoeffs[i]
		own.partialPubKey = errTestG.ScalarMult(xs[i])
		own.round4Data = &round4Data{sigma: sigma[i]}

		peers := make(map[string]*peer)
		for j := 0; j < 3; j++ {
			if i == j {
				continue
			}
			peers[ids[j]] = &peer{
				Peer:          message.NewPeer(ids[j]),
				ssidWithBk:    ssid,
				para:          peds[j],
				bk:            bks[j],
				bkcoefficient: bkCoeffs[j],
				partialPubKey: errTestG.ScalarMult(xs[j]),
				round1Data: &round1Data{
					countSigma:  mtaHat[i][j].count,
					kCiphertext: K[j],
					betahat:     mtaHat[i][j].betahat,
					Dhat:        append([]byte(nil), mtaHat[i][j].dhat...),
					Fhat:        mtaHat[i][j].fhat,
				},
				round2Data: &round2Data{
					psihatProoof: mtaHat[j][i].psihat,
					dhat:         new(big.Int).SetBytes(mtaHat[j][i].dhat),
					fhat:         mtaHat[j][i].fhat,
					alphahat:     mtaHat[j][i].alpha,
				},
				round4Data: &round4Data{sigma: sigma[j], chi: chi[j]},
			}
		}
		h := newRound4HandlerErr2(bkMulShare[i], ks[i], rho[i], rX, K[i], keys[i], peers, i, own)
		h.R = R
		h.chi = chi[i]
		h.sigma = sigma[i]
		h.bkMulShare = bkMulShare[i]
		h.bkpartialPubKey = bkPartial[i]
		if err := h.buildSigmaVerifyFailureMsg(); err != nil {
			t.Fatal(err)
		}
		handlers[i] = h
		errMsgs[i] = &Message{Id: ids[i], Type: Type_Err2, Body: h.err2Msg.Body}
	}
	return handlers, errMsgs
}
