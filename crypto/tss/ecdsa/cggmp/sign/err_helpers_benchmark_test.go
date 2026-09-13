package sign

import (
	"math/big"
	"testing"

	paillierzkproof "github.com/getamis/alice/crypto/zkproof/paillier"
)

// BenchmarkMatchDecModQMaskEnum8 measures worst-case PublicX enumeration (2^8 VerifyModQ).
func BenchmarkMatchDecModQMaskEnum8(b *testing.B) {
	q := errTestPublicKey.GetCurve().Params().N
	share := big.NewInt(3)
	C := big.NewInt(12345)
	peerNs := make(map[string]*big.Int, 8)
	for i := 0; i < 8; i++ {
		id := string(rune('a' + i))
		peerNs[id] = new(big.Int).Add(errPaillierKeyA.GetN(), big.NewInt(int64(i+1000)))
	}
	// Proof for a wrong x - every mask fails; still exercises full 256 VerifyModQ loop.
	proof, err := paillierzkproof.NewDecModQMessage(
		paillierzkproof.NewS256(), []byte("bench"), big.NewInt(1), big.NewInt(1),
		errPaillierKeyA.GetN(), C, big.NewInt(1), errPedZKA,
	)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = matchDecModQWithBetaCorrection(
			proof, []byte("bench"), errPaillierKeyA.GetN(), C, share, q, peerNs, errPedZKA,
		)
	}
}
