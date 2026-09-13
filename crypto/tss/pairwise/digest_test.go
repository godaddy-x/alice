package pairwise

import "testing"

func TestEdgeDigestStableAndSensitive(t *testing.T) {
	dst := "AMIS-Alice-Test-Pairwise-Digest"
	ssid := []byte("ssid")
	d1 := EdgeDigest(dst, ssid, "R1", "a", "b", []byte("payload"))
	d2 := EdgeDigest(dst, ssid, "R1", "a", "b", []byte("payload"))
	if string(d1) != string(d2) {
		t.Fatal("digest not stable")
	}
	d3 := EdgeDigest(dst, ssid, "R1", "a", "b", []byte("payloae"))
	if string(d1) == string(d3) {
		t.Fatal("payload change should alter digest")
	}
	if len(d1) != DigestLen {
		t.Fatalf("expected %d bytes, got %d", DigestLen, len(d1))
	}
}

func TestValidateTable(t *testing.T) {
	dst := "AMIS-Alice-Test-Pairwise-Digest"
	ssid := []byte("ssid")
	sender := "s"
	peers := []string{"p1", "p2"}
	digests := map[string][]byte{
		"p1": EdgeDigest(dst, ssid, "R1", sender, "p1", []byte("a")),
		"p2": EdgeDigest(dst, ssid, "R1", sender, "p2", []byte("b")),
	}
	entries, root := CommitTable(dst, ssid, "R1", sender, digests)
	if _, err := ValidateTable(dst, ssid, "R1", sender, peers, entries, root); err != nil {
		t.Fatalf("valid table rejected: %v", err)
	}
	if _, err := ValidateTable(dst, ssid, "R1", sender, peers, entries[:1], root); err != ErrPairwiseDigestTable {
		t.Fatalf("expected table error, got %v", err)
	}
	badRoot := append([]byte(nil), root...)
	badRoot[0] ^= 0xff
	if _, err := ValidateTable(dst, ssid, "R1", sender, peers, entries, badRoot); err != ErrDigestTableRoot {
		t.Fatalf("expected root error, got %v", err)
	}
}

func TestStoreGetMiss(t *testing.T) {
	store := NewStore()
	if _, ok := store.Get(Round1, "a", "b"); ok {
		t.Fatal("expected miss")
	}
	want := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2}
	store.SetFinalized(Round1, "a", map[string][]byte{"b": want})
	got, ok := store.Get(Round1, "a", "b")
	if !ok || string(got) != string(want) {
		t.Fatal("expected hit with copy")
	}
	if !store.HasAny(Round1) {
		t.Fatal("expected HasAny true")
	}
}
