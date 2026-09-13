// Copyright © 2022 AMIS Technologies
package pairwise

// CloneBytes returns a deep copy of b.
func CloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	return append([]byte(nil), b...)
}
