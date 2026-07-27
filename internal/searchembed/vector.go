package searchembed

import (
	"hash/fnv"
	"math"
)

// Dims is the embedding dimensionality.
const Dims = 768

// baseNonZeros is how many ±1 components a base random-indexing vector has.
const baseNonZeros = 8

// splitmix64 is a tiny deterministic PRNG step (Steele et al.); good spectral
// properties from any seed, which lets FNV-1a token hashes drive it directly.
func splitmix64(state *uint64) uint64 {
	*state += 0x9e3779b97f4a7c15
	z := *state
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}

// BaseVector returns the deterministic sparse random-indexing vector for
// token: 8 distinct dimensions of Dims set to ±1, chosen by a splitmix64
// stream seeded with FNV-1a(token). The same token always yields the
// identical vector.
func BaseVector(token string) []float64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(token))
	state := h.Sum64()
	v := make([]float64, Dims)
	for placed := 0; placed < baseNonZeros; {
		r := splitmix64(&state)
		dim := int(r % Dims)
		if v[dim] != 0 {
			continue // collision: draw again for a distinct dimension
		}
		if (r>>32)&1 == 1 {
			v[dim] = 1
		} else {
			v[dim] = -1
		}
		placed++
	}
	return v
}

// l2Normalize scales v to unit length in place. The zero vector stays zero.
func l2Normalize(v []float64) {
	var sum float64
	for _, x := range v {
		sum += x * x
	}
	if sum == 0 {
		return
	}
	inv := 1 / math.Sqrt(sum)
	for i := range v {
		v[i] *= inv
	}
}

// Quantize maps a float vector to int8 components stored as bytes (two's
// complement): each component is scaled by 127/maxAbs and rounded. The zero
// vector quantizes to all zeros.
func Quantize(v []float64) []byte {
	out := make([]byte, len(v))
	var maxAbs float64
	for _, x := range v {
		if a := math.Abs(x); a > maxAbs {
			maxAbs = a
		}
	}
	if maxAbs == 0 {
		return out
	}
	scale := 127 / maxAbs
	for i, x := range v {
		q := math.Round(x * scale)
		if q > 127 {
			q = 127
		} else if q < -127 {
			q = -127
		}
		out[i] = byte(int8(q))
	}
	return out
}

// CosineInt8 computes cosine similarity between two int8-quantized vectors
// (as produced by Quantize) in float64. Mismatched lengths compare the
// common prefix; a zero vector yields 0.
func CosineInt8(a, b []byte) float64 {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	var dot, na, nb float64
	for i := 0; i < n; i++ {
		x := float64(int8(a[i]))
		y := float64(int8(b[i]))
		dot += x * y
		na += x * x
		nb += y * y
	}
	if na == 0 || nb == 0 {
		return 0
	}
	return dot / (math.Sqrt(na) * math.Sqrt(nb))
}
