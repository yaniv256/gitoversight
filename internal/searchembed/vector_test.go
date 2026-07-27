package searchembed

import (
	"math"
	"reflect"
	"testing"
)

func TestBaseVectorDeterministic(t *testing.T) {
	a := BaseVector("kanban")
	b := BaseVector("kanban")
	if !reflect.DeepEqual(a, b) {
		t.Fatal("same token produced different base vectors across calls")
	}
	if len(a) != Dims {
		t.Fatalf("base vector length = %d, want %d", len(a), Dims)
	}
	nonZero := 0
	for _, x := range a {
		switch x {
		case 0:
		case 1, -1:
			nonZero++
		default:
			t.Fatalf("base vector component %v, want 0 or ±1", x)
		}
	}
	if nonZero != 8 {
		t.Fatalf("base vector has %d non-zeros, want 8", nonZero)
	}
	if reflect.DeepEqual(a, BaseVector("launcher")) {
		t.Fatal("different tokens produced identical base vectors")
	}
}

func floatCosine(a, b []float64) float64 {
	var dot, na, nb float64
	for i := range a {
		dot += a[i] * b[i]
		na += a[i] * a[i]
		nb += b[i] * b[i]
	}
	if na == 0 || nb == 0 {
		return 0
	}
	return dot / (math.Sqrt(na) * math.Sqrt(nb))
}

func addScaled(dst, src []float64, w float64) {
	for i := range dst {
		dst[i] += w * src[i]
	}
}

func TestCosineInt8SelfIsOne(t *testing.T) {
	v := BaseVector("alpha")
	addScaled(v, BaseVector("beta"), 0.5)
	q := Quantize(v)
	if c := CosineInt8(q, q); math.Abs(c-1) > 1e-6 {
		t.Fatalf("self cosine = %v, want 1", c)
	}
}

// TestQuantizeCosinePreservesOrdering checks that int8 quantization keeps the
// relative ordering of cosine similarities seen in float space on fixture
// pairs: a is much closer to b (shared components) than to c (disjoint).
func TestQuantizeCosinePreservesOrdering(t *testing.T) {
	mix := func(tokens ...string) []float64 {
		v := make([]float64, Dims)
		for i, tok := range tokens {
			addScaled(v, BaseVector(tok), 1/float64(i+1))
		}
		return v
	}
	a := mix("kanban", "board", "agent", "tasks")
	b := mix("kanban", "board", "cards")
	c := mix("sourdough", "carbonara", "rosemary")

	fab, fac := floatCosine(a, b), floatCosine(a, c)
	if fab <= fac {
		t.Fatalf("fixture broken: float cos(a,b)=%v should exceed cos(a,c)=%v", fab, fac)
	}
	qa, qb, qc := Quantize(a), Quantize(b), Quantize(c)
	qab, qac := CosineInt8(qa, qb), CosineInt8(qa, qc)
	if qab <= qac {
		t.Fatalf("quantized ordering flipped: cos(a,b)=%v <= cos(a,c)=%v (float: %v vs %v)", qab, qac, fab, fac)
	}
	// The quantized cosine should also approximate the float cosine.
	if math.Abs(qab-fab) > 0.05 {
		t.Fatalf("quantized cos(a,b)=%v drifted from float %v", qab, fab)
	}
}

func TestQuantizeShape(t *testing.T) {
	q := Quantize(make([]float64, Dims))
	if len(q) != Dims {
		t.Fatalf("quantized length = %d, want %d", len(q), Dims)
	}
	for _, b := range q {
		if b != 0 {
			t.Fatal("zero vector must quantize to all zeros")
		}
	}
	v := make([]float64, 4)
	v[1] = 0.5
	v[3] = -1.0
	got := Quantize(v)
	if int8(got[3]) != -127 || int8(got[1]) != 64 && int8(got[1]) != 63 {
		t.Fatalf("quantize scaling wrong: %v", []int8{int8(got[0]), int8(got[1]), int8(got[2]), int8(got[3])})
	}
}
