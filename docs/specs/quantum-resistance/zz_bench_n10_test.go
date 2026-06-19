package main

// Read-only measurement harness added for the Gao-vs-MatRiCT-Au benchmark.
// Lives in the gao-ringct reference repo (NOT conceal-core / matrict-lib).
// Measures: structural serialized proof size (bytes), prove ms, verify ms for
// Gao's LinearSum ring signature and MatRiCT's OneOutOfMany ring signature, at
// ring sizes N=8 (closest below 10), N=10 (custom), N=16 (closest above).
//
// There is no serializer in the repo, so size is computed as:
//   total ring elements * d coefficients * bytesPerCoeff
// with bytesPerCoeff = ceil(bitlen(q)/8) (tight packing of each coeff mod q),
// plus the 1-element Fiat-Shamir challenge x (reported separately).

import (
	"fmt"
	"testing"
	"time"

	"github.com/dedis/lago/polynomial"
	"github.com/dedis/lago/ring"
)

// bytesPerCoeff returns ceil(bitlen(q)/8) for the current settings modulus.
func bytesPerCoeff() int {
	bits := settings.q.Value.BitLen()
	return (bits + 7) / 8
}

// ringMartixElems returns the number of ring elements (polynomials) in a matrix.
func ringMartixElems(m *RingMartix) int {
	if m == nil {
		return 0
	}
	return int(m.col) * int(m.row)
}

// proofElems sums ring elements in a (B,f,zb,zr,Ev) ring-signature proof.
func proofElems(B, f, zb, zr *RingMartix, Ev []RingMartix) int {
	n := ringMartixElems(B) + ringMartixElems(f) + ringMartixElems(zb) + ringMartixElems(zr)
	for i := range Ev {
		n += ringMartixElems(&Ev[i])
	}
	return n
}

// buildSetting mirrors setLinearSumSetting/setOneOutOfManySetting but with an
// explicit ring size N (beta=N, k=1) so we can run N=10 directly.
func buildSetting(N uint32) (Ga, Gb, pr *RingMartix, Pv []RingMartix, beta, k, l uint32) {
	setTestSettings()
	beta = N
	k = uint32(1)
	l = uint32(0)

	r := new(ring.Ring)
	r.N = settings.d
	r.Q = settings.q
	r.Poly, _ = polynomial.NewPolynomial(settings.d, settings.q, settings.nttParams)

	va := beta
	vb := k*va + settings.m
	Ga, _ = SamMat(va, 0)
	Gb, _ = SamMat(vb, 0)

	Pv = make([]RingMartix, N)
	rv := make([]RingMartix, N)
	zero, _ := NewRingMartix(beta, 1, settings.nttParams)
	zero.SetZeroRingMartix(r, settings.d)
	for i := uint32(0); i < N; i++ {
		Pui, pri, _ := Commitment(Ga, zero, 10)
		Pv[i] = *Pui
		rv[i] = *pri
	}
	pr = &rv[l]
	return
}

// timeMs runs f reps times and returns the mean ms.
func timeMs(reps int, f func()) float64 {
	// warm up
	f()
	start := time.Now()
	for i := 0; i < reps; i++ {
		f()
	}
	return float64(time.Since(start).Microseconds()) / float64(reps) / 1000.0
}

// proveOnce runs the proof generator once and returns the proof + validity.
func proveOnce(isGao bool, Ga, Gb, pr *RingMartix, l, k, beta uint32, Pv []RingMartix) (B, f, zb, zr *RingMartix, Ev []RingMartix, x *ring.Ring, ok bool) {
	if isGao {
		B, f, zb, zr, Ev, x, _ = LinearSumProof(Ga, Gb, pr, l, k, beta, Pv, 20, 14)
		ok, _ = LinearSumVerify(Ga, Gb, B, f, zb, zr, Pv, Ev, x)
	} else {
		B, f, zb, zr, Ev, x, _ = OneOutOfManyProof(Ga, Gb, pr, l, k, beta, Pv, 20, 14)
		ok, _ = OneOutOfManyVerify(Ga, Gb, B, f, zb, zr, Pv, Ev, x)
	}
	return
}

func runOne(label string, N uint32, isGao bool, reps int) {
	Ga, Gb, pr, Pv, beta, k, l := buildSetting(N)
	d := int(settings.d)
	bpc := bytesPerCoeff()

	// Get one VALID proof (rejection sampling => retry up to maxTry). Both
	// schemes can produce out-of-bound (invalid) proofs that real code would
	// re-roll; we re-roll to capture a representative valid proof for sizing.
	var B, f, zb, zr *RingMartix
	var Ev []RingMartix
	var x *ring.Ring
	var ok bool
	validTries := 0
	maxTry := 40
	for try := 0; try < maxTry; try++ {
		B, f, zb, zr, Ev, x, ok = proveOnce(isGao, Ga, Gb, pr, l, k, beta, Pv)
		validTries++
		if ok {
			break
		}
	}

	// prove timing (raw generator, no verify), reps runs
	proveMs := timeMs(reps, func() {
		if isGao {
			_, _, _, _, _, _, _ = LinearSumProof(Ga, Gb, pr, l, k, beta, Pv, 20, 14)
		} else {
			_, _, _, _, _, _, _ = OneOutOfManyProof(Ga, Gb, pr, l, k, beta, Pv, 20, 14)
		}
	})

	// verify timing on the captured valid proof
	verifyMs := timeMs(reps, func() {
		if isGao {
			_, _ = LinearSumVerify(Ga, Gb, B, f, zb, zr, Pv, Ev, x)
		} else {
			_, _ = OneOutOfManyVerify(Ga, Gb, B, f, zb, zr, Pv, Ev, x)
		}
	})

	elems := proofElems(B, f, zb, zr, Ev)
	xElems := 1 // Fiat-Shamir challenge polynomial (normally not transmitted)
	bytesNoX := elems * d * bpc
	bytesWithX := (elems + xElems) * d * bpc

	fmt.Printf("RESULT scheme=%-14s N=%-3d valid=%-5v tries=%d d=%d q_bytes/coeff=%d proof_elems=%d size_noX=%d B (%.2f KB) size_withX=%d B prove_ms=%.3f verify_ms=%.3f\n",
		label, N, ok, validTries, d, bpc, elems, bytesNoX, float64(bytesNoX)/1024.0, bytesWithX, proveMs, verifyMs)
}

func TestMeasureRingSigN10(t *testing.T) {
	reps := 20
	fmt.Println("=== GAO (LinearSum, 'this work') ring signature ===")
	for _, N := range []uint32{8, 10, 16} {
		runOne("Gao-LinearSum", N, true, reps)
	}
	fmt.Println("=== MatRiCT (OneOutOfMany) ring signature ===")
	for _, N := range []uint32{8, 10, 16} {
		runOne("MatRiCT-OOOM", N, false, reps)
	}
}
