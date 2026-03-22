package main

import (
	"io"
	_ "unsafe"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/cloudflare/circl/sign/mldsa/mldsa87"

	// Ensure internal packages are linked.
	_ "github.com/cloudflare/circl/kem/mlkem/mlkem512"
	_ "github.com/cloudflare/circl/kem/mlkem/mlkem768"
	_ "github.com/cloudflare/circl/kem/mlkem/mlkem1024"
)

// Access unexported CIRCL internal SignTo via go:linkname.
// The internal SignTo takes msg as func(io.Writer) and the raw rnd [32]byte.
// This is ML-DSA.Sign_internal per FIPS 204.

//go:linkname internalSignTo44 github.com/cloudflare/circl/sign/mldsa/mldsa44/internal.SignTo
func internalSignTo44(sk *mldsa44.PrivateKey, msg func(io.Writer), rnd [32]byte, signature []byte)

//go:linkname internalSignTo65 github.com/cloudflare/circl/sign/mldsa/mldsa65/internal.SignTo
func internalSignTo65(sk *mldsa65.PrivateKey, msg func(io.Writer), rnd [32]byte, signature []byte)

//go:linkname internalSignTo87 github.com/cloudflare/circl/sign/mldsa/mldsa87/internal.SignTo
func internalSignTo87(sk *mldsa87.PrivateKey, msg func(io.Writer), rnd [32]byte, signature []byte)

// circlSignTo44 signs using ML-DSA-44 with the given rnd value.
// Constructs M' = IntegerToBytes(0,1) || IntegerToBytes(|ctx|,1) || ctx || M
// with empty context (ctx = ""), so M' = 0x00 || 0x00 || msg.
func circlSignTo44(sk *mldsa44.PrivateKey, msg []byte, rnd [32]byte, sig []byte) {
	internalSignTo44(sk, func(w io.Writer) {
		w.Write([]byte{0, 0})
		w.Write(msg)
	}, rnd, sig)
}

func circlSignTo65(sk *mldsa65.PrivateKey, msg []byte, rnd [32]byte, sig []byte) {
	internalSignTo65(sk, func(w io.Writer) {
		w.Write([]byte{0, 0})
		w.Write(msg)
	}, rnd, sig)
}

func circlSignTo87(sk *mldsa87.PrivateKey, msg []byte, rnd [32]byte, sig []byte) {
	internalSignTo87(sk, func(w io.Writer) {
		w.Write([]byte{0, 0})
		w.Write(msg)
	}, rnd, sig)
}
