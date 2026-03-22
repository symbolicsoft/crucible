package main

import (
	_ "unsafe"

	_ "github.com/symbolicsoft/kyber-k2so"
)

// Access unexported K2SO internals via go:linkname.
// These are the internal functions Crucible needs to test.

type poly = [256]int16

//go:linkname k2soNtt github.com/symbolicsoft/kyber-k2so.ntt
func k2soNtt(p *poly) poly

//go:linkname k2soNttInv github.com/symbolicsoft/kyber-k2so.nttInv
func k2soNttInv(p *poly) poly

//go:linkname k2soNttFqMul github.com/symbolicsoft/kyber-k2so.nttFqMul
func k2soNttFqMul(a int16, b int16) int16

//go:linkname k2soNttBaseMul github.com/symbolicsoft/kyber-k2so.nttBaseMul
func k2soNttBaseMul(a0 int16, a1 int16, b0 int16, b1 int16, zeta int16) [2]int16

//go:linkname k2soPolyToBytes github.com/symbolicsoft/kyber-k2so.polyToBytes
func k2soPolyToBytes(dst []byte, a *poly)

//go:linkname k2soPolyFromBytes github.com/symbolicsoft/kyber-k2so.polyFromBytes
func k2soPolyFromBytes(a []byte) poly

//go:linkname k2soPolyCompress github.com/symbolicsoft/kyber-k2so.polyCompress
func k2soPolyCompress(dst []byte, a *poly, paramsK int)

//go:linkname k2soPolyDecompress github.com/symbolicsoft/kyber-k2so.polyDecompress
func k2soPolyDecompress(a []byte, paramsK int) poly

//go:linkname k2soByteopsBarrettReduce github.com/symbolicsoft/kyber-k2so.byteopsBarrettReduce
func k2soByteopsBarrettReduce(a int16) int16

//go:linkname k2soByteopsCSubQ github.com/symbolicsoft/kyber-k2so.byteopsCSubQ
func k2soByteopsCSubQ(a int16) int16

//go:linkname k2soPolyBaseMulMontgomery github.com/symbolicsoft/kyber-k2so.polyBaseMulMontgomery
func k2soPolyBaseMulMontgomery(a *poly, b *poly) poly

//go:linkname k2soPolyReduceFull github.com/symbolicsoft/kyber-k2so.polyReduceFull
func k2soPolyReduceFull(p *poly) poly

//go:linkname k2soPolyNtt github.com/symbolicsoft/kyber-k2so.polyNtt
func k2soPolyNtt(p *poly) poly

//go:linkname k2soPolyInvNttToMont github.com/symbolicsoft/kyber-k2so.polyInvNttToMont
func k2soPolyInvNttToMont(p *poly) poly
