package main

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	kyberk2so "github.com/symbolicsoft/kyber-k2so"
)

type Request struct {
	Function string            `json:"function"`
	Inputs   map[string]string `json:"inputs"`
	Params   map[string]int64  `json:"params"`
}

type Response struct {
	Outputs     map[string]string `json:"outputs,omitempty"`
	Error       *string           `json:"error,omitempty"`
	Unsupported bool              `json:"unsupported,omitempty"`
}

type Handshake struct {
	Implementation string   `json:"implementation"`
	Functions      []string `json:"functions"`
}

func main() {
	enc := json.NewEncoder(os.Stdout)

	// Send handshake.
	handshake := Handshake{
		Implementation: "kyber-k2so-v1.1.0",
		Functions: []string{
			"Compress_d",
			"Decompress_d",
			"ByteEncode_d",
			"ByteDecode_d",
			"ML_KEM_KeyGen",
			"ML_KEM_Encaps",
			"ML_KEM_Decaps",
		},
	}
	enc.Encode(handshake)

	// Process requests.
	scanner := bufio.NewScanner(os.Stdin)
	// Increase buffer for large inputs.
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			break
		}

		var req Request
		if err := json.Unmarshal([]byte(line), &req); err != nil {
			errMsg := fmt.Sprintf("invalid JSON: %v", err)
			enc.Encode(Response{Error: &errMsg})
			continue
		}

		resp := handleRequest(&req)
		enc.Encode(resp)
	}
}

func handleRequest(req *Request) Response {
	switch req.Function {
	case "Compress_d":
		return handleCompressD(req)
	case "Decompress_d":
		return handleDecompressD(req)
	case "ByteEncode_d":
		return handleByteEncodeD(req)
	case "ByteDecode_d":
		return handleByteDecodeD(req)
	case "NTT":
		return handleNTT(req)
	case "NTT_inv":
		return handleNTTInv(req)
	case "MultiplyNTTs":
		return handleMultiplyNTTs(req)
	case "ML_KEM_KeyGen":
		return handleKeyGen(req)
	case "ML_KEM_Encaps":
		return handleEncaps(req)
	case "ML_KEM_Decaps":
		return handleDecaps(req)
	default:
		return Response{Unsupported: true}
	}
}

func getInputBytes(req *Request, key string) ([]byte, error) {
	hexStr, ok := req.Inputs[key]
	if !ok {
		return nil, fmt.Errorf("missing input '%s'", key)
	}
	return hex.DecodeString(hexStr)
}

func getParam(req *Request, key string) (int64, error) {
	val, ok := req.Params[key]
	if !ok {
		return 0, fmt.Errorf("missing param '%s'", key)
	}
	return val, nil
}

func errResp(msg string) Response {
	return Response{Error: &msg}
}

func okResp(outputs map[string]string) Response {
	return Response{Outputs: outputs}
}

func handleKeyGen(req *Request) Response {
	paramSet, _ := getParam(req, "param_set")
	if paramSet == 0 {
		paramSet = 768
	}

	// Use deterministic keygen if randomness (d||z) is provided.
	randomness, hasRand := req.Inputs["randomness"]
	if hasRand {
		coins, err := hex.DecodeString(randomness)
		if err != nil || len(coins) != 64 {
			return errResp("randomness must be 64 hex-encoded bytes (d||z)")
		}
		var c [64]byte
		copy(c[:], coins)
		var pk, sk []byte
		switch paramSet {
		case 512:
			skArr, pkArr, e := kyberk2so.KemKeypairDerand512(c)
			if e != nil {
				return errResp(fmt.Sprintf("KemKeypairDerand512: %v", e))
			}
			sk = skArr[:]
			pk = pkArr[:]
		case 768:
			skArr, pkArr, e := kyberk2so.KemKeypairDerand768(c)
			if e != nil {
				return errResp(fmt.Sprintf("KemKeypairDerand768: %v", e))
			}
			sk = skArr[:]
			pk = pkArr[:]
		case 1024:
			skArr, pkArr, e := kyberk2so.KemKeypairDerand1024(c)
			if e != nil {
				return errResp(fmt.Sprintf("KemKeypairDerand1024: %v", e))
			}
			sk = skArr[:]
			pk = pkArr[:]
		default:
			return errResp(fmt.Sprintf("unsupported param_set: %d", paramSet))
		}
		return okResp(map[string]string{
			"ek": hex.EncodeToString(pk),
			"dk": hex.EncodeToString(sk),
		})
	}

	// Fallback: random keygen.
	var pk, sk []byte
	switch paramSet {
	case 512:
		skArr, pkArr, e := kyberk2so.KemKeypair512()
		if e != nil {
			return errResp(fmt.Sprintf("KemKeypair512: %v", e))
		}
		sk = skArr[:]
		pk = pkArr[:]
	case 768:
		skArr, pkArr, e := kyberk2so.KemKeypair768()
		if e != nil {
			return errResp(fmt.Sprintf("KemKeypair768: %v", e))
		}
		sk = skArr[:]
		pk = pkArr[:]
	case 1024:
		skArr, pkArr, e := kyberk2so.KemKeypair1024()
		if e != nil {
			return errResp(fmt.Sprintf("KemKeypair1024: %v", e))
		}
		sk = skArr[:]
		pk = pkArr[:]
	default:
		return errResp(fmt.Sprintf("unsupported param_set: %d", paramSet))
	}
	return okResp(map[string]string{
		"ek": hex.EncodeToString(pk),
		"dk": hex.EncodeToString(sk),
	})
}

func handleEncaps(req *Request) Response {
	ekBytes, err := getInputBytes(req, "ek")
	if err != nil {
		return errResp(err.Error())
	}

	// Check for deterministic encaps (randomness = 32-byte message m).
	var m *[32]byte
	if rndHex, ok := req.Inputs["randomness"]; ok {
		rndBytes, e := hex.DecodeString(rndHex)
		if e != nil || len(rndBytes) != 32 {
			return errResp("randomness must be 32 hex-encoded bytes")
		}
		var mb [32]byte
		copy(mb[:], rndBytes)
		m = &mb
	}

	switch len(ekBytes) {
	case kyberk2so.Kyber512PKBytes:
		var pk [kyberk2so.Kyber512PKBytes]byte
		copy(pk[:], ekBytes)
		if m != nil {
			ct, ss, e := kyberk2so.KemEncryptDerand512(pk, *m)
			if e != nil {
				return errResp(fmt.Sprintf("KemEncryptDerand512: %v", e))
			}
			return okResp(map[string]string{"c": hex.EncodeToString(ct[:]), "K": hex.EncodeToString(ss[:])})
		}
		ct, ss, e := kyberk2so.KemEncrypt512(pk)
		if e != nil {
			return errResp(fmt.Sprintf("KemEncrypt512: %v", e))
		}
		return okResp(map[string]string{"c": hex.EncodeToString(ct[:]), "K": hex.EncodeToString(ss[:])})
	case kyberk2so.Kyber768PKBytes:
		var pk [kyberk2so.Kyber768PKBytes]byte
		copy(pk[:], ekBytes)
		if m != nil {
			ct, ss, e := kyberk2so.KemEncryptDerand768(pk, *m)
			if e != nil {
				return errResp(fmt.Sprintf("KemEncryptDerand768: %v", e))
			}
			return okResp(map[string]string{"c": hex.EncodeToString(ct[:]), "K": hex.EncodeToString(ss[:])})
		}
		ct, ss, e := kyberk2so.KemEncrypt768(pk)
		if e != nil {
			return errResp(fmt.Sprintf("KemEncrypt768: %v", e))
		}
		return okResp(map[string]string{"c": hex.EncodeToString(ct[:]), "K": hex.EncodeToString(ss[:])})
	case kyberk2so.Kyber1024PKBytes:
		var pk [kyberk2so.Kyber1024PKBytes]byte
		copy(pk[:], ekBytes)
		if m != nil {
			ct, ss, e := kyberk2so.KemEncryptDerand1024(pk, *m)
			if e != nil {
				return errResp(fmt.Sprintf("KemEncryptDerand1024: %v", e))
			}
			return okResp(map[string]string{"c": hex.EncodeToString(ct[:]), "K": hex.EncodeToString(ss[:])})
		}
		ct, ss, e := kyberk2so.KemEncrypt1024(pk)
		if e != nil {
			return errResp(fmt.Sprintf("KemEncrypt1024: %v", e))
		}
		return okResp(map[string]string{"c": hex.EncodeToString(ct[:]), "K": hex.EncodeToString(ss[:])})
	default:
		return errResp(fmt.Sprintf("invalid encapsulation key length: %d bytes", len(ekBytes)))
	}
}

func handleDecaps(req *Request) Response {
	cBytes, err := getInputBytes(req, "c")
	if err != nil {
		return errResp(err.Error())
	}
	dkBytes, err := getInputBytes(req, "dk")
	if err != nil {
		return errResp(err.Error())
	}

	// Determine param set from dk length.
	switch len(dkBytes) {
	case kyberk2so.Kyber512SKBytes:
		if len(cBytes) != kyberk2so.Kyber512CTBytes {
			return errResp(fmt.Sprintf("invalid ciphertext length for 512: %d", len(cBytes)))
		}
		var sk [kyberk2so.Kyber512SKBytes]byte
		var ct [kyberk2so.Kyber512CTBytes]byte
		copy(sk[:], dkBytes)
		copy(ct[:], cBytes)
		ss, err := kyberk2so.KemDecrypt512(ct, sk)
		if err != nil {
			return errResp(fmt.Sprintf("KemDecrypt512: %v", err))
		}
		return okResp(map[string]string{
			"K": hex.EncodeToString(ss[:]),
		})
	case kyberk2so.Kyber768SKBytes:
		if len(cBytes) != kyberk2so.Kyber768CTBytes {
			return errResp(fmt.Sprintf("invalid ciphertext length for 768: %d", len(cBytes)))
		}
		var sk [kyberk2so.Kyber768SKBytes]byte
		var ct [kyberk2so.Kyber768CTBytes]byte
		copy(sk[:], dkBytes)
		copy(ct[:], cBytes)
		ss, err := kyberk2so.KemDecrypt768(ct, sk)
		if err != nil {
			return errResp(fmt.Sprintf("KemDecrypt768: %v", err))
		}
		return okResp(map[string]string{
			"K": hex.EncodeToString(ss[:]),
		})
	case kyberk2so.Kyber1024SKBytes:
		if len(cBytes) != kyberk2so.Kyber1024CTBytes {
			return errResp(fmt.Sprintf("invalid ciphertext length for 1024: %d", len(cBytes)))
		}
		var sk [kyberk2so.Kyber1024SKBytes]byte
		var ct [kyberk2so.Kyber1024CTBytes]byte
		copy(sk[:], dkBytes)
		copy(ct[:], cBytes)
		ss, err := kyberk2so.KemDecrypt1024(ct, sk)
		if err != nil {
			return errResp(fmt.Sprintf("KemDecrypt1024: %v", err))
		}
		return okResp(map[string]string{
			"K": hex.EncodeToString(ss[:]),
		})
	default:
		return errResp(fmt.Sprintf("invalid decapsulation key length: %d bytes", len(dkBytes)))
	}
}

// ---- Internal function handlers ----

const paramsQ = 3329

// Compress_d: per-coefficient compression using FIPS 203 formula.
// ⌈(2^d / q) · x⌋ mod 2^d = floor((2^d * x + q/2) / q) mod 2^d
func handleCompressD(req *Request) Response {
	d, err := getParam(req, "d")
	if err != nil {
		return errResp(err.Error())
	}
	xBytes, err := getInputBytes(req, "x")
	if err != nil {
		return errResp(err.Error())
	}

	x := uint32(binary.LittleEndian.Uint16(pad2(xBytes)))
	if x >= paramsQ {
		return errResp(fmt.Sprintf("x must be < q=%d, got %d", paramsQ, x))
	}

	twoD := uint64(1) << uint(d)
	y := uint32(((twoD*uint64(x) + paramsQ/2) / paramsQ) % twoD)

	var buf [2]byte
	binary.LittleEndian.PutUint16(buf[:], uint16(y))
	return okResp(map[string]string{"y": hex.EncodeToString(buf[:])})
}

// Decompress_d: per-coefficient decompression.
// ⌈(q / 2^d) · y⌋ = floor((q * y + 2^(d-1)) / 2^d)
func handleDecompressD(req *Request) Response {
	d, err := getParam(req, "d")
	if err != nil {
		return errResp(err.Error())
	}
	yBytes, err := getInputBytes(req, "y")
	if err != nil {
		return errResp(err.Error())
	}

	y := uint32(binary.LittleEndian.Uint16(pad2(yBytes)))
	twoD := uint64(1) << uint(d)
	x := uint32((uint64(paramsQ)*uint64(y) + twoD/2) / twoD)

	var buf [2]byte
	binary.LittleEndian.PutUint16(buf[:], uint16(x))
	return okResp(map[string]string{"x": hex.EncodeToString(buf[:])})
}

// ByteEncode_d / ByteDecode_d: use K2SO's polyToBytes/polyFromBytes for d=12,
// and implement generic versions for other d.
func handleByteEncodeD(req *Request) Response {
	d, err := getParam(req, "d")
	if err != nil {
		return errResp(err.Error())
	}
	fBytes, err := getInputBytes(req, "F")
	if err != nil {
		return errResp(err.Error())
	}

	p := polyFromCrucibleBytes(fBytes)

	if d == 12 {
		dst := make([]byte, 384)
		k2soPolyToBytes(dst, &p)
		return okResp(map[string]string{"B": hex.EncodeToString(dst)})
	}

	// Generic ByteEncode for d < 12.
	encoded := byteEncode(&p, int(d))
	return okResp(map[string]string{"B": hex.EncodeToString(encoded)})
}

func handleByteDecodeD(req *Request) Response {
	d, err := getParam(req, "d")
	if err != nil {
		return errResp(err.Error())
	}
	b, err := getInputBytes(req, "B")
	if err != nil {
		return errResp(err.Error())
	}

	if d == 12 {
		p := k2soPolyFromBytes(b)
		return okResp(map[string]string{"F": hex.EncodeToString(polyToCrucibleBytes(&p))})
	}

	// Generic ByteDecode for d < 12.
	p := byteDecode(b, int(d))
	return okResp(map[string]string{"F": hex.EncodeToString(polyToCrucibleBytes(&p))})
}

// NTT/NTT_inv/MultiplyNTTs: K2SO uses Montgomery domain internally.
// Its ntt/nttInv/baseMul are tightly coupled — the Montgomery factors
// cancel across the full pipeline but don't individually match the
// spec's standard-domain Algorithm 9/10/11 definitions.
// Mark these as unsupported since K2SO doesn't expose spec-standard NTT.
func handleNTT(req *Request) Response {
	return Response{Unsupported: true}
}

func handleNTTInv(req *Request) Response {
	return Response{Unsupported: true}
}

func handleMultiplyNTTs(req *Request) Response {
	return Response{Unsupported: true}
}

// ---- Polynomial <-> Crucible byte format conversion ----

// Crucible sends polynomials as 512 bytes: 256 coefficients × 2 bytes LE each.
func polyFromCrucibleBytes(b []byte) poly {
	var p poly
	for i := 0; i < 256 && i*2+1 < len(b); i++ {
		p[i] = int16(binary.LittleEndian.Uint16(b[2*i : 2*i+2]))
	}
	return p
}

func polyToCrucibleBytes(p *poly) []byte {
	b := make([]byte, 512)
	for i := 0; i < 256; i++ {
		// Ensure positive representation.
		v := p[i]
		if v < 0 {
			v += paramsQ
		}
		binary.LittleEndian.PutUint16(b[2*i:], uint16(v))
	}
	return b
}

// pad2 ensures a byte slice is at least 2 bytes (for Uint16 reads).
func pad2(b []byte) []byte {
	if len(b) >= 2 {
		return b[:2]
	}
	var buf [2]byte
	copy(buf[:], b)
	return buf[:]
}

// ---- Generic ByteEncode/ByteDecode for d < 12 ----

func byteEncode(f *poly, d int) []byte {
	bits := make([]byte, 256*d)
	for i := 0; i < 256; i++ {
		a := uint32(f[i])
		for j := 0; j < d; j++ {
			bits[i*d+j] = byte(a & 1)
			a >>= 1
		}
	}
	return bitsToBytes(bits)
}

func byteDecode(b []byte, d int) poly {
	bits := bytesToBits(b)
	m := uint32(1) << uint(d)
	if d == 12 {
		m = paramsQ
	}
	var p poly
	for i := 0; i < 256; i++ {
		var val uint32
		for j := d - 1; j >= 0; j-- {
			val = 2*val + uint32(bits[i*d+j])
		}
		p[i] = int16(val % m)
	}
	return p
}

func bitsToBytes(bits []byte) []byte {
	byteLen := (len(bits) + 7) / 8
	bytes := make([]byte, byteLen)
	for i, bit := range bits {
		bytes[i/8] |= bit << uint(i%8)
	}
	return bytes
}

func bytesToBits(bytes []byte) []byte {
	bits := make([]byte, len(bytes)*8)
	for i, b := range bytes {
		for j := 0; j < 8; j++ {
			bits[8*i+j] = (b >> uint(j)) & 1
		}
	}
	return bits
}
