// Crucible ML-KEM Harness Template — Go
//
// Fill in the TODO sections to wire your ML-KEM implementation to Crucible.
// Each function receives hex-decoded byte inputs and returns hex-encoded outputs.
//
// Build: go build -o harness-yourname .
// Run:   crucible ./harness-yourname

package main

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
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

	// TODO: Update implementation name and supported functions list.
	enc.Encode(Handshake{
		Implementation: "your-implementation-name",
		Functions: []string{
			// List only functions your harness implements.
			"Compress_d",
			"Decompress_d",
			"ByteEncode_d",
			"ByteDecode_d",
			"NTT",
			"NTT_inv",
			"MultiplyNTTs",
			"SamplePolyCBD",
			"SampleNTT",
			"ML_KEM_KeyGen",
			"ML_KEM_Encaps",
			"ML_KEM_Decaps",
		},
	})

	scanner := bufio.NewScanner(os.Stdin)
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
		enc.Encode(handle(&req))
	}
}

func handle(req *Request) Response {
	switch req.Function {
	case "Compress_d":
		return handleCompressD(req)
	case "Decompress_d":
		return handleDecompressD(req)
	case "ML_KEM_KeyGen":
		return handleKeyGen(req)
	case "ML_KEM_Encaps":
		return handleEncaps(req)
	case "ML_KEM_Decaps":
		return handleDecaps(req)
	// TODO: Add cases for all functions you support.
	default:
		return Response{Unsupported: true}
	}
}

// ---- Helpers ----

func getBytes(req *Request, key string) ([]byte, error) {
	h, ok := req.Inputs[key]
	if !ok {
		return nil, fmt.Errorf("missing input '%s'", key)
	}
	return hex.DecodeString(h)
}

func getParam(req *Request, key string) (int64, bool) {
	v, ok := req.Params[key]
	return v, ok
}

func errResp(msg string) Response {
	return Response{Error: &msg}
}

func okResp(outputs map[string]string) Response {
	return Response{Outputs: outputs}
}

// ---- Function handlers ----
// Polynomials: 512 bytes = 256 coefficients × 2 bytes little-endian.

func handleCompressD(req *Request) Response {
	d, _ := getParam(req, "d")
	xBytes, err := getBytes(req, "x")
	if err != nil {
		return errResp(err.Error())
	}
	x := uint32(binary.LittleEndian.Uint16(pad2(xBytes)))

	// TODO: Call your Compress_d(x, d).
	var y uint32
	_ = d
	_ = x
	panic("TODO: implement Compress_d")

	var buf [2]byte
	binary.LittleEndian.PutUint16(buf[:], uint16(y))
	return okResp(map[string]string{"y": hex.EncodeToString(buf[:])})
}

func handleDecompressD(req *Request) Response {
	d, _ := getParam(req, "d")
	yBytes, err := getBytes(req, "y")
	if err != nil {
		return errResp(err.Error())
	}
	y := uint32(binary.LittleEndian.Uint16(pad2(yBytes)))

	// TODO: Call your Decompress_d(y, d).
	var x uint32
	_ = d
	_ = y
	panic("TODO: implement Decompress_d")

	var buf [2]byte
	binary.LittleEndian.PutUint16(buf[:], uint16(x))
	return okResp(map[string]string{"x": hex.EncodeToString(buf[:])})
}

func handleKeyGen(req *Request) Response {
	// Input "randomness": 64 bytes (d||z). Param "param_set": 512/768/1024.
	// Output "ek", "dk".
	panic("TODO: implement ML_KEM_KeyGen")
}

func handleEncaps(req *Request) Response {
	// Input "ek": encapsulation key, "randomness": 32 bytes.
	// Output "c": ciphertext, "K": shared secret.
	panic("TODO: implement ML_KEM_Encaps")
}

func handleDecaps(req *Request) Response {
	// Input "c": ciphertext, "dk": decapsulation key.
	// Output "K": shared secret.
	panic("TODO: implement ML_KEM_Decaps")
}

func pad2(b []byte) []byte {
	if len(b) >= 2 {
		return b[:2]
	}
	var buf [2]byte
	copy(buf[:], b)
	return buf[:]
}
