package main

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/trailofbits/ml-dsa/mldsa44"
	"github.com/trailofbits/ml-dsa/mldsa65"
	"github.com/trailofbits/ml-dsa/mldsa87"
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

	enc.Encode(Handshake{
		Implementation: "tob-mldsa-v0.1.0",
		Functions: []string{
			"ML_KEM_KeyGen",
			"ML_KEM_Encaps",
			"ML_KEM_Decaps",
			"ML_DSA_KeyGen",
			"ML_DSA_Sign",
			"ML_DSA_Verify",
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
	case "ML_KEM_KeyGen", "ML_KEM_Encaps", "ML_KEM_Decaps":
		// This library only implements ML-DSA, not ML-KEM.
		return Response{Unsupported: true}
	case "ML_DSA_KeyGen":
		return handleDSAKeyGen(req)
	case "ML_DSA_Sign":
		return handleDSASign(req)
	case "ML_DSA_Verify":
		return handleDSAVerify(req)
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

// ---- ML-DSA ----

func handleDSAKeyGen(req *Request) Response {
	seed, err := getBytes(req, "seed")
	if err != nil {
		return errResp(err.Error())
	}
	if len(seed) != 32 {
		return errResp(fmt.Sprintf("seed must be 32 bytes, got %d", len(seed)))
	}

	paramSet, _ := getParam(req, "param_set")

	// Use GenerateKeyPair with a seed reader for deterministic keygen.
	// This returns the correctly typed *PublicKey and *PrivateKey.
	seedReader := bytes.NewReader(seed)

	switch paramSet {
	case 44:
		pk, sk, err := mldsa44.GenerateKeyPair(seedReader)
		if err != nil {
			return errResp(fmt.Sprintf("GenerateKeyPair: %v", err))
		}
		return okResp(map[string]string{
			"pk": hex.EncodeToString(pk.Bytes()),
			"sk": hex.EncodeToString(sk.EncodeExpanded()),
		})
	case 65:
		pk, sk, err := mldsa65.GenerateKeyPair(seedReader)
		if err != nil {
			return errResp(fmt.Sprintf("GenerateKeyPair: %v", err))
		}
		return okResp(map[string]string{
			"pk": hex.EncodeToString(pk.Bytes()),
			"sk": hex.EncodeToString(sk.EncodeExpanded()),
		})
	case 87:
		pk, sk, err := mldsa87.GenerateKeyPair(seedReader)
		if err != nil {
			return errResp(fmt.Sprintf("GenerateKeyPair: %v", err))
		}
		return okResp(map[string]string{
			"pk": hex.EncodeToString(pk.Bytes()),
			"sk": hex.EncodeToString(sk.EncodeExpanded()),
		})
	default:
		return errResp(fmt.Sprintf("unsupported param_set: %d", paramSet))
	}
}

func handleDSASign(req *Request) Response {
	skBytes, err := getBytes(req, "sk")
	if err != nil {
		return errResp(err.Error())
	}
	message, err := getBytes(req, "message")
	if err != nil {
		return errResp(err.Error())
	}
	rnd, err := getBytes(req, "rnd")
	if err != nil {
		return errResp(err.Error())
	}
	if len(rnd) != 32 {
		return errResp(fmt.Sprintf("rnd must be 32 bytes, got %d", len(rnd)))
	}

	paramSet, _ := getParam(req, "param_set")

	// The ToB library's Sign(rand io.Reader, message, opts) reads 32 bytes
	// of randomness from the reader. We use a bytes.Reader to inject our rnd.
	rndReader := bytes.NewReader(rnd)

	switch paramSet {
	case 44:
		sk, err := mldsa44.PrivateKeyFromExpanded(skBytes)
		if err != nil {
			return errResp(fmt.Sprintf("invalid sk: %v", err))
		}
		sig, err := sk.Sign(rndReader, message, nil)
		if err != nil {
			return errResp(fmt.Sprintf("Sign: %v", err))
		}
		return okResp(map[string]string{
			"sigma": hex.EncodeToString(sig),
		})
	case 65:
		sk, err := mldsa65.PrivateKeyFromExpanded(skBytes)
		if err != nil {
			return errResp(fmt.Sprintf("invalid sk: %v", err))
		}
		sig, err := sk.Sign(rndReader, message, nil)
		if err != nil {
			return errResp(fmt.Sprintf("Sign: %v", err))
		}
		return okResp(map[string]string{
			"sigma": hex.EncodeToString(sig),
		})
	case 87:
		sk, err := mldsa87.PrivateKeyFromExpanded(skBytes)
		if err != nil {
			return errResp(fmt.Sprintf("invalid sk: %v", err))
		}
		sig, err := sk.Sign(rndReader, message, nil)
		if err != nil {
			return errResp(fmt.Sprintf("Sign: %v", err))
		}
		return okResp(map[string]string{
			"sigma": hex.EncodeToString(sig),
		})
	default:
		return errResp(fmt.Sprintf("unsupported param_set: %d", paramSet))
	}
}

func handleDSAVerify(req *Request) Response {
	pkBytes, err := getBytes(req, "pk")
	if err != nil {
		return errResp(err.Error())
	}
	message, err := getBytes(req, "message")
	if err != nil {
		return errResp(err.Error())
	}
	sigBytes, err := getBytes(req, "sigma")
	if err != nil {
		return errResp(err.Error())
	}

	paramSet, _ := getParam(req, "param_set")

	switch paramSet {
	case 44:
		pk, err := mldsa44.PublicKeyFromBytes(pkBytes)
		if err != nil {
			return errResp(fmt.Sprintf("invalid pk: %v", err))
		}
		valid := pk.Verify(message, sigBytes)
		if valid {
			return okResp(map[string]string{"valid": "01"})
		}
		return okResp(map[string]string{"valid": "00"})
	case 65:
		pk, err := mldsa65.PublicKeyFromBytes(pkBytes)
		if err != nil {
			return errResp(fmt.Sprintf("invalid pk: %v", err))
		}
		valid := pk.Verify(message, sigBytes)
		if valid {
			return okResp(map[string]string{"valid": "01"})
		}
		return okResp(map[string]string{"valid": "00"})
	case 87:
		pk, err := mldsa87.PublicKeyFromBytes(pkBytes)
		if err != nil {
			return errResp(fmt.Sprintf("invalid pk: %v", err))
		}
		valid := pk.Verify(message, sigBytes)
		if valid {
			return okResp(map[string]string{"valid": "01"})
		}
		return okResp(map[string]string{"valid": "00"})
	default:
		return errResp(fmt.Sprintf("unsupported param_set: %d", paramSet))
	}
}
