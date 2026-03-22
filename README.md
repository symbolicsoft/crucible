# Crucible

**Cryptographic implementation conformance testing, forged from real-world audit findings.**

Crucible tests ML-KEM (FIPS 203) and ML-DSA (FIPS 204) implementations by targeting the specific bug classes that Symbolic Software has found repeatedly in production cryptographic code — including code marketed as "formally verified" and "high-assurance."

NIST's Known Answer Tests verify final outputs. Formal verification tools verify abstract models. Neither catches the bugs that live in between. Crucible does.

---

## Quick Start

```bash
# Build Crucible
cargo build --release

# Run the ML-KEM battery against an implementation
cargo run --bin crucible -- ./target/debug/harness-reference

# Run with JSON output
cargo run --bin crucible -- ./target/debug/harness-reference --json

# Run the ML-DSA battery
cargo run --bin crucible -- ./target/harness-circl --battery ml-dsa
```

## What It Tests

### ML-KEM (FIPS 203) — 78 tests across 6 categories

| Category | Tests | What it catches |
|---|---|---|
| 1. Compression | 4 | Rounding errors in Compress/Decompress, floating-point arithmetic (§3.3 violation) |
| 2. NTT | 7 | Wrong zeta ordering, missing inverse NTT, multiply bugs, plus black-box keygen/encaps/decaps correctness |
| 3. Bounds | 3 | Dead bounds checks, encapsulation key modulus bypass (§7.2), bit-boundary encoding errors |
| 4. Decapsulation | 4 | Missing implicit rejection, FO re-encryption bypass, wrong-length key/ciphertext acceptance |
| 5. Serialization | 4 | ByteEncode/Decode round-trip failures, mod-q reduction errors, key length validation |
| 6. Sampling | 4 | CBD distribution errors, SampleNTT rejection failures, non-determinism |

### ML-DSA (FIPS 204) — 51 tests across 6 categories

| Category | Tests | What it catches |
|---|---|---|
| 1. Norm Checks | 3 | z-norm bound bypass, malformed hint acceptance, basic sign/verify correctness |
| 2. Arithmetic | 3 | Power2Round boundary errors, Decompose edge cases, NTT correctness |
| 3. Signing | 3 | Deterministic signing divergence, keygen divergence, SampleInBall properties |
| 4. Verification | 3 | Signature malleability, wrong-key acceptance, empty message handling |
| 5. Serialization | 3 | Key encoding round-trip, wrong-length signature/key rejection |
| 6. Timing | 2 | Deterministic signing consistency, hedged signing variance |

## CLI Usage

```
crucible <harness-command> [harness-args...] [OPTIONS]
```

### Options

| Flag | Description |
|---|---|
| `--battery`, `-b` | Battery to run: `ml-kem` (default) or `ml-dsa` |
| `--json` | Output results as JSON (default: human-readable) |
| `--category`, `-c` | Only run tests from this category (repeatable) |
| `--param-set`, `-p` | Only run against this parameter set (repeatable) |
| `--filter`, `-f` | Only run tests whose ID contains this substring |
| `--timeout`, `-t` | Harness spawn timeout in seconds (default: 30) |

### Examples

```bash
# Test a single implementation
cargo run --bin crucible -- ./target/harness-circl

# JSON output for CI integration
cargo run --bin crucible -- ./target/harness-circl --json > results.json

# Only compression tests
cargo run --bin crucible -- ./target/harness-circl --category compression

# Only ML-KEM-768
cargo run --bin crucible -- ./target/harness-circl --param-set ML-KEM-768

# ML-DSA battery
cargo run --bin crucible -- ./target/harness-circl --battery ml-dsa

# Combine filters
cargo run --bin crucible -- ./target/harness-circl --category decapsulation --param-set ML-KEM-1024

# Search for a specific test
cargo run --bin crucible -- ./target/harness-circl --filter ek-modulus
```

### Running All Implementations

```bash
# ML-KEM against all harnesses
for h in \
  target/debug/harness-reference \
  target/debug/harness-libcrux \
  target/harness-k2so \
  target/harness-mlkem-native \
  target/harness-go-stdlib \
  target/harness-aws-lc \
  target/harness-pq-crystals \
  target/harness-circl \
  target/harness-liboqs \
  harnesses/bouncy-castle/harness-bouncy-castle.sh \
  target/harness-wolfssl \
  target/harness-itzmeanjan \
  target/harness-pqcrypto \
  target/harness-pqclean \
; do
  echo "=== $(basename $h) ==="
  cargo run --quiet --bin crucible -- "$h"
  echo
done

# ML-DSA against ML-DSA-capable harnesses
for h in \
  target/harness-circl \
  target/harness-liboqs \
  harnesses/bouncy-castle/harness-bouncy-castle.sh \
  target/harness-tob-mldsa \
; do
  echo "=== $(basename $h) (ML-DSA) ==="
  cargo run --quiet --bin crucible -- "$h" --battery ml-dsa
  echo
done
```

### Exit Codes

| Code | Meaning |
|---|---|
| 0 | All tests passed (or skipped) |
| 1 | At least one test failed or errored |

## Tested Implementations

Crucible ships with harnesses for 15 implementations across 5 languages:

| # | Implementation | Language | ML-KEM | ML-DSA | Deterministic |
|---|---|---|---|---|---|
| 1 | Reference (Crucible) | Rust | Yes | — | Yes |
| 2 | libcrux (Cryspen) | Rust | Yes | — | Yes |
| 3 | Kyber-K2SO | Go | Yes | — | No |
| 4 | mlkem-native (PQCA) | C | Yes | — | Yes |
| 5 | Go stdlib `crypto/mlkem` | Go | Yes | — | Yes |
| 6 | AWS-LC | C | Yes | — | Yes |
| 7 | pq-crystals ref (NIST) | C | Yes | — | Yes |
| 8 | CIRCL (Cloudflare) | Go | Yes | Yes | Yes |
| 9 | liboqs (OQS) | C | Yes | Yes | Yes (KEM) |
| 10 | Bouncy Castle | Java | Yes | Yes | No |
| 11 | wolfCrypt (wolfSSL) | C | Yes | — | Yes |
| 12 | itzmeanjan | C++20 | Yes | — | Yes |
| 13 | pqcrypto (rustpq) | Rust | Yes | — | No |
| 14 | PQClean | C | Yes | — | Yes |
| 15 | Trail of Bits ml-dsa | Go | — | Yes | Yes |

"Deterministic" means the harness accepts explicit randomness seeds, enabling byte-for-byte comparison against the reference implementation.

### Rebuilding Harnesses

```bash
# Rust harnesses (reference, libcrux — built by cargo)
cargo build

# Go harnesses
cd harnesses/kyber-k2so && go build -o ../../target/harness-k2so .
cd harnesses/circl && go build -o ../../target/harness-circl .
cd harnesses/go-stdlib && go build -o ../../target/harness-go-stdlib .
cd harnesses/tob-mldsa && go build -o ../../target/harness-tob-mldsa .

# Java harness
cd harnesses/bouncy-castle
/opt/homebrew/opt/openjdk/bin/javac -cp bcprov.jar CrucibleHarness.java

# pqcrypto (standalone Rust, outside workspace)
cd harnesses/pqcrypto && cargo build --release && cp target/release/harness-pqcrypto ../../target/
```

C/C++ harness binaries are pre-built in `target/`. To rebuild, see the compilation commands in each harness directory.

## Harness Protocol

Crucible communicates with implementations via a JSON line protocol over stdin/stdout. Any language can implement a harness.

### Handshake

On startup, the harness prints a single JSON line:

```json
{"implementation":"my-impl-v1.0","functions":["ML_KEM_KeyGen","ML_KEM_Encaps","ML_KEM_Decaps"]}
```

### Request/Response

Crucible sends one JSON line per request:

```json
{"function":"ML_KEM_KeyGen","inputs":{"randomness":"0102..."},"params":{"param_set":768}}
```

The harness responds with one JSON line:

```json
{"outputs":{"ek":"abcd...","dk":"ef01..."}}
```

Or on error:

```json
{"error":"invalid key length"}
```

Or if the function isn't supported:

```json
{"unsupported":true}
```

### Data Encoding

- All byte data is hex-encoded in JSON strings.
- Polynomials are 512 bytes: 256 coefficients as 2-byte little-endian unsigned integers.
- Shared secrets are always 32 bytes.

### ML-KEM Functions

| Function | Inputs | Params | Outputs |
|---|---|---|---|
| `Compress_d` | `x` (2 bytes) | `d` (1–11) | `y` (2 bytes) |
| `Decompress_d` | `y` (2 bytes) | `d` (1–11) | `x` (2 bytes) |
| `ByteEncode_d` | `F` (512 bytes) | `d` (1–12) | `B` (32·d bytes) |
| `ByteDecode_d` | `B` (32·d bytes) | `d` (1–12) | `F` (512 bytes) |
| `NTT` | `f` (512 bytes) | — | `f_hat` (512 bytes) |
| `NTT_inv` | `f_hat` (512 bytes) | — | `f` (512 bytes) |
| `MultiplyNTTs` | `f_hat`, `g_hat` (512 bytes each) | — | `h_hat` (512 bytes) |
| `SamplePolyCBD` | `B` (64·η bytes) | `eta` (2 or 3) | `f` (512 bytes) |
| `SampleNTT` | `B` (34 bytes) | — | `a_hat` (512 bytes) |
| `ML_KEM_KeyGen` | `randomness` (64 bytes = d‖z) | `param_set` (512/768/1024) | `ek`, `dk` |
| `ML_KEM_Encaps` | `ek`, `randomness` (32 bytes) | — | `c`, `K` (32 bytes) |
| `ML_KEM_Decaps` | `c`, `dk` | — | `K` (32 bytes) |

### ML-DSA Functions

| Function | Inputs | Params | Outputs |
|---|---|---|---|
| `ML_DSA_KeyGen` | `seed` (32 bytes) | `param_set` (44/65/87) | `pk`, `sk` |
| `ML_DSA_Sign` | `sk`, `message`, `rnd` (32 bytes) | — | `sigma` |
| `ML_DSA_Verify` | `pk`, `message`, `sigma` | — | `valid` ("01" or "00") |

## Writing a New Harness

Harness templates are provided in `harnesses/templates/` for Rust, Go, and C.

1. Copy the template for your language.
2. Fill in the `TODO` sections, mapping Crucible function names to your implementation's API.
3. List only the functions you actually implement in the handshake — Crucible skips tests for unsupported functions.
4. Never crash on bad input — return `{"error":"..."}` instead. Crucible deliberately sends malformed inputs to test robustness.
5. Build and run: `cargo run --bin crucible -- ./my-harness`

### Tips

- **Internal functions (NTT, Compress, etc.)** provide the deepest testing but most implementations don't expose them. The black-box tests (deterministic keygen/encaps comparison, round-trip, implicit rejection) catch the same bugs through their effects on outputs.
- **Deterministic APIs** are strongly preferred. If your implementation accepts explicit randomness for keygen and encaps, Crucible can compare outputs byte-for-byte against the reference. Without determinism, only round-trip and robustness tests are available.
- **Montgomery domain NTT** — if your implementation uses Montgomery form internally, don't try to convert. Mark NTT/NTT_inv/MultiplyNTTs as unsupported. The black-box tests cover NTT correctness through the full pipeline.

## Verdict Format

Every test result includes:

| Field | Description |
|---|---|
| **Bug class** | Category/subcategory (e.g., `bounds-check/ek-validation`, `dead-code/missing-ntt`) |
| **Spec reference** | FIPS section, algorithm number, line number |
| **Severity** | `info`, `low`, `medium`, `high`, `critical` |
| **Provenance** | The real-world audit finding that motivated this test (where public) |

Example failure output:

```
FAIL [critical] Encapsulation key rejects coefficients in [q, 4095] (ML-KEM-768)
  Bug class: bounds-check/ek-validation
  Spec ref:  FIPS 203 §7.2, Algorithm 20 line 2
  Expected:  rejection (encapsulation key fails modulus check)
  Actual:    encapsulation succeeded
  Detail:    ML-KEM.Encaps accepted an ek with raw 12-bit coefficient 3329 (≥ q).
             FIPS 203 §7.2 requires ByteEncode_12(ByteDecode_12(ek_PKE)) == ek_PKE.
```

## Architecture

```
crucible/
  crates/
    crucible-core/       — Harness protocol, test orchestrator, verdict reporting, timing
    crucible-ml-kem/     — ML-KEM reference math + 78 test cases
    crucible-ml-dsa/     — ML-DSA reference math + 51 test cases
    crucible-cli/        — CLI entry point
  harnesses/
    reference/           — Reference harness (Crucible's own math)
    libcrux/             — libcrux (Cryspen, Rust)
    kyber-k2so/          — Kyber-K2SO (Symbolic Software, Go)
    circl/               — CIRCL (Cloudflare, Go)
    go-stdlib/           — Go standard library crypto/mlkem
    mlkem-native/        — mlkem-native (PQ Code Package, C)
    pq-crystals/         — pq-crystals Kyber ref (NIST, C)
    pqclean/             — PQClean (C)
    pqcrypto/            — pqcrypto/rustpq (Rust FFI to PQClean)
    itzmeanjan/          — itzmeanjan ml-kem (C++20)
    aws-lc/              — AWS-LC (C)
    liboqs/              — liboqs/Open Quantum Safe (C)
    bouncy-castle/       — Bouncy Castle (Java)
    wolfssl/             — wolfCrypt/wolfSSL (C)
    tob-mldsa/           — Trail of Bits ml-dsa (Go)
    templates/           — Harness templates for new implementations
  refs/                  — FIPS 203 and FIPS 204 PDFs
  PLAN.md                — Detailed test plan with spec references
  CANDIDATES.md          — Candidate implementations for testing
```

## License

Apache 2.0
