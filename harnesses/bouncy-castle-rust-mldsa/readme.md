# Bouncy Castle Rust ML-DSA harness

Since bouncycastle-rust is not on crates.io yet, this harness assumes the
[bc-rust](https://github.com/bcgit/bc-rust) repo is cloned adjacent to the
crucible repo, on the `release/0.1.2alpha` branch:

```bash
# from the directory containing crucible/
git clone --branch release/0.1.2alpha https://github.com/bcgit/bc-rust
```

bc-rust uses nightly-only features (`generic_const_exprs`, `adt_const_params`),
and its own `rust-toolchain.toml` does not propagate when it is consumed as a
path dependency, so this directory carries a `rust-toolchain.toml` that selects
nightly automatically (requires rustup).

## Build and run

```bash
cd harnesses/bouncy-castle-rust
cargo build --release
cp target/release/harness-bc-rust ../../target/

# from the repo root
cargo run --bin crucible -- ./target/harness-bc-rust --battery ml-dsa
```

## Notes

- The harness targets the FIPS 204 §6 internal algorithms via bc-rust's
  "External Mu" interface: Crucible sends the formatted message M', the
  harness computes µ = SHAKE256(tr ‖ M', 64) and calls the `*_mu` APIs.
- Key generation constructs the seed `KeyMaterial` with
  `allow_hazardous_operations()` so that the all-zero seed — which bc-rust
  otherwise classifies as `KeyType::Zeroized` and refuses — can be exercised
  by the battery (FIPS 204 Algorithm 6 accepts any 32-byte seed).
