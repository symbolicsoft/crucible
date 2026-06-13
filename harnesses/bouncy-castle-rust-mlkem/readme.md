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

* bc-rust's ML-KEM implementation does not implement compress_d() and decompress_d() as standalone functions. It's implicit in a few places:
    * byte_encode() / byte_decode() implicitly inlines compress_1 https://github.com/bcgit/bc-rust/blob/main/crypto/mlkem/src/aux_functions.rs#L29
    * compress_pol_vec() / decompress_pol_vec() implicitly inlines compress_d / decompress_d: https://github.com/bcgit/bc-rust/blob/main/crypto/mlkem/src/matrix.rs#L162

  So the crucible harness functions    have been left 
