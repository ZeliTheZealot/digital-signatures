# digital-signatures

A Rust workspace wrapping the libraries `libsecp256k1-rs` and `schnorrkel`, with tests and benches. 

## Usage

Refer to the documentation in each crate. 

## Areas of future work 

Dependency clash between crates: `libsecp256k1-rs` uses rand 0.4 while `schnorrkel` uses rand 0.6, and these dependencies do clash.

Note: in `multisig`, the underlying dependency `schnorrkel` returns `struct`s that are not wrapped with `Result`s, so the error handling is not obvious / non-existent. We have wrapped these trivially in `Result`s but errors are still unhandled. 

## License

To be added. 