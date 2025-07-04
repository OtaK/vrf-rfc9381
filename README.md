# VRF-RFC9381

[![Crates.io](https://img.shields.io/crates/v/vrf-rfc9381.svg)](https://crates.io/crates/vrf-rfc9381)
[![docs.rs](https://docs.rs/vrf-rfc9381/badge.svg)](https://docs.rs/vrf-rfc9381)

## Description

Rust implementation of VRFs (Verifiable Random Functions) as described in RFC9381.

Compatible with WASM (`wasm32-unknown-unknown` target). Uses RustCrypto primitives.

Only ECVRF support is baked in as of now, and passes the spec test vectors for it.

If there's enough interest, I can bake in RSA-FDH-VRF support.

As usual, it has not been audited, might be insecure, proceed with caution.

Note: This library uses the curve-25519-dalek fork at <https://github.com/iquerejeta/curve25519-dalek> for its support of Hash2Curve w/ Elligator encoding (See RFC9380 Section 3-4.2.1), which is needed for VRFs. If you're unhappy with this situation, hold on a bit until this gets merged.

### Features

- `edwards25519`: Enables support for `ECVRF-EDWARDS25519-SHA512-TAI` and `ECVRF-EDWARDS25519-SHA512-ELL2`
- `p256`: Enables support for `ECVRF-P256-SHA256-TAI` and `ECVRF-P256-SHA256-SSWU`

## Documentation

Here: [https://docs.rs/vrf-rfc9381](https://docs.rs/vrf-rfc9381)

It's still a work in progress when it comes to documentation, so you're basically on your own (or look at the tests) until then.

## License

Licensed under either of these:

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
  [https://www.apache.org/licenses/LICENSE-2.0](https://www.apache.org/licenses/LICENSE-2.0))
- MIT license ([LICENSE-MIT](LICENSE-MIT) or
  [https://opensource.org/licenses/MIT](https://opensource.org/licenses/MIT))
