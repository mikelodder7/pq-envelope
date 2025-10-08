# pq-envelope

[![Crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![Apache2/MIT licensed][license-image]
[![Downloads][downloads-image]][crate-link]
![build](https://github.com/mikelodder7/pq-envelope/actions/workflows/pq-envelope.yml/badge.svg)
![MSRV][msrv-image]

Post Quantum Safe Hybrid Encryption for multiple recipients.

### NOTE on AES

To speed up AES, there are a few options available:

- `RUSTFLAGS="--cfg aes_armv8" cargo build --release` ensures that the ARMv8 AES instructions are used if available.

By default, the `aes` feature auto-detects the best AES implementation for your platform
for x86 and x86_64,
but not on ARMv8 where it defaults to the software implementation as of this writing.
To enable the ARMv8 AES instructions, the `aes_armv8` feature is enabled in the `.cargo/config` file in this crate.

Enabling aesni provides the fastest Aes algorithm.

### NOTE on SHAKE
Shake auto detects the best implementation for your platform.

## License

Licensed under

- [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)
- [MIT license](http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.

[//]: # (badges)

[crate-image]: https://img.shields.io/crates/v/pq-envelope.svg
[crate-link]: https://crates.io/crates/pq-envelope
[docs-image]: https://docs.rs/pq-envelope/badge.svg
[docs-link]: https://docs.rs/pq-envelope/
[license-image]: https://img.shields.io/badge/license-Apache2.0/MIT-blue.svg
[downloads-image]: https://img.shields.io/crates/d/pq-envelope.svg
[msrv-image]: https://img.shields.io/badge/rustc-1.90+-blue.svg