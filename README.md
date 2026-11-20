## Keyring Core

[![build](https://github.com/open-source-cooperative/keyring-core/actions/workflows/ci.yaml/badge.svg)](https://github.com/open-source-cooperative/keyring-core/actions) [![crates.io](https://img.shields.io/crates/v/keyring-core.svg)](https://crates.io/crates/keyring-core) [![docs.rs](https://docs.rs/keyring-core/badge.svg)](https://docs.rs/keyring-core) [![codecov](https://codecov.io/gh/open-source-cooperative/keyring-core/graph/badge.svg)](https://codecov.io/gh/open-source-cooperative/keyring-core)

This crate, `keyring-core`, is part of the [Keyring ecosystem](https://github.com/open-source-cooperative/keyring-core/wiki/Keyring). It provides a cross-platform library to manage storage and retrieval of passwords (and other secrets) in secure credential stores, such as the [demonstration keyring applications](https://github.com/open-source-cooperative/keyring-rs/wiki/Keyring-Applications). If you are a developer looking to integrate secret-management facilities into your app, this is the crate you should use as a dependency, along with one or more keyring-compatible credential-stores.

## Usage

To use this crate in your project, include it in your `Cargo.toml`, either with or without the `sample` feature (which enables a credential store useful while testing). There are no default features.

There is some very simple sample code in the `usage` example, and some sophisticated sample code in the `ambiguity` example. Developers who use this crate should absolutely read this crate’s [design documentation](https://github.com/open-source-cooperative/keyring-rs/wiki/Keyring-Core) as well as the [developer docs](https://docs.rs/keyring-core/).

## Credential Stores

This crate comes with two cross-platform credential stores that can be used by clients who want to test their credential-store-independent logic. The first of these is a mock store with no persistence that allows mocking errors as well as successes. The other is a sample store with file-based persistence. Neither of these stores is secure or robust, so they should not be used in production. See the [developer docs](https://docs.rs/keyring-core/) for details.

## Changelog

See the [release history on GitHub](https://github.com/open-source-cooperative/keyring-core/releases). Since this crate contains code that was originally written as part of the [keyring crate](https://github.com/open-source-cooperative/keyring-rs/),  refer [to that crate’s release history](https://github.com/open-source-cooperative/keyring-rs/releases) for changes made prior to this crate’s creation.

## License

Licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
