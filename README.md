## Keyring Core

[![build](https://github.com/open-source-cooperative/keyring-core/actions/workflows/ci.yaml/badge.svg)](https://github.com/hwchen/keyring-rs/actions)
[![dependencies](https://deps.rs/repo/github/open-source-cooperative/keyring-core/status.svg)](https://deps.rs/repo/github/open-source-cooperative/keyring-core)
[![crates.io](https://img.shields.io/crates/v/keyring-core.svg?style=flat-square)](https://crates.io/crates/keyring)
[![docs.rs](https://docs.rs/keyring-core/badge.svg)](https://docs.rs/keyring-core)

`keyring-core` is a cross-platform library to manage storage and retrieval of passwords (and other secrets) in secure
credential stores. It provides the API used by the [keyring CLI](https://crates.io/crates/keyring). If you are a
developer looking to integrate secret-management facilities into your app, this is the crate you should use as a
dependency, along with one or more keyring-compatible credential-stores.

## Usage

To use this crate in your project, include it in your `Cargo.toml`, either with or without the `sample` feature (which
enables a credential store useful while testing). There are no default features.

In your client code, set your default credential store using the `set_default_store` function. Then you can
use the `Entry::new` function to create a new keyring entry. The `new` function takes a service name and a user's name
which together identify the entry.

Passwords (strings) or secrets (binary data) can be added to an entry using its `set_password` or `set_secret` methods,
respectively. (These methods create or update an entry in your chosen credential store.) The password or secret can then
be read back using the `get_password` or `get_secret` methods. The underlying credential (with its password/secret data)
can be removed using the `delete_credential` method.

```rust
use keyring_core::{set_default_store, mock, Entry, Result};

fn main() -> Result<()> {
    set_default_store(mock::default_store());
    let entry = Entry::new("my-service", "my-name")?;
    entry.set_password("topS3cr3tP4$$w0rd")?;
    let password = entry.get_password()?;
    println!("My password is '{}'", password);
    entry.delete_credential()?;
    Ok(())
}
```

## Errors

Creating and operating on entries can yield an `Error` enum that
classifies the error and, where relevant, includes underlying credential store errors or more information about what
went wrong.

## Credential Stores

This crate comes with two cross-platform credential stores that can be used by clients who want to test their
credential-store independent
logic. Neither of these stores are either secure or robust, so they should not be used in production.

The first of these is a mock store with no persistence which allows mocking errors as well as successes. The other is a
sample store with file-based persistence. See the [developer docs](https://docs.rs/keyring-core/) for details.

## API changes

There are a few changes in the API since its last inclusion in
the [keyring crate v3](https://crates.io/crates/keyring/3.6.2):

* The older API expected credential stores to be singletons, so that each store module's `default_credential_store`
  function could be called multiple times and relied on to return the same store. In the current API, credential stores
  can be objects with their own lifecycle, so they are given to `set_default_credential_store` via an `Arc` rather than
  a `Box`.
* The new API is a lot more crisp about whether an entry has been created directly or has been created by wrapping a
  credential, and what the difference between those two scenarios are. As a result, the Ambiguous error returns a list
  of entries rather than a list of credentials, and it makes clear which of those entries (if any) is the one that holds
  the credential that would have been created by the API on a `set_password` call.

## License

Licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contributors

The full list of library contributors may be found in the [Contributors file](Contributors.md).

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as
defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
