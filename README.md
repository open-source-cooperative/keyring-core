## Keyring Core

[![build](https://github.com/open-source-cooperative/keyring-core/actions/workflows/ci.yaml/badge.svg)](https://github.com/open-source-cooperative/keyring-core/actions) [![crates.io](https://img.shields.io/crates/v/keyring-core.svg)](https://crates.io/crates/keyring-core) [![docs.rs](https://docs.rs/keyring-core/badge.svg)](https://docs.rs/keyring-core)

This crate, `keyring-core`, is part of the [Keyring ecosystem](https://github.com/open-source-cooperative/keyring-core/wiki/Keyring). It provides a cross-platform library to manage storage and retrieval of passwords (and other secrets) in secure credential stores, as used by the [keyring application](https://crates.io/crates/keyring). If you are a developer looking to integrate secret-management facilities into your app, this is the crate you should use as a dependency, along with one or more keyring-compatible credential-stores.

## Usage

To use this crate in your project, include it in your `Cargo.toml`, either with or without the `sample` feature (which enables a credential store useful while testing). There are no default features.

In your application code, set your default credential store using `set_default_store` when you start up, and unset it with `unset_default_store` when you shut down. Use the `Entry::new` function to create a new keyring entry. The `new` function takes a service name and a user's name which together identify the entry.

Passwords (strings) or secrets (binary data) can be added to an entry using its `set_password` or `set_secret` methods, respectively. (These methods create or update an entry in your chosen credential store.) The password or secret can then be read back using the `get_password` or `get_secret` methods. The underlying credential (with its password/secret data) can be removed using the `delete_credential` method.

Here is a simple example application that uses the (included) mock credential store and does absolutely nothing:

```rust
use keyring_core::{mock, Entry, Result};

fn main() -> Result<()> {
    keyring_core::set_default_store(mock::Store::new()?);
    let entry = Entry::new("my-service", "my-name")?;
    entry.set_password("topS3cr3tP4$$w0rd")?;
    let password = entry.get_password()?;
    println!("My password is '{password}'");
    entry.delete_credential()?;
    keyring_core::unset_default_store();
    Ok(())
}
```

## Errors

Creating and operating on entries can yield an `Error` enum that classifies the error and, where relevant, includes underlying credential store errors or more information about what went wrong.

## Credential Stores

This crate comes with two cross-platform credential stores that can be used by clients who want to test their credential-store-independent logic. The first of these is a mock store with no persistence that allows mocking errors as well as successes. The other is a sample store with file-based persistence. Neither of these stores is secure or robust, so they should not be used in production. See the [developer docs](https://docs.rs/keyring-core/) for details.

## API changes

There are some changes in the API relative to that in the [keyring crate v3](https://crates.io/crates/keyring/3.6.2). Both client and credential store developers will need to make changes. Developers should read the [keyring-core design document](https://github.com/open-source-cooperative/keyring-rs/wiki/Keyring-Core) to better understand the new API.

### Client changes

* In the older API, credential stores were fairly opaque, exposing only a credential builder function (which was a   singleton). In the current API, credential stores are richer objects with their own lifecycle, so `set_default_credential_builder` has become `set_default_store`, and it receives the default store via a shared `Arc` rather than an owning `Box`. There is also an `unset_default_store` function to release the store.
* The new client-facing API does not reveal the `Credential` object, which is exclusively part of the credential-store provider API. As part of this change, the `Ambiguous` error now returns a list of entries.
* The new API's `get_credential` call now fails if there is no existing credential for an entry, and returns an entry rather than a credential.
* The `new_with_target` API has been replaced by `new_with_modifiers`, where `target` is just one of the possible keys in the modifiers map. Check your credential store to see if `target` is accepted as a modifier key.
* The new API exposes credential search and returns entries for all the matching credentials. Many thanks to @wiimmers for showing the way with his [keyring-search](https://crates.io/crates/keyring-search) crate. I am hoping he will integrate his search facilities into all the new credential stores.

## Changelog

See the [release history on GitHub](https://github.com/open-source-cooperative/keyring-core/releases) for full details.

## License

Licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contributors

The full list of library contributors may be found in the [Contributors file](Contributors.md).

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
