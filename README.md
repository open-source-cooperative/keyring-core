## Keyring Core

[![build](https://github.com/open-source-cooperative/keyring-core/actions/workflows/ci.yaml/badge.svg)](https://github.com/hwchen/keyring-rs/actions)
[![dependencies](https://deps.rs/repo/github/open-source-cooperative/keyring-core/status.svg)](https://deps.rs/repo/github/open-source-cooperative/keyring-core)
[![crates.io](https://img.shields.io/crates/v/keyring-core.svg?style=flat-square)](https://crates.io/crates/keyring)
[![docs.rs](https://docs.rs/keyring-core/badge.svg)](https://docs.rs/keyring-core)

`keyring-core` is a cross-platform library to manage storage and retrieval of passwords (and other secrets) in platform-specific credential stores. It provides the API used in the [keyring crate](https://crates.io/crates/keyring). If you are a developer looking to integrate secret-management facilities into your app, this is the crate you should use as a dependency, along with any compatible credential-store crates, such as [dbus-secret-service-keyring](https://crates.io/crates/dbus-secret-service-keyring]) or [apple-native-keyring](https://crates.io/crates/apple-native-keyring).

## Usage

To use this crate in your project, include it in your `Cargo.toml`:

```toml
keyring-core = "1"
```

In your client code, set your default credential store using the `set_default_credential_builder` function. Then you can use the `Entry::new` function to create a new keyring entry. The `new` function takes a service name and a user's name which together identify the entry.

Passwords (strings) or secrets (binary data) can be added to an entry using its `set_password` or `set_secret` methods, respectively. (These methods create or update an entry in your chosen credential store.) The password or secret can then be read back using the `get_password` or `get_secret` methods. The underlying credential (with its password/secret data) can be removed using the `delete_credential` method.

```rust
use keyring::{set_default_credential_builder, mock, Entry, Result};

fn main() -> Result<()> {
    set_default_credential_builder(mock::default_credential_builder);
    let entry = Entry::new("my-service", "my-name")?;
    entry.set_password("topS3cr3tP4$$w0rd")?;
    let password = entry.get_password()?;
    println!("My password is '{}'", password);
    entry.delete_credential()?;
    Ok(())
}
```

## Errors

Creating and operating on entries can yield a `keyring::Error` which provides both a platform-independent code that classifies the error and, where relevant, underlying credential store errors or more information about what went wrong.

## Client Testing

This crate comes with a mock credential store that can be used by clients who want to test their platform-independent logic as opposed to their credential-store-specific logic. The mock store allows mocking errors as well as successes. See the [developer docs](https://docs.rs/keyring-core/) for details.

## Credential Stores

This crate allows for pluggable credential stores by providing traits that credential stores can implement. See the [developer docs](https://docs.rs/keyring/) for details.

## License

Licensed under either of

* Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
* MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contributors

Thanks to the following for helping make this library better, whether through contributing code, discussion, or bug reports!

- @Alexei-Barnes
- @benwr
- @bhkaminski
- @Brooooooklyn
- @brotskydotcom
- @complexspaces
- @connor4312
- @dario23
- @dten
- @gondolyr
- @hwchen
- @jankatins
- @jasikpark
- @jkhsjdhjs
- @jonathanmorley
- @jyuch
- @klemensn
- @landhb
- @lexxvir
- @noib3
- @MaikKlein
- @Phrohdoh
- @phlip9
- @ReactorScram
- @Rukenshia
- @russellbanks
- @ryanavella
- @samuela
- @ShaunSHamilton
- @soywod
- @stankec
- @steveatinfincia
- @Sytten
- @thewh1teagle
- @tmpfs
- @unkcpz
- @VorpalBlade
- @zschreur

If you should be on this list, but don't find yourself, please contact @brotskydotcom.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
