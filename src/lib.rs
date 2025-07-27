#![cfg_attr(docsrs, feature(doc_cfg))]
/*!

# Keyring-core

This crate provides a cross-platform library that supports storage and retrieval
of passwords (or other secrets) in a variety of secure credential stores.
A top-level introduction to the library's usage, as well as a small code sample,
may be found on [crates.io](https://crates.io/crates/keyring-core).
A working CLI application, and pointers to many compatible credential stores,
can be found in the [keyring crate](https://crates.io/crates/keyring).

This crate provides two cross-platform credential stores. These
are provided to support client testing and as a guide for developers who
would like to build keyring-compatible wrappers for existing stores. These
stores are explicitly _not_ warranted to be either secure or robust.
See the [mock] and [sample] modules for details. (Note: the [sample]
module is only built if the `sample` feature is specified.)

## Design

This crate implements a platform-independent concrete object called an _entry_.
Entries support setting, getting, and forgetting (aka deleting) UTF-8 passwords
and binary secrets. Each entry relies on an API-compatible
_credential store_ to provide security for and persistence of its data
by storing that data in a _credential_.

There are two kinds of entry: a _wrapper_ that represents a specific credential
that already exists in a credential store, and a _specification_ that represents a
credential that might or might not already exist in the store. Let's look at these
in the opposite order.

### Specifications

Most entries are _specifications_ for a credential that may or may not yet exist
in the store. When a set-password operation is requested on a specification
entry, the credential matching the specification is found or created, and the
password is stored in that credential. When a get-password operation is
requested on the entry, the credential matching the specification (if any) is
found, and its data is returned.

There are two APIs for creating entries that are specifiers:

* [Entry::new] takes two parameters--a `service` string and a `user` string--
  and specifies a "default" credential defined by the store for holding that
  user's password for that service. While each store will define "default"
  in its own way, each `<service, user>` pair is guaranteed to specify
  a different credential,
  so that entries for different services and/or users never conflict with
  one another. This is the _only_ credential-creation API needed by most keyring
  clients.

* [Entry::new_with_modifiers], in addition to the `service` and `user` parameters,
  takes a key-value map of credential-store-specific "modifiers".
  These modifiers may change which credential is specified, or they may
  change characteristics of the specified credential in the store.
  This API is used by clients who have credential-store-specific needs.

For example, let's consider a credential store that uses the macOS Keychain
for its storage. Such a store might interpret `Entry::new(service1, user1)`
to specify a _generic credential_ in the `Login` keychain whose
service attribute is `service1` and whose user attribute is `user1`.
If we were to set that entry's password to be `password1`, and
then go into the Keychain Access application on our Mac,
we would see a created item with this display:

* Kind: application password
* Name: `service1`
* Where: `service1`
* Account: `user1`

If then told Keychain Access to reveal the password for that entry,
it would require the logged-in user's permission and
then display the password `password1`.

Although exactly which credential is specified by an entry is controlled
by the credential store, different entries with the same specification (same `service`,
`user`, and optional `modifier` parameters) obey an important invariant: they
always represent the _same_ credential. It doesn't matter which entry you use to
get the password and which entry you use to set the password: you will always get
the same password. This invariant, which is enforced by the credential stores,
is what allows you to run a keychain-based application multiple times and get
consistent results: as long as the specifications remain the same, so will the
credentials used.

### Wrappers

Some entries, rather than specifying credentials by their characteristics,
directly _wrap_ (aka identify) specific credentials which already exist
in a credential store.
Setting a password on a wrapper entry will store the password in the credential
wrapped by that entry.
Getting a password will read the it from the wrapped credential.

There are two APIs for creating entries that are wrappers:

* [Entry::new_with_credential] takes an existing store-specific credential object
  and wraps an entry around it. This is useful when you want to use the keyring API
  to manage credentials created or retrieved by store-specific code in your application.

* [Entry::search_for_credentials] takes a store-specific search specification
  and returns entries wrapping each of the existing credentials in the store
  that match the search.
  This is useful when you want to use the keyring API to manage credentials
  that were created by other applications.

Wrappers can be indispensable when you need to
operate on a particular credential.
But most keychain clients will only need them
if non-keychain clients are creating conflicting credentials
in a credential store (see [Ambiguity](#Ambiguity) below).

### Specifiers vs. Wrappers

From an API point of view, the difference between specifiers and wrappers
is in the error conditions that can arise when setting or getting passwords.

* When you set a password on a specifier entry, you can never receive
  a [NoEntry][Error::NoEntry] error response because, if there is no
  credential matching the specification, the store will create one.
* When you retrieve a password from a wrapper entry, you can never
  receive an [Ambiguous][Error::Ambiguous] response (described [below](#Ambiguity)),
  because the entry identifies a specific credential from which to
  retrieve the password.

An entry can be both a specifier and a wrapper simultaneously; that is, it may
both identify an existing credential and specify how to create that credential
if it doesn't exist. To see this, consider a credential store (such as the
Windows Credential Manager) that identifies credentials using a specific
attribute, and allows clients to specify that attribute when creating a
credential. Suppose the credential store implementation uses a particular
combination of the specifier's `service` and `user` strings as the identifier
for the specified credential. The combined string both acts as a
specifier for the credential to create and an identifier for an existing
credential. Thus, an entry containing that string is both a specifier and a
wrapper.

If you have a specifier entry you've created and set a password for,
and you want to get a wrapper for that entry's associated credential,
you can call [Entry::get_credential] on that entry.

## Ambiguity

The service name, username, and modifiers used when a specifier
entry is created are interpreted by the store to specify a credential
in the store that will store that entry's password. In some stores,
however, that specification may be _ambiguous_, that is, there may
be multiple credentials in the store that meet
the specification. In such cases, trying to set or read
the entry's password will return an [Ambiguous](Error::Ambiguous) error.
The returned error will contain a list of wrapper entries, each of which
wraps one of the matching credentials.

For example, credential stores that use the Secret Service typically
map the service name and username in a specifier entry to attributes
on a Secret Service item. There may be multiple items in a
Secret Service store that agree on those attributes but differ
on other attributes and, in
such a case, all those items will match the entry's specification.

Since a keychain client will never create multiple
different credentials for a single specification, the usual source
of ambiguity in a credential store is the presence of credentials
written by non-keyring clients. The keyring API
exposes ambiguity because keyring clients will often want to
interoperate with these other clients.

Not all credential stores allow ambiguity. Check the documentation
for each credential store to find out whether it does.

## Attributes

Most credential stores, in addition to storing secrets in credentials,
allow them to be decorated with additional information. The keyring
API exposes this capability in a cross-platform way by providing
two calls:

* [Entry::get_attributes] returns key-value string pairs that the
  store can use to expose decorations on the underlying credential.
  Like [get_password](Entry::get_password), this call will fail
  unless there is an existing credential underlying this entry.

* [Entry::update_attributes] asks the store to update any existing
  decorations with those provided by the client.
  Unlike [set_password](Entry::set_password), this call will
  never cause the creation of a credential. You cannot force
  a credential to be decorated at creation time unless
  the store provides an entry modifier that can be used
  to request this.

Consult the docs of each credential store to find out which attributes it exposes
and which ones can be updated.

## Thread Safety

While this crate's code is thread-safe, and requires credential store objects
to be both Send and Sync, the underlying credential
stores may not handle access to a single credential
from different threads reliably.
See the documentation of each credential store for details.
 */

use log::debug;
use std::collections::HashMap;
use std::sync::Arc;

pub mod api;
pub mod error;

pub mod mock;

#[cfg(feature = "sample")]
pub mod sample;

pub use api::{Credential, CredentialPersistence, CredentialStore};
pub use error::{Error, Result};

#[derive(Default, Debug)]
struct DefaultStore {
    inner: Option<Arc<CredentialStore>>,
}

static DEFAULT_STORE: std::sync::RwLock<DefaultStore> =
    std::sync::RwLock::new(DefaultStore { inner: None });

/// Set the credential store used by default to create entries.
///
/// This is meant for use by clients who use one credential store.
/// If you are using multiple credential stores and want
/// precise control over which credential is in which store,
/// you may prefer to create the credentials directly in the store and
/// wrap them with [new_with_credential](Entry::new_with_credential).
///
/// This will block waiting for all other threads currently creating entries
/// to complete what they are doing. It's really meant to be called
/// at app startup before you start creating entries.
pub fn set_default_store(new: Arc<CredentialStore>) {
    debug!("setting default credential store to {new:?}");
    let mut guard = DEFAULT_STORE
        .write()
        .expect("Poisoned RwLock in keyring_core::set_default_store: please report a bug!");
    guard.inner = Some(new);
}

// Release the default credential store.
//
// This returns the old value for the default credential store,
// and forgets what it was. Since the default credential store
// is kept in a static variable, not releasing it will cause
// your credential store never to be released, which may have
// unintended side effects.
pub fn unset_default_store() -> Option<Arc<CredentialStore>> {
    debug!("unset the default credential store");
    let mut guard = DEFAULT_STORE
        .write()
        .expect("Poisoned RwLock in keyring_core::unset_default_store: please report a bug!");
    guard.inner.take()
}

fn build_default_credential(
    service: &str,
    user: &str,
    attrs: Option<&HashMap<&str, &str>>,
) -> Result<Entry> {
    let guard = DEFAULT_STORE
        .read()
        .expect("Poisoned RwLock in keyring-rs: please report a bug!");
    match guard.inner.as_ref() {
        Some(store) => {
            let credential = store.build(service, user, attrs)?;
            Ok(Entry { inner: credential })
        }
        None => Err(Error::NoDefaultStore),
    }
}

#[derive(Debug)]
pub struct Entry {
    inner: Arc<Credential>,
}

impl Entry {
    /// Create an entry for the given service and user.
    ///
    /// The default credential builder is used.
    ///
    /// # Errors
    ///
    /// Returns an [Invalid][Error::Invalid] error
    /// if the `service` or `user` values are not
    /// acceptable to the default credential store.
    ///
    /// Returns a [NoDefaultStore][Error::NoDefaultStore] error
    /// if the default credential store has not been set.
    pub fn new(service: &str, user: &str) -> Result<Entry> {
        debug!("creating entry with service {service}, user {user}");
        let entry = build_default_credential(service, user, None)?;
        debug!("created entry {:?}", entry.inner);
        Ok(entry)
    }

    /// Create an entry for the given service and user, passing store-specific modifiers.
    ///
    /// The default credential builder is used.
    ///
    /// See the documentation for each credential store to understand what
    /// modifiers may be specified for that store.
    ///
    /// # Errors
    ///
    /// Returns an [Invalid][Error::Invalid] error
    /// if the `service`, `user`, or `modifier` pairs are not
    /// acceptable to the default credential store.
    ///
    /// Returns a [NoDefaultStore][Error::NoDefaultStore] error
    /// if the default credential store has not been set.
    pub fn new_with_modifiers(
        service: &str,
        user: &str,
        modifiers: &HashMap<&str, &str>,
    ) -> Result<Entry> {
        debug!("creating entry with service {service}, user {user}, and mods {modifiers:?}");
        let entry = build_default_credential(service, user, Some(modifiers))?;
        debug!("created entry {:?}", entry.inner);
        Ok(entry)
    }

    /// Create an entry for the given target modifier, service, and user.
    ///
    /// This is just a convenience wrapper for [new_with_modifiers](Entry::new_with_modifiers)
    /// that specifies only the `target` modifier.  It is provided for legacy compatibility.
    pub fn new_with_target(target: &str, service: &str, user: &str) -> Result<Entry> {
        debug!("creating entry with service {service}, user {user}, and target {target}");
        let map = HashMap::from([("target", target)]);
        let entry = build_default_credential(service, user, Some(&map))?;
        debug!("created entry {:?}", entry.inner);
        Ok(entry)
    }

    /// Create an entry that wraps a pre-existing credential. The credential can
    /// be from any credential store.
    pub fn new_with_credential(credential: Arc<Credential>) -> Entry {
        debug!("create entry wrapping {credential:?}");
        Entry { inner: credential }
    }

    /// Search for credentials, returning entries that wrap any found.
    ///
    /// The default credential store is searched.
    /// See the documentation of each credential store for how searches are specified.
    ///
    /// # Errors
    ///
    /// Returns an [Invalid][Error::Invalid] error
    /// if the `spec` value is not acceptable to the default credential store.
    ///
    /// Returns a [NoDefaultStore][Error::NoDefaultStore] error
    /// if the default credential store has not been set.
    pub fn search_for_credentials(spec: &HashMap<&str, &str>) -> Result<Vec<Entry>> {
        debug!("searching for {spec:?}");
        let guard = DEFAULT_STORE
            .read()
            .expect("Poisoned RwLock in keyring-rs: please report a bug!");
        match guard.inner.as_ref() {
            Some(store) => {
                let creds = store.search(spec)?;
                let entries: Vec<Entry> = creds.into_iter().map(|c| Entry { inner: c }).collect();
                Ok(entries)
            }
            None => Err(Error::NoDefaultStore),
        }
    }

    /// Set the password for this entry.
    ///
    /// If a credential for this entry already exists in the store,
    /// this will update its password. Otherwise, a new credential
    /// will be created to store the password.
    ///
    /// # Errors
    ///
    /// If this entry is a wrapper, and the
    /// underlying credential has been deleted,
    /// may return a [NoEntry](Error::NoEntry) error.
    ///
    /// Returns an [Ambiguous](Error::Ambiguous) error
    /// if there is more than one matching credential.
    ///
    /// If a credential cannot store the given password (not
    /// all stores support empty passwords, and some have length limits),
    /// then an [Invalid](Error::Invalid) error is returned.
    pub fn set_password(&self, password: &str) -> Result<()> {
        debug!("set password for entry {:?}", self.inner);
        self.inner.set_password(password)
    }

    /// Set the secret for this entry.
    ///
    /// If a credential for this entry already exists in the store,
    /// this will update its secret. Otherwise, a new credential
    /// will be created to store the secret.
    ///
    /// # Errors
    ///
    /// If this entry is a wrapper, and the
    /// underlying credential has been deleted,
    /// may return a [NoEntry](Error::NoEntry) error.
    ///
    /// Returns an [Ambiguous](Error::Ambiguous) error
    /// if there is more than one matching credential.
    ///
    /// If a credential cannot store the given password (not
    /// all stores support empty passwords, and some have length limits),
    /// then an [Invalid](Error::Invalid) error is returned.
    pub fn set_secret(&self, secret: &[u8]) -> Result<()> {
        debug!("set secret for entry {:?}", self.inner);
        self.inner.set_secret(secret)
    }

    /// Retrieve the password saved for this entry.
    ///
    /// # Errors
    ///
    /// Returns a [NoEntry](Error::NoEntry) error if there is no
    /// matching credential.
    ///
    /// Returns an [Ambiguous](Error::Ambiguous) error
    /// if there is more than one matching credential.
    ///
    /// Will return a [BadEncoding](Error::BadEncoding) error
    /// containing the data as a byte array if the password is
    /// not a valid UTF-8 string.
    pub fn get_password(&self) -> Result<String> {
        debug!("get password from entry {:?}", self.inner);
        self.inner.get_password()
    }

    /// Retrieve the secret saved for this entry.
    ///
    /// # Errors
    ///
    /// Returns a [NoEntry](Error::NoEntry) error if there is no
    /// matching credential.
    ///
    /// Returns an [Ambiguous](Error::Ambiguous) error
    /// if there is more than one matching credential.
    pub fn get_secret(&self) -> Result<Vec<u8>> {
        debug!("get secret from entry {:?}", self.inner);
        self.inner.get_secret()
    }

    /// Get the store-specific decorations on this entry's credential.
    ///
    /// See the documentation for each credential store
    /// for details of what decorations are supported
    /// and how they are returned.
    ///
    /// # Errors
    ///
    /// Returns a [NoEntry](Error::NoEntry) error if there is no
    /// matching credential.
    ///
    /// Returns an [Ambiguous](Error::Ambiguous) error
    /// if there is more than one matching credential.
    pub fn get_attributes(&self) -> Result<HashMap<String, String>> {
        debug!("get attributes from entry {:?}", self.inner);
        self.inner.get_attributes()
    }

    /// Update the store-specific decorations on this entry's credential.
    ///
    /// See the documentation for each credential store
    /// for details of what decorations can be updated
    /// and how updates are expressed.
    ///
    /// # Errors
    ///
    /// Returns a [NoEntry](Error::NoEntry) error if there is no
    /// matching credential.
    ///
    /// Returns an [Ambiguous](Error::Ambiguous) error
    /// if there is more than one matching credential.
    pub fn update_attributes(&self, attributes: &HashMap<&str, &str>) -> Result<()> {
        debug!(
            "update attributes for entry {:?} from map {attributes:?}",
            self.inner
        );
        self.inner.update_attributes(attributes)
    }

    /// Delete the matching credential for this entry.
    ///
    /// # Errors
    ///
    /// Returns a [NoEntry](Error::NoEntry) error if there is no
    /// matching credential.
    ///
    /// Returns an [Ambiguous](Error::Ambiguous) error
    /// if there is more than one matching credential.
    ///
    /// Note: This does _not_ affect the lifetime of the [Entry]
    /// structure, which is controlled by Rust.  It only
    /// affects the underlying credential store.
    pub fn delete_credential(&self) -> Result<()> {
        debug!("delete entry {:?}", self.inner);
        self.inner.delete_credential()
    }

    /// Get a wrapper for the currently matching credential.
    ///
    /// # Errors
    ///
    /// Returns a [NoEntry](Error::NoEntry) error if there is no
    /// matching credential.
    ///
    /// Returns an [Ambiguous](Error::Ambiguous) error
    /// if there is more than one matching credential.
    pub fn get_credential(&self) -> Result<Entry> {
        debug!("get credential for entry {:?}", self.inner);
        match self.inner.get_credential() {
            Ok(Some(inner)) => Ok(Entry { inner }),
            Ok(None) => Ok(Entry {
                inner: self.inner.clone(),
            }),
            Err(e) => Err(e),
        }
    }

    /// Return a reference to the concrete credential object in this entry.
    ///
    /// The reference is of the [Any](std::any::Any) type, so it can be
    /// downgraded to a concrete credential object for the
    /// containing store.
    pub fn as_credential(&self) -> &dyn std::any::Any {
        self.inner.as_any()
    }
}

#[cfg(doctest)]
doc_comment::doctest!("../README.md", readme);
