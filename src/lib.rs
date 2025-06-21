#![cfg_attr(docsrs, feature(doc_cfg))]
/*!

# Keyring

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
See the [mock] and [sample] modules (built by those features) for details.

## Design

This crate implements a very simple, platform-independent concrete object called an _entry_.
Entries support setting, getting, and forgetting (aka deleting) UTF-8 passwords
and binary secrets. Each entry relies on an API-compatible
_credential store_ to provide security for and persistence of its data
by storing that data in a _credential_.

There are two ways of thinking about what an entry is.

### Entry as specification

In this view, an entry is a specification for a credential in a credential
store. The entry is identified by two UTF-8 strings, a _service name_ and a _username_,
and the credential store determines which credential in the store is specified
by that entry. If the entry's password is set, and there is no existing
credential which matches it, the store will create one and store the password there.

For example, an API-compatible credential store that uses the macOS Keychain
for its storage might decide that the entry `<service1, user1>`
specifies a "generic credential" in the `login` keychain whose
service attribute is `service1` and whose user attribute is `user1`.
If we set that entry's password to be `password1` and went into the
Keychain Access application on our Mac, we would
see an item whose displayed Kind is `application password`,
whose displayed Name and Where are both `service1`,
and whose displayed Account is `user1`.
If we then asked Keychain Access to show the password for that entry
(which would require permission from the login user),
the displayed password would be `password1`.

There are two APIs for creating entries that are specifiers:

* [Entry::new] takes just the service name and username as parameters.
  This uses each credential store's default algorithm for mapping the entry
  to a credential. Clients who use this API need never conditionalize their
  code based on the credential store being used.

* [Entry::new_with_modifiers], in addition to the service name and username parameters,
  takes a key-value map of credential-store-specific "modifiers".
  These modifiers may change which credential is specified, or they may
  change characteristics of the credential in the store. See the documentation
  for each credential store for details of allowed modifiers and their meaning.

### Entry as wrapper

In this view, an entry "wraps" a specific, existing credential in the store.
Setting a password on that entry will store the password in that credential.
If that credential is deleted, setting a password on the entry will fail,
because there is no credential to store it.

There are two APIs for creating entries that are wrappers:

* [Entry::new_from_credential] takes an existing store-specific credential object
  and wraps an entry around it. This is useful when you want to use the keyring API
  to manage credentials created or retrieved by third-party code.

* [Entry::search_for_credentials] takes a store-specific search specification
  and returns entries for all the existing credentials that match the search.
  Note that not all credential stores support search.

### Wrappers that specify

From a client point of view, the difference between specifiers and wrappers
is whether [set_password](Entry::set_password) can return a
[NoEntry](Error::NoEntry) error.
Entries that are specifiers will always create a credential if necessary,
but entries that are wrappers may not be able to because it may not be
possible for the store to re-create a wrapped credential
after it has been deleted.

The [Entry::is_specifier] method will tell you whether an entry
is a specifier. Of course, this method will return true for all
methods created as specifiers. But it can also return true
for entries that were created as wrappers.
To understand why this might be true, see the
next section.

### Ambiguity

The service name, username, and modifiers used when an
entry is created are combined by the store to specify a credential
in the store that will store that entry's password. In some stores,
however, that specification may be _ambiguous_, that is, there may
be multiple credentials in the store that meet
the specification. In such cases, trying to set or read
the entry's password will return an [Ambiguous](Error::Ambiguous) error.
The returned error will contain a list of entries, each of which
wraps one of the matching credentials.

For example, credential stores that use the Secret Service typically
map the service name and username in an entry to named attributes
on a Secret Service item. There may be multiple items in a
Secret Service store that agree on those attributes but differ
in other attributes, and in
such a case all those items will match the entry's specification.

Since a single client will not typically write multiple
different credentials for a single specification, the usual source
of ambiguity in a credential store is the presence of credentials
written by multiple clients with differing conventions. This crate
exposes ambiguity because keyring clients will often want to
interoperate with other clients.

When ambiguity is encountered reading or writing an entry's secret,
the keyring client typically wants to know which of the credentials
in the returned entries were written by it, and which by clients with
other conventions. If one of the returned entries is marked as a
specifier, then that will be the one that the keyring client wrote,
because it wraps a credential that's identical to one that the
keyring client would have created had there been no such credential.

It's worth noting that not all credential stores allow ambiguity.
Each keyring-compatible store should document whether it does.

### Credential Attributes

Most credential stores, in addition to storing secrets in credentials,
allow them to be decorated with additional information. The keyring
API exposes this capability in a cross-platform way by providing
two calls:

* [Entry::get_attributes] returns key-value string pairs that the
  store can use to expose decorations on the underlying credential.
  Like [get_password](Entry::get_password), this call will fail
  unless there is an existing credential underlying this entry.

* [Entry::set_attributes] asks the store to update any existing
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

pub use api::{Credential, CredentialStore};
pub use error::{Error, Result};

#[derive(Default, Debug)]
struct DefaultStore {
    inner: Option<Arc<CredentialStore>>,
}

static DEFAULT_STORE: std::sync::RwLock<DefaultStore> =
    std::sync::RwLock::new(DefaultStore { inner: None });

/// Set the credential builder used by default to create entries.
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
    debug!("setting default credential store to {:?}", new);
    let mut guard = DEFAULT_STORE
        .write()
        .expect("Poisoned RwLock in keyring_core::set_default_store: please report a bug!");
    guard.inner = Some(new);
}

// Release the default credential builder.
//
// This returns the old value for the default credential builder,
// and forgets what it was.
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
    inner: Box<Credential>,
}

impl Entry {
    /// Create an entry for the given service and user.
    ///
    /// The default credential builder is used.
    ///
    /// # Errors
    ///
    /// This function will return an [Invalid][Error::Invalid] error
    /// if the `service` or `user` values are not
    /// acceptable to the default credential store.
    ///
    /// # Panics
    ///
    /// In the very unlikely event that the internal credential builder's `RwLock`` is poisoned, this function
    /// will panic. If you encounter this, and especially if you can reproduce it, please report a bug with the
    /// details (and preferably a backtrace) so the developers can investigate.
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
    /// # Errors
    ///
    /// This function will return an [Invalid][Error::Invalid] error
    /// if the `service`, `user`, or `modifier` pairs are not
    /// acceptable to the default credential store.
    /// See the documentation for each credential store
    /// for a list of the modifiers and values accepted at entry creation time.
    ///
    /// # Panics
    ///
    /// In the very unlikely event that the internal credential builder's `RwLock`` is poisoned, this function
    /// will panic. If you encounter this, and especially if you can reproduce it, please report a bug with the
    /// details (and preferably a backtrace) so the developers can investigate.
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
    pub fn new_with_credential(credential: Box<Credential>) -> Entry {
        debug!("create entry wrapping {credential:?}");
        Entry { inner: credential }
    }

    /// Check if this entry is a specifier
    pub fn is_specifier(&self) -> bool {
        let result = self.inner.is_specifier();
        debug!("is_specifier of {:?} is {}", self.inner, result);
        result
    }

    /// Set the password for this entry.
    ///
    /// If a credential for this entry already exists in the store,
    /// this will update its password. Otherwise, a new credential
    /// will be created to store the password.
    ///
    /// # Errors
    ///
    /// If this entry is a wrapper and not a specifier, and the
    /// underlying credential has been deleted,
    /// returns a [NoEntry](Error::NoEntry) error.
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
    /// If this entry is a wrapper and not a specifier, and the
    /// underlying credential has been deleted,
    /// returns a [NoEntry](Error::NoEntry) error.
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

    /// Return a reference to this entry's matching credential.
    ///
    /// The reference is of the [Any](std::any::Any) type, so it can be
    /// downgraded to a concrete credential object for the
    /// containing store.
    ///
    /// # Errors
    ///
    /// Returns a [NoEntry](Error::NoEntry) error if there is no
    /// matching credential.
    ///
    /// Returns an [Ambiguous](Error::Ambiguous) error
    /// if there is more than one matching credential.
    pub fn get_credential(&self) -> &dyn std::any::Any {
        self.inner.as_any()
    }
}

#[cfg(doctest)]
doc_comment::doctest!("../README.md", readme);
