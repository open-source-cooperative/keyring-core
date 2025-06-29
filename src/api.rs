/*!

# Platform-independent secure storage model

This module defines a plug and play model for credential stores.
The model comprises two traits: [CredentialStoreApi] for
store-level operations
and [CredentialApi] for
entry-level operations.  These traits must be implemented
in a thread-safe way, a requirement captured in the [CredentialStore] and
[Credential] types that wrap them.
 */
use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;

use super::{Error, Result};

/// The API that [credentials](Credential) implement.
pub trait CredentialApi {
    /// Set the entry's protected data to be the given string.
    ///
    /// This method has a default implementation in terms of
    /// [set_secret](CredentialApi::set_secret), which see.
    fn set_password(&self, password: &str) -> Result<()> {
        self.set_secret(password.as_bytes())
    }

    /// Set the credential's protected data to be the given byte array.
    ///
    /// Expected behavior:
    ///
    /// - If the entry has no associated credential:
    ///   - If the entry is a specifier, create a credential and save the data in it.
    ///   - If the entry is a wrapper, return a [NoEntry](Error::NoEntry) error.
    /// - If the entry has exactly one associated credential,
    ///   this will update the data saved in that credential.
    /// - If the entry has multiple associated credentials,
    ///   return an [Ambiguous](Error::Ambiguous) error.
    ///
    /// Note: The API allows passwords to be empty. If a store does not support
    /// empty passwords, and one is specified,
    /// return an [Invalid](Error::Invalid) error.
    fn set_secret(&self, secret: &[u8]) -> Result<()>;

    /// Retrieve the protected data as a UTF-8 string from the associated credential.
    ///
    /// This method has a default implementation in terms of
    /// [get_secret](CredentialApi::get_secret), which see.
    /// If the data in the credential is not valid UTF-8, the default implementation
    /// returns a [BadEncoding](Error::BadEncoding) error containing the data.
    fn get_password(&self) -> Result<String> {
        let secret = self.get_secret()?;
        super::error::decode_password(secret)
    }

    /// Retrieve the protected data as a byte array from the underlying credential.
    ///
    /// Expected behavior:
    ///
    /// - If there is no associated credential for this entry,
    ///   return a [NoEntry](Error::NoEntry) error.
    /// - If there is exactly one associated credential for this entry,
    ///   return its protected data.
    /// - If there are multiple associated credentials for this entry,
    ///   return an [Ambiguous](Error::Ambiguous) error whose data
    ///   is a list of entries each of which wraps one of the credentials.
    fn get_secret(&self) -> Result<Vec<u8>>;

    /// Return any store-specific decorations on this entry's credential.
    ///
    /// The expected error and success cases are the same as with
    /// [get_secret](CredentialApi::get_secret), which see.
    ///
    /// For convenience, a default implementation of this method is
    /// provided which doesn't return any decorations. Credential
    /// store implementations which support decorations should
    /// override this method.
    fn get_attributes(&self) -> Result<HashMap<String, String>> {
        // this should err in the same cases as get_secret, so first call that for effect
        self.get_secret()?;
        // if we got this far, return success with no attributes
        Ok(HashMap::new())
    }

    /// Update the secure store attributes on this entry's credential.
    ///
    /// Each credential store may support reading and updating different
    /// named attributes; see the documentation on each of the stores
    /// for details. The implementation will ignore any attribute names
    /// that you supply that are not available for update. Because the
    /// names used by the different stores tend to be distinct, you can
    /// write cross-platform code that will work correctly on each platform.
    ///
    /// We provide a default no-op implementation of this method.
    fn update_attributes(&self, _: &HashMap<&str, &str>) -> Result<()> {
        // this should err in the same cases as get_secret, so first call that for effect
        self.get_secret()?;
        // if we got this far, return success after setting no attributes
        Ok(())
    }

    /// Delete the underlying credential if there is one.
    ///
    /// If the underlying credential doesn't exist, return
    /// a [NoEntry](Error::NoEntry) error.
    ///
    /// If there is more than one matching credential,
    /// return an [Ambiguous](Error::Ambiguous) error.
    fn delete_credential(&self) -> Result<()>;

    /// Return a wrapper for the underlying credential.
    ///
    /// If `self` is already a wrapper, return None.
    ///
    /// If the underlying credential doesn't exist, return
    /// a [NoEntry](Error::NoEntry) error.
    ///
    /// If there is more than one matching credential,
    /// return an [Ambiguous](Error::Ambiguous) error.
    fn get_credential(&self) -> Result<Option<Arc<Credential>>>;

    /// Return the inner credential object cast to [Any].
    ///
    /// This call is used to expose the Debug trait for credentials.
    fn as_any(&self) -> &dyn Any;

    /// The Debug trait call for the object.
    ///
    /// This is used to implement the Debug trait on this type; it
    /// allows generic code to provide debug printing as provided by
    /// the underlying concrete object.
    ///
    /// We provide a (no-op) default implementation of this method.
    fn debug_fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self.as_any(), f)
    }
}

/// A thread-safe implementation of the [Credential API](CredentialApi).
pub type Credential = dyn CredentialApi + Send + Sync;

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.debug_fmt(f)
    }
}

/// A descriptor for the lifetime of stored credentials, returned from
/// a credential store's [persistence](CredentialStoreApi::persistence) call.
///
/// This enum may change even in patch versions of the library, so it's
/// marked as non-exhaustive.
#[non_exhaustive]
pub enum CredentialPersistence {
    /// Credential storage is in the entry, so storage vanishes when the entry is dropped.
    EntryOnly,
    /// Credential storage is in process memory,
    /// so storage vanishes when the process terminates
    ProcessOnly,
    /// Credential storage is in user-space memory, so storage vanishes when user logs out
    UntilLogout,
    /// Credentials stored in kernel-space memory, so storage vanishes when machine reboots
    UntilReboot,
    /// Credentials stored on disk, so storage vanishes when the credential is deleted
    UntilDelete,
    /// Placeholder for cases not (yet) handled here
    Unspecified,
}

/// The API that [credential stores](CredentialStore) implement.
pub trait CredentialStoreApi {
    /// The name of the "vendor" that provided this store.
    ///
    /// This allows clients to conditionalize their code for specific vendors.
    fn vendor(&self) -> String;

    /// The ID of this credential store instance.
    ///
    /// IDs need not be unique across vendors or processes, but if two
    /// stores from the same vendor in the same process have the same ID,
    /// then they are the same store.
    fn id(&self) -> String;

    /// Create an entry specified by the given service and user,
    /// perhaps with additional creation-time attributes.
    ///
    /// This typically has no effect on the content of the underlying store.
    /// A credential need not be persisted until its password is set.
    fn build(
        &self,
        service: &str,
        user: &str,
        attrs: Option<&HashMap<&str, &str>>,
    ) -> Result<Arc<Credential>>;

    /// Search for credentials that match the given spec.
    ///
    /// Returns a list of the matching credentials.
    ///
    /// Should return an [Invalid](Error::Invalid) error if the spec is bad.
    ///
    /// The default implementation returns a
    /// [NotSupportedByStore](Error::NotSupportedByStore) error; that is,
    /// credential stores need not provide support for search.
    fn search(&self, _spec: &HashMap<&str, &str>) -> Result<Vec<Arc<Credential>>> {
        let vendor = self.vendor();
        Err(Error::NotSupportedByStore(vendor))
    }

    /// Return the inner store object cast to [Any].
    ///
    /// This call is used to expose the Debug trait for stores.
    fn as_any(&self) -> &dyn Any;

    /// The lifetime of credentials produced by this builder.
    ///
    /// A default implementation is provided for backward compatibility,
    /// since this API was added in a minor release.  The default assumes
    /// that keystores use disk-based credential storage.
    fn persistence(&self) -> CredentialPersistence {
        CredentialPersistence::UntilDelete
    }

    /// The Debug trait call for the object.
    ///
    /// This is used to implement the Debug trait on this type; it
    /// allows generic code to provide debug printing as provided by
    /// the underlying concrete object.
    ///
    /// We provide a (no-op) default implementation of this method.
    fn debug_fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self.as_any(), f)
    }
}

impl std::fmt::Debug for CredentialStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.debug_fmt(f)
    }
}

/// A thread-safe implementation of the [CredentialBuilder API](CredentialStoreApi).
pub type CredentialStore = dyn CredentialStoreApi + Send + Sync;
