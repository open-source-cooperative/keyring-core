/*!

# Mock credential store

To facilitate testing of clients, this crate provides a Mock credential store
that is platform-independent, provides no persistence, and allows the client
to specify the return values (including errors) for each call. The credentials
in this store have no attributes at all.

To use this credential store instead of the default, make this call during
application startup _before_ creating any entries:
```rust
keyring_core::set_default_credential_store(keyring_core::mock::default_store());
```

You can then create entries as you usually do, and call their usual methods
to set, get, and delete passwords.  There is no persistence other than
in the entry itself, so getting a password before setting it will always result
in a [NoEntry](Error::NoEntry) error.

If you want a method call on an entry to fail in a specific way, you can
downcast the entry to a [MockCredential] and then call [set_error](MockCredential::set_error)
with the appropriate error.  The next entry method called on the credential
will fail with the error you set.  The error will then be cleared, so the next
call on the mock will operate as usual.  Here's a complete example:
```rust
# use keyring_core::{Entry, Error, mock, mock::MockCredential};
keyring_core::set_default_credential_store(mock::default_store());
let entry = Entry::new("service", "user").unwrap();
let mock: &MockCredential = entry.get_credential().downcast_ref().unwrap();
mock.set_error(Error::Invalid("mock error".to_string(), "takes precedence".to_string()));
entry.set_password("test").expect_err("error will override");
entry.set_password("test").expect("error has been cleared");
```
 */
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::Mutex;

use super::api::{
    Credential, CredentialApi, CredentialPersistence, CredentialStore, CredentialStoreApi,
};
use super::error::{Error, Result, decode_password};

/// The concrete mock credential
///
/// Mocks use an internal mutability pattern since entries are read-only.
/// The mutex is used to make sure these are Sync.
#[derive(Debug)]
pub struct MockCredential {
    pub inner: Mutex<RefCell<MockData>>,
}

impl Default for MockCredential {
    fn default() -> Self {
        Self {
            inner: Mutex::new(RefCell::new(Default::default())),
        }
    }
}

/// The (in-memory) persisted data for a mock credential.
///
/// We keep a password, but unlike most keystores
/// we also keep an intended error to return on the next call.
///
/// (Everything about this structure is public for transparency.
/// Most keystore implementation hide their internals.)
#[derive(Debug, Default)]
pub struct MockData {
    pub secret: Option<Vec<u8>>,
    pub error: Option<Error>,
}

impl CredentialApi for MockCredential {
    /// Every mock credential is a specifier
    fn is_specifier(&self) -> bool {
        true
    }

    /// Set a password on a mock credential.
    ///
    /// If there is an error in the mock, it will be returned
    /// and the password will _not_ be set.  The error will
    /// be cleared, so calling again will set the password.
    fn set_password(&self, password: &str) -> Result<()> {
        let mut inner = self.inner.lock().expect("Can't access mock data for set");
        let data = inner.get_mut();
        let err = data.error.take();
        match err {
            None => {
                data.secret = Some(password.as_bytes().to_vec());
                Ok(())
            }
            Some(err) => Err(err),
        }
    }

    /// Set a password on a mock credential.
    ///
    /// If there is an error in the mock, it will be returned
    /// and the password will _not_ be set.  The error will
    /// be cleared, so calling again will set the password.
    fn set_secret(&self, secret: &[u8]) -> Result<()> {
        let mut inner = self.inner.lock().expect("Can't access mock data for set");
        let data = inner.get_mut();
        let err = data.error.take();
        match err {
            None => {
                data.secret = Some(secret.to_vec());
                Ok(())
            }
            Some(err) => Err(err),
        }
    }

    /// Get the password from a mock credential, if any.
    ///
    /// If there is an error set in the mock, it will
    /// be returned instead of a password.
    fn get_password(&self) -> Result<String> {
        let mut inner = self.inner.lock().expect("Can't access mock data for get");
        let data = inner.get_mut();
        let err = data.error.take();
        match err {
            None => match &data.secret {
                None => Err(Error::NoEntry),
                Some(val) => decode_password(val.clone()),
            },
            Some(err) => Err(err),
        }
    }

    /// Get the password from a mock credential, if any.
    ///
    /// If there is an error set in the mock, it will
    /// be returned instead of a password.
    fn get_secret(&self) -> Result<Vec<u8>> {
        let mut inner = self.inner.lock().expect("Can't access mock data for get");
        let data = inner.get_mut();
        let err = data.error.take();
        match err {
            None => match &data.secret {
                None => Err(Error::NoEntry),
                Some(val) => Ok(val.clone()),
            },
            Some(err) => Err(err),
        }
    }

    /// Delete the password in a mock credential
    ///
    /// If there is an error, it will be returned and
    /// the deletion will not happen.
    ///
    /// If there is no password, a [NoEntry](Error::NoEntry) error
    /// will be returned.
    fn delete_credential(&self) -> Result<()> {
        let mut inner = self
            .inner
            .lock()
            .expect("Can't access mock data for delete");
        let data = inner.get_mut();
        let err = data.error.take();
        match err {
            None => match data.secret {
                Some(_) => {
                    data.secret = None;
                    Ok(())
                }
                None => Err(Error::NoEntry),
            },
            Some(err) => Err(err),
        }
    }

    /// Return this mock credential concrete object
    /// wrapped in the [Any](std::any::Any) trait,
    /// so it can be downcast.
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    /// Expose the concrete debug formatter for use via the [Credential] trait
    fn debug_fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

impl MockCredential {
    /// Make a new mock credential.
    ///
    /// Since mocks have no persistence between sessions,
    /// new mocks always have no password.
    fn new() -> Result<Self> {
        Ok(Default::default())
    }

    /// Set an error to be returned from this mock credential.
    ///
    /// Error returns always take precedence over the normal
    /// behavior of the mock.  But once an error has been
    /// returned it is removed, so the mock works thereafter.
    pub fn set_error(&self, err: Error) {
        let mut inner = self
            .inner
            .lock()
            .expect("Can't access mock data for set_error");
        let data = inner.get_mut();
        data.error = Some(err);
    }
}

/// The builder for mock credentials.
pub struct MockCredentialBuilder {}

impl CredentialStoreApi for MockCredentialBuilder {
    fn vendor(&self) -> String {
        String::from("mock")
    }

    fn id(&self) -> String {
        String::from("mock")
    }

    /// Build a mock credential for the service and user. Any attributes are ignored.
    ///
    /// Since mocks don't persist beyond the life of their entry,  all mocks
    /// start off without passwords.
    fn build(
        &self,
        _service: &str,
        _user: &str,
        _: Option<&HashMap<&str, &str>>,
    ) -> Result<Box<Credential>> {
        let credential = MockCredential::new()?;
        Ok(Box::new(credential))
    }

    /// Get an [Any][std::any::Any] reference to the mock credential builder.
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    /// This keystore keeps the password in the entry!
    fn persistence(&self) -> CredentialPersistence {
        CredentialPersistence::EntryOnly
    }
}

/// Return a mock credential builder for use by clients.
pub fn default_store() -> Box<CredentialStore> {
    Box::new(MockCredentialBuilder {})
}

#[cfg(test)]
mod tests {
    use super::{MockCredential, default_store};
    use crate::api::CredentialPersistence;
    use crate::{Entry, Error};
    use std::collections::HashMap;

    #[test]
    fn test_persistence() {
        assert!(matches!(
            default_store().persistence(),
            CredentialPersistence::EntryOnly
        ))
    }

    fn entry_new(_service: &str, _user: &str) -> Entry {
        let credential = MockCredential::new().unwrap();
        Entry::new_with_credential(Box::new(credential))
    }

    fn generate_random_string() -> String {
        use fastrand;
        use std::iter::repeat_with;
        repeat_with(fastrand::alphanumeric).take(30).collect()
    }

    fn generate_random_bytes() -> Vec<u8> {
        use fastrand;
        use std::iter::repeat_with;
        repeat_with(|| fastrand::u8(..)).take(24).collect()
    }

    // A round-trip password test that doesn't delete the credential afterward
    fn test_round_trip_no_delete(case: &str, entry: &Entry, in_pass: &str) {
        entry
            .set_password(in_pass)
            .unwrap_or_else(|err| panic!("Can't set password for {case}: {err:?}"));
        let out_pass = entry
            .get_password()
            .unwrap_or_else(|err| panic!("Can't get password for {case}: {err:?}"));
        assert_eq!(
            in_pass, out_pass,
            "Passwords don't match for {case}: set='{in_pass}', get='{out_pass}'",
        )
    }

    // A round-trip password test that does delete the credential afterward
    fn test_round_trip(case: &str, entry: &Entry, in_pass: &str) {
        test_round_trip_no_delete(case, entry, in_pass);
        entry
            .delete_credential()
            .unwrap_or_else(|err| panic!("Can't delete password for {case}: {err:?}"));
        let password = entry.get_password();
        assert!(
            matches!(password, Err(Error::NoEntry)),
            "Read deleted password for {case}",
        );
    }

    // A round-trip secret test that does delete the credential afterward
    pub fn test_round_trip_secret(case: &str, entry: &Entry, in_secret: &[u8]) {
        entry
            .set_secret(in_secret)
            .unwrap_or_else(|err| panic!("Can't set secret for {case}: {err:?}"));
        let out_secret = entry
            .get_secret()
            .unwrap_or_else(|err| panic!("Can't get secret for {case}: {err:?}"));
        assert_eq!(
            in_secret, &out_secret,
            "Secrets don't match for {case}: set='{in_secret:?}', get='{out_secret:?}'",
        );
        entry
            .delete_credential()
            .unwrap_or_else(|err| panic!("Can't delete credential for {case}: {err:?}"));
        let secret = entry.get_secret();
        assert!(
            matches!(secret, Err(Error::NoEntry)),
            "Read deleted password for {case}",
        );
    }

    #[test]
    fn test_empty_service_and_user() {
        let name = generate_random_string();
        let in_pass = "doesn't matter";
        test_round_trip("empty user", &entry_new(&name, ""), in_pass);
        test_round_trip("empty service", &entry_new("", &name), in_pass);
        test_round_trip("empty service & user", &entry_new("", ""), in_pass);
    }

    #[test]
    fn test_missing_entry() {
        let name = generate_random_string();
        let entry = entry_new(&name, &name);
        assert!(
            matches!(entry.get_password(), Err(Error::NoEntry)),
            "Missing entry has password"
        )
    }

    #[test]
    fn test_round_trip_ascii_password() {
        let name = generate_random_string();
        let entry = entry_new(&name, &name);
        test_round_trip("ascii password", &entry, "test ascii password");
    }

    #[test]
    fn test_round_trip_non_ascii_password() {
        let name = generate_random_string();
        let entry = entry_new(&name, &name);
        test_round_trip("non-ascii password", &entry, "このきれいな花は桜です");
    }

    #[test]
    fn test_round_trip_random_secret() {
        let name = generate_random_string();
        let entry = entry_new(&name, &name);
        let secret = generate_random_bytes();
        test_round_trip_secret("non-ascii password", &entry, secret.as_slice());
    }

    #[test]
    fn test_update() {
        let name = generate_random_string();
        let entry = entry_new(&name, &name);
        test_round_trip_no_delete("initial ascii password", &entry, "test ascii password");
        test_round_trip(
            "updated non-ascii password",
            &entry,
            "このきれいな花は桜です",
        );
    }

    #[test]
    fn test_get_update_attributes() {
        let name = generate_random_string();
        let entry = entry_new(&name, &name);
        assert!(
            matches!(entry.get_attributes(), Err(Error::NoEntry)),
            "Read missing credential in attribute test",
        );
        let map = HashMap::from([("test attribute name", "test attribute value")]);
        assert!(
            matches!(entry.update_attributes(&map), Err(Error::NoEntry)),
            "Updated missing credential in attribute test",
        );
        // create the credential and test again
        entry
            .set_password("test password for attributes")
            .unwrap_or_else(|err| panic!("Can't set password for attribute test: {err:?}"));
        match entry.get_attributes() {
            Err(err) => panic!("Couldn't get attributes: {err:?}"),
            Ok(attrs) if attrs.is_empty() => {}
            Ok(attrs) => panic!("Unexpected attributes: {attrs:?}"),
        }
        assert!(
            matches!(entry.update_attributes(&map), Ok(())),
            "Couldn't update attributes in attribute test",
        );
        match entry.get_attributes() {
            Err(err) => panic!("Couldn't get attributes after update: {err:?}"),
            Ok(attrs) if attrs.is_empty() => {}
            Ok(attrs) => panic!("Unexpected attributes after update: {attrs:?}"),
        }
        entry
            .delete_credential()
            .unwrap_or_else(|err| panic!("Can't delete credential for attribute test: {err:?}"));
        assert!(
            matches!(entry.get_attributes(), Err(Error::NoEntry)),
            "Read deleted credential in attribute test",
        );
    }

    #[test]
    fn test_set_error() {
        let name = generate_random_string();
        let entry = entry_new(&name, &name);
        let password = "test ascii password";
        let mock: &MockCredential = entry
            .inner
            .as_any()
            .downcast_ref()
            .expect("Downcast failed");
        mock.set_error(Error::Invalid(
            "mock error".to_string(),
            "is an error".to_string(),
        ));
        assert!(
            matches!(entry.set_password(password), Err(Error::Invalid(_, _))),
            "set: No error"
        );
        entry
            .set_password(password)
            .expect("set: Error not cleared");
        mock.set_error(Error::NoEntry);
        assert!(
            matches!(entry.get_password(), Err(Error::NoEntry)),
            "get: No error"
        );
        let stored_password = entry.get_password().expect("get: Error not cleared");
        assert_eq!(
            stored_password, password,
            "Retrieved and set ascii passwords don't match"
        );
        mock.set_error(Error::TooLong("mock".to_string(), 3));
        assert!(
            matches!(entry.delete_credential(), Err(Error::TooLong(_, 3))),
            "delete: No error"
        );
        entry
            .delete_credential()
            .expect("delete: Error not cleared");
        assert!(
            matches!(entry.get_password(), Err(Error::NoEntry)),
            "Able to read a deleted ascii password"
        )
    }
}
