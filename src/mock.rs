/*!

# Mock credential store

To facilitate testing of clients, this crate provides a Mock credential store
that is platform-independent, provides no persistence, and allows the client
to specify the return values (including errors) for each call. The credentials
in this store have no attributes at all.

To use this credential store instead of the default, make this call during
application startup _before_ creating any entries:
```rust
keyring_core::set_default_store(keyring_core::mock::Store::new().unwrap());
```

You can then create entries as usual and call their usual methods
to set, get, and delete passwords. There is no persistence except in-memory
so, once you drop the store, all the credentials will be gone.

If you want a method call on an entry to fail in a specific way, you can
downcast the entry to a [Cred] and then call [set_error](Cred::set_error)
with the appropriate error.  The next entry method called on the credential
will fail with the error you set.  The error will then be cleared, so the next
call on the mock will operate as usual.  Setting an error will not affect
the value of the credential (if any). Here's a complete example:

```rust
# use keyring_core::{Entry, Error, mock};
keyring_core::set_default_store(mock::Store::new().unwrap());
let entry = Entry::new("service", "user").unwrap();
entry.set_password("test").expect("the entry's password is now test");
let mock: &mock::Cred = entry.as_any().downcast_ref().unwrap();
mock.set_error(Error::Invalid("mock error".to_string(), "takes precedence".to_string()));
_ = entry.get_password().expect_err("the error will be returned");
let val = entry.get_password().expect("the error has been cleared");
assert_eq!(val, "test", "the error did not affect the password");
```

 */
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::api::{CredentialApi, CredentialStoreApi};
use crate::{Credential, CredentialPersistence, Entry, Error, Result};

/// The concrete mock credential
///
/// Mocks use an internal mutability pattern since entries are read-only.
/// The mutex is used to make sure these are Sync.
#[derive(Debug)]
pub struct Cred {
    pub specifiers: (String, String),
    pub inner: Mutex<RefCell<CredData>>,
}

/// The (in-memory) persisted data for a mock credential.
///
/// We keep a password but, unlike most credentials stores,
/// we also keep an intended error to return on the next call.
///
/// (Everything about this structure is public for transparency.
/// Most credential store implementations hide their internals.)
#[derive(Debug, Default)]
pub struct CredData {
    pub secret: Option<Vec<u8>>,
    pub error: Option<Error>,
}

impl CredentialApi for Cred {
    /// See the API docs.
    ///
    /// If there is an error in the mock, it will be returned
    /// and the secret will _not_ be set.  The error will
    /// be cleared, so calling again will set the secret.
    fn set_secret(&self, secret: &[u8]) -> Result<()> {
        let mut inner = self
            .inner
            .lock()
            .expect("Can't access mock data for set_secret: please report a bug!");
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

    /// See the API docs.
    ///
    /// If there is an error set in the mock, it will
    /// be returned instead of a secret. The existing
    /// secret will not change.
    fn get_secret(&self) -> Result<Vec<u8>> {
        let mut inner = self
            .inner
            .lock()
            .expect("Can't access mock data for get: please report a bug!");
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

    /// See the API docs.
    ///
    /// If there is an error, it will be returned and
    /// cleared. Calling again will delete the cred.
    fn delete_credential(&self) -> Result<()> {
        let mut inner = self
            .inner
            .lock()
            .expect("Can't access mock data for delete: please report a bug!");
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

    /// See the API docs.
    ///
    /// If there is an error in the mock, it's returned instead and cleared.
    /// Calling again will retry the operation.
    fn get_credential(&self) -> Result<Option<Arc<Credential>>> {
        let mut inner = self
            .inner
            .lock()
            .expect("Can't access mock data for get_credential: please report a bug!");
        let data = inner.get_mut();
        let err = data.error.take();
        match err {
            None => match data.secret {
                Some(_) => Ok(None),
                None => Err(Error::NoEntry),
            },
            Some(err) => Err(err),
        }
    }

    /// See the API docs.
    fn get_specifiers(&self) -> Option<(String, String)> {
        Some(self.specifiers.clone())
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

impl Cred {
    /// Set an error to be returned from this mock credential.
    ///
    /// Error returns always take precedence over the normal
    /// behavior of the mock.  But once an error has been
    /// returned, it is removed, so the mock works thereafter.
    pub fn set_error(&self, err: Error) {
        let mut inner = self
            .inner
            .lock()
            .expect("Can't access mock data for set_error: please report a bug!");
        let data = inner.get_mut();
        data.error = Some(err);
    }
}

/// The builder for mock credentials.
///
/// We keep them in a vector so we can reuse them
/// for entries with the same service and user.
/// Yes, a hashmap might be faster, but this is
/// way simpler.
pub struct Store {
    pub id: String,
    pub inner: Mutex<RefCell<Vec<Arc<Cred>>>>,
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store")
            .field("vendor", &self.vendor())
            .field("id", &self.id)
            .finish()
    }
}

impl Store {
    pub fn new() -> Result<Arc<Self>> {
        Ok(Arc::new(Store {
            id: format!(
                "Crate version {}, Instantiated at {}",
                env!("CARGO_PKG_VERSION"),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_else(|_| Duration::new(0, 0))
                    .as_secs_f64()
            ),
            inner: Mutex::new(RefCell::new(Vec::new())),
        }))
    }
}

impl CredentialStoreApi for Store {
    fn vendor(&self) -> String {
        String::from("Mock store, https://crates.io/crates/keyring-core")
    }

    fn id(&self) -> String {
        self.id.clone()
    }

    /// Build a mock credential for the service and user. No modifiers are allowed.
    ///
    /// Since mocks don't persist beyond the life of their entry, all mocks
    /// start off without passwords.
    fn build(
        &self,
        service: &str,
        user: &str,
        mods: Option<&HashMap<&str, &str>>,
    ) -> Result<Entry> {
        if mods.is_some_and(|m| !m.is_empty()) {
            let msg = "The mock store doesn't allow entry modifiers";
            return Err(Error::NotSupportedByStore(msg.to_string()));
        }
        let mut inner = self
            .inner
            .lock()
            .expect("Can't access mock store data: please report a bug!");
        let creds = inner.get_mut();
        for cred in creds.iter() {
            if service == cred.specifiers.0 && user == cred.specifiers.1 {
                return Ok(Entry {
                    inner: cred.clone(),
                });
            }
        }
        let cred = Arc::new(Cred {
            specifiers: (service.to_string(), user.to_string()),
            inner: Mutex::new(RefCell::new(Default::default())),
        });
        creds.push(cred.clone());
        Ok(Entry { inner: cred })
    }

    /// Search for mock credentials matching the spec.
    ///
    /// Attributes other than `service` and `user` are ignored.
    /// Their values are used in unanchored substring searches against the specifier.
    fn search(&self, spec: &HashMap<&str, &str>) -> Result<Vec<Entry>> {
        let mut result: Vec<Entry> = Vec::new();
        let svc = spec.get("service").unwrap_or(&"");
        let usr = spec.get("user").unwrap_or(&"");
        let mut inner = self
            .inner
            .lock()
            .expect("Can't access mock store data: please report a bug!");
        let creds = inner.get_mut();
        for cred in creds.iter() {
            if !cred.specifiers.0.as_str().contains(svc) {
                continue;
            }
            if !cred.specifiers.1.as_str().contains(usr) {
                continue;
            }
            result.push(Entry {
                inner: cred.clone(),
            });
        }
        Ok(result)
    }

    /// Get an [Any][std::any::Any] reference to the mock credential builder.
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    /// This keystore keeps the password in the entry!
    fn persistence(&self) -> CredentialPersistence {
        CredentialPersistence::ProcessOnly
    }

    /// Expose the concrete debug formatter
    /// for use via the [CredentialStore](crate::CredentialStore) trait
    fn debug_fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}
