use dashmap::DashMap;
use log::{debug, error};
use serde::{Deserialize, Serialize};
use std::any::Any;
use std::collections::HashMap;
use std::fmt::Debug;
use std::sync::{Arc, RwLock, Weak};

use super::credential::{CredId, CredKey};
use crate::{
    Credential,
    Error::{Invalid, PlatformFailure},
    Result,
    api::{CredentialPersistence, CredentialStoreApi},
};

// The data store for a credential
#[derive(Debug, Serialize, Deserialize)]
pub struct CredValue {
    pub secret: Vec<u8>,
    pub comment: Option<String>,
    pub creation_date: Option<String>,
}

// A map from <service, user> pairs to matching credentials
pub type CredMap = DashMap<CredId, Vec<Option<CredValue>>>;

// The list of extant credential stores.
//
// Because credentials are created with a reference to their store,
// and stores shouldn't keep self-references (which would be circular),
// all created stores keep their index position in this static
// and get their self-reference from there.
//
// These static references are intentionally weak, so that stores can
// in fact be dropped (by dropping the store itself and all
// credentials from that store).
static STORES: RwLock<Vec<Weak<Store>>> = RwLock::new(Vec::new());

// A credential store.
//
// The credential data is kept in the CredMap.
pub struct Store {
    pub index: usize,            // index into the STORES vector
    pub creds: CredMap,          // the credential store data
    pub backing: Option<String>, // the backing file, if any
}

impl Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store")
            .field("index", &self.index)
            .field("backing", &self.backing)
            .field("cred-count", &self.creds.len())
            .finish()
    }
}

impl Drop for Store {
    fn drop(&mut self) {
        debug!("Saving store {:?} on drop...", self);
        match self.save() {
            Ok(_) => debug!("Save of store {:?} complete.", self),
            Err(e) => error!("Save of store {:?} failed: {:?}", self, e),
        }
    }
}

impl Store {
    // Create a new, empty store with no backing file.
    pub fn new() -> Arc<Self> {
        Self::new_internal(DashMap::new(), None)
    }

    // Create a new store from a backing file.
    //
    // The backing file must be a valid path, but it need not exist,
    // in which case the store starts off empty. If the file does
    // exist, the initial contents of the store are loaded from it.
    pub fn new_with_backing(path: &str) -> Result<Arc<Self>> {
        Ok(Self::new_internal(
            Self::load_credentials(path)?,
            Some(String::from(path)),
        ))
    }

    // Save this store to its backing file.
    //
    // This is a no-op if there is no backing file.
    pub fn save(&self) -> Result<()> {
        if self.backing.is_none() {
            return Ok(());
        };
        let content = ron::ser::to_string_pretty(&self.creds, ron::ser::PrettyConfig::new())
            .map_err(|e| PlatformFailure(Box::from(e)))?;
        std::fs::write(self.backing.as_ref().unwrap(), content)
            .map_err(|e| PlatformFailure(Box::from(e)))?;
        Ok(())
    }

    // Create a store with the given credentials and backing file.
    //
    // This inserts the store into the list of all stores, and saves
    // the index of its reference in the store itself.
    pub fn new_internal(creds: CredMap, backing: Option<String>) -> Arc<Self> {
        let mut guard = STORES
            .write()
            .expect("Poisoned RwLock creating a store: report a bug!");
        let store = Arc::new(Store {
            index: guard.len(),
            creds,
            backing,
        });
        guard.push(Arc::downgrade(&store));
        store
    }

    // Loads store content from a backing file.
    //
    // If the backing file does not exist, the returned store is empty.
    pub fn load_credentials(path: &str) -> Result<CredMap> {
        match std::fs::exists(path) {
            Ok(true) => match std::fs::read_to_string(path) {
                Ok(s) => Ok(ron::de::from_str(&s).map_err(|e| PlatformFailure(Box::from(e)))?),
                Err(e) => Err(PlatformFailure(Box::from(e))),
            },
            Ok(false) => Ok(DashMap::new()),
            Err(e) => Err(Invalid("Invalid path".to_string(), e.to_string())),
        }
    }
}

impl CredentialStoreApi for Store {
    fn vendor(&self) -> String {
        String::from("keyring-core-sample")
    }

    fn id(&self) -> String {
        format!("sample-store-{}", self.index)
    }

    fn build(
        &self,
        service: &str,
        user: &str,
        mods: Option<&HashMap<&str, &str>>,
    ) -> Result<Box<Credential>> {
        let id = CredId {
            service: service.to_owned(),
            username: user.to_owned(),
        };
        let guard = STORES
            .read()
            .expect("Poisoned RwLock at credential creation: report a bug!");
        let store = guard
            .get(self.index)
            .expect("Missing weak pointer at credential creation: report a bug!")
            .upgrade()
            .expect("Missing store at credential creation: report a bug!");
        let mut key = CredKey {
            store,
            id: id.clone(),
            cred_index: 0,
        };
        if let Some(mods) = mods {
            if let Some(target) = mods.get("target") {
                let value = CredValue {
                    secret: Vec::new(),
                    comment: Some(target.to_string()),
                    creation_date: Some(chrono::Local::now().to_rfc2822()),
                };
                match self.creds.get_mut(&id) {
                    None => {
                        self.creds.insert(id, vec![Some(value)]);
                    }
                    Some(mut creds) => {
                        (*creds).push(Some(value));
                        key.cred_index = creds.len() - 1;
                    }
                };
            }
        }
        Ok(Box::new(key))
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn persistence(&self) -> CredentialPersistence {
        if self.backing.is_none() {
            CredentialPersistence::ProcessOnly
        } else {
            CredentialPersistence::UntilDelete
        }
    }

    /// Expose the concrete debug formatter for use via the [CredentialStore] trait
    fn debug_fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}
