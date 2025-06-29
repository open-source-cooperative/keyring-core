use std::any::Any;
use std::collections::HashMap;
use std::sync::{Arc, RwLock, Weak};

use super::credential::{CredId, CredKey};
use crate::{
    Credential,
    Error::{Invalid, PlatformFailure},
    Result,
    api::{CredentialPersistence, CredentialStoreApi},
};
use dashmap::DashMap;
use log::{debug, error};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The stored data for a credential
#[derive(Debug, Serialize, Deserialize)]
pub struct CredValue {
    pub secret: Vec<u8>,
    pub comment: Option<String>,
    pub creation_date: Option<String>,
}

impl CredValue {
    pub fn new(secret: &[u8]) -> Self {
        CredValue {
            secret: secret.to_vec(),
            comment: None,
            creation_date: None,
        }
    }

    pub fn new_ambiguous(comment: &str) -> CredValue {
        CredValue {
            secret: vec![],
            comment: Some(comment.to_string()),
            creation_date: Some(chrono::Local::now().to_rfc2822()),
        }
    }
}

/// A map from <service, user> pairs to matching credentials
pub type CredMap = DashMap<CredId, DashMap<String, CredValue>>;

/// The list of extant credential stores.
///
/// Because credentials are created with a reference to their store,
/// and stores shouldn't keep self-references (which would be circular),
/// all created stores keep their index position in this static
/// and get their self-reference from there.
///
/// These static references are intentionally weak, so that stores can
/// in fact be dropped (by dropping the store itself and all
/// credentials from that store).
static STORES: RwLock<Vec<Weak<Store>>> = RwLock::new(Vec::new());

/// A credential store.
///
/// The credential data is kept in the CredMap.
pub struct Store {
    pub index: usize,
    /// index into the STORES vector
    pub creds: CredMap,
    /// the credential store data
    pub backing: Option<String>, // the backing file, if any
}

impl std::fmt::Debug for Store {
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
        if self.backing.is_none() {
            debug!("dropping store {:?}", self)
        } else {
            debug!("Saving store {:?} on drop...", self);
            match self.save() {
                Ok(_) => debug!("Save of store {:?} completed", self),
                Err(e) => error!("Save of store {:?} failed: {:?}", self, e),
            }
        }
    }
}

impl Store {
    /// Create a new, empty store with no backing file.
    pub fn new() -> Arc<Self> {
        Self::new_internal(DashMap::new(), None)
    }

    /// Create a new store from a backing file.
    ///
    /// The backing file must be a valid path, but it need not exist,
    /// in which case the store starts off empty. If the file does
    /// exist, the initial contents of the store are loaded from it.
    pub fn new_with_backing(path: &str) -> Result<Arc<Self>> {
        Ok(Self::new_internal(
            Self::load_credentials(path)?,
            Some(String::from(path)),
        ))
    }

    /// Save this store to its backing file.
    ///
    /// This is a no-op if there is no backing file.
    ///
    /// Stores will save themselves to their backing file
    /// when they go out of scope (i.e., are dropped),
    /// but this call can be very useful if you specify
    /// an instance of your store as the keyring-core
    /// API default store, because the default store
    /// is kept in a static variable
    /// and thus is *never* dropped.
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

    /// Create a store with the given credentials and backing file.
    ///
    /// This inserts the store into the list of all stores, and saves
    /// the index of its reference in the store itself (so it can
    /// pass the reference on to its credentials).
    ///
    /// The reference in the list of all stores is weak, so it
    /// won't keep the store from being destroyed when it goes
    /// out of scope.
    pub fn new_internal(creds: CredMap, backing: Option<String>) -> Arc<Self> {
        let mut guard = STORES
            .write()
            .expect("Poisoned RwLock creating a store: report a bug!");
        let store = Arc::new(Store {
            index: guard.len(),
            creds,
            backing,
        });
        debug!("Created new store: {:?}", store);
        guard.push(Arc::downgrade(&store));
        store
    }

    /// Loads store content from a backing file.
    ///
    /// If the backing file does not exist, the returned store is empty.
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
    /// See the API docs.
    ///
    /// The vendor string for this store is `keyring-core-sample`.
    fn vendor(&self) -> String {
        String::from("keyring-core-sample")
    }

    /// See the API docs.
    ///
    /// The store ID is based on its sequence number
    /// in the list of created stores.
    fn id(&self) -> String {
        format!("sample-store-{}", self.index)
    }

    /// See the API docs.
    ///
    /// The only modifier you can specify is `target`; all others are ignored.
    /// The `target` modifier forces immediate credential creation, and can
    /// be used with the same service name and username to create ambiguity.
    ///
    /// When the target modifier is specified, the created credential gets
    /// an empty password/secret, a `comment` attribute with the value of the modifier,
    /// and a `creation_date` attribute with a string for the current local time.
    fn build(
        &self,
        service: &str,
        user: &str,
        mods: Option<&HashMap<&str, &str>>,
    ) -> Result<Arc<Credential>> {
        let id = CredId {
            service: service.to_owned(),
            user: user.to_owned(),
        };
        let guard = STORES
            .read()
            .expect("Poisoned RwLock at credential creation: report a bug!");
        let store = guard
            .get(self.index)
            .expect("Missing weak ref at credential creation: report a bug!")
            .upgrade()
            .expect("Missing store at credential creation: report a bug!");
        let key = CredKey {
            store,
            id: id.clone(),
            uuid: None,
        };
        if let Some(mods) = mods {
            if let Some(target) = mods.get("target") {
                let uuid = Uuid::new_v4().to_string();
                let value = CredValue::new_ambiguous(target);
                match self.creds.get(&id) {
                    None => {
                        let creds = DashMap::new();
                        creds.insert(uuid, value);
                        self.creds.insert(id, creds);
                    }
                    Some(creds) => {
                        creds.value().insert(uuid, value);
                    }
                };
            }
        }
        Ok(Arc::new(key))
    }

    /// See the API docs.
    ///
    /// The specification must contain exactly two keys - `service` and `user` -
    /// and their values must be valid regular expressions.
    /// Every credential whose service name matches the service regex
    /// _and_ whose username matches the user regex will be returned.
    /// (The match is a substring match, so the empty string will match every value.)
    fn search(&self, spec: &HashMap<&str, &str>) -> Result<Vec<Arc<Credential>>> {
        let mut result: Vec<Arc<Credential>> = Vec::new();
        let svc = regex::Regex::new(
            spec.get("service")
                .ok_or_else(|| Invalid("service".to_string(), "must be specified".to_string()))?,
        )
        .map_err(|e| Invalid("service regex".to_string(), e.to_string()))?;
        let usr = regex::Regex::new(
            spec.get("user")
                .ok_or_else(|| Invalid("user".to_string(), "must be specified".to_string()))?,
        )
        .map_err(|e| Invalid("user regex".to_string(), e.to_string()))?;
        if spec.len() != 2 {
            return Err(Invalid(
                "spec".to_string(),
                "must only have service and entry".to_string(),
            ));
        }
        let guard = STORES
            .read()
            .expect("Poisoned RwLock at credential creation: report a bug!");
        let store = guard
            .get(self.index)
            .expect("Missing weak ref at credential creation: report a bug!")
            .upgrade()
            .expect("Missing store at credential creation: report a bug!");
        for pair in self.creds.iter() {
            if !svc.is_match(pair.key().service.as_str()) {
                continue;
            }
            if !usr.is_match(pair.key().user.as_str()) {
                continue;
            }
            for cred in pair.value().iter() {
                result.push(Arc::new(CredKey {
                    store: store.clone(),
                    id: pair.key().clone(),
                    uuid: Some(cred.key().clone()),
                }))
            }
        }
        Ok(result)
    }

    //// See the API docs.
    fn as_any(&self) -> &dyn Any {
        self
    }

    //// See the API docs.
    ////
    //// If this store has a backing file, credential persistence is
    //// `UntilDelete`. Otherwise, it's `ProcessOnly`.
    fn persistence(&self) -> CredentialPersistence {
        if self.backing.is_none() {
            CredentialPersistence::ProcessOnly
        } else {
            CredentialPersistence::UntilDelete
        }
    }

    /// See the API docs.
    fn debug_fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}
