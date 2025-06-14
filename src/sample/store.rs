use dashmap::DashMap;
use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::api::{CredentialApi, CredentialPersistence, CredentialStoreApi};
use crate::{Credential, Error, Result};

type CredMap = Arc<DashMap<CredId, Vec<Option<CredValue>>>>;

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub struct CredId {
    service: String,
    username: String,
}

#[derive(Clone)]
pub struct CredKey {
    pub store_id: String,
    pub store_creds: CredMap,
    pub id: CredId,
    pub index: usize,
}

impl std::fmt::Debug for CredKey {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("CredKey")
            .field("id", &self.id)
            .field("index", &self.index)
            .field("store_id", &self.store_id)
            .finish()
    }
}

impl CredentialApi for CredKey {
    fn is_specifier(&self) -> bool {
        self.index == 0
    }

    fn set_secret(&self, secret: &[u8]) -> Result<()> {
        match self.store_creds.get_mut(&self.id) {
            None => {
                if self.index != 0 {
                    return Err(Error::NoEntry);
                }
                let cred = CredValue {
                    secret: secret.to_vec(),
                    comment: None,
                };
                self.store_creds.insert(self.id.clone(), vec![Some(cred)]);
                Ok(())
            }
            Some(mut creds) => match creds.get_mut(self.index) {
                None => Err(Error::NoEntry),
                Some(None) if self.index == 0 => {
                    (*creds)[0] = Some(CredValue {
                        secret: secret.to_vec(),
                        comment: None,
                    });
                    Ok(())
                }
                Some(None) => Err(Error::NoEntry),
                Some(Some(cred)) => {
                    cred.secret = secret.to_vec();
                    Ok(())
                }
            },
        }
    }

    fn get_secret(&self) -> Result<Vec<u8>> {
        match self.store_creds.get(&self.id) {
            None => Err(Error::NoEntry),
            Some(creds) => match creds.get(self.index) {
                None => Err(Error::NoEntry),
                Some(None) => Err(Error::NoEntry),
                Some(Some(cred)) => Ok(cred.secret.clone()),
            },
        }
    }

    fn get_attributes(&self) -> Result<HashMap<String, String>> {
        match self.store_creds.get(&self.id) {
            None => Err(Error::NoEntry),
            Some(creds) => match creds.get(self.index) {
                None => Err(Error::NoEntry),
                Some(None) => Err(Error::NoEntry),
                Some(Some(cred)) => match &cred.comment {
                    None => Ok(HashMap::new()),
                    Some(comment) => Ok(HashMap::from([(
                        "create-comment".to_string(),
                        comment.clone(),
                    )])),
                },
            },
        }
    }

    fn delete_credential(&self) -> Result<()> {
        match self.store_creds.get_mut(&self.id) {
            None => Err(Error::NoEntry),
            Some(mut creds) => match creds.get(self.index) {
                None => Err(Error::NoEntry),
                Some(None) => Err(Error::NoEntry),
                Some(Some(_)) => {
                    (*creds)[self.index] = None;
                    Ok(())
                }
            },
        }
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    /// Expose the concrete debug formatter for use via the [Credential] trait
    fn debug_fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}

#[derive(Debug)]
pub struct CredValue {
    pub secret: Vec<u8>,
    pub comment: Option<String>,
}

pub struct Store {
    pub vendor: String,
    pub id: String,
    pub credentials: CredMap,
}

impl Default for Store {
    fn default() -> Self {
        let millis = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        Store {
            vendor: "keyring::sample".to_string(),
            id: format!("sample-{}", millis % 100000),
            credentials: Arc::new(DashMap::new()),
        }
    }
}

impl std::fmt::Debug for Store {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Store")
            .field("vendor", &self.vendor)
            .field("id", &self.id)
            .field("credential_count", &self.credentials.len())
            .finish()
    }
}

impl Store {
    pub fn new() -> Self {
        Default::default()
    }
}

impl CredentialStoreApi for Store {
    fn vendor(&self) -> String {
        self.vendor.clone()
    }

    fn id(&self) -> String {
        self.id.clone()
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
        let mut key = CredKey {
            store_id: self.id.clone(),
            store_creds: self.credentials.clone(),
            id: id.clone(),
            index: 0,
        };
        if let Some(mods) = mods {
            if let Some(create) = mods.get("create") {
                let value = CredValue {
                    secret: Vec::new(),
                    comment: Some(create.to_string()),
                };
                match self.credentials.get_mut(&id) {
                    None => {
                        self.credentials.insert(id, vec![Some(value)]);
                    }
                    Some(mut creds) => {
                        (*creds).push(Some(value));
                        key.index = creds.len() - 1;
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
        CredentialPersistence::ProcessOnly
    }

    /// Expose the concrete debug formatter for use via the [CredentialStore] trait
    fn debug_fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}
