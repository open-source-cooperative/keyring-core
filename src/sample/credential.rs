use serde::{Deserialize, Serialize};
use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;

use crate::Error;
use crate::api::CredentialApi;

use super::store::{CredValue, Store};

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct CredId {
    pub service: String,
    pub username: String,
}

#[derive(Debug, Clone)]
pub struct CredKey {
    pub store: Arc<Store>,
    pub id: CredId,
    pub cred_index: usize,
}

impl CredentialApi for CredKey {
    fn is_specifier(&self) -> bool {
        self.cred_index == 0
    }

    fn set_secret(&self, secret: &[u8]) -> crate::Result<()> {
        match self.store.creds.get_mut(&self.id) {
            None => {
                if self.cred_index != 0 {
                    return Err(Error::NoEntry);
                }
                let cred = CredValue {
                    secret: secret.to_vec(),
                    comment: None,
                };
                self.store.creds.insert(self.id.clone(), vec![Some(cred)]);
                Ok(())
            }
            Some(mut creds) => match creds.get_mut(self.cred_index) {
                None => Err(Error::NoEntry),
                Some(None) if self.cred_index == 0 => {
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

    fn get_secret(&self) -> crate::Result<Vec<u8>> {
        match self.store.creds.get(&self.id) {
            None => Err(Error::NoEntry),
            Some(creds) => match creds.get(self.cred_index) {
                None => Err(Error::NoEntry),
                Some(None) => Err(Error::NoEntry),
                Some(Some(cred)) => Ok(cred.secret.clone()),
            },
        }
    }

    fn get_attributes(&self) -> crate::Result<HashMap<String, String>> {
        match self.store.creds.get(&self.id) {
            None => Err(Error::NoEntry),
            Some(creds) => match creds.get(self.cred_index) {
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

    fn delete_credential(&self) -> crate::Result<()> {
        match self.store.creds.get_mut(&self.id) {
            None => Err(Error::NoEntry),
            Some(mut creds) => match creds.get(self.cred_index) {
                None => Err(Error::NoEntry),
                Some(None) => Err(Error::NoEntry),
                Some(Some(_)) => {
                    (*creds)[self.cred_index] = None;
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
