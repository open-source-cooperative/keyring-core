use serde::{Deserialize, Serialize};
use std::any::Any;
use std::collections::HashMap;
use std::sync::Arc;

use crate::Error;
use crate::api::CredentialApi;

use super::store::{CredValue, Store};

/// Credentials are specified by a pair of service name and username.
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct CredId {
    pub service: String,
    pub user: String,
}

/// Each of these keys specifies a specific credential in the store.
///
/// For each credential ID, the store maintains a list of all the
/// credentials associated with that ID. The first in that list
/// (element 0) is the credential _specified_ by the ID, so it's
/// the one that's auto-created if there are no credentials with
/// that ID in the store and a password is set. All keys with
/// indices higher than 0 are wrappers for a specific credential,
/// but they do not _specify_ a credential.
#[derive(Debug, Clone)]
pub struct CredKey {
    pub store: Arc<Store>,
    pub id: CredId,
    pub cred_index: usize,
}

impl CredentialApi for CredKey {
    /// See the API docs.
    ///
    /// In this store, only the key with index 0 is a specifier;
    /// all the others are only wrappers.
    fn is_specifier(&self) -> bool {
        self.cred_index == 0
    }

    /// See the API docs.
    fn set_secret(&self, secret: &[u8]) -> crate::Result<()> {
        match self.store.creds.get_mut(&self.id) {
            None => {
                if self.cred_index != 0 {
                    return Err(Error::NoEntry);
                }
                let cred = CredValue {
                    secret: secret.to_vec(),
                    comment: None,
                    creation_date: None,
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
                        creation_date: None,
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

    /// See the API docs.
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

    /// See the API docs.
    ///
    /// The only attributes on credentials in this store are `comment`
    /// and `creation_date`.
    fn get_attributes(&self) -> crate::Result<HashMap<String, String>> {
        match self.store.creds.get(&self.id) {
            None => Err(Error::NoEntry),
            Some(creds) => match creds.get(self.cred_index) {
                None => Err(Error::NoEntry),
                Some(None) => Err(Error::NoEntry),
                Some(Some(cred)) => {
                    let mut attrs = HashMap::new();
                    if cred.creation_date.is_some() {
                        attrs.insert(
                            "creation_date".to_string(),
                            cred.creation_date.as_ref().unwrap().to_string(),
                        );
                    }
                    if cred.comment.is_some() {
                        attrs.insert(
                            "comment".to_string(),
                            cred.comment.as_ref().unwrap().to_string(),
                        );
                    }
                    Ok(attrs)
                }
            },
        }
    }

    /// See the API docs.
    ///
    /// Only the `comment` attribute can be updated. The `creation_date`
    /// attribute cannot be modified and specifying it will produce an error.
    /// All other attributes are ignored.
    fn update_attributes(&self, attrs: &HashMap<&str, &str>) -> crate::Result<()> {
        match self.store.creds.get_mut(&self.id) {
            None => Err(Error::NoEntry),
            Some(mut creds) => match creds.get_mut(self.cred_index) {
                None => Err(Error::NoEntry),
                Some(None) => Err(Error::NoEntry),
                Some(Some(cred)) => {
                    if attrs.contains_key("creation_date") {
                        return Err(Error::Invalid(
                            "creation_date".to_string(),
                            "cannot be updated".to_string(),
                        ));
                    }
                    if let Some(comment) = attrs.get("comment") {
                        cred.comment = Some(comment.to_string());
                    }
                    Ok(())
                }
            },
        }
    }

    /// See the API docs.
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

    /// See the API docs.
    fn as_any(&self) -> &dyn Any {
        self
    }

    /// See the API docs.
    fn debug_fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Debug::fmt(self, f)
    }
}
