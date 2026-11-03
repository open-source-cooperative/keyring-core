use std::any::Any;
use std::collections::HashMap;

use crate::api::CredentialStoreApi;
use crate::{Entry, Error};

mod api;
mod attributes;
mod error;
mod lib;
mod mock;

pub fn generate_random_string() -> String {
    use fastrand;
    use std::iter::repeat_with;
    repeat_with(fastrand::alphanumeric).take(30).collect()
}

pub fn generate_random_bytes() -> Vec<u8> {
    use fastrand;
    use std::iter::repeat_with;
    repeat_with(|| fastrand::u8(..)).take(24).collect()
}

// minimal store that uses only the default impls;
// we use it to test the default impls only
struct MinimalStore;

impl CredentialStoreApi for MinimalStore {
    fn vendor(&self) -> String {
        unimplemented!()
    }

    fn id(&self) -> String {
        unimplemented!()
    }

    fn build(&self, _: &str, _: &str, mods: Option<&HashMap<&str, &str>>) -> crate::Result<Entry> {
        match mods {
            Some(mods) => Err(Error::Invalid("mods".to_string(), mods.len().to_string())),
            None => Err(Error::Invalid("no-mods".to_string(), "0".to_string())),
        }
    }

    fn as_any(&self) -> &dyn Any {
        unimplemented!()
    }
}
