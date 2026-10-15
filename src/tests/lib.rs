use std::sync::Arc;

use crate::{CredentialStore, Error};

use super::MinimalStore;

#[test]
fn test_named_store_methods() {
    let _ = env_logger::builder().is_test(true).try_init();
    let store1: Arc<CredentialStore> = Arc::new(MinimalStore);
    let store2: Arc<CredentialStore> = Arc::new(MinimalStore);

    // Attempting to access "default" with named store methods must return Invalid
    assert!(matches!(
        crate::add_named_store("default", store1.clone()),
        Err(Error::Invalid(attr, _)) if attr == "name"
    ));
    assert!(matches!(
        crate::drop_named_store("default"),
        Err(Error::Invalid(attr, _)) if attr == "name"
    ));
    assert!(matches!(
        crate::get_named_store("default"),
        Err(Error::Invalid(attr, _)) if attr == "name"
    ));

    // Unset custom store returns Ok(None)
    assert!(crate::get_named_store("custom").unwrap().is_none());

    // Add custom store
    assert!(
        crate::add_named_store("custom", store1.clone())
            .unwrap()
            .is_none()
    );
    let retrieved = crate::get_named_store("custom").unwrap().unwrap();
    assert!(Arc::ptr_eq(&retrieved, &store1));

    // Overwrite custom store
    let prev = crate::add_named_store("custom", store2.clone())
        .unwrap()
        .unwrap();
    assert!(Arc::ptr_eq(&prev, &store1));
    let retrieved = crate::get_named_store("custom").unwrap().unwrap();
    assert!(Arc::ptr_eq(&retrieved, &store2));

    // Drop custom store
    let dropped = crate::drop_named_store("custom").unwrap().unwrap();
    assert!(Arc::ptr_eq(&dropped, &store2));
    assert!(crate::get_named_store("custom").unwrap().is_none());
    assert!(crate::drop_named_store("custom").unwrap().is_none());
}
