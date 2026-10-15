use std::collections::HashMap;
use std::sync::Arc;

use crate::api::CredentialStore;
use crate::{Entry, Error};

use super::MinimalStore;

#[test]
fn test_entry_methods() {
    let _ = env_logger::builder().is_test(true).try_init();
    assert!(crate::get_default_store().is_none());
    assert!(matches!(
        Entry::new("test", "test"),
        Err(Error::NoDefaultStore)
    ));
    assert!(matches!(
        Entry::new_with_modifiers("test", "test", &HashMap::new()),
        Err(Error::NoDefaultStore)
    ));
    assert!(matches!(
        Entry::search(&HashMap::new()),
        Err(Error::NoDefaultStore)
    ));
    let default: Arc<CredentialStore> = Arc::new(MinimalStore);
    crate::set_default_store(default.clone());
    let current = crate::get_default_store().unwrap();
    assert!(Arc::ptr_eq(&current, &default));
    let last = crate::unset_default_store().unwrap();
    assert!(Arc::ptr_eq(&last, &default));
    assert!(crate::get_default_store().is_none());
    crate::set_default_store(default.clone());
    assert!(matches!(
        Entry::new("test", "test"),
        Err(Error::Invalid(x, y)) if x == "no-mods" && y == "0"
    ));
    assert!(matches!(
        Entry::new_with_modifiers("test", "test", &HashMap::new()),
        Err(Error::Invalid(x, y)) if x == "mods" && y == "0"
    ));
    assert!(matches!(
        Entry::new_with_modifiers("test", "test", &HashMap::from([("k1", "v1"), ("k2", "v2")])),
        Err(Error::Invalid(x, y)) if x == "mods" && y == "2"
    ));
    assert!(matches!(
        Entry::new_in_store(&default, "test", "test"),
        Err(Error::Invalid(x, y)) if x == "no-mods" && y == "0"
    ));
    assert!(matches!(
        Entry::new_in_store_with_modifiers(&default, "test", "test", &HashMap::new()),
        Err(Error::Invalid(x, y)) if x == "mods" && y == "0"
    ));
    assert!(matches!(
        Entry::new_in_store_with_modifiers(
            &default,
            "test",
            "test",
            &HashMap::from([("k1", "v1"), ("k2", "v2")])
        ),
        Err(Error::Invalid(x, y)) if x == "mods" && y == "2"
    ));
    assert!(matches!(
        Entry::search(&HashMap::new()),
        Err(Error::NotSupportedByStore(_))
    ));
    crate::unset_default_store();
    assert!(crate::get_default_store().is_none());

    // Named store tests
    assert!(matches!(
        Entry::new_in_named_store("default", "test", "test"),
        Err(Error::Invalid(attr, _)) if attr == "name"
    ));
    assert!(matches!(
        Entry::new_in_named_store_with_modifiers("default", "test", "test", &HashMap::new()),
        Err(Error::Invalid(attr, _)) if attr == "name"
    ));
    assert!(matches!(
        Entry::new_in_named_store("custom_entry_api", "test", "test"),
        Err(Error::Invalid(attr, reason)) if attr == "name" && reason == "no such store"
    ));
    assert!(matches!(
        Entry::new_in_named_store_with_modifiers("custom_entry_api", "test", "test", &HashMap::new()),
        Err(Error::Invalid(attr, reason)) if attr == "name" && reason == "no such store"
    ));
    assert!(matches!(
        Entry::search_in_named_store("custom_entry_api", &HashMap::new()),
        Err(Error::Invalid(attr, reason)) if attr == "name" && reason == "no such store"
    ));

    crate::add_named_store("custom_entry_api", default.clone()).unwrap();
    assert!(matches!(
        Entry::new_in_named_store("custom_entry_api", "test", "test"),
        Err(Error::Invalid(x, y)) if x == "no-mods" && y == "0"
    ));
    assert!(matches!(
        Entry::new_in_named_store_with_modifiers("custom_entry_api", "test", "test", &HashMap::new()),
        Err(Error::Invalid(x, y)) if x == "mods" && y == "0"
    ));
    assert!(matches!(
        Entry::new_in_named_store_with_modifiers(
            "custom_entry_api",
            "test",
            "test",
            &HashMap::from([("k1", "v1"), ("k2", "v2")])
        ),
        Err(Error::Invalid(x, y)) if x == "mods" && y == "2"
    ));
    assert!(matches!(
        Entry::search_in_named_store("custom_entry_api", &HashMap::new()),
        Err(Error::NotSupportedByStore(_))
    ));
    crate::drop_named_store("custom_entry_api").unwrap();
}
