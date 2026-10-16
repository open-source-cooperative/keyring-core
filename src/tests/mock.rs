use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use crate::mock::{Cred, Store};
use crate::{CredentialPersistence, CredentialStore, Entry, Error};

use super::{generate_random_bytes, generate_random_string};

static STORE: OnceLock<Arc<CredentialStore>> = OnceLock::new();

fn get_store() -> &'static Arc<CredentialStore> {
    STORE.get_or_init(|| Store::new().unwrap())
}

#[test]
fn test_vendor_and_id() {
    let s1 = get_store();
    let s2 = Store::new().unwrap() as Arc<CredentialStore>;
    assert_eq!(
        s1.vendor(),
        "Mock store, https://crates.io/crates/keyring-core"
    );
    assert_eq!(s1.vendor(), s2.vendor());
    assert_ne!(s1.id(), s2.id());
}

#[test]
fn test_modifiers() {
    let empty_mods = HashMap::new();
    let name = generate_random_string();
    let store = get_store();
    Entry::new_in_store_with_modifiers(store, &name, &name, &empty_mods).unwrap();
    let non_empty_mods = HashMap::from([("mod-arg", "mod-val")]);
    assert!(matches!(
        Entry::new_in_store_with_modifiers(store, "fail", "fail", &non_empty_mods),
        Err(Error::NotSupportedByStore(_))
    ));
}

fn entry_new(service: &str, user: &str) -> Entry {
    Entry::new_in_store(get_store(), service, user).unwrap_or_else(|err| {
        panic!("Couldn't create entry (service: {service}, user: {user}): {err:?}")
    })
}

// A round-trip password test that doesn't delete the credential afterward
fn test_round_trip_no_delete(case: &str, entry: &Entry, in_pass: &str) {
    entry
        .set_password(in_pass)
        .unwrap_or_else(|err| panic!("Can't set password: {case}: {err:?}"));
    let out_pass = entry
        .get_password()
        .unwrap_or_else(|err| panic!("Can't get password: {case}: {err:?}"));
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
        .unwrap_or_else(|err| panic!("Can't delete password: {case}: {err:?}"));
    let password = entry.get_password();
    assert!(matches!(password, Err(Error::NoEntry)));
}

// A round-trip secret test that does delete the credential afterward
fn test_round_trip_secret(case: &str, entry: &Entry, in_secret: &[u8]) {
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
    assert!(matches!(secret, Err(Error::NoEntry)));
}

#[test]
fn test_empty_service_and_user() {
    let name = generate_random_string();
    let in_pass = "value doesn't matter";
    test_round_trip("empty user", &entry_new(&name, ""), in_pass);
    test_round_trip("empty service", &entry_new("", &name), in_pass);
    test_round_trip("empty service and user", &entry_new("", ""), in_pass);
}

#[test]
fn test_empty_password() {
    let name = generate_random_string();
    let in_pass = "";
    test_round_trip("empty password", &entry_new(&name, &name), in_pass);
}

#[test]
fn test_missing_entry() {
    let name = generate_random_string();
    let entry = entry_new(&name, &name);
    assert!(matches!(entry.get_password(), Err(Error::NoEntry)))
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
fn test_entries_with_same_and_different_specifiers() {
    let name1 = generate_random_string();
    let name2 = generate_random_string();
    let entry1 = entry_new(&name1, &name2);
    let entry2 = entry_new(&name1, &name2);
    let entry3 = entry_new(&name2, &name1);
    entry1.set_password("test password").unwrap();
    let pw2 = entry2.get_password().unwrap();
    assert_eq!(pw2, "test password");
    _ = entry3.get_password().unwrap_err();
    entry1.delete_credential().unwrap();
    _ = entry2.get_password().unwrap_err();
    entry3.delete_credential().unwrap_err();
}

#[test]
fn test_get_credential_and_specifiers() {
    let name = generate_random_string();
    let entry1 = entry_new(&name, &name);
    assert!(matches!(entry1.get_credential(), Err(Error::NoEntry)));
    entry1.set_password("password for entry1").unwrap();
    let wrapper = entry1.get_credential().unwrap();
    let (service, user) = wrapper.get_specifiers().unwrap();
    assert_eq!(service, name);
    assert_eq!(user, name);
    wrapper.delete_credential().unwrap();
    entry1.delete_credential().unwrap_err();
    wrapper.delete_credential().unwrap_err();
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
fn test_set_error() {
    let name = generate_random_string();
    let entry = entry_new(&name, &name);
    let password = "test ascii password";
    let mock: &Cred = entry.as_any().downcast_ref().unwrap();
    mock.set_error(Error::Invalid(
        "mock error".to_string(),
        "is an error".to_string(),
    ));
    assert!(matches!(
        entry.set_password(password),
        Err(Error::Invalid(_, _))
    ));
    entry.set_password(password).unwrap();
    mock.set_error(Error::NoEntry);
    assert!(matches!(entry.get_password(), Err(Error::NoEntry)));
    let stored_password = entry.get_password().unwrap();
    assert_eq!(stored_password, password);
    mock.set_error(Error::TooLong("mock".to_string(), 3));
    assert!(matches!(
        entry.delete_credential(),
        Err(Error::TooLong(_, 3))
    ));
    entry.delete_credential().unwrap();
    assert!(matches!(entry.get_password(), Err(Error::NoEntry)))
}

#[test]
fn test_get_update_attributes() {
    let name = generate_random_string();
    let entry = entry_new(&name, &name);
    assert!(matches!(entry.get_attributes(), Err(Error::NoEntry)));
    entry.set_password("password").unwrap();
    let attrs = entry.get_attributes().unwrap();
    assert_eq!(attrs.len(), 0);
    assert!(matches!(
        entry.update_attributes(&HashMap::new()),
        Err(Error::NotSupportedByStore(_))
    ));
    entry.delete_credential().unwrap();
}

#[test]
fn test_search() {
    let store: Arc<CredentialStore> = Store::new().unwrap();
    let all = Entry::search_in_store(&store, &HashMap::from([])).unwrap();
    assert!(all.is_empty());
    let all = store
        .search(&HashMap::from([("service", ""), ("user", "")]))
        .unwrap();
    assert!(all.is_empty());
    let e1 = store.build("foo", "bar", None).unwrap();
    e1.set_password("e1").unwrap();
    let all = Entry::search_in_store(&store, &HashMap::from([])).unwrap();
    assert_eq!(all.len(), 1);
    let all = store
        .search(&HashMap::from([("service", ""), ("user", "")]))
        .unwrap();
    assert_eq!(all.len(), 1);
    let e2 = store.build("foo", "bam", None).unwrap();
    e2.set_password("e2").unwrap();
    let one = Entry::search_in_store(&store, &HashMap::from([("user", "m")])).unwrap();
    assert_eq!(one.len(), 1);
    let one = store
        .search(&HashMap::from([("service", "foo"), ("user", "bar")]))
        .unwrap();
    assert_eq!(one.len(), 1);
    let two = Entry::search_in_store(&store, &HashMap::from([("service", "foo")])).unwrap();
    assert_eq!(two.len(), 2);
    let all = Entry::search_in_store(&store, &HashMap::from([("foo", "bar")])).unwrap();
    assert_eq!(all.len(), 2);
}

#[test]
fn test_persistence() {
    let store: Arc<CredentialStore> = Store::new().unwrap();
    assert!(matches!(
        store.persistence(),
        CredentialPersistence::ProcessOnly
    ))
}
