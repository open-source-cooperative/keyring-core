use std::collections::HashMap;
use std::sync::Once;

use crate::{CredentialStore, Entry, Error, Result, api::CredentialPersistence};

static SET_STORE: Once = Once::new();

fn entry_new(service: &str, user: &str) -> Entry {
    SET_STORE.call_once(|| {
        crate::set_default_credential_store(Box::new(super::store::Store::new()));
    });
    Entry::new(service, user).unwrap_or_else(|err| {
        panic!("Couldn't create entry (service: {service}, user: {user}): {err:?}")
    })
}

fn entry_new_with_modifiers(
    service: &str,
    user: &str,
    mods: &HashMap<&str, &str>,
) -> Result<Entry> {
    SET_STORE.call_once(|| {
        crate::set_default_credential_store(Box::new(super::store::Store::new()));
    });
    Entry::new_with_modifiers(service, user, mods)
}

fn generate_random_string() -> String {
    use fastrand;
    use std::iter::repeat_with;
    repeat_with(fastrand::alphanumeric).take(30).collect()
}

fn generate_random_bytes() -> Vec<u8> {
    use fastrand;
    use std::iter::repeat_with;
    repeat_with(|| fastrand::u8(..)).take(24).collect()
}

// A round-trip password test that doesn't delete the credential afterward
fn test_round_trip_no_delete(case: &str, entry: &Entry, in_pass: &str) {
    entry
        .set_password(in_pass)
        .unwrap_or_else(|err| panic!("Can't set password for {case}: {err:?}"));
    let out_pass = entry
        .get_password()
        .unwrap_or_else(|err| panic!("Can't get password for {case}: {err:?}"));
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
        .unwrap_or_else(|err| panic!("Can't delete password for {case}: {err:?}"));
    let password = entry.get_password();
    assert!(
        matches!(password, Err(Error::NoEntry)),
        "Read deleted password for {case}",
    );
}

// A round-trip secret test that does delete the credential afterward
pub fn test_round_trip_secret(case: &str, entry: &Entry, in_secret: &[u8]) {
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
    assert!(
        matches!(secret, Err(Error::NoEntry)),
        "Read deleted password for {case}",
    );
}

#[test]
fn test_empty_service_and_user() {
    let name = generate_random_string();
    let in_pass = "doesn't matter";
    test_round_trip("empty user", &entry_new(&name, ""), in_pass);
    test_round_trip("empty service", &entry_new("", &name), in_pass);
    test_round_trip("empty service & user", &entry_new("", ""), in_pass);
}

#[test]
fn test_missing_entry() {
    let name = generate_random_string();
    let entry = entry_new(&name, &name);
    assert!(
        matches!(entry.get_password(), Err(Error::NoEntry)),
        "Missing entry has password"
    )
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
fn test_credential_and_ambiguous_credential() {
    let name = generate_random_string();
    let entry1 = entry_new_with_modifiers(&name, &name, &HashMap::from([("create", "entry1")]))
        .expect("Couldn't create entry1 for ambiguity test");
    assert!(entry1.is_specifier(), "entry1 is not a specifier");
    entry1
        .set_password("password for entry1")
        .expect("Can't set password for entry1");
    let credential1: &super::store::CredKey = entry1
        .get_credential()
        .downcast_ref()
        .expect("Not a sample store credential");
    assert_eq!(credential1.index, 0, "entry1 index should be 0");
    let entry2 = entry_new_with_modifiers(&name, &name, &HashMap::from([("create", "entry2")]))
        .expect("Couldn't create entry2 for ambiguity test");
    assert!(!entry2.is_specifier(), "entry2 is a specifier");
    entry2
        .set_password("password for entry2")
        .expect("Can't set password for entry2");
    let credential2: &super::store::CredKey = entry2
        .get_credential()
        .downcast_ref()
        .expect("Not a sample store credential");
    assert_eq!(credential2.index, 1, "entry2 index should be 1");
    entry2
        .delete_credential()
        .expect("Couldn't delete entry2 credential");
    assert!(matches!(entry2.get_password(), Err(Error::NoEntry)));
    entry2
        .set_password("second password for entry2")
        .expect_err("Can set password after deleting entry2");
    entry1
        .delete_credential()
        .expect("Couldn't delete entry1 credential");
    entry1
        .set_password("second password for entry1")
        .expect("Can't set password after deleting entry1");
    entry1
        .delete_credential()
        .expect("Couldn't delete entry1 credential after resetting password");
    assert!(matches!(entry1.get_password(), Err(Error::NoEntry)));
}

#[test]
fn test_get_update_attributes() {
    let name = generate_random_string();
    let entry = entry_new_with_modifiers(&name, &name, &HashMap::from([("create", "entry")]))
        .expect("Couldn't create entry for attributes test");
    let expected = HashMap::from([("create-comment".to_string(), "entry".to_string())]);
    let actual = entry.get_attributes().expect("Failed to get attributes");
    assert_eq!(actual, expected, "Attributes don't match expected");
    entry
        .update_attributes(&HashMap::from([("foo", "bar")]))
        .expect("Update attributes failed");
    let actual = entry.get_attributes().expect("Failed to get attributes");
    assert_eq!(actual, expected, "Attributes don't match after update");
    entry
        .delete_credential()
        .unwrap_or_else(|err| panic!("Can't delete credential for attribute test: {err:?}"));
    assert!(
        matches!(entry.get_attributes(), Err(Error::NoEntry)),
        "Read deleted credential in attribute test",
    );
}

#[test]
fn test_persistence() {
    let store: Box<CredentialStore> = Box::new(super::store::Store::new());
    assert!(matches!(
        store.persistence(),
        CredentialPersistence::ProcessOnly
    ))
}
