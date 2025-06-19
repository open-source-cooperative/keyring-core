use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Once};

use crate::{CredentialStore, Entry, Error, api::CredentialPersistence};

static TEST_STORE: LazyLock<Arc<CredentialStore>> = LazyLock::new(|| super::store::Store::new());

static SET_STORE: Once = Once::new();

fn entry_new(service: &str, user: &str) -> Entry {
    SET_STORE.call_once(|| {
        let _ = env_logger::builder().is_test(true).try_init();
        crate::set_default_store((*TEST_STORE).clone());
    });
    Entry::new(service, user).unwrap_or_else(|err| {
        panic!("Couldn't create entry (service: {service}, user: {user}): {err:?}")
    })
}

fn entry_new_with_modifiers(service: &str, user: &str, mods: &HashMap<&str, &str>) -> Entry {
    SET_STORE.call_once(|| {
        let _ = env_logger::builder().is_test(true).try_init();
        crate::set_default_store((*TEST_STORE).clone());
    });
    Entry::new_with_modifiers(service, user, mods).unwrap_or_else(|err| {
        panic!("Couldn't create entry (service: {service}, user: {user}): {err:?}")
    })
}

fn generate_random_string() -> String {
    use fastrand;
    use std::iter::repeat_with;
    repeat_with(fastrand::alphanumeric).take(12).collect()
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
fn test_empty_password() {
    let name = generate_random_string();
    let in_pass = "";
    test_round_trip("empty password", &entry_new(&name, &name), in_pass);
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
    let entry1 = entry_new_with_modifiers(&name, &name, &HashMap::from([("create", "entry1")]));
    assert!(entry1.is_specifier(), "entry1 is not a specifier");
    entry1
        .set_password("password for entry1")
        .expect("Can't set password for entry1");
    let credential1: &super::credential::CredKey = entry1
        .get_credential()
        .downcast_ref()
        .expect("Not a sample store credential");
    assert_eq!(credential1.cred_index, 0, "entry1 index should be 0");
    let entry2 = entry_new_with_modifiers(&name, &name, &HashMap::from([("create", "entry2")]));
    assert!(!entry2.is_specifier(), "entry2 is a specifier");
    entry2
        .set_password("password for entry2")
        .expect("Can't set password for entry2");
    let credential2: &super::credential::CredKey = entry2
        .get_credential()
        .downcast_ref()
        .expect("Not a sample store credential");
    assert_eq!(credential2.cred_index, 1, "entry2 index should be 1");
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
    let entry = entry_new_with_modifiers(&name, &name, &HashMap::from([("create", "entry")]));
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
fn test_create_then_move() {
    let name = generate_random_string();
    let entry = entry_new(&name, &name);
    let test = move || {
        let password = "test ascii password";
        entry
            .set_password(password)
            .expect("Can't set initial ascii password");
        let stored_password = entry.get_password().expect("Can't get ascii password");
        assert_eq!(
            stored_password, password,
            "Retrieved and set initial ascii passwords don't match"
        );
        let password = "このきれいな花は桜です";
        entry
            .set_password(password)
            .expect("Can't set non-ascii password");
        let stored_password = entry.get_password().expect("Can't get non-ascii password");
        assert_eq!(
            stored_password, password,
            "Retrieved and set non-ascii passwords don't match"
        );
        entry
            .delete_credential()
            .expect("Can't delete non-ascii password");
        assert!(
            matches!(entry.get_password(), Err(Error::NoEntry)),
            "Able to read a deleted non-ascii password"
        );
    };
    let handle = std::thread::spawn(test);
    assert!(handle.join().is_ok(), "Couldn't execute on thread")
}

#[test]
fn test_simultaneous_create_then_move() {
    let mut handles = vec![];
    for i in 0..10 {
        let name = format!("{}-{}", generate_random_string(), i);
        let entry = entry_new(&name, &name);
        let test = move || {
            entry.set_password(&name).expect("Can't set ascii password");
            let stored_password = entry.get_password().expect("Can't get ascii password");
            assert_eq!(
                stored_password, name,
                "Retrieved and set ascii passwords don't match"
            );
            entry
                .delete_credential()
                .expect("Can't delete ascii password");
            assert!(
                matches!(entry.get_password(), Err(Error::NoEntry)),
                "Able to read a deleted ascii password"
            );
        };
        handles.push(std::thread::spawn(test))
    }
    for handle in handles {
        handle.join().expect("Couldn't execute on thread")
    }
}

#[test]
fn test_create_set_then_move() {
    let name = generate_random_string();
    let entry = entry_new(&name, &name);
    let password = "test ascii password";
    entry
        .set_password(password)
        .expect("Can't set ascii password");
    let test = move || {
        let stored_password = entry.get_password().expect("Can't get ascii password");
        assert_eq!(
            stored_password, password,
            "Retrieved and set ascii passwords don't match"
        );
        entry
            .delete_credential()
            .expect("Can't delete ascii password");
        assert!(
            matches!(entry.get_password(), Err(Error::NoEntry)),
            "Able to read a deleted ascii password"
        );
    };
    let handle = std::thread::spawn(test);
    assert!(handle.join().is_ok(), "Couldn't execute on thread")
}

#[test]
fn test_simultaneous_create_set_then_move() {
    let mut handles = vec![];
    for i in 0..10 {
        let name = format!("{}-{}", generate_random_string(), i);
        let entry = entry_new(&name, &name);
        entry.set_password(&name).expect("Can't set ascii password");
        let test = move || {
            let stored_password = entry.get_password().expect("Can't get ascii password");
            assert_eq!(
                stored_password, name,
                "Retrieved and set ascii passwords don't match"
            );
            entry
                .delete_credential()
                .expect("Can't delete ascii password");
            assert!(
                matches!(entry.get_password(), Err(Error::NoEntry)),
                "Able to read a deleted ascii password"
            );
        };
        handles.push(std::thread::spawn(test))
    }
    for handle in handles {
        handle.join().expect("Couldn't execute on thread")
    }
}

#[test]
fn test_simultaneous_independent_create_set() {
    let mut handles = vec![];
    for i in 0..10 {
        let name = format!("thread_entry{i}");
        let test = move || {
            let entry = entry_new(&name, &name);
            entry.set_password(&name).expect("Can't set ascii password");
            let stored_password = entry.get_password().expect("Can't get ascii password");
            assert_eq!(
                stored_password, name,
                "Retrieved and set ascii passwords don't match"
            );
            entry
                .delete_credential()
                .expect("Can't delete ascii password");
            assert!(
                matches!(entry.get_password(), Err(Error::NoEntry)),
                "Able to read a deleted ascii password"
            );
        };
        handles.push(std::thread::spawn(test))
    }
    for handle in handles {
        handle.join().expect("Couldn't execute on thread")
    }
}

#[test]
fn test_multiple_create_delete_single_thread() {
    let name = generate_random_string();
    let entry = entry_new(&name, &name);
    let repeats = 10;
    for _i in 0..repeats {
        entry.set_password(&name).expect("Can't set ascii password");
        let stored_password = entry.get_password().expect("Can't get ascii password");
        assert_eq!(
            stored_password, name,
            "Retrieved and set ascii passwords don't match"
        );
        entry
            .delete_credential()
            .expect("Can't delete ascii password");
        assert!(
            matches!(entry.get_password(), Err(Error::NoEntry)),
            "Able to read a deleted ascii password"
        );
    }
}

#[test]
fn test_simultaneous_multiple_create_delete_single_thread() {
    let mut handles = vec![];
    for t in 0..10 {
        let name = generate_random_string();
        let test = move || {
            let name = format!("{name}-{t}");
            let entry = entry_new(&name, &name);
            let repeats = 10;
            for _i in 0..repeats {
                entry.set_password(&name).expect("Can't set ascii password");
                let stored_password = entry.get_password().expect("Can't get ascii password");
                assert_eq!(
                    stored_password, name,
                    "Retrieved and set ascii passwords don't match"
                );
                entry
                    .delete_credential()
                    .expect("Can't delete ascii password");
                assert!(
                    matches!(entry.get_password(), Err(Error::NoEntry)),
                    "Able to read a deleted ascii password"
                );
            }
        };
        handles.push(std::thread::spawn(test))
    }
    for handle in handles {
        handle.join().expect("Couldn't execute on thread")
    }
}

#[test]
fn test_persistence() {
    assert!(matches!(
        (*TEST_STORE).persistence(),
        CredentialPersistence::ProcessOnly
    ))
}
