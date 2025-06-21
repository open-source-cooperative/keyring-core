use std::collections::HashMap;
use std::sync::{Arc, Once};

use crate::{CredentialStore, Entry, Error, api::CredentialPersistence};

static SET_STORE: Once = Once::new();

fn usually_goes_in_main() {
    let _ = env_logger::builder().is_test(true).try_init();
    crate::set_default_store(super::store::Store::new());
}

fn entry_new(service: &str, user: &str) -> Entry {
    SET_STORE.call_once(usually_goes_in_main);
    Entry::new(service, user).unwrap_or_else(|err| {
        panic!("Couldn't create entry (service: {service}, user: {user}): {err:?}")
    })
}

fn entry_new_with_modifiers(service: &str, user: &str, mods: &HashMap<&str, &str>) -> Entry {
    SET_STORE.call_once(usually_goes_in_main);
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
fn test_duplicate_entries() {
    let name = generate_random_string();
    let entry1 = entry_new(&name, &name);
    let entry2 = entry_new(&name, &name);
    entry1
        .set_password("password for entry1")
        .expect("Can't set password for entry1");
    let password = entry2
        .get_password()
        .expect("Can't get password for entry2");
    assert_eq!(password, "password for entry1");
    entry2
        .set_password("password for entry2")
        .expect("Can't set password for entry2");
    let password = entry1
        .get_password()
        .expect("Can't get password for entry1");
    assert_eq!(password, "password for entry2");
    entry1.delete_credential().expect("Can't delete entry1");
    entry2.delete_credential().expect_err("Can delete entry2");
}

#[test]
fn test_get_update_attributes() {
    let name = generate_random_string();
    let entry1 = entry_new(&name, &name);
    assert!(matches!(entry1.get_attributes(), Err(Error::NoEntry)));
    entry1
        .set_password("password for entry1")
        .expect("Can't set password for entry1");
    let attrs = entry1
        .get_attributes()
        .expect("Can't get entry1 attributes");
    assert_eq!(attrs.len(), 0);
    let no_op_map = HashMap::from([("foo", "bar")]);
    let forbidden_map = HashMap::from([("creation_date", "doesn't matter")]);
    let comment_map = HashMap::from([("comment", "some comment")]);
    assert!(matches!(entry1.update_attributes(&no_op_map), Ok(())));
    assert!(matches!(
        entry1.update_attributes(&forbidden_map),
        Err(Error::Invalid(_, _))
    ));
    entry1
        .update_attributes(&comment_map)
        .expect("Can't update attributes for entry1");
    assert_eq!(
        entry1
            .get_attributes()
            .expect("Can't get attributes for entry1")
            .get("comment")
            .expect("No comment on entry1"),
        "some comment"
    );
    let entry2 = entry_new_with_modifiers(&name, &name, &HashMap::from([("target", "entry2")]));
    assert_eq!(
        entry2.get_password().expect("Can't get entry2 password"),
        ""
    );
    let attrs = entry2
        .get_attributes()
        .expect("Can't get entry2 attributes");
    assert_eq!(attrs.len(), 2);
    assert_eq!(attrs.get("comment").unwrap(), "entry2");
    assert!(attrs.contains_key("creation_date"));
    entry2
        .update_attributes(&comment_map)
        .expect("Can't update attributes for entry1");
    assert_eq!(
        entry2
            .get_attributes()
            .expect("Can't get attributes for entry2")
            .get("comment")
            .expect("No comment on entry2"),
        "some comment"
    );
    entry1.delete_credential().expect("Can't delete entry1");
    entry2.delete_credential().expect("Can't delete entry2");
}

#[test]
fn test_credential_and_ambiguous_credential() {
    let name = generate_random_string();
    let entry1 = entry_new_with_modifiers(&name, &name, &HashMap::from([("target", "entry1")]));
    assert!(entry1.is_specifier(), "entry1 is not a specifier");
    entry1
        .set_password("password for entry1")
        .expect("Can't set password for entry1");
    let credential1: &super::credential::CredKey = entry1
        .get_credential()
        .downcast_ref()
        .expect("Not a sample store credential");
    assert_eq!(credential1.cred_index, 0, "entry1 index should be 0");
    let entry2 = entry_new_with_modifiers(&name, &name, &HashMap::from([("target", "entry2")]));
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
fn test_persistence_no_backing() {
    let store: Arc<CredentialStore> = super::store::Store::new();
    assert!(matches!(
        store.persistence(),
        CredentialPersistence::ProcessOnly
    ));
}

#[test]
fn test_persistence_with_backing_and_save() {
    let path = std::env::temp_dir()
        .join("store-save-test.ron")
        .to_str()
        .unwrap()
        .to_string();
    _ = std::fs::remove_file(&path);
    let s1 =
        super::store::Store::new_with_backing(&path).expect("Failed to create empty, backed store");
    let cred_store: Arc<CredentialStore> = s1.clone();
    assert!(matches!(
        cred_store.persistence(),
        CredentialPersistence::UntilDelete
    ));
    assert_eq!(s1.as_ref().creds.len(), 0);
    let e1 = cred_store
        .build("s1", "u1", None)
        .expect("Couldn't create e1 cred");
    assert_eq!(s1.as_ref().creds.len(), 0);
    e1.set_password("pw1").expect("Couldn't set e1 password");
    assert_eq!(s1.as_ref().creds.len(), 1);
    let e2 = cred_store
        .build("s2", "u2", None)
        .expect("Couldn't create e2 cred");
    assert_eq!(s1.as_ref().creds.len(), 1);
    e2.set_password("pw2").expect("Couldn't set e2 password");
    assert_eq!(s1.as_ref().creds.len(), 2);
    s1.save().expect("Failure saving store");
    let s2 =
        super::store::Store::new_with_backing(&path).expect("Failed to re-create existing store");
    assert_eq!(s2.as_ref().creds.len(), 2);
}

#[test]
fn test_persistence_with_backing_and_drop() {
    let path = std::env::temp_dir()
        .join("store-drop-test.ron")
        .to_str()
        .unwrap()
        .to_string();
    _ = std::fs::remove_file(&path);
    {
        let s1 = super::store::Store::new_with_backing(&path)
            .expect("Failed to create empty, backed store");
        let cred_store: Arc<CredentialStore> = s1.clone();
        assert_eq!(s1.as_ref().creds.len(), 0);
        let e1 = cred_store
            .build("s1", "u1", None)
            .expect("Couldn't create e1 cred");
        assert_eq!(s1.as_ref().creds.len(), 0);
        e1.set_password("pw1").expect("Couldn't set e1 password");
        assert_eq!(s1.as_ref().creds.len(), 1);
        let e2 = cred_store
            .build("s2", "u2", None)
            .expect("Couldn't create e2 cred");
        assert_eq!(s1.as_ref().creds.len(), 1);
        e2.set_password("pw2").expect("Couldn't set e2 password");
        assert_eq!(s1.as_ref().creds.len(), 2);
    }
    let s2 =
        super::store::Store::new_with_backing(&path).expect("Failed to re-create existing store");
    assert_eq!(s2.as_ref().creds.len(), 2);
}
