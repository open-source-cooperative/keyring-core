use keyring_core::{Entry, Error, Result, mock, sample};

fn main() {
    single_store().unwrap();
    multi_store().unwrap();
}

fn single_store() -> Result<()> {
    // create the store and set it as the default store
    keyring_core::set_default_store(mock::Store::new()?);
    // make an entry in the store
    let entry = Entry::new("my-service", "my-name")?;
    // entries do not have associated credentials until their password/secret is first set
    assert!(matches!(entry.get_credential(), Err(Error::NoEntry)));
    // set the entry's secret, which creates and stores the secret in an associated credential
    let mut secret = [0u8; 64];
    fastrand::fill(&mut secret);
    entry.set_secret(&secret)?;
    // retrieve the secret from the entry's credential
    let retrieved_secret = entry.get_secret()?;
    assert_eq!(secret, retrieved_secret.as_slice());
    // delete the credential: the secret goes with it
    entry.delete_credential()?;
    assert!(matches!(entry.get_secret(), Err(Error::NoEntry)));
    // releasing the default store allows it to release its resources,
    // assuming you aren't holding onto any other references to it
    keyring_core::unset_default_store();
    println!("Single store: success");
    Ok(())
}

fn multi_store() -> Result<()> {
    // create two different stores and remember them under different names
    keyring_core::add_named_store("mock", mock::Store::new()?)?;
    keyring_core::add_named_store("sample", sample::Store::new()?)?;
    // create an entry in each of the stores using the same username and service
    let mock_entry = Entry::new_in_named_store("mock", "my-service", "my-name")?;
    let sample_entry = Entry::new_in_named_store("sample", "my-service", "my-name")?;
    // set and retrieve passwords, they can be different because the entries are in different stores
    // so they don't share their credentials even though they have the same username and service
    mock_entry.set_password("password1")?;
    sample_entry.set_password("password2")?;
    assert_ne!(mock_entry.get_password()?, sample_entry.get_password()?);
    // a named store can also be used as the default store
    let mock = keyring_core::get_named_store("mock")?.unwrap();
    keyring_core::set_default_store(mock);
    let entry = Entry::new("my-service", "my-name")?;
    // these two entries are in the same store, so they both refer to the same credential
    assert_eq!(entry.get_password()?, mock_entry.get_password()?);
    keyring_core::unset_default_store();
    // doesn't matter whether we delete `entry`'s credential or `mock_entry`'s credential,
    // because they are the same credential
    entry.delete_credential()?;
    assert!(matches!(
        mock_entry.delete_credential(),
        Err(Error::NoEntry)
    ));
    sample_entry.delete_credential()?;
    keyring_core::drop_named_store("mock")?;
    keyring_core::drop_named_store("sample")?;
    println!("Multiple stores: success");
    Ok(())
}
