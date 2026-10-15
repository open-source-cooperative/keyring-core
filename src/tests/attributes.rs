use std::collections::HashMap;

use crate::Error::Invalid;
use crate::attributes::{externalize_attributes, parse_attributes};

#[test]
fn test_parse_attributes() {
    let attrs = HashMap::from([("key1", "value1"), ("key2", "true"), ("key3", "false")]);
    assert_eq!(parse_attributes(&["key1"], None).unwrap().len(), 0);
    assert_eq!(
        parse_attributes(&["key1", "key2", "key3"], Some(&attrs))
            .unwrap()
            .len(),
        3
    );
    let parsed = parse_attributes(&["+key1", "*key2", "*key3"], Some(&attrs)).unwrap();
    assert_eq!(parsed.len(), 3);
    assert_eq!(parsed.get("key1"), Some(&"value1".to_string()));
    assert_eq!(parsed.get("key2"), Some(&"true".to_string()));
    assert_eq!(parsed.get("key3"), Some(&"false".to_string()));
    let bad_attrs = HashMap::from([("key1", "t")]);
    match parse_attributes(&["*key1"], Some(&bad_attrs)) {
        Err(Invalid(key, msg)) => {
            assert_eq!(key, "key1");
            assert_eq!(msg, "must be 'true' or 'false'");
        }
        _ => panic!("Incorrect error for invalid boolean attribute"),
    }
    let bad_attrs = HashMap::from([("key1", "")]);
    match parse_attributes(&["+key1"], Some(&bad_attrs)) {
        Err(Invalid(key, msg)) => {
            assert_eq!(key, "key1");
            assert_eq!(msg, "must not be empty");
        }
        _ => panic!("Incorrect error for empty string attribute"),
    }
    match parse_attributes(&["other_key"], Some(&bad_attrs)) {
        Err(Invalid(key, msg)) => {
            assert_eq!(key, "key1");
            assert_eq!(msg, "unknown key");
        }
        _ => panic!("Incorrect error for unknown attribute"),
    }
}

#[test]
fn test_externalize_attributes() {
    let attrs = HashMap::from([("key1", "value1"), ("key2", "true"), ("key3", "false")]);
    let externalized = externalize_attributes(&attrs);
    assert_eq!(externalized.len(), 3);
    assert_eq!(externalized.get("key1"), Some(&"value1".to_string()));
    assert_eq!(externalized.get("key2"), Some(&"true".to_string()));
    assert_eq!(externalized.get("key3"), Some(&"false".to_string()));
}
