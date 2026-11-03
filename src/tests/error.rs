use crate::error::{Error, decode_password};

#[test]
fn test_bad_password() {
    // malformed sequences here taken from:
    // https://www.cl.cam.ac.uk/~mgk25/ucs/examples/UTF-8-test.txt
    for bytes in [b"\x80".to_vec(), b"\xbf".to_vec(), b"\xed\xa0\xa0".to_vec()] {
        match decode_password(bytes.clone()) {
            Err(Error::BadEncoding(str)) => assert_eq!(str, bytes),
            Err(other) => panic!("Bad password ({bytes:?}) decode gave wrong error: {other}"),
            Ok(s) => panic!("Bad password ({bytes:?}) decode gave results: {s:?}"),
        }
    }
}

#[test]
fn test_source() {
    use std::error::Error as StdError;

    let box_err = |s: &str| -> Box<dyn StdError + Send + Sync + 'static> {
        Box::new(std::io::Error::other(s))
    };
    let err: &dyn StdError = &Error::PlatformFailure(box_err("test"));
    assert!(err.source().is_some());
    let err: &dyn StdError = &Error::NoStorageAccess(box_err("test"));
    assert!(err.source().is_some());
    let err: &dyn StdError = &Error::BadDataFormat(vec![0x80], box_err("test"));
    assert!(err.source().is_some());
    let err: &dyn StdError = &Error::BadEncoding(vec![0x80]);
    assert!(err.source().is_none());
}
