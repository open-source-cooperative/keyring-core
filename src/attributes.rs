/*!

Utility functions for attribute maps

 */
use std::collections::HashMap;

use crate::{Error::Invalid, Result};

/// Parse an optional key-value &str map for allowed keys, returning a map of owned strings.
///
/// If a key is prefixed with a `*`, it is required to have a boolean value,
/// and the `*` is stripped from the key name when parsing and returning the map.
///
/// If a key is prefixed with a `+`, it is required to have a non-empty value,
/// and the `+` is stripped from the key name when parsing and returning the map.
///
/// Returns an [Invalid] error if not all keys are allowed, or if one of the keys
/// marked as boolean has a value other than `true` or `false`.
pub fn parse_attributes(
    keys: &[&str],
    attrs: Option<&HashMap<&str, &str>>,
) -> Result<HashMap<String, String>> {
    let mut result: HashMap<String, String> = HashMap::new();
    if attrs.is_none() {
        return Ok(result);
    }
    let key_map: HashMap<String, char> = keys
        .iter()
        .map(|k| {
            if k.starts_with("*") {
                (k.split_at(1).1.to_string(), '*')
            } else if k.starts_with("+") {
                (k.split_at(1).1.to_string(), '+')
            } else {
                (k.to_string(), ' ')
            }
        })
        .collect();
    for (key, value) in attrs.unwrap() {
        if let Some(prefix) = key_map.get(*key) {
            match *prefix {
                '*' if *value != "true" && *value != "false" => {
                    let msg = "must be 'true' or 'false'";
                    return Err(Invalid(key.to_string(), msg.to_string()));
                }
                '+' if value.is_empty() => {
                    let msg = "must not be empty";
                    return Err(Invalid(key.to_string(), msg.to_string()));
                }
                _ => {}
            }
            result.insert(key.to_string(), value.to_string());
        } else {
            return Err(Invalid(key.to_string(), "unknown key".to_string()));
        }
    }
    Ok(result)
}

/// Convert a borrowed key-value map of borrowed strings to an owned map of owned strings.
pub fn externalize_attributes(attrs: &HashMap<&str, &str>) -> HashMap<String, String> {
    attrs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}
