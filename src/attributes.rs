/*!

Utility functions for attribute maps

 */
use std::collections::HashMap;

use crate::{Error::Invalid, Result};

/// Parse an optional key-value &str map for allowed keys, returning a map of owned strings.
///
/// Returns an [Invalid] error if not all keys are allowed.
pub fn parse_attributes(
    keys: &[&str],
    attrs: Option<&HashMap<&str, &str>>,
) -> Result<HashMap<String, String>> {
    let mut result: HashMap<String, String> = HashMap::new();
    if attrs.is_none() {
        return Ok(result);
    }
    for (key, value) in attrs.unwrap() {
        if keys.contains(key) {
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
