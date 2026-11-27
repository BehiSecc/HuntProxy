//! Readers for MCP tool arguments. An absent argument and `null` mean the
//! same, because some clients send every schema property with `null` for the
//! unused ones. An integer may also arrive as a numeric string such as "173",
//! which some clients send for every id.

use crate::domain::{DomainError, DomainResult};
use serde_json::Value;

/// The argument, unless it is absent or `null`.
pub(super) fn present<'a>(args: &'a Value, name: &str) -> Option<&'a Value> {
    args.get(name).filter(|value| !value.is_null())
}

/// An integer given as a JSON integer or a numeric string.
pub(super) fn integer(value: &Value) -> Option<i64> {
    match value {
        Value::Number(number) => number.as_i64(),
        Value::String(text) => text.trim().parse().ok(),
        _ => None,
    }
}

fn unsigned(value: &Value) -> Option<u64> {
    match value {
        Value::Number(number) => number.as_u64(),
        Value::String(text) => text.trim().parse().ok(),
        _ => None,
    }
}

pub(super) fn optional_i64(args: &Value, name: &str) -> DomainResult<Option<i64>> {
    present(args, name)
        .map(|value| {
            integer(value).ok_or_else(|| DomainError::invalid(format!("{name} must be an integer")))
        })
        .transpose()
}

pub(super) fn required_i64(args: &Value, name: &str) -> DomainResult<i64> {
    optional_i64(args, name)?.ok_or_else(|| DomainError::invalid(format!("{name} required")))
}

pub(super) fn optional_u64(args: &Value, name: &str) -> DomainResult<Option<u64>> {
    present(args, name)
        .map(|value| {
            unsigned(value).ok_or_else(|| {
                DomainError::invalid(format!("{name} must be a non-negative integer"))
            })
        })
        .transpose()
}

pub(super) fn optional_bool(args: &Value, name: &str) -> DomainResult<Option<bool>> {
    present(args, name)
        .map(|value| {
            value
                .as_bool()
                .ok_or_else(|| DomainError::invalid(format!("{name} must be a boolean")))
        })
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn booleans_must_be_booleans_and_null_is_absent() {
        let args = json!({"yes": true, "no": false, "text": "true", "nothing": null});
        assert_eq!(optional_bool(&args, "yes").unwrap(), Some(true));
        assert_eq!(optional_bool(&args, "no").unwrap(), Some(false));
        assert_eq!(optional_bool(&args, "nothing").unwrap(), None);
        assert_eq!(optional_bool(&args, "absent").unwrap(), None);
        assert_eq!(
            optional_bool(&args, "text").unwrap_err().to_string(),
            "text must be a boolean"
        );
    }

    #[test]
    fn integers_may_be_numbers_or_numeric_strings() {
        let args = json!({"a": 173, "b": "173", "c": " -4 ", "d": null});
        assert_eq!(required_i64(&args, "a").unwrap(), 173);
        assert_eq!(required_i64(&args, "b").unwrap(), 173);
        assert_eq!(required_i64(&args, "c").unwrap(), -4);
        assert_eq!(optional_i64(&args, "d").unwrap(), None);
        assert_eq!(optional_i64(&args, "missing").unwrap(), None);
    }

    #[test]
    fn missing_and_null_are_required_and_anything_else_must_be_an_integer() {
        let args = json!({"nothing": null, "text": "abc", "empty": "", "fraction": 1.5,
                          "decimal": "1.5", "flag": true, "list": [1]});
        for name in ["nothing", "absent"] {
            assert_eq!(
                required_i64(&args, name).unwrap_err().to_string(),
                format!("{name} required")
            );
        }
        for name in ["text", "empty", "fraction", "decimal", "flag", "list"] {
            let error = required_i64(&args, name).unwrap_err();
            assert_eq!(error.to_string(), format!("{name} must be an integer"));
            assert!(optional_i64(&args, name).is_err());
        }
    }

    #[test]
    fn unsigned_arguments_reject_negative_numbers_and_strings() {
        let args = json!({"a": 25, "b": "25", "c": -1, "d": "-1", "e": "x", "f": null});
        assert_eq!(optional_u64(&args, "a").unwrap(), Some(25));
        assert_eq!(optional_u64(&args, "b").unwrap(), Some(25));
        assert_eq!(optional_u64(&args, "f").unwrap(), None);
        for name in ["c", "d", "e"] {
            assert_eq!(
                optional_u64(&args, name).unwrap_err().to_string(),
                format!("{name} must be a non-negative integer")
            );
        }
    }
}
