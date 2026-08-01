use super::FuzzTemplate;
use crate::domain::{DomainError, DomainResult, ErrorCode};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum PayloadGenerator {
    Numbers {
        from: i64,
        to: i64,
        step: i64,
    },
    RegexBypass {
        input: String,
        #[serde(default)]
        encoding: RegexBypassEncoding,
        #[serde(default = "default_regex_modes")]
        modes: Vec<RegexBypassMode>,
        #[serde(default)]
        byte_from: u16,
        #[serde(default = "default_byte_to")]
        byte_to: u16,
        #[serde(default)]
        include_alphanumeric: bool,
        #[serde(default = "default_regex_max_payloads")]
        max_payloads: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegexBypassEncoding {
    Url,
    Unicode,
    Raw,
    DoubleUrl,
}

impl Default for RegexBypassEncoding {
    fn default() -> Self {
        Self::Url
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegexBypassMode {
    Start,
    #[serde(alias = "separators")]
    Separator,
    End,
    #[serde(alias = "regex_meta")]
    RegexMetachar,
}

fn default_regex_modes() -> Vec<RegexBypassMode> {
    vec![
        RegexBypassMode::Start,
        RegexBypassMode::Separator,
        RegexBypassMode::End,
        RegexBypassMode::RegexMetachar,
    ]
}

const fn default_byte_to() -> u16 {
    255
}

const fn default_regex_max_payloads() -> u64 {
    2_000
}

pub(super) fn expand_generators(
    template: &mut FuzzTemplate,
    max_payloads: u64,
) -> DomainResult<()> {
    // Generated material shares one project-sized budget so several
    // generators cannot each allocate a maximum-sized list. Inline and file
    // wordlists retain their existing combination-count semantics.
    let mut allocated = 0u64;
    for generator in &template.payload_generators {
        let remaining = max_payloads - allocated;
        let payloads = match generator {
            PayloadGenerator::Numbers { from, to, step } => {
                generate_numbers(*from, *to, *step, remaining)?
            }
            PayloadGenerator::RegexBypass {
                input,
                encoding,
                modes,
                byte_from,
                byte_to,
                include_alphanumeric,
                max_payloads: generator_max,
            } => generate_regex_bypass(
                input,
                *encoding,
                modes,
                *byte_from,
                *byte_to,
                *include_alphanumeric,
                (*generator_max).min(remaining),
            )?,
        };
        allocated += payloads.len() as u64;
        template.wordlists.push(payloads);
    }
    Ok(())
}

const ASCII_PUNCTUATION: &str = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";
const REGEX_METACHARS: &str = ".^$*+-?()[]{}\\|";
const MAX_REGEX_INPUT_BYTES: usize = 4 * 1024;

fn generate_regex_bypass(
    input: &str,
    encoding: RegexBypassEncoding,
    modes: &[RegexBypassMode],
    byte_from: u16,
    byte_to: u16,
    include_alphanumeric: bool,
    max_payloads: u64,
) -> DomainResult<Vec<String>> {
    if input.is_empty() {
        return Err(DomainError::invalid(
            "regex bypass generator input must not be empty",
        ));
    }
    if input.len() > MAX_REGEX_INPUT_BYTES {
        return Err(DomainError::invalid(format!(
            "regex bypass generator input exceeds {MAX_REGEX_INPUT_BYTES} bytes"
        )));
    }
    if byte_from > byte_to || byte_to > 255 {
        return Err(DomainError::invalid(
            "regex bypass byte range must satisfy 0 <= byte_from <= byte_to <= 255",
        ));
    }
    if modes.is_empty() {
        return Err(DomainError::invalid(
            "regex bypass generator requires at least one mode",
        ));
    }
    let unique_modes = modes.iter().copied().collect::<BTreeSet<_>>();
    if unique_modes.len() != modes.len() {
        return Err(DomainError::invalid(
            "regex bypass generator modes must not contain duplicates",
        ));
    }
    if max_payloads == 0 {
        return Err(DomainError::new(
            ErrorCode::CombinationLimit,
            "regex bypass max_payloads must be greater than zero and fit within the project limit",
        ));
    }

    let bytes = (byte_from..=byte_to)
        .map(|byte| byte as u8)
        .filter(|byte| include_alphanumeric || !byte.is_ascii_alphanumeric())
        .collect::<Vec<_>>();
    if bytes.is_empty() {
        return Err(DomainError::invalid(
            "regex bypass byte range contains no bytes after excluding alphanumerics",
        ));
    }

    let char_positions = input
        .char_indices()
        .map(|(start, character)| (start, start + character.len_utf8(), character))
        .collect::<Vec<_>>();
    let mut output = BTreeSet::new();
    let mut add_at = |start: usize, end: usize| -> DomainResult<()> {
        for byte in &bytes {
            let encoded = encode_byte(*byte, encoding);
            let candidate = format!("{}{}{}", &input[..start], encoded, &input[end..]);
            if candidate != input
                && !output.contains(&candidate)
                && output.len() as u64 >= max_payloads
            {
                return Err(DomainError::new(
                    ErrorCode::CombinationLimit,
                    format!(
                        "regex bypass generator exceeds its available payload limit of {max_payloads}; narrow the byte range or modes, or raise max_payloads"
                    ),
                ));
            }
            if candidate != input {
                output.insert(candidate);
            }
        }
        Ok(())
    };

    if unique_modes.contains(&RegexBypassMode::Start) {
        add_at(0, 0)?;
    }
    if unique_modes.contains(&RegexBypassMode::Separator) {
        for (start, end, character) in &char_positions {
            if ASCII_PUNCTUATION.contains(*character) {
                add_at(*start, *start)?;
                add_at(*end, *end)?;
            }
        }
    }
    if unique_modes.contains(&RegexBypassMode::End) {
        add_at(input.len(), input.len())?;
    }
    if unique_modes.contains(&RegexBypassMode::RegexMetachar) {
        for (start, end, character) in &char_positions {
            if REGEX_METACHARS.contains(*character) {
                add_at(*start, *end)?;
            }
        }
    }
    if output.is_empty() {
        return Err(DomainError::invalid(
            "regex bypass modes produced no payloads for this input",
        ));
    }
    Ok(output.into_iter().collect())
}

fn encode_byte(byte: u8, encoding: RegexBypassEncoding) -> String {
    match encoding {
        RegexBypassEncoding::Url => format!("%{byte:02x}"),
        RegexBypassEncoding::Unicode => format!("\\u{byte:04x}"),
        // Recollapse skips LF/VT/FF and ESC in raw mode. Its replacement modes
        // consequently delete the replaced metacharacter for those bytes.
        RegexBypassEncoding::Raw if matches!(byte, 10..=12 | 27) => String::new(),
        RegexBypassEncoding::Raw => char::from(byte).to_string(),
        RegexBypassEncoding::DoubleUrl => format!("%25{byte:02x}"),
    }
}

fn generate_numbers(from: i64, to: i64, step: i64, max_payloads: u64) -> DomainResult<Vec<String>> {
    if step == 0 {
        return Err(DomainError::invalid(
            "number generator step must not be zero",
        ));
    }
    if (from < to && step < 0) || (from > to && step > 0) {
        return Err(DomainError::invalid(
            "number generator step must move from the starting number toward the ending number",
        ));
    }

    let distance = (i128::from(to) - i128::from(from)).unsigned_abs();
    let step_size = i128::from(step).unsigned_abs();
    let intervals = distance / step_size;
    let include_unaligned_end = distance % step_size != 0;
    let count = intervals
        .saturating_add(1)
        .saturating_add(u128::from(include_unaligned_end));
    if count > u128::from(max_payloads) {
        return Err(DomainError::new(
            ErrorCode::CombinationLimit,
            format!(
                "number generator would create {count} payloads, exceeding the remaining generated-payload budget of {max_payloads}"
            ),
        ));
    }
    let capacity = usize::try_from(count).map_err(|_| {
        DomainError::new(
            ErrorCode::CombinationLimit,
            "number generator is too large for this platform",
        )
    })?;
    let mut payloads = Vec::with_capacity(capacity);
    let mut current = i128::from(from);
    let end = i128::from(to);
    let delta = i128::from(step);
    while if delta > 0 {
        current <= end
    } else {
        current >= end
    } {
        payloads.push(current.to_string());
        current += delta;
    }
    if payloads.last().is_none_or(|last| last != &to.to_string()) {
        payloads.push(to.to_string());
    }
    Ok(payloads)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn numbers_include_both_ends_and_respect_step() {
        assert_eq!(
            generate_numbers(1, 10, 3, 10).unwrap(),
            ["1", "4", "7", "10"]
        );
        assert_eq!(
            generate_numbers(10, 1, -4, 10).unwrap(),
            ["10", "6", "2", "1"]
        );
        assert_eq!(generate_numbers(5, 5, 2, 10).unwrap(), ["5"]);
    }

    #[test]
    fn numbers_reject_invalid_direction_and_preallocate_bound() {
        assert!(generate_numbers(1, 10, -1, 100).is_err());
        assert!(generate_numbers(10, 1, 1, 100).is_err());
        assert!(generate_numbers(1, 10, 0, 100).is_err());
        let error = generate_numbers(i64::MIN, i64::MAX, 1, 100).unwrap_err();
        assert_eq!(error.code(), ErrorCode::CombinationLimit);
    }

    #[test]
    fn regex_core_modes_match_recollapse_counts_and_selected_outputs() {
        let cases = [
            (RegexBypassMode::Start, "ab", 194),
            (RegexBypassMode::Separator, "a.b", 388),
            (RegexBypassMode::End, "ab", 194),
            (RegexBypassMode::RegexMetachar, "a.b", 194),
        ];
        for (mode, input, expected_count) in cases {
            let output = generate_regex_bypass(
                input,
                RegexBypassEncoding::Url,
                &[mode],
                0,
                255,
                false,
                2_000,
            )
            .unwrap();
            assert_eq!(output.len(), expected_count, "mode {mode:?}");
        }
        let separator = generate_regex_bypass(
            "a.b",
            RegexBypassEncoding::Url,
            &[RegexBypassMode::Separator],
            0,
            3,
            true,
            20,
        )
        .unwrap();
        assert_eq!(
            separator,
            ["a%00.b", "a%01.b", "a%02.b", "a%03.b", "a.%00b", "a.%01b", "a.%02b", "a.%03b"]
        );
    }

    #[test]
    fn regex_encoding_and_bounds_are_explicit() {
        let unicode = generate_regex_bypass(
            "x",
            RegexBypassEncoding::Unicode,
            &[RegexBypassMode::Start],
            65,
            65,
            true,
            1,
        )
        .unwrap();
        assert_eq!(unicode, ["\\u0041x"]);
        let double = generate_regex_bypass(
            "x",
            RegexBypassEncoding::DoubleUrl,
            &[RegexBypassMode::End],
            0,
            0,
            true,
            1,
        )
        .unwrap();
        assert_eq!(double, ["x%2500"]);
        assert!(generate_regex_bypass(
            "a.b",
            RegexBypassEncoding::Url,
            &[RegexBypassMode::Separator],
            0,
            3,
            true,
            7,
        )
        .is_err());
    }

    #[test]
    fn generators_share_one_budget_and_preserve_their_definitions() {
        let mut template = FuzzTemplate {
            base_exchange_id: None,
            draft: Default::default(),
            insertion_points: vec![],
            wordlists: vec![vec!["existing".into(), "payload".into()]],
            wordlist_files: vec![],
            payload_generators: vec![
                PayloadGenerator::Numbers {
                    from: 1,
                    to: 3,
                    step: 1,
                },
                PayloadGenerator::Numbers {
                    from: 8,
                    to: 10,
                    step: 1,
                },
            ],
            transforms: vec![],
            strategy: crate::domain::FuzzStrategy::Sniper,
        };
        let error = expand_generators(&mut template, 5).unwrap_err();
        assert_eq!(error.code(), ErrorCode::CombinationLimit);
        assert_eq!(template.payload_generators.len(), 2);

        template.wordlists.truncate(1);
        expand_generators(&mut template, 6).unwrap();
        assert_eq!(
            template.wordlists,
            vec![
                vec!["existing", "payload"],
                vec!["1", "2", "3"],
                vec!["8", "9", "10"],
            ]
        );
        assert_eq!(template.payload_generators.len(), 2);
    }

    #[test]
    fn regex_fixture_matches_recollapse_supported_modes() {
        let output = generate_regex_bypass(
            "a.b",
            RegexBypassEncoding::Url,
            &[
                RegexBypassMode::Start,
                RegexBypassMode::Separator,
                RegexBypassMode::End,
                RegexBypassMode::RegexMetachar,
            ],
            0,
            2,
            true,
            20,
        )
        .unwrap();
        assert_eq!(
            output,
            [
                "%00a.b", "%01a.b", "%02a.b", "a%00.b", "a%00b", "a%01.b", "a%01b", "a%02.b",
                "a%02b", "a.%00b", "a.%01b", "a.%02b", "a.b%00", "a.b%01", "a.b%02",
            ]
        );
    }
}
