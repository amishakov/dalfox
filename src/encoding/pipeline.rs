//! Composable pre-encoding pipelines.
//!
//! The legacy `pre_encoding: Option<String>` slot supports a single
//! transformation (`base64`, `2base64`, `2url`, `3url`). Real-world endpoints
//! often wrap payloads in multiple layers, e.g.
//!
//! ```text
//! ?qs=BASE64({"move_url":"<INJECT>", "acc_domain":"…"})
//! ```
//!
//! where the actual injection point is one *field* of a JSON object that is
//! itself base64-encoded as the query value. To express that, payloads are
//! transformed through an ordered `EncodingPipeline` before they hit the wire.
//!
//! `infer_nested_pipelines` inspects an existing parameter value and, when it
//! looks like base64-of-JSON, returns one [`NestedField`] per leaf string
//! field — each carrying the pipeline that injects a payload at that field.
//! The reflection check is invariant to the pipeline because the server
//! decodes/parses the payload back to a plain string before reflecting it.

use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};

/// A single transformation applied to a payload string.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EncodingStep {
    /// Plug the payload into a JSON template at the given RFC 6901 pointer
    /// and serialize the result. The template carries every other field of
    /// the original value verbatim, so the server-side parser sees a complete
    /// object.
    JsonField {
        pointer: String,
        template: serde_json::Value,
    },
    /// Standard base64 (with padding).
    Base64,
    /// Single-round percent encoding. Useful when an outer layer (e.g. JSON
    /// stringify) preserves characters that a query value cannot carry.
    Url,
}

impl EncodingStep {
    pub fn apply(&self, payload: &str) -> Result<String, String> {
        match self {
            EncodingStep::Base64 => Ok(STANDARD.encode(payload)),
            EncodingStep::Url => Ok(urlencoding::encode(payload).to_string()),
            EncodingStep::JsonField { pointer, template } => {
                let mut value = template.clone();
                set_by_pointer(
                    &mut value,
                    pointer,
                    serde_json::Value::String(payload.to_string()),
                )?;
                serde_json::to_string(&value).map_err(|e| e.to_string())
            }
        }
    }
}

/// Ordered list of transformations applied left-to-right.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
pub struct EncodingPipeline {
    pub steps: Vec<EncodingStep>,
}

impl EncodingPipeline {
    pub fn new(steps: Vec<EncodingStep>) -> Self {
        Self { steps }
    }

    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }

    /// Run the payload through every step in order. Returns `Err` if any
    /// step fails (e.g. invalid JSON pointer); callers may fall back to the
    /// raw payload.
    pub fn apply(&self, payload: &str) -> Result<String, String> {
        let mut current = payload.to_string();
        for step in &self.steps {
            current = step.apply(&current)?;
        }
        Ok(current)
    }
}

/// Set the value at `pointer` (RFC 6901) inside `root`. Creates the leaf
/// entry on objects when it doesn't exist; for arrays the index must already
/// be in range. Empty pointer replaces `root` itself.
fn set_by_pointer(
    root: &mut serde_json::Value,
    pointer: &str,
    new_val: serde_json::Value,
) -> Result<(), String> {
    if pointer.is_empty() {
        *root = new_val;
        return Ok(());
    }
    if !pointer.starts_with('/') {
        return Err(format!("pointer must start with '/': {pointer}"));
    }
    let segs: Vec<String> = pointer[1..]
        .split('/')
        .map(|s| s.replace("~1", "/").replace("~0", "~"))
        .collect();
    let last_idx = segs.len() - 1;
    let mut cur = root;
    for (i, seg) in segs.iter().enumerate() {
        let last = i == last_idx;
        match cur {
            serde_json::Value::Object(map) => {
                if last {
                    map.insert(seg.clone(), new_val);
                    return Ok(());
                }
                cur = map
                    .get_mut(seg)
                    .ok_or_else(|| format!("missing key {seg}"))?;
            }
            serde_json::Value::Array(arr) => {
                let idx: usize = seg
                    .parse()
                    .map_err(|_| format!("array segment is not an index: {seg}"))?;
                if idx >= arr.len() {
                    return Err(format!("index out of range: {idx}"));
                }
                if last {
                    arr[idx] = new_val;
                    return Ok(());
                }
                cur = &mut arr[idx];
            }
            _ => return Err(format!("cannot descend into scalar at segment {seg}")),
        }
    }
    Ok(())
}

/// One inferred injection point inside a structurally-encoded parameter.
#[derive(Debug, Clone, PartialEq)]
pub struct NestedField {
    /// JSON pointer to the leaf, e.g. `/move_url` or `/items/0/name`.
    pub pointer: String,
    /// Field path components, for human-readable naming. Indexes are stored
    /// as decimal strings (`["items","0","name"]`).
    pub path: Vec<String>,
    /// Original leaf value (so probing can preserve realistic context if
    /// needed in the future).
    pub original_value: String,
    /// Pipeline that maps a raw payload to the wire value of the *outer*
    /// parameter (e.g. base64-of-JSON-with-this-field-replaced).
    pub pipeline: EncodingPipeline,
}

/// Maximum recursion depth into nested objects/arrays.
const MAX_DEPTH: usize = 4;
/// Maximum number of leaf fields to enumerate per parameter.
const MAX_LEAVES: usize = 32;
/// Minimum value length before we attempt base64 decoding. Below this the
/// false-positive rate is too high — short tokens ("abc=") look like b64.
const MIN_B64_CANDIDATE_LEN: usize = 16;

/// Inspect a parameter value and, if it decodes as base64-of-JSON, return one
/// [`NestedField`] per leaf string field. The returned pipelines all start
/// with `JsonField{template: <decoded JSON with leaf cleared>}` followed by
/// `Base64`.
///
/// Returns an empty vec when the value doesn't match the heuristic — every
/// caller treats "no nested fields" as "fall back to plain probes".
pub fn infer_nested_pipelines(value: &str) -> Vec<NestedField> {
    if value.len() < MIN_B64_CANDIDATE_LEN {
        return Vec::new();
    }
    if !looks_like_base64(value) {
        return Vec::new();
    }
    let Ok(decoded_bytes) = STANDARD.decode(value) else {
        return Vec::new();
    };
    let Ok(decoded) = std::str::from_utf8(&decoded_bytes) else {
        return Vec::new();
    };
    let trimmed = decoded.trim_start();
    if !(trimmed.starts_with('{') || trimmed.starts_with('[')) {
        return Vec::new();
    }
    let Ok(json) = serde_json::from_str::<serde_json::Value>(decoded) else {
        return Vec::new();
    };

    let mut leaves: Vec<NestedField> = Vec::new();
    walk_json(&json, &mut Vec::new(), &mut leaves, 0);

    // Build pipelines now, after we know every leaf, so each NestedField
    // carries its own copy of the template.
    leaves
        .into_iter()
        .map(|mut nf| {
            nf.pipeline = EncodingPipeline::new(vec![
                EncodingStep::JsonField {
                    pointer: nf.pointer.clone(),
                    template: json.clone(),
                },
                EncodingStep::Base64,
            ]);
            nf
        })
        .collect()
}

/// Cheap charset/length filter for base64 — we only run a real decode after
/// this passes. Accepts both `+/` and url-safe `-_` alphabets, with optional
/// `=` padding and optional URL-encoded `%2b`/`%3d` survivors.
fn looks_like_base64(s: &str) -> bool {
    let trimmed = s.trim();
    if trimmed.len() < MIN_B64_CANDIDATE_LEN {
        return false;
    }
    let mut alnum_or_pad = 0usize;
    let mut other = 0usize;
    for c in trimmed.chars() {
        if c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '-' | '_' | '=') {
            alnum_or_pad += 1;
        } else {
            other += 1;
        }
    }
    other == 0 && alnum_or_pad >= MIN_B64_CANDIDATE_LEN
}

fn walk_json(
    node: &serde_json::Value,
    path: &mut Vec<String>,
    out: &mut Vec<NestedField>,
    depth: usize,
) {
    if out.len() >= MAX_LEAVES || depth > MAX_DEPTH {
        return;
    }
    match node {
        serde_json::Value::String(s) => {
            out.push(NestedField {
                pointer: build_pointer(path),
                path: path.clone(),
                original_value: s.clone(),
                pipeline: EncodingPipeline::default(),
            });
        }
        serde_json::Value::Object(map) => {
            for (k, v) in map {
                path.push(k.clone());
                walk_json(v, path, out, depth + 1);
                path.pop();
                if out.len() >= MAX_LEAVES {
                    break;
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for (i, v) in arr.iter().enumerate() {
                path.push(i.to_string());
                walk_json(v, path, out, depth + 1);
                path.pop();
                if out.len() >= MAX_LEAVES {
                    break;
                }
            }
        }
        _ => {}
    }
}

fn build_pointer(path: &[String]) -> String {
    let mut s = String::new();
    for seg in path {
        s.push('/');
        for c in seg.chars() {
            match c {
                '~' => s.push_str("~0"),
                '/' => s.push_str("~1"),
                _ => s.push(c),
            }
        }
    }
    s
}

#[cfg(test)]
mod tests;
