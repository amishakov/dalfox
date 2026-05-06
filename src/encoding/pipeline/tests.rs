use super::*;

fn b64(s: &str) -> String {
    STANDARD.encode(s)
}

#[test]
fn step_base64_roundtrip() {
    let s = EncodingStep::Base64;
    let out = s.apply("hello").expect("base64 encode");
    assert_eq!(out, "aGVsbG8=");
}

#[test]
fn step_url_basic() {
    let s = EncodingStep::Url;
    let out = s.apply("a b<c").expect("url encode");
    assert_eq!(out, "a%20b%3Cc");
}

#[test]
fn step_jsonfield_top_level_replace() {
    let template: serde_json::Value =
        serde_json::from_str(r#"{"a":"x","b":"y"}"#).expect("parse template");
    let step = EncodingStep::JsonField {
        pointer: "/a".to_string(),
        template,
    };
    let out = step.apply("PAYLOAD").expect("apply");
    let parsed: serde_json::Value = serde_json::from_str(&out).expect("parse out");
    assert_eq!(
        parsed["a"],
        serde_json::Value::String("PAYLOAD".to_string())
    );
    // Sibling preserved
    assert_eq!(parsed["b"], serde_json::Value::String("y".to_string()));
}

#[test]
fn step_jsonfield_nested_object() {
    let template: serde_json::Value =
        serde_json::from_str(r#"{"outer":{"inner":"x"},"sib":"y"}"#).expect("parse template");
    let step = EncodingStep::JsonField {
        pointer: "/outer/inner".to_string(),
        template,
    };
    let out = step.apply("XSS").expect("apply");
    let parsed: serde_json::Value = serde_json::from_str(&out).expect("parse out");
    assert_eq!(parsed["outer"]["inner"], "XSS");
    assert_eq!(parsed["sib"], "y");
}

#[test]
fn step_jsonfield_array_index() {
    let template: serde_json::Value =
        serde_json::from_str(r#"{"items":["a","b","c"]}"#).expect("parse template");
    let step = EncodingStep::JsonField {
        pointer: "/items/1".to_string(),
        template,
    };
    let out = step.apply("Z").expect("apply");
    let parsed: serde_json::Value = serde_json::from_str(&out).expect("parse out");
    assert_eq!(parsed["items"][0], "a");
    assert_eq!(parsed["items"][1], "Z");
    assert_eq!(parsed["items"][2], "c");
}

#[test]
fn step_jsonfield_invalid_pointer_returns_err() {
    let template: serde_json::Value = serde_json::from_str(r#"{"a":"x"}"#).expect("parse");
    let step = EncodingStep::JsonField {
        pointer: "no-leading-slash".to_string(),
        template,
    };
    assert!(step.apply("p").is_err());
}

#[test]
fn pipeline_chains_jsonfield_then_base64() {
    let template: serde_json::Value =
        serde_json::from_str(r#"{"move_url":"x","domain":"k.com"}"#).expect("parse");
    let pipeline = EncodingPipeline::new(vec![
        EncodingStep::JsonField {
            pointer: "/move_url".to_string(),
            template,
        },
        EncodingStep::Base64,
    ]);
    let out = pipeline.apply("PAYLOAD").expect("apply");
    // Decoded should be valid JSON with move_url=PAYLOAD
    let decoded = String::from_utf8(STANDARD.decode(&out).expect("b64")).expect("utf8");
    let parsed: serde_json::Value = serde_json::from_str(&decoded).expect("json");
    assert_eq!(parsed["move_url"], "PAYLOAD");
    assert_eq!(parsed["domain"], "k.com");
}

#[test]
fn pipeline_empty_returns_payload_unchanged() {
    let pipeline = EncodingPipeline::default();
    assert_eq!(pipeline.apply("hi").expect("apply"), "hi");
    assert!(pipeline.is_empty());
}

#[test]
fn infer_returns_empty_for_short_value() {
    assert!(infer_nested_pipelines("abc").is_empty());
    assert!(infer_nested_pipelines("eyJ=").is_empty()); // length < 16
}

#[test]
fn infer_returns_empty_for_non_b64_charset() {
    let v = "hello world this is not base64";
    assert!(infer_nested_pipelines(v).is_empty());
}

#[test]
fn infer_returns_empty_for_b64_of_non_json() {
    let v = b64("just a plain string, not JSON, but long enough");
    assert!(infer_nested_pipelines(&v).is_empty());
}

#[test]
fn infer_finds_top_level_string_fields() {
    let json = r#"{"move_url":"as","acc_domain":"k.com"}"#;
    let v = b64(json);
    let nested = infer_nested_pipelines(&v);
    assert_eq!(nested.len(), 2);
    let pointers: Vec<&str> = nested.iter().map(|n| n.pointer.as_str()).collect();
    assert!(pointers.contains(&"/move_url"));
    assert!(pointers.contains(&"/acc_domain"));
}

#[test]
fn infer_pipeline_roundtrips_to_kakao_shape() {
    // Mirrors the real-world payload structure.
    let json = r#"{"move_url":"as","acc_domain":"kakaoinvestment.com","auth_domain":"en.kakaoinvestment.com"}"#;
    let value = b64(json);
    let nested = infer_nested_pipelines(&value);
    let move_url = nested
        .iter()
        .find(|n| n.pointer == "/move_url")
        .expect("found move_url");
    let injected = move_url.pipeline.apply("DALFOX_MARKER").expect("apply");
    let decoded = String::from_utf8(STANDARD.decode(&injected).expect("b64")).expect("utf8");
    let parsed: serde_json::Value = serde_json::from_str(&decoded).expect("json");
    assert_eq!(parsed["move_url"], "DALFOX_MARKER");
    // Other fields preserved verbatim
    assert_eq!(parsed["acc_domain"], "kakaoinvestment.com");
    assert_eq!(parsed["auth_domain"], "en.kakaoinvestment.com");
}

#[test]
fn infer_walks_into_nested_objects() {
    let json = r#"{"outer":{"inner":"v"},"top":"t"}"#;
    let v = b64(json);
    let nested = infer_nested_pipelines(&v);
    let pointers: Vec<&str> = nested.iter().map(|n| n.pointer.as_str()).collect();
    assert!(pointers.contains(&"/outer/inner"));
    assert!(pointers.contains(&"/top"));
}

#[test]
fn infer_walks_into_arrays() {
    let json = r#"{"items":["a","b"]}"#;
    let v = b64(json);
    let nested = infer_nested_pipelines(&v);
    let pointers: Vec<&str> = nested.iter().map(|n| n.pointer.as_str()).collect();
    assert!(pointers.contains(&"/items/0"));
    assert!(pointers.contains(&"/items/1"));
}

#[test]
fn infer_skips_non_string_leaves() {
    let json = r#"{"name":"x","count":3,"flag":true,"nada":null}"#;
    let v = b64(json);
    let nested = infer_nested_pipelines(&v);
    assert_eq!(nested.len(), 1);
    assert_eq!(nested[0].pointer, "/name");
}

#[test]
fn infer_caps_total_leaves() {
    // Build an object with way more than MAX_LEAVES string keys.
    let mut map = serde_json::Map::new();
    for i in 0..100 {
        map.insert(format!("k{}", i), serde_json::Value::String("v".into()));
    }
    let json = serde_json::Value::Object(map).to_string();
    let v = b64(&json);
    let nested = infer_nested_pipelines(&v);
    assert!(
        nested.len() <= MAX_LEAVES,
        "expected ≤ {} leaves, got {}",
        MAX_LEAVES,
        nested.len()
    );
}

#[test]
fn infer_handles_url_encoded_b64_survivors() {
    // %2b → '+' is a common surviving character; our charset filter must
    // still accept the value once URL-decoding occurred upstream.
    let json = r#"{"f":"v_long_enough_now"}"#;
    let v = b64(json);
    assert!(looks_like_base64(&v));
}

#[test]
fn pointer_escapes_special_chars() {
    // Field names with `/` and `~` should round-trip through the pointer
    // encoding back to the original key.
    let mut map = serde_json::Map::new();
    map.insert("a/b".into(), serde_json::Value::String("x".into()));
    map.insert("c~d".into(), serde_json::Value::String("y".into()));
    let json = serde_json::Value::Object(map).to_string();
    let v = b64(&json);
    let nested = infer_nested_pipelines(&v);
    let pointers: Vec<&str> = nested.iter().map(|n| n.pointer.as_str()).collect();
    assert!(pointers.iter().any(|p| p.contains("~1"))); // '/' escape
    assert!(pointers.iter().any(|p| p.contains("~0"))); // '~' escape

    // Apply each pipeline and verify the leaf actually got replaced.
    for nf in &nested {
        let out = nf.pipeline.apply("ZZZ").expect("apply");
        let decoded = String::from_utf8(STANDARD.decode(&out).expect("b64")).expect("utf8");
        let parsed: serde_json::Value = serde_json::from_str(&decoded).expect("json");
        let key = nf.path[0].clone();
        assert_eq!(parsed[&key], "ZZZ", "field {key} replaced");
    }
}
