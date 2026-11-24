use super::*;

#[test]
fn prototype_pollution_payloads_are_non_empty_and_unique() {
    let payloads = get_prototype_pollution_payloads();
    assert!(!payloads.is_empty());

    let mut seen = std::collections::HashSet::new();
    for payload in &payloads {
        assert!(seen.insert(payload), "duplicate payload: {payload}");
        assert!(!payload.is_empty());
        assert!(!payload.contains('\n'));
    }
}

#[test]
fn prototype_pollution_payloads_cover_merge_keys() {
    let payloads = get_prototype_pollution_payloads();
    for needle in ["__proto__", "constructor", "prototype", "polluted"] {
        assert!(
            payloads.iter().any(|p| p.contains(needle)),
            "missing {needle} shape"
        );
    }
    assert!(
        payloads.iter().any(|p| p.starts_with("__proto__[")),
        "bracket syntax is the common query-string merge shape"
    );
    assert!(
        payloads.iter().any(|p| p.contains("constructor.prototype")),
        "dot syntax catches parsers that split on dots"
    );
}

#[test]
fn prototype_pollution_payloads_carry_scan_markers_and_xss_gadgets() {
    let payloads = get_prototype_pollution_payloads();
    assert!(
        payloads
            .iter()
            .all(|p| crate::scanning::markers::carries_scan_marker(p)),
        "every payload must be attributable to this scan"
    );
    assert!(
        payloads.iter().any(|p| p.contains("onerror=alert(1)")),
        "need an HTML gadget"
    );
    assert!(
        payloads
            .iter()
            .any(|p| p.contains("data:text/javascript,alert(1)")),
        "need a URL gadget"
    );
}

#[test]
fn prototype_pollution_payloads_include_json_body_shapes() {
    let payloads = get_prototype_pollution_payloads();
    assert!(
        payloads
            .iter()
            .any(|p| p.starts_with('{') && p.contains("\"__proto__\"")),
        "JSON merge payload is missing"
    );
    assert!(
        payloads
            .iter()
            .any(|p| p.starts_with('{') && p.contains("\"constructor\"")),
        "JSON constructor.prototype payload is missing"
    );
}
