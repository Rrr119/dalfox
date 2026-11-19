use super::*;
use crate::parameter_analysis::{DelimiterType, InjectionContext, Location};

fn param(context: InjectionContext) -> Param {
    Param {
        injection_context: Some(context),
        ..Param::new("q".to_string(), "seed".to_string(), Location::Query)
    }
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|v| (*v).to_string()).collect()
}

#[test]
fn html_keeps_markup_and_drops_bare_js_or_protocol_text() {
    let param = param(InjectionContext::Html(None));
    let selected = select_for_param(
        &param,
        strings(&[
            "<svg onload=alert(1)>",
            "javascript:alert(1)",
            "alert(1)",
            "onmouseover=alert(1)",
            "</script><img src=x onerror=alert(1)>",
            "<math><mtext><img src=x onerror=alert(1)></mtext></math>",
        ]),
        false,
    );

    assert_eq!(
        selected.payloads,
        strings(&[
            "<svg onload=alert(1)>",
            "<math><mtext><img src=x onerror=alert(1)></mtext></math>",
            "</script><img src=x onerror=alert(1)>",
        ])
    );
    assert_eq!(selected.dropped, 3);
}

#[test]
fn attribute_keeps_breakouts_handlers_and_protocols() {
    let param = param(InjectionContext::Attribute(Some(
        DelimiterType::DoubleQuote,
    )));
    let selected = select_for_param(
        &param,
        strings(&[
            "alert(1)",
            "\" onfocus=alert(1) autofocus id=dlx1\"",
            "\"><img src=x onerror=alert(1)>\"",
            "javascript:alert(1)",
            "';alert(1)//",
        ]),
        false,
    );

    assert_eq!(
        selected.payloads,
        strings(&[
            "\" onfocus=alert(1) autofocus id=dlx1\"",
            "javascript:alert(1)",
            "\"><img src=x onerror=alert(1)>\"",
        ])
    );
    assert_eq!(selected.dropped, 2);
}

#[test]
fn attribute_url_prioritizes_protocol_payloads() {
    let param = param(InjectionContext::AttributeUrl(None));
    let selected = select_for_param(
        &param,
        strings(&[
            "\"><svg onload=alert(1)>",
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "onmouseover=alert(1)",
        ]),
        false,
    );

    assert_eq!(
        selected.payloads,
        strings(&[
            "javascript:alert(1)",
            "data:text/html,<script>alert(1)</script>",
            "\"><svg onload=alert(1)>",
            "onmouseover=alert(1)",
        ])
    );
    assert_eq!(selected.dropped, 0);
}

#[test]
fn javascript_keeps_expressions_and_tag_breakouts() {
    let param = param(InjectionContext::Javascript(Some(
        DelimiterType::SingleQuote,
    )));
    let selected = select_for_param(
        &param,
        strings(&[
            "';alert(1)//",
            "<svg onload=alert(1)>",
            "onmouseover=alert(1)",
            "javascript:alert(1)",
            "</script><script>alert(1)</script>",
        ]),
        false,
    );

    assert_eq!(
        selected.payloads,
        strings(&[
            "';alert(1)//",
            "</script><script>alert(1)</script>",
            "<svg onload=alert(1)>",
        ])
    );
    assert_eq!(selected.dropped, 2);
}

#[test]
fn css_keeps_style_breakouts_and_markup() {
    let param = param(InjectionContext::Css(None));
    let selected = select_for_param(
        &param,
        strings(&[
            "alert(1)",
            "</style><svg onload=alert(1)>",
            "javascript:alert(1)",
            "<img src=x onerror=alert(1)>",
        ]),
        false,
    );

    assert_eq!(
        selected.payloads,
        strings(&[
            "</style><svg onload=alert(1)>",
            "<img src=x onerror=alert(1)>",
        ])
    );
    assert_eq!(selected.dropped, 2);
}

#[test]
fn encoded_tag_payloads_are_classified_as_markup() {
    assert_eq!(
        classify_payload("%3Csvg%20onload%3Dalert%281%29%3E"),
        PayloadShape::HtmlMarkup
    );
    assert_eq!(
        classify_payload("&#x3c;svg onload=alert(1)&#x3e;"),
        PayloadShape::HtmlMarkup
    );
}

#[test]
fn jsonp_verifiers_survive_every_known_context() {
    for context in [
        InjectionContext::Html(None),
        InjectionContext::Attribute(None),
        InjectionContext::Css(None),
    ] {
        let selected = select_for_param(
            &param(context),
            strings(&["alert(document.domain)//"]),
            false,
        );
        assert_eq!(
            selected.payloads,
            strings(&["alert(document.domain)//"]),
            "JSONP verifier must not be dropped by HTML-oriented context selection"
        );
        assert_eq!(
            selected.payloads.first().map(String::as_str),
            Some("alert(document.domain)//"),
            "JSONP verifier must stay ahead of the DOM early-exit window"
        );
    }
}

#[test]
fn reflection_selection_keeps_one_sentinel_per_dropped_shape() {
    let param = param(InjectionContext::Html(None));
    let selected = select_reflection_for_param(
        &param,
        strings(&[
            "<svg onload=alert(1)>",
            "javascript:alert(1)",
            "alert(1)",
            "onmouseover=alert(1)",
            "<img src=x onerror=alert(1)>",
        ]),
        false,
    );

    assert_eq!(
        selected.payloads,
        strings(&[
            "javascript:alert(1)",
            "alert(1)",
            "onmouseover=alert(1)",
            "<svg onload=alert(1)>",
            "<img src=x onerror=alert(1)>",
        ])
    );
    assert_eq!(
        selected.dropped, 3,
        "dropped counts every non-markup payload even though one representative per shape is retained"
    );
}

#[test]
fn unknown_context_deep_scan_and_js_exec_sink_are_untouched() {
    let payloads = strings(&["alert(1)", "javascript:alert(1)"]);
    let unknown = Param::new("q".to_string(), "seed".to_string(), Location::Query);
    assert_eq!(
        select_for_param(&unknown, payloads.clone(), false).payloads,
        payloads
    );

    let html = param(InjectionContext::Html(None));
    assert_eq!(
        select_for_param(&html, payloads.clone(), true).payloads,
        payloads
    );

    let mut js_sink = html;
    js_sink.in_js_exec_sink = true;
    assert_eq!(
        select_for_param(&js_sink, payloads.clone(), false).payloads,
        payloads
    );
}
