use super::*;

#[test]
fn detects_inline_source_to_sink_flow() {
    let html = r#"<!doctype html><html><body>
        <div id="out"></div>
        <script>
            document.getElementById("out").innerHTML = location.hash.substring(1);
        </script>
    </body></html>"#;

    let detection = detect_inline_dom_xss(html);
    assert_eq!(detection.inline_scripts, 1);
    assert!(detection.has_dom_xss());
    assert!(
        detection.flows.iter().any(|flow| {
            flow.source.contains("location.hash") && flow.sink.contains("innerHTML")
        })
    );
}

#[test]
fn ignores_external_scripts_and_non_executable_bodies() {
    let html = r#"<html><body>
        <script src="/app.js">document.body.innerHTML = location.hash;</script>
        <script type="application/json">{"source":"location.hash","sink":"innerHTML"}</script>
    </body></html>"#;

    let detection = detect_inline_dom_xss(html);
    assert_eq!(
        detection.inline_scripts, 1,
        "external script bodies are not inline code; JSON is still parsed but yields no flow"
    );
    assert!(!detection.has_dom_xss());
}

#[test]
fn deduplicates_identical_flows_from_repeated_snippets() {
    let snippet = "document.body.innerHTML = location.search;";
    let html =
        format!("<html><body><script>{snippet}</script><script>{snippet}</script></body></html>");

    let detection = detect_inline_dom_xss(&html);
    assert_eq!(detection.inline_scripts, 2);
    assert_eq!(detection.flows.len(), 1);
}

#[test]
fn response_evidence_matches_the_dom_verifier() {
    let payload = format!(
        "<svg onload=alert(1) class={}>",
        crate::scanning::markers::class_marker()
    );
    let body = format!("<html><body>{payload}</body></html>");
    assert_eq!(
        classify_response_evidence(&payload, &body, "text/html"),
        Some(DomEvidenceKind::Marker)
    );

    let url_payload = "javascript:alert(1)";
    let url_body = format!(r#"<html><body><a href="{url_payload}">x</a></body></html>"#);
    assert_eq!(
        classify_response_evidence(url_payload, &url_body, "text/html"),
        Some(DomEvidenceKind::ExecutableUrl)
    );
}
