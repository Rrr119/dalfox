//! DOM-XSS detection facade.
//!
//! Dalfox has two separate DOM paths:
//!
//! * static analysis of a page's JavaScript (`AstDomAnalyzer`) — reports
//!   client-side source→sink flows even when the server never reflects a
//!   parameter; and
//! * response evidence on an injected payload (marker element, executable URL
//!   attribute, parsed handler/script sink, JS-context AST) — upgrades a
//!   reflected payload to `V`.
//!
//! This module exposes both behind small, testable entry points. Production
//! scanning keeps using the richer orchestration in [`super::ast_dom_phase`]
//! and [`super::check_dom_verification`]; the facade exists so labs and callers
//! that only have an HTML body can ask the same questions without duplicating
//! script extraction or evidence classification.

use crate::scanning::ast_dom_analysis::{AstDomAnalyzer, DomXssVulnerability};

pub use crate::scanning::check_dom_verification::DomEvidenceKind;

/// One inline script that could not be analysed, plus the parser/limit reason.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomScriptSkip {
    pub index: usize,
    pub reason: String,
}

/// Static DOM-XSS inventory for an HTML document.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DomDetection {
    /// Number of inline `<script>` bodies inspected.
    pub inline_scripts: usize,
    /// Deduplicated source→sink flows found by the AST analyzer.
    pub flows: Vec<DomXssVulnerability>,
    /// Inline scripts the analyzer skipped (oversized, over-nested, or parse
    /// errors). A clean `flows` list beside a non-empty `skipped` list is not
    /// proof that the page has no DOM XSS.
    pub skipped: Vec<DomScriptSkip>,
}

impl DomDetection {
    /// True when at least one source→sink flow was found.
    pub fn has_dom_xss(&self) -> bool {
        !self.flows.is_empty()
    }
}

/// Analyse the inline JavaScript in `html` for DOM-XSS source→sink flows.
///
/// External `<script src>` bodies are intentionally not fetched here: doing so
/// needs a client, target policy/scope, and byte limits, all of which the scan
/// orchestration already owns. `<script src>` elements with inline fallback
/// content are skipped because browsers do not execute that content.
pub fn detect_inline_dom_xss(html: &str) -> DomDetection {
    let document = crate::utils::html::parse_document_bounded(html);
    let analyzer = AstDomAnalyzer::new();
    let mut detection = DomDetection::default();

    for script in document.select(crate::scanning::selectors::script()) {
        if script.value().attr("src").is_some() {
            continue;
        }
        let code: String = script.text().collect();
        if code.trim().is_empty() {
            continue;
        }
        let index = detection.inline_scripts;
        detection.inline_scripts += 1;
        match analyzer.analyze(&code) {
            Ok(flows) => detection.flows.extend(flows),
            Err(reason) => detection.skipped.push(DomScriptSkip { index, reason }),
        }
    }

    // The same page can contain identical inline snippets (templates,
    // hydration fallbacks). Keep one finding per flow signature; line/column
    // stay part of the key so two distinct sinks at different offsets survive.
    detection.flows.sort_by(|a, b| {
        (a.line, a.column, &a.source, &a.sink).cmp(&(b.line, b.column, &b.source, &b.sink))
    });
    detection.flows.dedup_by(|a, b| {
        a.line == b.line && a.column == b.column && a.source == b.source && a.sink == b.sink
    });
    detection
}

/// Fast predicate for callers that only need the boolean answer.
pub fn has_inline_dom_xss(html: &str) -> bool {
    detect_inline_dom_xss(html).has_dom_xss()
}

/// Classify browser-executable evidence for `payload` in a `content_type`
/// response body. This is the same classifier the DOM-verification phase uses,
/// exposed for labs and focused integrations.
pub fn classify_response_evidence(
    payload: &str,
    body: &str,
    content_type: &str,
) -> Option<DomEvidenceKind> {
    crate::scanning::check_dom_verification::classify_dom_evidence_for_response(
        payload,
        body,
        content_type,
    )
}

#[cfg(test)]
mod tests;
