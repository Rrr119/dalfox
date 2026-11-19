//! Context-aware payload selection.
//!
//! The per-context catalogs in [`crate::scanning::xss_common`] and
//! [`crate::scanning::payload_families`] intentionally contain more than one
//! execution shape: a quoted attribute can be broken with a quote or with a
//! URL scheme, a script block can be escaped with a string breakout or a
//! `</script>` tag, and shared/WAF/custom payloads are appended after those
//! families. Some of those entries cannot execute at the reflected landing
//! site at all — a bare `javascript:` URI in HTML text, an `onerror=` fragment
//! in a `<script>` body, or a plain `alert(1)` in an attribute value.
//!
//! This module removes those context-incompatible shapes from the base
//! reflection and DOM catalogs before the per-parameter request caps are
//! applied, while preserving the original catalog order inside each compatible
//! shape. WAF and shared CSP/technology payloads are appended later and keep
//! their existing path. The selection is deliberately conservative:
//!
//! * unknown contexts and JS-execution sinks are left untouched;
//! * custom-only scans keep exactly what the operator supplied;
//! * JSONP verifiers stay in every catalog, because they are valid proof for
//!   an `application/javascript` response regardless of how the HTML-oriented
//!   context classifier labelled the parameter;
//! * if filtering would empty a catalog, the catalog is returned unchanged.
//!
//! Removing a payload here is a request-budget optimisation, not a finding
//! claim: the remaining DOM/AST verifiers and the reflection classifier still
//! decide whether an echoed payload is exploitable.

use crate::parameter_analysis::{InjectionContext, Param};

/// Coarse landing-site class used to choose payload shapes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadContext {
    Html,
    HtmlComment,
    Attribute,
    AttributeUrl,
    Javascript,
    Css,
    Unknown,
}

impl PayloadContext {
    /// Derive the selection class from the context recorded during discovery.
    pub fn from_param(param: &Param) -> Self {
        match param.injection_context {
            Some(InjectionContext::Html(Some(
                crate::parameter_analysis::DelimiterType::Comment,
            ))) => Self::HtmlComment,
            Some(InjectionContext::Html(_)) => Self::Html,
            Some(InjectionContext::AttributeUrl(_)) => Self::AttributeUrl,
            Some(InjectionContext::Attribute(_)) => Self::Attribute,
            Some(InjectionContext::Javascript(_)) => Self::Javascript,
            Some(InjectionContext::Css(_)) => Self::Css,
            None => Self::Unknown,
        }
    }
}

/// The execution shape a payload depends on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadShape {
    /// Opens or closes markup (a tag, an encoded tag, mXSS, clobbering).
    HtmlMarkup,
    /// A `javascript:` / `data:text/html` / `vbscript:` URL.
    ProtocolUrl,
    /// An `on*=` handler fragment that does not open a tag of its own.
    AttributeHandler,
    /// A JavaScript expression / string breakout for an existing script body
    /// or event-handler value.
    JsExpression,
    /// A `</script>` breakout. Also useful from HTML text, where it can close
    /// an existing script before opening the injected tag.
    ScriptBreakout,
    /// A `</style>` breakout.
    StyleBreakout,
    /// Text with no markup or executable JavaScript shape.
    PlainText,
}

/// Result of a context-selection pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContextSelection {
    pub payloads: Vec<String>,
    pub dropped: usize,
    pub context: PayloadContext,
}

/// True when `payload` is one of the JSONP-callable verifiers.
///
/// These are kept even when the HTML context detector labels a parameter as
/// HTML/attribute: `application/javascript` JSONP endpoints are classified
/// from their body text, and the callback payload is often the only shape that
/// verifies there.
fn is_jsonp_verifier(payload: &str) -> bool {
    matches!(
        payload.trim(),
        "alert(document.domain)//" | ";alert(1)//" | "-alert(1)-"
    )
}

/// ASCII-case-insensitive `needle` search without allocating a lowercased
/// copy. Payload strings are small, but this runs over every catalog entry.
fn contains_ascii_ci(haystack: &str, needle: &str) -> bool {
    haystack
        .as_bytes()
        .windows(needle.len())
        .any(|w| w.eq_ignore_ascii_case(needle.as_bytes()))
}

/// Decode the common transport forms a payload may be encoded in before it is
/// classified. Kept local so classification observes `%3Csvg…` and
/// `&lt;svg…` the same way the server's HTML parser eventually will.
fn decoded_payload(payload: &str) -> String {
    let html_decoded = crate::scanning::decode_html_entities(payload);
    match urlencoding::decode(&html_decoded) {
        Ok(decoded) => decoded.into_owned(),
        Err(_) => html_decoded,
    }
}

/// True when the normalized text opens a tag, including encoded tag openers.
fn opens_markup(text: &str) -> bool {
    let bytes = text.as_bytes();
    bytes.windows(2).any(|w| {
        w[0] == b'<' && (w[1].is_ascii_alphabetic() || w[1] == b'/' || w[1] == b'!' || w[1] == b'?')
    })
}

/// True when an `on<event>` attribute starts in `text` and has an `=` value.
fn has_attribute_handler(text: &str) -> bool {
    let bytes = text.as_bytes();
    for i in 0..bytes.len().saturating_sub(2) {
        if !(bytes[i] | 0x20).eq(&b'o') || !(bytes[i + 1] | 0x20).eq(&b'n') {
            continue;
        }
        if i > 0 && (bytes[i - 1].is_ascii_alphanumeric() || matches!(bytes[i - 1], b'_' | b'-')) {
            continue;
        }
        let mut k = i + 2;
        while k < bytes.len() && bytes[k].is_ascii_alphabetic() {
            k += 1;
        }
        if k == i + 2 {
            continue;
        }
        while k < bytes.len() && bytes[k].is_ascii_whitespace() {
            k += 1;
        }
        if k < bytes.len() && bytes[k] == b'=' {
            return true;
        }
    }
    false
}

/// Classify one payload by the browser feature it needs.
///
/// Order matters. A `</script><img onerror=…>` payload is both a script
/// breakout and markup; classifying it as a script breakout lets it remain
/// valid in a JavaScript context as well as in HTML.
pub fn classify_payload(payload: &str) -> PayloadShape {
    let decoded = decoded_payload(payload);
    let text = decoded.as_str();
    let lower = text.to_ascii_lowercase();

    // A protocol URL is one attribute value even when its payload bytes
    // contain `</script>` or markup (e.g. `data:text/html,<script>…`). Check it
    // first so the URL-attribute selector does not mistake it for a breakout.
    let trimmed = lower.trim_start();
    if trimmed.starts_with("javascript:")
        || trimmed.starts_with("data:text/html")
        || trimmed.starts_with("vbscript:")
    {
        return PayloadShape::ProtocolUrl;
    }
    if contains_ascii_ci(text, "</script") {
        return PayloadShape::ScriptBreakout;
    }
    if contains_ascii_ci(text, "</style") {
        return PayloadShape::StyleBreakout;
    }
    if opens_markup(text) {
        return PayloadShape::HtmlMarkup;
    }

    if has_attribute_handler(&lower) {
        return PayloadShape::AttributeHandler;
    }
    if crate::scanning::js_context_verify::payload_carries_js_sink(&lower) {
        return PayloadShape::JsExpression;
    }
    PayloadShape::PlainText
}

/// Whether `shape` has a plausible execution path at `context`.
fn shape_fits(context: PayloadContext, shape: PayloadShape) -> bool {
    match context {
        PayloadContext::Unknown => true,
        PayloadContext::Html | PayloadContext::HtmlComment => matches!(
            shape,
            PayloadShape::HtmlMarkup | PayloadShape::ScriptBreakout | PayloadShape::StyleBreakout
        ),
        // A quoted attribute can be escaped into markup, or the value itself
        // can be a URL/handler. A bare JS expression cannot execute until a
        // quote is broken, and that breakout is a different catalog entry.
        PayloadContext::Attribute => matches!(
            shape,
            PayloadShape::HtmlMarkup | PayloadShape::AttributeHandler | PayloadShape::ProtocolUrl
        ),
        PayloadContext::AttributeUrl => matches!(
            shape,
            PayloadShape::ProtocolUrl | PayloadShape::HtmlMarkup | PayloadShape::AttributeHandler
        ),
        // In a script body, either a JS expression or a tag breakout can
        // execute. Attribute-handler fragments are inert as script source.
        PayloadContext::Javascript => matches!(
            shape,
            PayloadShape::JsExpression | PayloadShape::ScriptBreakout | PayloadShape::HtmlMarkup
        ),
        PayloadContext::Css => {
            matches!(
                shape,
                PayloadShape::StyleBreakout | PayloadShape::HtmlMarkup
            )
        }
    }
}

/// Stable partition: shapes that fit first, compatible-but-less-direct shapes
/// after them. The existing catalog order is preserved as much as possible;
/// this only moves shared/custom entries appended at the tail ahead when their
/// shape is the context's primary strategy.
fn affinity(context: PayloadContext, shape: PayloadShape) -> u8 {
    let preferred = match context {
        PayloadContext::Html | PayloadContext::HtmlComment => {
            matches!(shape, PayloadShape::HtmlMarkup)
        }
        PayloadContext::Attribute => matches!(
            shape,
            PayloadShape::AttributeHandler | PayloadShape::ProtocolUrl
        ),
        PayloadContext::AttributeUrl => matches!(shape, PayloadShape::ProtocolUrl),
        PayloadContext::Javascript => {
            matches!(
                shape,
                PayloadShape::JsExpression | PayloadShape::ScriptBreakout
            )
        }
        PayloadContext::Css => matches!(shape, PayloadShape::StyleBreakout),
        PayloadContext::Unknown => true,
    };
    if preferred { 0 } else { 1 }
}

/// Select the subset of `payloads` whose execution shape can work at `param`'s
/// recorded injection context, then order the primary shapes first.
///
/// `deep_scan` and custom-only scans are returned unchanged. JS-execution
/// sinks are also returned unchanged: the bare expression is the intended
/// exploit and the surrounding catalog may contain multiple equivalent
/// spellings that the sink verifier understands.
pub fn select_for_param(param: &Param, payloads: Vec<String>, deep_scan: bool) -> ContextSelection {
    select_inner(param, payloads, deep_scan, false)
}

/// Reflection-phase variant of [`select_for_param`].
///
/// Reflection answers a weaker question than execution: "did the bytes come
/// back?" An endpoint that escapes markup can still reflect a non-markup
/// payload, and that `R` is useful evidence even when the shape is unlikely to
/// execute at the recorded context. Keep one representative of each otherwise
/// dropped shape at the front (at most a handful of requests), while the DOM
/// catalog uses the strict selection above. This preserves the diagnostic
/// signal without paying for hundreds of redundant shape variants.
pub fn select_reflection_for_param(
    param: &Param,
    payloads: Vec<String>,
    deep_scan: bool,
) -> ContextSelection {
    select_inner(param, payloads, deep_scan, true)
}

fn select_inner(
    param: &Param,
    payloads: Vec<String>,
    deep_scan: bool,
    fallback_sentinels: bool,
) -> ContextSelection {
    let context = PayloadContext::from_param(param);
    let total = payloads.len();
    if deep_scan
        || context == PayloadContext::Unknown
        || param.in_js_exec_sink
        || payloads.is_empty()
    {
        return ContextSelection {
            payloads,
            dropped: 0,
            context,
        };
    }

    let mut kept: Vec<(String, PayloadShape)> = Vec::with_capacity(payloads.len());
    // JSONP verifiers lead every catalog. They are valid proof for an
    // application/javascript response even when the HTML-oriented classifier
    // labelled the parameter as HTML/attribute, and the DOM phase's early-exit
    // budgets only sample a prefix.
    let mut front: Vec<String> = Vec::new();
    let mut sentinels: Vec<String> = Vec::new();
    let mut sentinel_shapes: Vec<PayloadShape> = Vec::new();
    for payload in payloads.iter() {
        if is_jsonp_verifier(payload) {
            front.push(payload.clone());
            continue;
        }
        let shape = classify_payload(payload);
        if shape_fits(context, shape) {
            kept.push((payload.clone(), shape));
        } else if fallback_sentinels
            && shape != PayloadShape::PlainText
            && !sentinel_shapes.contains(&shape)
        {
            sentinel_shapes.push(shape);
            sentinels.push(payload.clone());
        }
    }

    // A context filter must not turn a catalog into an empty one. That would
    // turn an uncertain classification into a silent no-test parameter.
    if kept.is_empty() {
        return ContextSelection {
            payloads,
            dropped: 0,
            context,
        };
    }

    // Stable sort by primary/secondary shape. `sort_by_key` is stable, so
    // encoder variants stay in their original relative order.
    kept.sort_by_key(|(_, shape)| affinity(context, *shape));
    let dropped = total - kept.len() - front.len();
    let mut selected = front;
    selected.extend(sentinels);
    selected.extend(kept.into_iter().map(|(payload, _)| payload));
    ContextSelection {
        payloads: selected,
        dropped,
        context,
    }
}

#[cfg(test)]
mod tests;
