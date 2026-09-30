import React from "react";
import { InputSanitizer } from "@owasp-webshield/core";

/**
 * React hook wrapper around core InputSanitizer.
 */
export function useInputSanitizer(profile = "strict") {
  return React.useMemo(() => new InputSanitizer(profile), [profile]);
}

/**
 * Renders `html` after sanitizing it. The sanitizer's output is HTML (entities
 * encoded, only allowlisted tags kept), so it is inserted as markup; passing it
 * as a text child would escape it a second time ("Tom &amp; Jerry").
 */
export function SanitizedText({ html, profile = "strict" }) {
  const sanitizer = useInputSanitizer(profile);
  const clean = React.useMemo(() => sanitizer.sanitizeHTML(html), [sanitizer, html]);
  return React.createElement("span", { dangerouslySetInnerHTML: { __html: clean } });
}
