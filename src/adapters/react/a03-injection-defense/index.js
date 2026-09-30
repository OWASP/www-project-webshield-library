import React from "react";
import { InputSanitizer } from "@owasp-webshield/core";
import { useStableValue } from "../useStableValue.js";

/**
 * React hook wrapper around core InputSanitizer.
 * @param {"strict"|"moderate"} [profile]
 * @param {{allowedClasses?: string[]}} [options]
 */
export function useInputSanitizer(profile = "strict", options = {}) {
  const stableOptions = useStableValue(options);
  return React.useMemo(() => new InputSanitizer(profile, stableOptions), [profile, stableOptions]);
}

/**
 * Renders `html` after sanitizing it. The sanitizer's output is HTML (entities
 * encoded, only allowlisted tags kept), so it is inserted as markup; passing it
 * as a text child would escape it a second time ("Tom &amp; Jerry").
 */
export function SanitizedText({ html, profile = "strict", allowedClasses }) {
  const sanitizer = useInputSanitizer(profile, { allowedClasses });
  const clean = React.useMemo(() => sanitizer.sanitizeHTML(html), [sanitizer, html]);
  return React.createElement("span", { dangerouslySetInnerHTML: { __html: clean } });
}
