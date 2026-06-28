import React from "react";
import { InputSanitizer } from "../../../core/a03-injection-defense/InputSanitizer.js";

/**
 * React hook wrapper around core InputSanitizer.
 */
export function useInputSanitizer(profile = "strict") {
  return React.useMemo(() => new InputSanitizer(profile), [profile]);
}

export function SanitizedText({ html, profile = "strict" }) {
  const sanitizer = new InputSanitizer(profile);
  const clean = sanitizer.sanitizeHTML(html);
  return React.createElement("span", null, clean);
}