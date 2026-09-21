# A03 — Injection

Allowlist-based HTML sanitization (`InputSanitizer`) plus schema, email, URL, and length validation (`InputValidator`).

## Core API (`@owasp-js/owl`)

```js
import {
  INJECTION_DEFENSE_TYPES,
  InputSanitizer,
  InputValidator
} from "@owasp-js/owl";

const sanitizer = new InputSanitizer("moderate");
const cleanHtml = sanitizer.sanitizeHTML('<a href="javascript:alert(1)" onclick="alert(1)">safe</a>');

const validator = new InputValidator();
const validation = validator.validateSchema(
  { email: "user@example.com", password: "secret-123" },
  {
    email: { required: true, pattern: /^[^\s@]+@[^\s@]+\.[^\s@]+$/ },
    password: { required: true, minLength: 8 }
  }
);

validator.validateEmail("user@example.com");
validator.validateUrl("https://example.com/profile");
validator.validateLength("secret-123", { min: 8, max: 64 });
console.log(cleanHtml, validation.valid, INJECTION_DEFENSE_TYPES);
```

::: tip `strict` vs `moderate`
`InputSanitizer` is tokenizer-based, not regex-based — it closes bypasses via unclosed `<script>` tags, `/`-separated event handlers (e.g. `<svg/onload=...>`), and obfuscated `javascript:` URLs. The `moderate` profile allows a fixed set of formatting tags; `strict` strips all markup.
:::

## React Adapter (`@owasp-js/owl-react`)

```jsx
import React from "react";
import { SanitizedText, useInputSanitizer } from "@owasp-js/owl-react";

export function CommentPreview({ rawHtml }) {
  const sanitizer = useInputSanitizer("moderate");
  const clean = sanitizer.sanitizeHTML(rawHtml);

  return (
    <div>
      <div>{clean}</div>
      <SanitizedText profile="strict" html={rawHtml} />
    </div>
  );
}
```
