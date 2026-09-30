# A03 — Injection

Allowlist-based HTML sanitization (`InputSanitizer`) plus schema, email, URL, and length validation (`InputValidator`).

## Core API (`@owasp-webshield/core`)

```js
import {
  INJECTION_DEFENSE_TYPES,
  InputSanitizer,
  InputValidator
} from "@owasp-webshield/core";

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

- Moderate-profile attributes are limited to `title`, `href`/`target`/`rel` on links, and `src`/`alt`/`width`/`height` on images, with URLs restricted to `http:`, `https:`, `mailto:` and `tel:`.
- `class` is removed by default: user content could otherwise borrow your own CSS (for example Tailwind's `fixed inset-0 z-50`) to cover the page with a fake login form. To keep specific class names, pass them explicitly: `new InputSanitizer("moderate", { allowedClasses: ["highlight"] })`, or `<SanitizedText profile="moderate" allowedClasses={["highlight"]} />` in React.

## React Adapter (`@owasp-webshield/react`)

```jsx
import React from "react";
import { SanitizedText, useInputSanitizer } from "@owasp-webshield/react";

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
