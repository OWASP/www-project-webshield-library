# Node API Integration Example

## Goal

Apply OWL core controls in a Node API service pipeline.

## Middleware-style pattern

```js
import {
  InputValidator,
  InputSanitizer,
  SecurityConfigManager,
  HardeningReporter,
  SecurityLogger
} from "@owl/core";

const validator = new InputValidator();
const sanitizer = new InputSanitizer("strict");
const logger = new SecurityLogger();

export function validateRequest(schema) {
  return (req, res, next) => {
    const result = validator.validateSchema(req.body, schema);
    if (!result.valid) {
      logger.warn("validation.failed", { errors: result.errors });
      res.status(400).json({ errors: result.errors });
      return;
    }
    next();
  };
}

export function sanitizeBody(req, _res, next) {
  if (typeof req.body?.content === "string") {
    req.body.content = sanitizer.sanitizeHTML(req.body.content);
  }
  next();
}
```

## Startup hardening check

```js
const configManager = new SecurityConfigManager({
  debug: process.env.NODE_ENV !== "production",
  cors: { origin: process.env.CORS_ORIGIN || "self" },
  cookies: { secure: true, sameSite: "Strict" }
});

const report = new HardeningReporter(configManager).generate();
if (report.some((f) => f.severity === "high")) {
  throw new Error("Refusing to start with high-severity security misconfiguration.");
}
```

## Security checklist

- Validate request schema at boundary.
- Sanitize user-generated rich text before persistence/rendering.
- Fail startup for critical misconfiguration in production profiles.
