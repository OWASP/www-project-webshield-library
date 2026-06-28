# GitHub Actions Security Gate Example

## Workflow

```yaml
name: owl-security-gate

on:
  pull_request:
  push:
    branches: [main]

jobs:
  quality:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup Node
        uses: actions/setup-node@v4
        with:
          node-version: 22
          cache: npm

      - name: Install
        run: npm ci

      - name: Lint
        run: npm run lint

      - name: Test
        run: npm run test

      - name: Build
        run: npm run build
```

## Optional policy gate extension

- Add a step that executes A05/A06 checks from your app bootstrap or policy script.
- Fail the pipeline when high-severity findings are detected.
