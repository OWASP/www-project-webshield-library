# Deployment Recipes

## 1. Local quality gate

```bash
npm install
npm run check
npm run build
```

## 2. Container pipeline recipe

```dockerfile
FROM node:22-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run check && npm run build

FROM node:22-alpine
WORKDIR /app
COPY --from=build /app/dist ./dist
COPY --from=build /app/package*.json ./
RUN npm ci --omit=dev
CMD ["node", "dist/index.cjs"]
```

## 3. Environment profile recommendations

- Development:
  - verbose logging allowed
  - mock tokens only in local environments
- Staging:
  - production-like auth and SSRF policy enabled
  - strict config validation
- Production:
  - secure cookies and strict same-site policy
  - no debug flags
  - startup hardening report gate enabled

## 4. Release checklist

1. Run lint/test/build.
2. Update CHANGELOG.
3. Tag release and publish artifacts.
4. Announce security-impacting changes in release notes.
