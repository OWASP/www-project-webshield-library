// OWL wiring for the pinned OWASP NodeGoat deployment (issue #54).
// Started as `node --import wiring/nodegoat.mjs server.js`; upstream sources
// are untouched. Controls applied, per documented OWL API:
//   - `securityHeaders()` on every response (A05, nodegoat.md #8)
//   - `assertPermission()` over `RBACManager` for /benefits and the
//     allocations listing (A01, nodegoat.md #14); ownership of
//     `/allocations/:userId` is deliberately NOT checked - that is the
//     documented IDOR gap (nodegoat.md #13)
//   - `verifyCsrf()` synchronizer token for `POST /profile` (A01/A08,
//     nodegoat.md #17)
//   - `assertValidInput()` numeric patterns for the contributions amount and
//     the `$where` threshold (A03, nodegoat.md #1 and #2)
//   - `sanitizeFields()` with `InputSanitizer("moderate")` for memos (A03,
//     nodegoat.md #4)
//   - `SecurityLogger` JSON sink behind `console.log`/`console.error` so CR/LF
//     from user input stay inside one structured line (A09, nodegoat.md #3)
//   - `toErrorResponse()` replacing the app's error renderer (A05)
//   - brute force (nodegoat.md #12) has no OWL control: deliberately left
//     exploitable, which the benchmark records as a gap.
import { createRequire } from "node:module";
import { join } from "node:path";
import { InputSanitizer, RBACManager, SecurityLogger } from "@owasp-webshield/core";
import {
  assertPermission,
  assertValidInput,
  issueCsrfToken,
  sanitizeFields,
  securityHeaders,
  toErrorResponse,
  verifyCsrf
} from "@owasp-webshield/node";
import { hookExpress, onModuleLoad, prependRouteGuards } from "./hook.mjs";

const APP_DIR = process.env.OWL_BENCH_NODEGOAT_DIR;
if (!APP_DIR) throw new Error("OWL_BENCH_NODEGOAT_DIR must point at the NodeGoat deployment");

// --- A09: structured logging. The original console functions are captured     //
// before the swap so the logger's sink cannot recurse.                         //
const rawLog = console.log.bind(console);
const logger = new SecurityLogger({ sink: (entry) => rawLog(JSON.stringify(entry)) });
const formatArgs = (args) =>
  args
    .map((arg) => {
      if (typeof arg === "string") return arg;
      try {
        return JSON.stringify(arg);
      } catch {
        return String(arg);
      }
    })
    .join(" ");
console.log = (...args) => logger.info("console.log", { message: formatArgs(args) });
console.error = (...args) => logger.error("console.error", { message: formatArgs(args) });

// --- RBAC: seeded users are numeric `_id`s, `isAdmin` decides the role -------- //
const rbac = new RBACManager();
rbac.defineRole("user", [
  "read:allocations",
  "read:memos",
  "write:memos",
  "read:profile",
  "update:profile",
  "read:contributions",
  "update:contributions",
  "read:dashboard"
]);
rbac.defineRole("admin", ["*"]);

const requireFromApp = createRequire(join(APP_DIR, "package.json"));
const { MongoClient } = requireFromApp("mongodb");
const MONGO_URL = process.env.MONGODB_URI || "mongodb://localhost:27017/nodegoat";
let databasePromise;
const appDatabase = () => {
  if (!databasePromise) {
    databasePromise = new Promise((resolve, reject) => {
      MongoClient.connect(MONGO_URL, (error, database) => (error ? reject(error) : resolve(database)));
    });
  }
  return databasePromise;
};
const rolesFor = async (userId) => {
  const database = await appDatabase();
  const user = await new Promise((resolve, reject) => {
    database.collection("users").findOne({ _id: userId }, (error, doc) => (error ? reject(error) : resolve(doc)));
  });
  if (!user) return null;
  return user.isAdmin ? ["admin"] : ["user"];
};

// --- Guards ------------------------------------------------------------------- //
const issueGuard = (req, res, next) => {
  if (!req.session || req.session.owlCsrf) return next();
  const { token, setCookie } = issueCsrfToken({ cookie: { secure: false } });
  req.session.owlCsrf = token;
  res.append("Set-Cookie", setCookie);
  return next();
};

const csrfGuard = async (req, res, next) => {
  try {
    await verifyCsrf(req, { getExpectedToken: async (request) => request.session?.owlCsrf ?? null });
    return next();
  } catch (error) {
    return next(error);
  }
};

const permissionGuard = (action, resource) => async (req, res, next) => {
  try {
    let session = null;
    if (req.session?.userId !== undefined && req.session?.userId !== null) {
      const roles = await rolesFor(req.session.userId);
      if (roles) session = { roles };
    }
    assertPermission({ session, action, resource }, { rbacManager: rbac });
    return next();
  } catch (error) {
    return next(error);
  }
};

const thresholdGuard = (req, res, next) => {
  try {
    assertValidInput({ threshold: req.query?.threshold }, { threshold: { type: "string", pattern: /^\d{1,3}$/ } });
    return next();
  } catch (error) {
    return next(error);
  }
};

const contributionsGuard = (req, res, next) => {
  try {
    assertValidInput(req.body, { preTax: { required: true, type: "string", pattern: /^\d{1,2}$/ } });
    return next();
  } catch (error) {
    return next(error);
  }
};

const memoGuard = (req, res, next) => {
  try {
    req.body = sanitizeFields(req.body, ["memo"], { sanitizer: new InputSanitizer("moderate") });
    return next();
  } catch (error) {
    return next(error);
  }
};

const guardsFor = (method, path) => {
  const guards = [];
  if (method === "get") {
    guards.push(issueGuard);
    if (path === "/benefits") guards.push(permissionGuard("read", "benefits"));
    if (path === "/allocations/:userId") guards.push(permissionGuard("read", "allocations"), thresholdGuard);
  }
  if (method === "post" && path === "/profile") guards.push(csrfGuard);
  if (method === "post" && path === "/contributions") guards.push(contributionsGuard);
  if (method === "post" && path === "/memos") guards.push(memoGuard);
  return guards;
};

hookExpress((app) => {
  app.use((req, res, next) => {
    res.set(securityHeaders());
    next();
  });
  prependRouteGuards(app, guardsFor);
});

// The app's error renderer (`app.use({ errorHandler })`, app/routes/index.js)
// is replaced: `require("./error").errorHandler` reads the property after this
// mutation, so every error - including route-guard SecurityErrors - is mapped
// by `toErrorResponse` instead of the HTML error template.
onModuleLoad(
  ({ resolved }) => resolved.endsWith("/app/routes/error.js"),
  (exports) => {
    if (exports.__owl) return exports;
    exports.__owl = true;
    exports.errorHandler = (error, req, res, next) => {
      if (res.headersSent) return next(error);
      logger.error("request.error", { message: String((error && error.message) || error), stack: String((error && error.stack) || "") });
      const mapped = toErrorResponse(error);
      res.status(mapped.status);
      res.set(mapped.headers);
      res.type("application/json");
      res.end(JSON.stringify(mapped.body));
    };
    return exports;
  }
);
