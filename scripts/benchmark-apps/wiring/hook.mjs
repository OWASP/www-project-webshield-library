// Module interception shared by the OWL wiring preloads (issue #54).
//
// The OWL-protected deployment of a pinned upstream app starts the unmodified
// upstream entry point with `node --import <wiring>.mjs <entry>`: no file of
// the app itself is patched. What the preload does instead is intercept
// `Module._load` before the app boots and installs OWL behavior where an
// adapter would sit:
//   1. the `express` factory is wrapped, so every app instance gets OWL
//      middleware as its FIRST layer and OWL guards PREPENDED to matching
//      routes (guards run after the app's own session/body middleware and
//      before the upstream handler);
//   2. selected modules (error renderers, coupon helpers) are replaced or
//      extended with OWL-controlled implementations.
import Module from "node:module";

const LOAD_PATCHES = [];
let hookInstalled = false;

function installLoadHook() {
  if (hookInstalled) return;
  hookInstalled = true;
  const originalLoad = Module._load;
  const replacements = new Map();
  Module._load = function (request) {
    const loaded = originalLoad.apply(this, arguments);
    if (LOAD_PATCHES.length === 0) return loaded;
    let resolved = "";
    try {
      resolved = Module._resolveFilename(request, arguments[1]);
    } catch {
      // Unresolvable requests (builtins, exotic parents) never match a patch.
    }
    for (const patch of LOAD_PATCHES) {
      if (!patch.match({ request, resolved })) continue;
      if (replacements.has(loaded)) return replacements.get(loaded);
      const replacement = patch.replace(loaded, { request, resolved });
      const next = replacement === undefined ? loaded : replacement;
      replacements.set(loaded, next);
      return next;
    }
    return loaded;
  };
}

/**
 * @param {(info: {request: string, resolved: string}) => boolean} match
 * @param {(exports: any, info: {request: string, resolved: string}) => any} replace
 *   return the replacement exports; mutating `exports` in place and returning
 *   nothing is supported for namespace objects whose consumers read properties
 *   at call time.
 */
export function onModuleLoad(match, replace) {
  installLoadHook();
  LOAD_PATCHES.push({ match, replace });
}

/** Wraps the `express` factory and calls `install(app)` once per instance. */
export function hookExpress(install) {
  onModuleLoad(
    ({ request }) => request === "express",
    (express) =>
      new Proxy(express, {
        apply(target, thisArg, args) {
          const app = Reflect.apply(target, thisArg, args);
          if (app && typeof app.use === "function" && !app.__owlInstalled) {
            app.__owlInstalled = true;
            install(app);
          }
          return app;
        }
      })
  );
}

const ROUTE_METHODS = ["get", "post", "put", "patch", "delete", "head"];

/**
 * Wraps every route-registration method on `app` so that
 * `guardsFor(method, path)` (an array of handlers, possibly empty) is
 * PREPENDED to matching routes. `app.get(name)` settings lookups (no handler
 * arguments) are passed through untouched.
 */
export function prependRouteGuards(app, guardsFor) {
  for (const method of ROUTE_METHODS) {
    const original = app[method].bind(app);
    app[method] = function (path, ...handlers) {
      if (handlers.length === 0) return original(path);
      const guards = guardsFor(method, path) || [];
      if (guards.length === 0) return original(path, ...handlers);
      return original(path, ...guards, ...handlers);
    };
  }
}
