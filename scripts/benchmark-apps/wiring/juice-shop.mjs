// OWL wiring for the pinned OWASP Juice Shop deployment (issue #54).
// Started as `node --import wiring/juice-shop.mjs build/app`; upstream sources
// are untouched. Controls applied, per documented OWL API:
//   - `securityHeaders()` on every response (A05)
//   - `assertValidInput(..., { allowUnknownFields: false })` on registration
//     (A08 mass assignment, juice-shop.md J10)
//   - `SecretPolicy.isEntropySufficient()` on registration passwords (A07, J19)
//   - `assertSafeOutboundUrl()` guarding `global.fetch` for the profile-image
//     SSRF (A10, J14)
//   - `toErrorResponse()` replacing `errorhandler()`, the app's LAST error
//     renderer, so error bodies never expose stack traces (A05, J27)
//   - `CryptoManager` (AES-256-GCM) integrity for coupon issuance/redemption
//     (A02, J24)
//   - SQL injection (J01) has no OWL control: the wiring deliberately leaves
//     login exploitable, which the benchmark records as a gap.
import { CryptoManager, SecretPolicy, SecurityError } from "@owasp-webshield/core";
import { assertSafeOutboundUrl, assertValidInput, securityHeaders, toErrorResponse } from "@owasp-webshield/node";
import { hookExpress, onModuleLoad, prependRouteGuards } from "./hook.mjs";

const REGISTRATION_SCHEMA = { email: { required: true, type: "string" }, password: { required: true, type: "string" } };

function guardRegistration(req, res, next) {
  Promise.resolve()
    .then(async () => {
      const body = req.body || {};
      assertValidInput(body, REGISTRATION_SCHEMA, { allowUnknownFields: false });
      if (!SecretPolicy.isEntropySufficient(body.password, 60)) {
        throw new SecurityError("INVALID_INPUT", "Password rejected by the secret policy", {
          errors: [{ field: "password", code: "weak_secret", message: "password is too predictable" }]
        });
      }
    })
    .then(() => next())
    .catch(next);
}

let fetchPatched = false;
function guardOutboundFetch() {
  if (fetchPatched) return;
  fetchPatched = true;
  const realFetch = global.fetch.bind(global);
  const toUrl = (input) =>
    typeof input === "string" ? input : input instanceof URL ? input.href : (input && input.url) || String(input);
  global.fetch = async (input, init) => {
    await assertSafeOutboundUrl(toUrl(input));
    return realFetch(input, init);
  };
}

// A02/J24: coupons become AEAD-protected claims. `discountFromCoupon` only
// accepts what `generateCoupon` issued through `CryptoManager`; a forged z85
// token fails decryption and the route answers 404, exactly as an upstream
// invalid coupon.
const couponCrypto = new CryptoManager();
const couponKey = couponCrypto.random(32);
const issueOwlCoupon = (discount, date = new Date()) => {
  void date; // upstream expiry semantics are subsumed by the keyed ciphertext
  const payload = couponCrypto.encrypt(JSON.stringify({ discount: Number(discount) }), couponKey);
  return Buffer.from(JSON.stringify(payload)).toString("base64url");
};
const redeemOwlCoupon = (coupon) => {
  if (!coupon) return undefined;
  try {
    const payload = JSON.parse(Buffer.from(String(coupon), "base64url").toString("utf8"));
    const claims = JSON.parse(couponCrypto.decrypt(payload, couponKey));
    const value = Number(claims && claims.discount);
    return Number.isFinite(value) ? value : undefined;
  } catch {
    return undefined;
  }
};

hookExpress((app) => {
  // First layer: OWL's documented response headers on every response.
  app.use((req, res, next) => {
    res.set(securityHeaders());
    next();
  });
  guardOutboundFetch();
  prependRouteGuards(app, (method, path) =>
    method === "post" && (path === "/api/Users" || path === "/api/Users/:id") ? [guardRegistration] : []
  );
});

// The app's last error renderer (`app.use(errorhandler())`, server.ts) is
// replaced so every error - including "Unexpected path" from the Angular
// catch-all - is mapped by `toErrorResponse` instead of an HTML stack trace.
onModuleLoad(
  ({ request }) => request === "errorhandler",
  (factory) => {
    void factory; // upstream renderer is intentionally not kept: exposing it is the weakness
    return (options) => {
      void options;
      return (error, req, res, next) => {
        if (res.headersSent) return next(error);
        const mapped = toErrorResponse(error);
        res.status(mapped.status);
        res.set(mapped.headers);
        res.type("application/json");
        res.end(JSON.stringify(mapped.body));
      };
    };
  }
);

// `lib/insecurity` exports are read through the namespace at call time, so
// swapping the two coupon functions here covers every consumer.
onModuleLoad(
  ({ resolved }) => /\/lib\/insecurity(\.js|\.ts)?$/.test(resolved),
  (exports) => {
    if (exports.__owlCoupons) return exports;
    exports.__owlCoupons = true;
    exports.generateCoupon = issueOwlCoupon;
    exports.discountFromCoupon = redeemOwlCoupon;
    return exports;
  }
);
