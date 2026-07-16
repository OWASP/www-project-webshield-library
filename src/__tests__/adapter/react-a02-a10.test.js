import React from "react";
import { describe, expect, test } from "@jest/globals";
import { act, render, renderHook, screen } from "@testing-library/react";
import {
  A02CryptoIntegrity,
  A03InjectionDefense,
  A04InsecureDesignGuard,
  A05SecurityMisconfiguration,
  A06VulnerableComponents,
  A08DataIntegrity,
  SecurityAlert,
  SecurityProvider,
  A09LoggingMonitoring,
  withSecurityHeaders,
  A10SSRFDefense
} from "../../adapters/react/index.js";

describe("React adapter A02-A10 hooks", () => {
  test("A02 useCryptoManager creates manager with working deriveKey", () => {
    const { result } = renderHook(() => A02CryptoIntegrity.useCryptoManager());
    const derived = result.current.deriveKey("password");
    expect(derived.key).toBeTruthy();
    expect(derived.salt).toBeTruthy();
  });

  test("A03 useInputSanitizer sanitizes malicious html", () => {
    const { result } = renderHook(() => A03InjectionDefense.useInputSanitizer("strict"));
    const cleaned = result.current.sanitizeHTML('<script>alert(1)</script><b>x</b>');
    expect(cleaned.includes("script")).toBe(false);
  });

  test("A04 useThreatModelGuard validates transitions", () => {
    const { result } = renderHook(() =>
      A04InsecureDesignGuard.useThreatModelGuard({ transitions: { draft: ["approved"] } })
    );
    expect(result.current.validateTransition("draft", "approved").valid).toBe(true);
  });

  test("A05 useHardeningReport returns findings for unsafe config", () => {
    const { result } = renderHook(() =>
      A05SecurityMisconfiguration.useHardeningReport({ debug: true, cors: { origin: "*" } })
    );
    expect(result.current.length).toBeGreaterThan(0);
  });

  test("A06 useDependencyRiskScanner runs scan", async () => {
    const provider = {
      scan: async () => [{ name: "pkg", severity: "high", fixedVersion: "2.0.0", currentVersion: "1.0.0" }]
    };
    const { result } = renderHook(() => A06VulnerableComponents.useDependencyRiskScanner(provider));

    await act(async () => {
      await result.current.runScan();
    });

    expect(result.current.results[0].package).toBe("pkg");
  });

  test("A06 useDependencyRiskScanner keeps a stable callback and exposes errors", async () => {
    const provider = {
      scan: async () => {
        throw new Error("scanner failed");
      }
    };
    const { result, rerender } = renderHook(({ currentProvider }) =>
      A06VulnerableComponents.useDependencyRiskScanner(currentProvider), {
      initialProps: { currentProvider: provider }
    });

    const firstRunScan = result.current.runScan;
    rerender({ currentProvider: provider });
    expect(result.current.runScan).toBe(firstRunScan);

    await act(async () => {
      await expect(result.current.runScan()).rejects.toThrow("scanner failed");
    });

    expect(result.current.error).toEqual(expect.objectContaining({ message: "scanner failed" }));
    expect(result.current.loading).toBe(false);
  });

  test("A08 useSecureHttpClient returns configured client", async () => {
    const fetchImpl = async () => ({
      ok: true,
      status: 200,
      headers: new Headers(),
      clone: () => ({ json: async () => ({ ok: true }) }),
      text: async () => ""
    });
    const { result } = renderHook(() =>
      A08DataIntegrity.useSecureHttpClient({ baseUrl: "https://api.example.com", fetchImpl })
    );
    const response = await result.current.request("/health", { method: "GET" });
    expect(response.ok).toBe(true);
  });

  test("A08 useSecureHttpClient supports async token providers", async () => {
    const fetchImpl = async (_url, options) => ({
      ok: true,
      status: 200,
      headers: new Headers(),
      clone: () => ({ json: async () => ({ headers: options.headers }) }),
      text: async () => ""
    });
    const { result } = renderHook(() =>
      A08DataIntegrity.useSecureHttpClient({
        baseUrl: "https://api.example.com",
        tokenProvider: async () => "token-async",
        fetchImpl
      })
    );

    const response = await result.current.request("/health", { method: "GET" });
    expect(response.data.headers.Authorization).toBe("Bearer token-async");
    expect(response.data.headers["X-CSRF-Token"]).toBeTruthy();
  });

  test("A08 withSecurityHeaders applies defaults without removing caller headers", () => {
    const headers = withSecurityHeaders({ headers: { "X-Request-Id": "req-1" } });
    expect(headers.headers["X-Content-Type-Options"]).toBe("nosniff");
    expect(headers.headers["X-Frame-Options"]).toBe("DENY");
    expect(headers.headers["X-Request-Id"]).toBe("req-1");
  });

  test("A09 useSecurityMonitoring reads provider context", () => {
    const wrapper = ({ children }) =>
      React.createElement(
        SecurityProvider,
        { logger: { info: () => {} }, events: { on: () => {} } },
        children
      );
    const { result } = renderHook(() => A09LoggingMonitoring.useSecurityMonitoring(), { wrapper });
    expect(result.current.logger).toBeTruthy();
  });

  test("A09 useSecurityMonitoring is safe without a provider", () => {
    const { result } = renderHook(() => A09LoggingMonitoring.useSecurityMonitoring());
    expect(result.current).toEqual({ logger: null, events: null });
  });

  test("A09 SecurityAlert renders as a presentational alert", () => {
    render(React.createElement(SecurityAlert, { level: "error", message: "Blocked request" }));
    const alert = screen.getByRole("alert");
    expect(alert.textContent).toBe("Blocked request");
    expect(alert.getAttribute("data-level")).toBe("error");
  });

  test("A10 useSafeFetcher enforces SSRF policy", async () => {
    const fetchImpl = async () => ({ ok: true });
    const { result } = renderHook(() => A10SSRFDefense.useSafeFetcher({}, fetchImpl));
    await expect(result.current.fetch("http://127.0.0.1/internal")).rejects.toThrow();
  });
});