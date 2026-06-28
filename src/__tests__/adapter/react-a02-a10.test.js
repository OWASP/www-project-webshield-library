import React from "react";
import { describe, expect, test } from "@jest/globals";
import { act, renderHook } from "@testing-library/react";
import {
  A02CryptoIntegrity,
  A03InjectionDefense,
  A04InsecureDesignGuard,
  A05SecurityMisconfiguration,
  A06VulnerableComponents,
  A08DataIntegrity,
  SecurityProvider,
  A09LoggingMonitoring,
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

  test("A10 useSafeFetcher enforces SSRF policy", async () => {
    const fetchImpl = async () => ({ ok: true });
    const { result } = renderHook(() => A10SSRFDefense.useSafeFetcher({}, fetchImpl));
    await expect(result.current.fetch("http://127.0.0.1/internal")).rejects.toThrow();
  });
});