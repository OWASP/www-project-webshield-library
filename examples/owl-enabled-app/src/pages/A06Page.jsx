import React from "react";
import { useDependencyRiskScanner } from "@owl/react-adapter/a06-vulnerable-components/index.js";

const provider = {
  async scan() {
    return [
      { name: "left-pad", severity: "low", currentVersion: "1.0.0", fixedVersion: "1.1.0" },
      { name: "legacy-lib", severity: "high", currentVersion: "2.3.0", fixedVersion: "2.4.1" },
      { name: "jwt-old", severity: "critical", currentVersion: "0.9.0", fixedVersion: "1.2.0" }
    ];
  }
};

export default function A06Page() {
  const { results, loading, runScan } = useDependencyRiskScanner(provider);

  return (
    <>
      <section className="panel">
        <h2 className="panel-title">A06 Vulnerable and Outdated Components</h2>
        <p className="mt-2 text-sm text-slate-600">Run a dependency scan and block promotion by severity threshold.</p>
        <button className="btn mt-4" onClick={() => void runScan()} type="button">Run Dependency Scan</button>
      </section>
      <section className="panel">
        <h3 className="panel-title">Scan Findings</h3>
        {loading ? <p className="mt-3 text-sm">Scanning...</p> : null}
        {results.length > 0 ? <pre className="code-block mt-3">{JSON.stringify(results, null, 2)}</pre> : null}
      </section>
    </>
  );
}
