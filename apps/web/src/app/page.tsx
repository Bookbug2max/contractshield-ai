"use client";

import { useEffect, useRef, useState, type ChangeEvent, type FormEvent } from "react";
import Link from "next/link";

import { api } from "@/lib/api/client";

const MAX_SOURCE_LENGTH = 200_000;

function formatCount(value: number): string {
  return new Intl.NumberFormat("en-US").format(value);
}

type Severity = "high" | "medium" | "low";

type Finding = {
  rule_id: string;
  title: string;
  severity: Severity;
  category: string;
  line: number;
  description: string;
  recommendation: string;
  evidence: string;
};

type AnalysisResponse = {
  filename: string;
  analyzer: string;
  analysis_type: string;
  lines_of_code: number;
  result: "review_required" | "no_known_issues_found";
  findings_truncated: boolean;
  summary: { total: number; high: number; medium: number; low: number };
  findings: Finding[];
  limitations: string[];
};

type ApiState = "checking" | "connected" | "unavailable";

function ShieldMark() {
  return (
    <svg aria-hidden="true" viewBox="0 0 36 36" fill="none">
      <path d="M18 3.5 30 8v9.3c0 7.3-4.8 12.4-12 15.2C10.8 29.7 6 24.6 6 17.3V8l12-4.5Z" fill="currentColor" />
      <path d="m12.8 18.4 3.4 3.4 7.2-7.4" stroke="#14241E" strokeLinecap="round" strokeLinejoin="round" strokeWidth="2.5" />
    </svg>
  );
}

function apiErrorMessage(error: unknown): string {
  if (error instanceof Error) return error.message;
  return "The analysis request failed. Check the API and try again.";
}

export default function Home() {
  const fileInput = useRef<HTMLInputElement>(null);
  const [filename, setFilename] = useState("Contract.sol");
  const [source, setSource] = useState("");
  const [apiState, setApiState] = useState<ApiState>("checking");
  const [analysis, setAnalysis] = useState<AnalysisResponse | null>(null);
  const [error, setError] = useState("");
  const [isAnalyzing, setIsAnalyzing] = useState(false);

  useEffect(() => {
    api
      .get<{ status: string }>("/health")
      .then(() => setApiState("connected"))
      .catch(() => setApiState("unavailable"));
  }, []);

  async function handleFileChange(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    if (!file) return;
    setAnalysis(null);
    setError("");

    if (!file.name.toLowerCase().endsWith(".sol")) {
      setError("Choose a Solidity source file with a .sol extension.");
      event.target.value = "";
      return;
    }
    if (file.size > MAX_SOURCE_LENGTH) {
      setError("This file is larger than the 200 KB analysis limit.");
      event.target.value = "";
      return;
    }

    try {
      const text = await file.text();
      if (text.length > MAX_SOURCE_LENGTH) {
        setError("This file is larger than the 200 KB analysis limit.");
        event.target.value = "";
        return;
      }
      setFilename(file.name);
      setSource(text);
      setAnalysis(null);
      setError("");
    } catch {
      setError("The selected file could not be read. Choose another Solidity file.");
    }
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    setAnalysis(null);

    if (!source.trim()) {
      setError("Select a Solidity file or paste source code before starting the analysis.");
      return;
    }
    if (source.length > MAX_SOURCE_LENGTH) {
      setError("Source code must be 200 KB or smaller.");
      return;
    }

    setIsAnalyzing(true);
    try {
      const result = await api.post<AnalysisResponse>("/analysis/solidity", {
        filename,
        source,
      });
      setAnalysis(result);
    } catch (requestError) {
      setError(apiErrorMessage(requestError));
    } finally {
      setIsAnalyzing(false);
    }
  }

  function clearSource() {
    setFilename("Contract.sol");
    setSource("");
    setAnalysis(null);
    setError("");
    if (fileInput.current) fileInput.current.value = "";
  }

  return (
    <main className="app-shell">
      <header className="topbar">
        <Link aria-label="ContractShield home" className="brand" href="/">
          <span className="brand-mark"><ShieldMark /></span>
          <span className="brand-name">contract<span>shield</span></span>
        </Link>
        <div className="topbar-right">
          <span className={`api-indicator ${apiState}`}>
            <i />
            {apiState === "checking" && "Checking analysis service"}
            {apiState === "connected" && "Analysis service ready"}
            {apiState === "unavailable" && "Analysis service unavailable"}
          </span>
          <span className="product-label">SOLIDITY ANALYSIS</span>
        </div>
      </header>

      <section className="page-content">
        <div className="intro">
          <span className="eyebrow"><span /> SMART CONTRACT SECURITY</span>
          <h1>Review your contract.<br /><span>Know what to fix.</span></h1>
          <p>
            Analyze Solidity source for known risk patterns and get targeted recommendations
            based on the code you provide.
          </p>
        </div>

        <div className="analysis-layout">
          <form className="source-panel" onSubmit={handleSubmit}>
            <div className="panel-header">
              <div>
                <span className="step-label">CONTRACT SOURCE</span>
                <h2>Start a security review</h2>
              </div>
              <span className="file-type">.SOL</span>
            </div>

            <div className="file-row">
              <div className="selected-file">
                <span className="file-icon" aria-hidden="true">{"{}"}</span>
                <span className="file-copy">
                  <strong>{source ? filename : "No file selected"}</strong>
                  <small>{source ? "Solidity source ready for analysis" : "Choose a .sol file or paste source code"}</small>
                </span>
              </div>
              <input
                ref={fileInput}
                accept=".sol"
                aria-label="Choose Solidity source file"
                className="visually-hidden"
                onChange={handleFileChange}
                type="file"
              />
              <button className="secondary-button" onClick={() => fileInput.current?.click()} type="button">
                Choose file
              </button>
            </div>

            <label className="source-label" htmlFor="source-code">Or paste your source code</label>
            <textarea
              id="source-code"
              className="source-editor"
              maxLength={MAX_SOURCE_LENGTH}
              onChange={(event) => {
                setSource(event.target.value);
                setAnalysis(null);
                setError("");
              }}
              placeholder={"// Paste Solidity source here\n// The code is sent to your configured ContractShield API for analysis."}
              spellCheck={false}
              value={source}
            />
            <div className="editor-footer">
              <span>{formatCount(source.length)} / {formatCount(MAX_SOURCE_LENGTH)} characters</span>
              <span>Source is analyzed in memory and is not saved by this endpoint.</span>
            </div>

            {error && <p className="error-message" role="alert">{error}</p>}

            <div className="form-actions">
              <button className="clear-button" onClick={clearSource} type="button">Clear source</button>
              <button className="analyze-button" disabled={isAnalyzing || apiState !== "connected"} type="submit">
                {isAnalyzing ? <><span className="spinner" /> Analyzing source…</> : <>Analyze contract <span aria-hidden="true">→</span></>}
              </button>
            </div>
            {apiState === "unavailable" && (
              <p className="service-warning" role="status">
                Start the ContractShield API to analyze source. Your code has not been analyzed.
              </p>
            )}
          </form>

          <aside className="method-panel">
            <div className="method-icon"><ShieldMark /></div>
            <span className="step-label">HOW THIS WORKS</span>
            <h2>Recommendations tied to findings</h2>
            <p>
              ContractShield checks the submitted source for specific security patterns.
              Each result includes the matching line, why it may matter, and a remediation
              suggestion.
            </p>
            <div className="method-divider" />
            <div className="checks-title">CURRENT CHECKS</div>
            <ul className="checks-list">
              <li><span>01</span> tx.origin authorization</li>
              <li><span>02</span> delegatecall usage</li>
              <li><span>03</span> selfdestruct usage</li>
              <li><span>04</span> External call before later assignment</li>
            </ul>
            <div className="scope-note">
              <strong>Scope matters</strong>
              <p>This is limited static source screening, not a compiler-backed or complete security audit.</p>
            </div>
          </aside>
        </div>

        {analysis && (
          <section aria-live="polite" className="results-panel">
            <div className="results-header">
              <div>
                <span className="step-label">ANALYSIS RESULTS</span>
                <h2>{analysis.filename}</h2>
                <p>{formatCount(analysis.lines_of_code)} code lines inspected · {analysis.analyzer}</p>
              </div>
              <span className={`result-badge ${analysis.result}`}>
                <i />
                {analysis.result === "review_required" ? "Review findings" : "No known patterns found"}
              </span>
            </div>
            <div className="results-summary">
              <div><strong>{formatCount(analysis.summary.total)}</strong><span>Potential findings</span></div>
              <div><strong>{formatCount(analysis.summary.high)}</strong><span>High</span></div>
              <div><strong>{formatCount(analysis.summary.medium)}</strong><span>Medium</span></div>
              <div><strong>{formatCount(analysis.summary.low)}</strong><span>Low</span></div>
            </div>
            {analysis.findings_truncated && (
              <p className="truncation-note">The result was limited to the first 200 findings. Review the source with a full static-analysis tool.</p>
            )}
            {analysis.findings.length > 0 ? (
              <div className="finding-list">
                {analysis.findings.map((finding, index) => (
                  <article className="finding-card" key={`${finding.rule_id}-${finding.line}-${index}`}>
                    <div className="finding-heading">
                      <span className={`severity-tag ${finding.severity}`}>{finding.severity}</span>
                      <span className="finding-rule">{finding.rule_id}</span>
                      <span className="finding-category">{finding.category}</span>
                      <span className="finding-location">Line {finding.line}</span>
                    </div>
                    <h3>{finding.title}</h3>
                    <p className="finding-description">{finding.description}</p>
                    <pre className="evidence"><code>{finding.evidence || "(empty source line)"}</code></pre>
                    <div className="recommendation">
                      <strong>Recommendation</strong>
                      <p>{finding.recommendation}</p>
                    </div>
                    <div className="rule-note">Pattern match · Verify in contract context</div>
                  </article>
                ))}
              </div>
            ) : (
              <div className="empty-findings">
                <span className="empty-check" aria-hidden="true">✓</span>
                <div>
                  <strong>No implemented risk patterns were detected in this source.</strong>
                  <p>This does not establish that the contract is safe. The checks do not cover every vulnerability.</p>
                </div>
              </div>
            )}
            <details className="limitations">
              <summary>Analysis limitations</summary>
              <ul>{analysis.limitations.map((limitation) => <li key={limitation}>{limitation}</li>)}</ul>
            </details>
          </section>
        )}

        <footer className="page-footer">
          <span>ContractShield · Automated Solidity source review</span>
          <span>No source retention by this analysis endpoint</span>
        </footer>
      </section>
    </main>
  );
}
