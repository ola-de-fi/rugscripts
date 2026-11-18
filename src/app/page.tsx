"use client";
import { FormEvent, useState } from "react";
import Image from "next/image";
type Finding = {
  id: string;
  severity: "Critical" | "High" | "Medium" | "Low" | "Info";
  title: string;
  explanation: string;
  evidence: string;
  source: string;
  nextAction: string;
};
type Result = {
  url: string;
  completedAt: string;
  status: string;
  analysisEngine: "static-html-js-v1";
  riskScore: number;
  scoreType: string;
  scriptsAnalyzed: number;
  externalDomains: string[];
  apiEndpoints: string[];
  findings: Finding[];
  riskBreakdown: Record<string, number>;
};
const caps = [
  [
    "01",
    "SCRIPT REVERSE ENGINEERING",
    "Inspect JavaScript source and identify suspicious functionality without executing it.",
  ],
  [
    "02",
    "WALLET THREAT ANALYSIS",
    "Investigate signing requests, token approvals, transaction construction, and wallet interaction patterns.",
  ],
  [
    "03",
    "FRONTEND INTELLIGENCE",
    "Discover external dependencies, referenced endpoints, and hidden frontend risks.",
  ],
  [
    "04",
    "REA INVESTIGATIONS · PLANNED",
    "Deeper, isolated reverse engineering is planned. REA is not connected to live scans yet.",
  ],
];
function XIcon({ className = "h-4 w-4" }: { className?: string }) {
  return (
    <svg
      aria-hidden="true"
      viewBox="0 0 24 24"
      fill="currentColor"
      className={className}
    >
      <path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817-5.97 6.817H1.677l7.73-8.835L1.254 2.25H9.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z" />
    </svg>
  );
}
const shareOnX = `https://x.com/intent/post?text=${encodeURIComponent(
  "I'm checking out RUGSCRIPTS — Web3 frontend reverse engineering and security intelligence. https://rugscripts.xyz",
)}`;
function severityColor(s: string) {
  return s === "Critical" || s === "High"
    ? "#ff563e"
    : s === "Medium"
      ? "#ffad55"
      : s === "Low"
        ? "#8eb6bd"
        : "#8c9599";
}
export default function Home() {
  const [url, setUrl] = useState(""),
    [loading, setLoading] = useState(false),
    [result, setResult] = useState<Result | null>(null),
    [error, setError] = useState("");
  async function submit(e: FormEvent) {
    e.preventDefault();
    setError("");
    setResult(null);
    setLoading(true);
    try {
      const r = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url }),
      });
      const data = await r.json();
      if (!r.ok) throw new Error(data.error || "Scan failed.");
      setResult(data);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Scan failed.");
    } finally {
      setLoading(false);
    }
  }
  return (
    <main>
      <header className="mx-auto flex max-w-7xl items-center justify-between px-6 py-6">
        <a
          href="#top"
          className="flex items-center gap-3 font-bold tracking-[.16em]"
        >
          <Image
            src="/branding/logo.svg"
            alt="RUGSCRIPTS"
            width={178}
            height={36}
            priority
            className="shrink-0"
          />
        </a>
        <nav className="flex items-center gap-1 text-sm text-[#aaa] sm:gap-8">
          <a href="#scanner" className="hover:text-white">
            Scanner
          </a>
          <a href="#how" className="hover:text-white">
            How it works
          </a>
          <a
            href="https://x.com/rugscripts"
            target="_blank"
            rel="noopener noreferrer"
            aria-label="Follow RUGSCRIPTS on X"
            title="Follow RUGSCRIPTS on X"
            className="flex items-center gap-2 hover:text-white"
          >
            <XIcon />
            <span className="hidden sm:inline">Follow on X</span>
          </a>
        </nav>
      </header>
      <section
        id="top"
        className="mx-auto max-w-7xl px-6 pb-16 pt-10 md:pb-20 md:pt-12"
      >
        <div className="mb-6 flex items-center gap-3 mono text-xs uppercase tracking-[.22em] text-[#ff745c]">
          <span className="h-px w-8 bg-[#ff4d35]" />
          Web3 frontend reverse engineering
        </div>
        <h1 className="max-w-5xl text-5xl font-black leading-[.98] tracking-[-.055em] md:text-7xl">
          EXPOSE THE SCRIPTS.
          <br />
          <span className="text-[#ff4d35]">BEFORE THEY EXPOSE YOU.</span>
        </h1>
        <p className="mt-7 max-w-2xl text-lg leading-8 text-[#a7abad]">
          Reverse-engineer Web3 websites. Uncover suspicious scripts, dangerous
          wallet interactions, and hidden frontend threats.
        </p>
        <form
          id="scanner"
          onSubmit={submit}
          className="mt-7 max-w-4xl border border-[#34383a] bg-[#101214] p-2 shadow-[0_20px_80px_#0008]"
        >
          <label className="sr-only" htmlFor="site-url">
            Website URL
          </label>
          <div className="flex flex-col gap-2 md:flex-row">
            <input
              id="site-url"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
              placeholder="Enter a website URL..."
              type="url"
              required
              className="min-w-0 flex-1 bg-transparent px-4 py-4 text-base outline-none placeholder:text-[#6c7376] mono"
            />
            <button
              disabled={loading}
              className="bg-[#ff4d35] px-7 py-4 text-sm font-bold tracking-[.12em] text-black transition hover:bg-[#ff785f] disabled:opacity-60"
            >
              {loading ? "ANALYZING…" : "SCAN WEBSITE"}
            </button>
          </div>
        </form>
        <a
          href="https://x.com/rugscripts"
          target="_blank"
          rel="noopener noreferrer"
          className="mt-5 inline-flex min-h-11 items-center gap-2 border border-[#34383a] px-4 py-3 mono text-xs tracking-[.12em] text-[#d2d6d6] transition hover:border-[#ff4d35] hover:text-white"
        >
          <XIcon />
          FOLLOW @RUGSCRIPTS
        </a>
        <div className="mt-3 flex flex-wrap gap-x-6 gap-y-2 mono text-[11px] uppercase tracking-wider text-[#757c7e]">
          <span>HTTP / HTTPS only</span>
          <span>NO SCRIPT EXECUTION</span>
          <span>NO WALLET CONNECTION</span>
        </div>
        {error && (
          <p role="alert" className="mt-4 text-sm text-[#ff7967]">
            {error}
          </p>
        )}
        {result && (
          <section
            className="mt-12 border border-[#313638] bg-[#0d0f10] p-5 md:p-8"
            aria-live="polite"
          >
            <div className="flex flex-wrap items-start justify-between gap-5 border-b border-[#292d2e] pb-6">
              <div>
                <div className="mono text-xs uppercase tracking-[.2em] text-[#ff765c]">
                  Scan complete ·{" "}
                  {new Date(result.completedAt).toLocaleString()}
                </div>
                <p className="mt-2 mono text-[10px] uppercase tracking-widest text-[#82898b]">
                  Analysis engine · {result.analysisEngine}
                </p>
                <h2 className="mt-3 break-all text-xl font-semibold">
                  {result.url}
                </h2>
                <p className="mt-2 mono text-xs text-[#848b8e]">
                  {result.scriptsAnalyzed} scripts analyzed ·{" "}
                  {result.externalDomains.length} external domains ·{" "}
                  {result.findings.length} findings
                </p>
              </div>
              <div className="min-w-32 border border-[#393d3e] px-5 py-3 text-center">
                <div
                  className="mono text-4xl font-bold"
                  style={{
                    color:
                      result.riskScore >= 55
                        ? "#ff563e"
                        : result.riskScore >= 25
                          ? "#ffad55"
                          : "#e4e7e6",
                  }}
                >
                  {result.riskScore}
                </div>
                <div className="mono text-[10px] uppercase tracking-[.15em] text-[#92989b]">
                  Heuristic risk / 100
                </div>
              </div>
            </div>
            <div className="grid gap-8 py-6 md:grid-cols-[1fr_2fr]">
              <div>
                <h3 className="mono text-xs uppercase tracking-widest text-[#a2a8aa]">
                  Risk breakdown
                </h3>
                <div className="mt-4 space-y-3">
                  {Object.entries(result.riskBreakdown).map(([s, n]) => (
                    <div key={s} className="flex justify-between mono text-xs">
                      <span style={{ color: severityColor(s) }}>{s}</span>
                      <span>{n}</span>
                    </div>
                  ))}
                </div>
                <h3 className="mt-8 mono text-xs uppercase tracking-widest text-[#a2a8aa]">
                  External domains
                </h3>
                <div className="mt-3 flex flex-wrap gap-2">
                  {result.externalDomains.map((d) => (
                    <span
                      key={d}
                      className="border border-[#303536] px-2 py-1 mono text-[10px] text-[#afb4b5]"
                    >
                      {d}
                    </span>
                  ))}
                </div>
              </div>
              <div>
                <h3 className="mono text-xs uppercase tracking-widest text-[#a2a8aa]">
                  Findings
                </h3>
                <div className="mt-3 space-y-2">
                  {result.findings.length === 0 ? (
                    <p className="border border-[#303536] p-4 text-sm text-[#aeb4b5]">
                      No configured patterns were detected in the inspected
                      source. This does not establish that the site is safe.
                    </p>
                  ) : (
                    result.findings.map((f) => (
                      <details
                        key={f.id}
                        className="group border border-[#303536] bg-[#101213]"
                      >
                        <summary className="flex cursor-pointer list-none items-center gap-3 p-4">
                          <span
                            className="mono text-[10px] uppercase"
                            style={{ color: severityColor(f.severity) }}
                          >
                            {f.severity}
                          </span>
                          <span className="flex-1 text-sm font-medium">
                            {f.title}
                          </span>
                          <span className="mono text-xs text-[#7d8587] group-open:rotate-45">
                            +
                          </span>
                        </summary>
                        <div className="space-y-3 border-t border-[#2a2f30] p-4 text-sm text-[#b1b7b8]">
                          <p>{f.explanation}</p>
                          <div>
                            <div className="mono text-[10px] uppercase tracking-widest text-[#777f81]">
                              Source · {f.source}
                            </div>
                            <pre className="mt-2 overflow-x-auto whitespace-pre-wrap break-words border border-[#282d2e] bg-black/30 p-3 mono text-xs text-[#d2b6ab]">
                              {f.evidence}
                            </pre>
                          </div>
                          <p>
                            <span className="text-white">Next action:</span>{" "}
                            {f.nextAction}
                          </p>
                        </div>
                      </details>
                    ))
                  )}
                </div>
              </div>
            </div>
            <div className="border-t border-[#292d2e] pt-5">
              <h3 className="mono text-xs uppercase tracking-widest text-[#a2a8aa]">
                Referenced API endpoints
              </h3>
              <div className="mt-3 flex flex-wrap gap-2">
                {result.apiEndpoints.length ? (
                  result.apiEndpoints.map((endpoint) => (
                    <span
                      key={endpoint}
                      className="max-w-full break-all border border-[#303536] px-2 py-1 mono text-[10px] text-[#afb4b5]"
                    >
                      {endpoint}
                    </span>
                  ))
                ) : (
                  <span className="text-xs text-[#81888a]">
                    No absolute API endpoint references found in inspected HTML.
                  </span>
                )}
              </div>
            </div>
            <p className="border-t border-[#292d2e] pt-4 text-xs leading-5 text-[#81888a]">
              RUGSCRIPTS provides heuristic frontend analysis, not proof of a
              scam or a guarantee that a website is safe. Server-side analysis
              does not execute downloaded scripts.
            </p>
            <a
              href={shareOnX}
              target="_blank"
              rel="noopener noreferrer"
              className="mt-4 inline-flex items-center gap-2 mono text-xs text-[#adb3b4] hover:text-white"
            >
              <XIcon />
              Share RUGSCRIPTS on X
            </a>
          </section>
        )}
      </section>
      <section className="border-y border-[#242829] bg-[#0c0e0f]">
        <div className="mx-auto grid max-w-7xl gap-0 px-6 md:grid-cols-2 xl:grid-cols-4">
          {caps.map(([n, title, body]) => (
            <article
              key={n}
              className="border-b border-[#242829] py-8 xl:border-b-0 xl:border-r xl:px-8 xl:py-10 first:xl:pl-0 last:xl:border-r-0"
            >
              <span className="mono text-xs text-[#ff674e]">
                {n} / CAPABILITY
              </span>
              <h2 className="mt-4 text-lg font-bold tracking-wide">{title}</h2>
              <p className="mt-2 max-w-sm text-sm leading-6 text-[#8f9698]">
                {body}
              </p>
            </article>
          ))}
        </div>
      </section>
      <section id="how" className="mx-auto max-w-7xl px-6 py-20">
        <div className="grid gap-12 md:grid-cols-[.8fr_1.2fr]">
          <div>
            <div className="mono text-xs uppercase tracking-[.2em] text-[#ff745c]">
              Method / 001
            </div>
            <h2 className="mt-5 text-4xl font-bold tracking-tight">
              Static inspection.
              <br />
              No execution.
            </h2>
          </div>
          <div className="space-y-5 text-sm leading-7 text-[#a3aaac]">
            <p>
              RUGSCRIPTS starts with a URL you submit, retrieves the public
              webpage and a bounded set of linked JavaScript resources, then
              searches that source for wallet APIs, approval patterns, dynamic
              code generation, and encoded payload signals.
            </p>
            <p>
              The scanner investigates those resources as text and returns
              categorized findings with technical evidence. Host validation,
              redirect checks, response size, script count, and time are
              bounded. Code is not executed, and no browser or wallet is
              launched.
            </p>
            <div className="border-l-2 border-[#ff4d35] py-1 pl-4 text-[#d3d6d6]">
              A wallet method is a capability, not a verdict. Context matters,
              and heuristic risk scores are indicators for further review.
            </div>
            <ol className="grid gap-3 pt-2 sm:grid-cols-2">
              {[
                "You submit a Web3 website URL.",
                "RUGSCRIPTS retrieves its page and linked frontend resources.",
                "Static analysis checks scripts and wallet-related patterns.",
                "You review categorized findings and their source evidence.",
              ].map((step, index) => (
                <li key={step} className="flex gap-3 text-sm text-[#c3c8c8]">
                  <span className="mono text-[#ff745c]">0{index + 1}</span>
                  {step}
                </li>
              ))}
            </ol>
            <p className="text-sm leading-6 text-[#8d9597]">
              REA (Reverse Engineer Anything) is not available in this
              deployment. Deeper REA investigations are planned as a separate,
              isolated capability and do not contribute to current scan results.
            </p>
            <a
              href="https://x.com/rugscripts"
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 text-sm text-[#d2d6d6] hover:text-white"
            >
              Follow our security research and project updates on X
              <XIcon />
            </a>
          </div>
        </div>
      </section>
      <footer className="border-t border-[#242829] px-6 py-7">
        <div className="mx-auto flex max-w-7xl flex-wrap justify-between gap-4 mono text-[10px] uppercase tracking-widest text-[#72797b]">
          <span>RUGSCRIPTS · $RUGSCRIPT</span>
          <span>Expose the scripts before they expose you.</span>
          <a
            href="https://x.com/rugscripts"
            target="_blank"
            rel="noopener noreferrer"
            className="inline-flex items-center gap-2 hover:text-white"
          >
            <XIcon />
            @rugscripts
          </a>
        </div>
      </footer>
    </main>
  );
}
