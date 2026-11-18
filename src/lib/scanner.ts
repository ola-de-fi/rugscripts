import dns from "node:dns/promises";
import { isIP } from "node:net";
import { Agent, fetch as undiciFetch } from "undici";

export type Severity = "Critical" | "High" | "Medium" | "Low" | "Info";
export type Finding = {
  id: string;
  severity: Severity;
  title: string;
  explanation: string;
  evidence: string;
  source: string;
  nextAction: string;
};
export type ScanResult = {
  url: string;
  completedAt: string;
  status: "complete";
  analysisEngine: "static-html-js-v1";
  riskScore: number;
  scoreType: "heuristic";
  scriptsAnalyzed: number;
  externalDomains: string[];
  apiEndpoints: string[];
  findings: Finding[];
  riskBreakdown: Record<Severity, number>;
};
const MAX_HTML = 1_000_000,
  MAX_SCRIPT = 500_000,
  MAX_SCRIPTS = 20,
  MAX_REDIRECTS = 4,
  TIMEOUT = 5000,
  DNS_TIMEOUT = 1800,
  TOTAL_TIMEOUT = 12000;
const denyHost = (hostname: string) => {
  const h = hostname
    .toLowerCase()
    .replace(/^\[|\]$/g, "")
    .replace(/\.$/, "");
  if (
    !h ||
    h === "localhost" ||
    h.endsWith(".localhost") ||
    h.endsWith(".local") ||
    h.endsWith(".internal") ||
    h === "metadata.google.internal"
  )
    return true;
  const ip = isIP(h);
  if (!ip) return false;
  if (ip === 4) {
    const [a, b, c] = h.split(".").map(Number);
    return (
      a === 0 ||
      a === 10 ||
      a === 127 ||
      a >= 224 ||
      (a === 100 && b! >= 64 && b! <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b! >= 16 && b! <= 31) ||
      (a === 192 && (b === 0 || b === 168)) ||
      (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100))) ||
      (a === 203 && b === 0 && c === 113)
    );
  }
  const normalized = h.toLowerCase();
  if (normalized.startsWith("::ffff:")) {
    const mapped = normalized.slice(7);
    if (isIP(mapped) === 4) return denyHost(mapped);
    const pieces = mapped.split(":");
    const last = parseInt(pieces.at(-1) || "0", 16);
    const prior = parseInt(pieces.at(-2) || "0", 16);
    return denyHost(`${prior >> 8}.${prior & 255}.${last >> 8}.${last & 255}`);
  }
  return (
    !/^2[0-9a-f]{0,3}:/.test(normalized) ||
    /^2001:db8:/.test(normalized) ||
    /^2002:/.test(normalized) ||
    /^2001:0:/.test(normalized)
  ); // only unreserved global-unicast 2000::/3 is permitted
};
type ScanOptions = { allowLocalFixture?: boolean };
async function safeUrl(
  raw: string,
  options: ScanOptions = {},
): Promise<{ url: URL; addresses: { address: string; family: number }[] }> {
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new Error("Enter a valid website URL.");
  }
  if (!["http:", "https:"].includes(u.protocol) || u.username || u.password)
    throw new Error(
      "Only public HTTP and HTTPS URLs without credentials are allowed.",
    );
  const localFixture =
    options.allowLocalFixture === true &&
    (u.hostname === "127.0.0.1" || u.hostname === "::1") &&
    u.port === "18761";
  if (denyHost(u.hostname) && !localFixture)
    throw new Error(
      "Private, local, and reserved network addresses are blocked.",
    );
  if (localFixture)
    return {
      url: u,
      addresses: [{ address: u.hostname, family: isIP(u.hostname) }],
    };
  const addresses = isIP(u.hostname)
    ? [{ address: u.hostname, family: isIP(u.hostname) }]
    : await Promise.race([
        dns.lookup(u.hostname, { all: true, verbatim: true }),
        new Promise<never>((_, reject) =>
          setTimeout(
            () =>
              reject(new Error("DNS lookup exceeded the scanner time limit.")),
            DNS_TIMEOUT,
          ),
        ),
      ]).catch(() => []);
  if (!addresses.length || addresses.some(({ address }) => denyHost(address)))
    throw new Error("The host did not resolve to a permitted public address.");
  return { url: u, addresses };
}
async function fetchBounded(
  raw: string,
  maxBytes: number,
  accept: string,
  deadline: number,
  options: ScanOptions,
) {
  let current = raw;
  for (let i = 0; i <= MAX_REDIRECTS; i++) {
    const { url: u, addresses } = await safeUrl(current, options);
    const remaining = deadline - Date.now();
    if (remaining <= 0)
      throw new Error("The scan exceeded its total time limit.");
    const controller = new AbortController();
    const timer = setTimeout(
      () => controller.abort(),
      Math.min(TIMEOUT, remaining),
    );
    let dispatcher: Agent | undefined;
    try {
      const lookup = (
        _hostname: string,
        options: { all?: boolean },
        callback: (...args: unknown[]) => void,
      ) => {
        if (options.all) callback(null, addresses);
        else callback(null, addresses[0].address, addresses[0].family);
      };
      dispatcher = new Agent({
        connect: { lookup: lookup as never },
        headersTimeout: Math.min(TIMEOUT, remaining),
        bodyTimeout: Math.min(TIMEOUT, remaining),
      });
      const response = await undiciFetch(u, {
        dispatcher,
        redirect: "manual",
        headers: {
          "user-agent": "RUGSCRIPTS-Scanner/1.0 (+static security analysis)",
          accept,
        },
        signal: controller.signal,
      });
      if ([301, 302, 303, 307, 308].includes(response.status)) {
        const location = response.headers.get("location");
        if (!location || i === MAX_REDIRECTS)
          throw new Error("Redirect limit reached or invalid redirect.");
        current = new URL(location, u).toString();
        await response.body?.cancel();
        continue;
      }
      if (!response.ok)
        throw new Error(`Target returned HTTP ${response.status}.`);
      const type = response.headers.get("content-type") || "";
      if (
        !type.includes("text/") &&
        !type.includes("javascript") &&
        !type.includes("json") &&
        !type.includes("xml")
      )
        throw new Error("Target response is not a readable text document.");
      const reader = response.body?.getReader();
      if (!reader) throw new Error("Target returned an empty response.");
      let size = 0,
        text = "";
      const decoder = new TextDecoder();
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        size += value.byteLength;
        if (size > maxBytes) {
          await reader.cancel();
          throw new Error("Target response exceeded the allowed size.");
        }
        text += decoder.decode(value, { stream: true });
      }
      text += decoder.decode();
      return { text, url: u };
    } finally {
      clearTimeout(timer);
      await dispatcher?.close();
    }
  }
  throw new Error("Could not safely fetch target.");
}
function evidence(text: string, regex: RegExp) {
  const m = regex.exec(text);
  if (!m) return "";
  const start = Math.max(0, m.index - 75),
    end = Math.min(text.length, m.index + (m[0]?.length || 1) + 75);
  return {
    snippet: text.slice(start, end).replace(/\s+/g, " ").slice(0, 220),
    match: m[0],
  };
}
function analyze(source: string, code: string, add: (f: Finding) => void) {
  const addPattern = (
    id: string,
    severity: Severity,
    title: string,
    regex: RegExp,
    explanation: string,
    nextAction: string,
  ) => {
    const ev = evidence(code, regex);
    if (ev)
      add({
        id: `${id}:${source}`,
        severity,
        title,
        explanation,
        evidence: ev.snippet,
        source,
        nextAction,
      });
  };
  addPattern(
    "eval",
    "High",
    "Dynamic code execution: eval() is present",
    /\beval\s*\(/,
    "eval() executes constructed code at runtime, making behavior harder to inspect and increasing injection risk.",
    "Inspect the call site and trace the exact value passed to eval().",
  );
  addPattern(
    "function",
    "Medium",
    "Dynamic code generation: Function constructor",
    /\bnew\s+Function\s*\(|\bFunction\s*\(/,
    "The Function constructor creates executable code from strings and can conceal runtime behavior.",
    "Review the generated string and whether it can be influenced by remote input.",
  );
  addPattern(
    "obfuscation",
    "Info",
    "Encoded string or decoder pattern",
    /(?:atob\s*\(|fromCharCode\s*\(|\\x[0-9a-f]{2})/i,
    "This source contains a string decoder or escaped-byte pattern. Such patterns are common in production bundles and are not suspicious by themselves.",
    "Treat this as context only; review it alongside behavior that could misuse the decoded value.",
  );
  const wallet = [
    ["eth_sign", /\beth_sign\b/i, "eth_sign signing request"],
    ["personal_sign", /\bpersonal_sign\b/i, "personal_sign request"],
    [
      "typed_data",
      /\beth_signTypedData(?:_v[0-9]+)?\b/i,
      "Typed-data signing request",
    ],
    [
      "permissions",
      /\bwallet_requestPermissions\b/i,
      "Wallet permission request",
    ],
    ["send_tx", /\beth_sendTransaction\b/i, "Transaction submission request"],
    [
      "set_approval",
      /\bsetApprovalForAll\b/i,
      "setApprovalForAll authorization",
    ],
    ["approve", /\.approve\s*\(|\bapprove\s*\(/i, "Token approval call"],
  ] as const;
  const present = wallet.filter(([, re]) => re.test(code));
  for (const [id, re, title] of present)
    addPattern(
      id,
      "Info",
      `Wallet capability detected: ${title}`,
      re,
      `${title} appears in the source. Wallet functionality is common in Web3 applications and this signal alone does not indicate malicious behavior.`,
      "Check the surrounding UI and transaction parameters before approving any request.",
    );
  const approval =
    /approve\s*\([^,]+,\s*(?:type\s*\(uint(?:256)?\)\.max|0x[fF]{8,}|[0-9]{30,})/i;
  addPattern(
    "unlimited_approval",
    "High",
    "Potential unlimited token approval",
    approval,
    "An approval amount resembles a maximum integer or an unusually large allowance, which can grant broad token spending authority.",
    "Confirm the spender, token, chain, and allowance amount. Prefer the smallest required allowance.",
  );
  if (
    present.some(([id]) =>
      [
        "eth_sign",
        "personal_sign",
        "typed_data",
        "permissions",
        "send_tx",
        "set_approval",
        "approve",
      ].includes(id),
    ) &&
    /https?:\/\//i.test(code)
  )
    addPattern(
      "wallet_external",
      "Medium",
      "Wallet capability combined with remote references",
      /https?:\/\/[^\s"'`<>]{4,}/i,
      "Wallet-related behavior and absolute remote references coexist in this source. This combination merits review but is not proof of abuse.",
      "Identify what remote data influences wallet requests and inspect request construction.",
    );
}
function collectReferences(
  code: string,
  domains: Set<string>,
  endpoints: Set<string>,
) {
  for (const match of code.matchAll(/https?:\/\/[^\s"'`<>]+/gi)) {
    try {
      const url = new URL(match[0].replace(/[),.;]+$/, ""));
      domains.add(url.hostname);
      if (url.pathname !== "/" || url.search)
        endpoints.add(url.origin + url.pathname);
    } catch {}
  }
}
function score(findings: Finding[]) {
  const weights: Record<Severity, number> = {
    Critical: 40,
    High: 22,
    Medium: 10,
    Low: 4,
    Info: 0,
  };
  const strongestByRule = new Map<string, Severity>();
  for (const finding of findings) {
    const rule = finding.id.split(":")[0];
    const prior = strongestByRule.get(rule);
    if (!prior || weights[finding.severity] > weights[prior])
      strongestByRule.set(rule, finding.severity);
  }
  const points = [...strongestByRule.values()].reduce(
    (sum, severity) => sum + weights[severity],
    0,
  );
  return Math.min(100, Math.round(100 * (1 - Math.exp(-points / 55))));
}
export async function scanWebsite(
  input: string,
  options: ScanOptions = {},
): Promise<ScanResult> {
  const deadline = Date.now() + TOTAL_TIMEOUT;
  const { url: requested } = await safeUrl(input, options);
  const { text: html, url: finalUrl } = await fetchBounded(
    requested.toString(),
    MAX_HTML,
    "text/html,application/xhtml+xml",
    deadline,
    options,
  );
  const findings: Finding[] = [];
  const apiEndpoints = new Set<string>();
  const add = (f: Finding) => {
    if (!findings.some((x) => x.id === f.id)) findings.push(f);
  };
  const scriptTags = [
    ...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi),
  ];
  const external: string[] = [];
  const domains = new Set<string>();
  for (const m of html.matchAll(/<script\b([^>]*)>/gi)) {
    const src = /\bsrc\s*=\s*(["'])(.*?)\1/i.exec(m[1] || "")?.[2];
    if (src) {
      try {
        const u = new URL(src, finalUrl);
        if (["http:", "https:"].includes(u.protocol)) {
          external.push(u.toString());
          domains.add(u.hostname);
        }
      } catch {}
    }
  }
  const links = [...html.matchAll(/\b(?:href|action)\s*=\s*(["'])(.*?)\1/gi)];
  for (const m of links) {
    try {
      const u = new URL(m[2], finalUrl);
      if (u.hostname !== finalUrl.hostname) domains.add(u.hostname);
    } catch {}
  }
  let scriptsAnalyzed = 0;
  for (const tag of scriptTags) {
    const attrs = tag[1] || "",
      body = tag[2] || "",
      src = /\bsrc\s*=\s*(["'])(.*?)\1/i.exec(attrs)?.[2];
    if (src) continue;
    if (!body.trim()) continue;
    scriptsAnalyzed++;
    analyze(`inline script ${scriptsAnalyzed}`, body, add);
    collectReferences(body, domains, apiEndpoints);
  }
  const externalScripts = external.slice(0, MAX_SCRIPTS);
  const unreadableScripts: string[] = [];
  for (let i = 0; i < externalScripts.length; i += 4) {
    const batch = await Promise.allSettled(
      externalScripts
        .slice(i, i + 4)
        .map(async (src) => ({
          src,
          ...(await fetchBounded(
            src,
            MAX_SCRIPT,
            "application/javascript,text/javascript,text/plain,*/*",
            deadline,
            options,
          )),
        })),
    );
    for (const item of batch) {
      if (item.status === "rejected") {
        unreadableScripts.push(externalScripts[i + batch.indexOf(item)]);
        continue;
      }
      const { text: code, url } = item.value;
      scriptsAnalyzed++;
      domains.add(url.hostname);
      analyze(url.toString(), code, add);
      collectReferences(code, domains, apiEndpoints);
    }
  }
  if (unreadableScripts.length)
    add({
      id: "unreadable_scripts",
      severity: "Info",
      title: "Some linked scripts could not be inspected",
      explanation: `${unreadableScripts.length} linked script${unreadableScripts.length === 1 ? "" : "s"} could not be fetched within the scanner's safety limits. They were not executed.`,
      evidence: unreadableScripts.slice(0, 5).join(" | "),
      source: finalUrl.toString(),
      nextAction:
        "Review these script URLs separately; this scan has incomplete script coverage.",
    });
  if (external.length > MAX_SCRIPTS)
    add({
      id: "script_limit",
      severity: "Low",
      title: "Script analysis limit reached",
      explanation: `The page references ${external.length} external scripts; only the first ${MAX_SCRIPTS} were fetched to bound scan resources.`,
      evidence: `${external.length} script URLs found`,
      source: finalUrl.toString(),
      nextAction: "Review the remaining script URLs separately.",
    });
  if (
    external.some((s) => {
      try {
        return new URL(s).hostname !== requested.hostname;
      } catch {
        return false;
      }
    })
  )
    add({
      id: "third_party_scripts",
      severity: "Low",
      title: "Third-party JavaScript loaded",
      explanation:
        "The page loads JavaScript from at least one host other than the website host. Third-party code runs with page privileges and expands the supply chain.",
      evidence: external
        .filter((s) => {
          try {
            return new URL(s).hostname !== requested.hostname;
          } catch {
            return false;
          }
        })
        .slice(0, 3)
        .join(" | "),
      source: finalUrl.toString(),
      nextAction:
        "Confirm each provider is expected and review its integrity and change controls.",
    });
  collectReferences(html, domains, apiEndpoints);
  const breakdown: Record<Severity, number> = {
    Critical: 0,
    High: 0,
    Medium: 0,
    Low: 0,
    Info: 0,
  };
  findings.forEach((f) => breakdown[f.severity]++);
  return {
    url: finalUrl.toString(),
    completedAt: new Date().toISOString(),
    status: "complete",
    analysisEngine: "static-html-js-v1",
    riskScore: score(findings),
    scoreType: "heuristic",
    scriptsAnalyzed,
    externalDomains: [...domains].slice(0, 50),
    apiEndpoints: [...apiEndpoints].slice(0, 50),
    findings,
    riskBreakdown: breakdown,
  };
}
