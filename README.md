# RUGSCRIPTS

RUGSCRIPTS is a Robinhood Chain focused Web3 reverse engineering and security intelligence platform. The deployed scanner currently performs bounded static analysis of public webpage HTML and linked JavaScript. It identifies wallet methods, approval patterns, dynamic code generation, encoded payload signals, third-party scripts, domains, and URL references. It does not execute downloaded code.

- Official site: https://rugscripts.xyz (DNS currently needs the records in the domain section below)
- Production fallback: https://rugscript.vercel.app
- X: https://x.com/rugscripts
- Token ticker: $RUGSCRIPT

## Run locally

```sh
npm install
npm run dev
```

Open http://localhost:3000. The scanner endpoint accepts `POST /api/scan` with JSON `{ "url": "https://example.com" }`.

## Checks

```sh
npm run lint
npm run typecheck
npm run build
npm run check:scanner
# In a second terminal, after npm run dev
npm run check:visual
```

The Playwright visual check captures desktop/mobile screenshots in `/tmp` and checks computed styles, CSS loading, console errors, overflow, and a live example scan. The fixture check starts a harmless local HTTP page and passes a fixed-port test-only option directly to the scanner. The API never enables this option; scans reject local, private, reserved, and metadata destinations.

## Analysis and limits

- API results identify the engine as `static-html-js-v1`. A result does not include REA analysis.
- Downloaded code is treated as text and never executed.
- HTTP/HTTPS only; credentials are rejected. DNS answers and every redirect are checked, response sizes, script count, and per-request time are bounded.
- The MVP scans the document and up to 20 external JavaScript files (up to 500 KB each); HTML is limited to 1 MB. It does not execute a browser, inspect dynamically rendered DOM, follow modules/import graphs, or perform bytecode/chain analysis.
- Findings and the 0–100 score are heuristic indicators, not proof of a scam or a guarantee that a site is safe.
- The in-memory API throttle is best-effort and per process. A distributed deployment should add an edge or shared-store rate limit.

## REA integration status

REA means Reverse Engineer Anything. No REA toolkit, CLI, package, or documentation is installed in the available workspace, so no REA API or capability can be verified and no REA scans are claimed. REA-powered investigations are planned; current scans remain static and are explicitly attributed in the result.

Once the actual toolkit and supported interface are available, integration should keep it behind a separate analysis adapter. If REA needs a persistent browser or runtime inspection, run it in an isolated worker service (for example, Railway) with per-job time and resource limits, no application secrets, and restricted network egress. The worker must be isolated from the Vercel scanner and from other jobs. Its contract and execution model must follow REA's real documentation rather than an assumed API.

## Production domain

The existing Vercel project is `rugscript`; this deployment name remains unchanged. Vercel reports that the third-party DNS provider currently returns no A or CNAME records for the attached `rugscripts.xyz` and `www.rugscripts.xyz` names. Configure these records at the domain DNS provider, then run `vercel domains verify rugscripts.xyz` and `vercel domains verify www.rugscripts.xyz`:

| Type | Name | Value |
| --- | --- | --- |
| A | `@` | `216.198.79.1` |
| A | `@` | `64.29.17.1` |
| CNAME | `www` | `1280465b35ab236c.vercel-dns-017.com.` |

The currently working production fallback is `https://rugscript.vercel.app`. Keep it as the metadata base until the official domain resolves to the Vercel application.
