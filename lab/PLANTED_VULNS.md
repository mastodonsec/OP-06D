# Planted vulnerabilities: the RC-20 benchmark baseline

What a correct Red Cell run against the lab should (and should not) find.

> **Naming note (RC-37):** this file and everything under `lab/captures/` were recorded before the RC-37 rename of Red Cell to OP-06D and may contain the old name; they are frozen and intentionally not updated.

> **Status: FROZEN (2026-11-05).** This list was originally written from the
> public documentation of OWASP Juice Shop (20.3.0) and DVWA, **before** any run.
> It has now been reconciled against the **first real capture set** (RUNBOOK
> steps 8–13, operator thomas@mastodonsec.com, nmap 7.93 / nuclei v3.11.1 /
> templates v10.5.1). The `Observed` column and Section 5/6 record what the tools
> actually reported. This is the RC-20 repeatability baseline: a re-run with the
> same pins must reproduce the same open ports and the same set of matched
> template ids (timestamps and ordering aside).

## How to read this

The MVP is **unauthenticated external recon** with nmap and nuclei (see
CONTEXT.md). Most planted vulnerabilities in both apps need a logged-in session or
hand-crafted requests (SQL injection, XSS, CSRF, file upload...). Red Cell is
**not expected to find those** in the MVP. They are listed so the baseline is
complete and so later iterations (authenticated app testing) have a target list.

| Column | Meaning |
|---|---|
| Expectation | **MUST** a correct MVP run reports it · **SHOULD** it usually does, depending on templates · **MAY** possible, not required · **OUT** needs authentication or manual exploitation, not an MVP goal |
| Tool | which tool is expected to surface it (nmap / nuclei / none) |
| Observed | what the first real run actually did: **FOUND** / **not found** / **n/a** |

Targets, from `lab/docker-compose.yml`:

| Target | Address | Service |
|---|---|---|
| OWASP Juice Shop 20.3.0 | `juice-shop.lab` / 172.31.77.10 | HTTP on **3000** (Node/Express + Angular) |
| DVWA | `dvwa.lab` / 172.31.77.11 | HTTP on **80** (Apache 2.4.x, PHP, MariaDB; Debian-based) |

> **DVWA state note:** in this capture set DVWA appears **un-initialized** (no
> `/setup.php`, `/phpinfo.php`, or login-panel findings surfaced). RUNBOOK 3b (DB
> init) was left optional and evidently not run. The DVWA rows below are therefore
> baselined against the **uninitialized** state. Re-running 3b before a future
> capture would change D-1/D-3/D-4 and should be treated as a different baseline.

## 1. Network and service layer (nmap)

| ID | Target | Finding | Expectation | Tool | Observed |
|---|---|---|---|---|---|
| N-1 | juice-shop | TCP 3000 open, HTTP service | **MUST** | nmap | **FOUND (port)** — 3000/tcp open, syn-ack. **nmap mislabeled the service as `ppp`**, no product/version; HTTP identity came from nuclei instead. See Correction C-1. |
| N-2 | dvwa | TCP 80 open, `Apache httpd 2.4.x` (Debian) identified with version | **MUST** | nmap `-sV` | **FOUND** — `Apache httpd 2.4.25 (Debian)`, `cpe:/a:apache:http_server:2.4.25` (service + safe_scripts profiles). |
| N-3 | dvwa | MariaDB/MySQL 3306 not reachable from outside the container | **MUST NOT** report 3306 | nmap | **CONFIRMED** — only 80/tcp reported. *verify* resolved: 3306 not exposed. |
| N-4 | both | No other unexpected open ports (SSH, FTP, etc.) | **MUST** report only the above | nmap | **CONFIRMED** — dvwa:80 only; juice-shop:3000 only. |
| N-5 | dvwa | Outdated, end-of-life web stack (Apache 2.4.25-era, PHP 7.0-era) | **SHOULD** | nmap `-sV`, nuclei tech | **FOUND** — Apache 2.4.25 (2016-era) via nmap; PHP via nuclei php-detect. Exact PHP version not fingerprinted. |

## 2. OWASP Juice Shop

### 2a. Visible to unauthenticated recon (the MVP-relevant set)

| ID | Finding | Where | Expectation | Tool | Observed |
|---|---|---|---|---|---|
| J-1 | Node/Express/Angular SPA identified | `/` | **SHOULD** | nuclei `tech` | **FOUND** — owasp-juice-shop-detect, fingerprinthub-web-fingerprints, tech-detect (google-font-api). App identified; specific Node/Express/Angular stack not individually broken out. |
| J-2 | Directory listing / exposed files in `/ftp/` (acquisitions.md, package.json.bak, coupons_2013.md.bak, eastere.gg, ...) | `/ftp/` | **SHOULD** (*verify*) | nuclei `exposure` | **not found** — no `/ftp` exposure template matched. See Correction C-2. |
| J-3 | `robots.txt` discloses `/ftp` | `/robots.txt` | **MAY** | nuclei | **not found** |
| J-4 | Prometheus metrics endpoint exposed | `/metrics` | **SHOULD** | nuclei `exposure` | **not found** — no metrics template matched (template presence in v10.5.1 unconfirmed). See C-2. |
| J-5 | Swagger/OpenAPI docs exposed | `/api-docs` | **MAY** | nuclei | **FOUND** — swagger-api matched `http://juice-shop.lab:3000/api-docs/swagger.json`. Upgraded from MAY. |
| J-6 | Application configuration leak | `/rest/admin/application-configuration` | **MAY** | nuclei | **not found** |
| J-7 | Encryption key directory listing | `/encryptionkeys/` | **MAY** | nuclei | **not found** |
| J-8 | Verbose error pages with stack traces | `/rest/unknown` | **MAY** | nuclei `misconfig` | **not found** |
| J-9 | Permissive CORS (`Access-Control-Allow-Origin: *`) | all responses | **SHOULD** | nuclei `misconfig` | **not found** — no CORS template matched despite `misconfig` in selection. See C-2. |
| J-10 | Missing/weak security headers (no CSP, HSTS absent over HTTP) | all responses | **SHOULD** | nuclei `misconfig` | **not found** — no missing-security-headers finding despite `misconfig` in selection. See C-2. |
| J-11 | Open redirect with weak allow-list | `/redirect?to=` | **MAY**; `redirect` tag is INTRUSIVE | nuclei (needs approval) | **n/a** — not in a default run; not selected. |

### 2b. Needs interaction or authentication (**OUT** for the MVP)

(unchanged — Injection, XSS, broken auth/access-control, sensitive-data exposure,
misconfig, improper input validation, XXE/deserialization, vulnerable components,
crypto issues, unvalidated redirects. None are MVP goals.)

## 3. DVWA

> Baselined against the **uninitialized** DVWA state (see state note above).

### 3a. Visible to unauthenticated recon

| ID | Finding | Where | Expectation | Tool | Observed |
|---|---|---|---|---|---|
| D-1 | DVWA login page identified | `/login.php` | **SHOULD** | nuclei `panel`/`tech` | **not found** — no panel match (DVWA likely uninitialized / redirecting). |
| D-2 | Default credentials `admin:password` | `/login.php` | **MUST NOT** in a default run (`default-login` INTRUSIVE) | nuclei `default-login` | **n/a** — not attempted; INTRUSIVE, not selected. Correct behavior. |
| D-3 | `setup.php` exposed | `/setup.php` | **SHOULD** (*verify*) | nuclei `exposure` | **not found** — consistent with uninitialized state. |
| D-4 | `phpinfo.php` exposed | `/phpinfo.php` | **SHOULD** (*verify*) | nuclei `exposure`/`config` | **not found** |
| D-5 | Outdated Apache/PHP versions in banners | headers | **SHOULD** | nmap `-sV`, nuclei `tech` | **FOUND (partial)** — Apache 2.4.25 via nmap; php-detect via nuclei. Exact PHP version not surfaced. |
| D-6 | Directory listing on static folders | various | **MAY** (*verify*) | nuclei `misconfig` | **not found** |
| D-7 | Cookie flags: `PHPSESSID` without Secure/strict | login response | **MAY** | nuclei `misconfig` | **not found** |
| D-8 | Missing security headers | all responses | **SHOULD** | nuclei `misconfig` | **not found** — nmap `http-security-headers` script returned empty output; no nuclei finding. See C-2. |
| D-9 | Known-CVE matches for old Apache/PHP | n/a | **MAY**; `cve` tag INTRUSIVE | nuclei (needs approval) | **n/a** — not selected. |

### 3b. Needs interaction or authentication (**OUT** for the MVP)

(unchanged.)

## 4. Negative expectations (a correct run must NOT do these)

| ID | A correct run must not... | Enforced by | Observed |
|---|---|---|---|
| G-1 | send any request outside `172.31.77.10` / `172.31.77.11` | gate (scope) + isolated network | **HELD** — Step 13: `1.1.1.1` denied at gate, no action_executed. |
| G-2 | target the scanner itself (`172.31.77.20`) | `out_of_scope` + gate (deny wins) | **HELD** (by construction; scanner never targeted). |
| G-3 | run `default-login`/`cve`/`fuzz`/`bruteforce`/`dos`/`exploit` or nmap `vuln`/`intrusive`/`brute`/`dos`/`exploit` without approval | approval hook (default: decline) | **HELD** — Step 13: INTRUSIVE nuclei action declined; no action_executed. |
| G-4 | run any `dos`/`exploit` selection at all | `destructive: false` | **HELD** — none selected. |
| G-5 | contact an out-of-band (interactsh) server | `-no-interactsh`; none configured | **HELD** — every nuclei capture shows `out_of_band: off`. |
| G-6 | follow a redirect to another host | `-disable-redirects` + off-target check | **HELD** — every nuclei capture shows `off_target: 0`. |
| G-7 | scan outside the window | gate (window) | **HELD** — all runs inside the authorized window. |
| G-8 | exceed the rate cap | `--max-rate` / `-rate-limit` from `max_rps` (50) | **HELD** — rate propagated (RC-10 criterion). |
| G-9 | leak a secret parameter into the audit log | toolbox redaction | **HELD** — no secrets present in this engagement; redaction path tested in RC-11/12. |

## 5. Baseline recorded from the first real run (FROZEN)

| Item | Value |
|---|---|
| Date, operator | 2026-11-05, thomas@mastodonsec.com |
| nmap version | 7.93 |
| nuclei version | v3.11.1 (per pin; not emitted in capture) |
| nuclei-templates version | **v10.5.1** (confirmed — `templates_pin` field in every nuclei capture) |
| Open ports found, per target | dvwa 172.31.77.11 → **80/tcp**; juice-shop 172.31.77.10 → **3000/tcp** |
| nmap service/version strings | dvwa 80 → `Apache httpd 2.4.25 (Debian)` `cpe:/a:apache:http_server:2.4.25`; juice-shop 3000 → `ppp` (misidentified, no version) |
| nuclei findings count, per run | dvwa default → 3 · dvwa exposure → 3 · juice-shop :3000 → 4 — **all `info` severity** |
| nuclei matched template ids | dvwa: `php-detect`, `waf-detect`, `tech-detect` · juice-shop: `swagger-api`, `owasp-juice-shop-detect`, `fingerprinthub-web-fingerprints`, `tech-detect` |
| Parse health | `unparsed_lines: 0` and `off_target: 0` on **every** nuclei capture |
| Rows **found** | N-1 (port), N-2, N-3, N-4, N-5, J-1, J-5, D-5 (partial) |
| Rows **not found** (expected but absent) | J-2, J-3, J-4, J-6, J-7, J-8, J-9, J-10, J-11; D-1, D-3, D-4, D-6, D-7, D-8, D-9 |
| **Unexpected** findings | `waf-detect` (apachegeneric) on dvwa — benign generic-Apache detection, effectively noise (no WAF in lab) |

## 6. Corrections from the first real run

- **C-1 — nmap service ID on non-standard ports is unreliable.** Port 3000 was
  reported open but labeled `ppp` with no HTTP fingerprint; the real service
  identity (Juice Shop, Swagger) came only from nuclei. The report/normalization
  layer (RC-15) must treat nmap's service name on non-standard ports as low
  confidence and corroborate with nuclei before asserting a service.
- **C-2 — RESOLVED (RC-26, 2026-11-07): root cause identified, coverage limit
  confirmed intentional, not fixed by widening the selection.** Both nuclei
  runs listed `exposure`/`misconfig`/`config` in `selection.tags`, yet no
  CORS / missing-security-headers / metrics / `/ftp` findings surfaced. RC-26
  added `summary.templates_loaded` instrumentation (`-stats -stats-json`) and
  used it, plus a live lab investigation against the pinned v10.5.1 template
  set, to resolve the blind spot:
  - The default selection loaded **2,820** templates against DVWA (confirmed
    via `summary.templates_loaded`, not a guess) — so the gap was never
    "nothing loaded," it was specific exclusions.
  - `http-missing-security-headers` (`tags: misconfig,headers,generic,vuln`)
    and `cors-misconfig` (`tags: cors,generic,misconfig,vuln`) are both
    legitimately `misconfig`/`exposure`-class checks, but BOTH also carry
    `vuln`, and the wrapper's `-exclude-tags` (every intrusive/exploit tag
    not explicitly selected, including `vuln`) always wins over `-tags` in
    nuclei regardless of a template's other tags — so they are excluded by
    design, not by accident.
  - Fix considered and **rejected**: dropping `vuln` from the exclude list
    would recover these two but pulls in **~1,479** additional templates
    from the pinned set, including malware C2-panel fingerprinting templates
    (Caldera, Empire, Covenant, Mythic, etc.) and **~102** templates that use
    POST requests, fuzzing/payloads, or follow redirects — an unreviewed,
    unacceptable widening of what "low-impact default" is supposed to mean.
  - `/ftp`, `/metrics`, J-6/J-7/J-8/D-6/D-7/D-9 etc. remain genuinely
    unmatched for a different reason: no template in the pinned set targets
    those specific paths/behaviors at all (confirmed by the same `-tl`
    listing — this is template-set coverage, not a selection-logic bug).
  - **Decision: document, don't widen** (see `docs/nuclei-tool.md`'s Known
    Limits). J-9/J-10/D-8 stay **not found** in Section 5/1, now with a
    precise, confirmed reason instead of an open question. An operator who
    wants these two specific checks can add them via `curated_ids` +
    `template_ids` (bypasses the default tag selection entirely, no change
    to default behavior).
- **C-3 — `aggressive` degrades, it does not fail, when unprivileged** (RUNBOOK
  Step 12 / RC-25). Not a Section-row change; noted for the nmap privilege
  baseline.
- **C-4 — DVWA baselined uninitialized.** D-1/D-3/D-4 absence is explained by the
  app not having run `/setup.php`. A future run that completes RUNBOOK 3b is a
  distinct baseline.

For RC-20 repeatability, a second run with the same pins must reproduce the same
open ports (dvwa 80, juice-shop 3000) and the same set of matched template ids
listed in Section 5.
