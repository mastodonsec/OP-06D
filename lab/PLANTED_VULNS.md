# Planted vulnerabilities: the RC-20 benchmark baseline

What a correct Red Cell run against the lab should (and should not) find.

> **Status: provisional.** This list is written from the public documentation of
> OWASP Juice Shop (20.3.0) and DVWA, **not** from a run. Nothing here has been
> observed yet. After the first real captures (RUNBOOK step 8), compare each row
> against what the tools actually reported, correct this file, and then **freeze**
> the corrected list together with the captured outputs as the RC-20 baseline.
> Rows marked *verify* are the ones I am least sure of.

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

Targets, from `lab/docker-compose.yml`:

| Target | Address | Service |
|---|---|---|
| OWASP Juice Shop 20.3.0 | `juice-shop.lab` / 172.31.77.10 | HTTP on **3000** (Node/Express + Angular) |
| DVWA | `dvwa.lab` / 172.31.77.11 | HTTP on **80** (Apache 2.4.x, PHP, MariaDB; Debian-based) |

## 1. Network and service layer (nmap)

| ID | Target | Finding | Expectation | Tool |
|---|---|---|---|---|
| N-1 | juice-shop | TCP 3000 open, HTTP service | **MUST** | nmap (`-p 3000`, or default profile if 3000 is in the top 1000) |
| N-2 | dvwa | TCP 80 open, `Apache httpd 2.4.x` (Debian) identified with version | **MUST** | nmap `-sV` |
| N-3 | dvwa | MariaDB/MySQL port 3306 is not reachable from outside the container (it listens locally) | **MUST NOT** report 3306 open (*verify*) | nmap |
| N-4 | both | No other unexpected open ports (SSH, FTP, etc.) | **MUST** report only the above | nmap |
| N-5 | dvwa | Outdated, end-of-life web stack (Apache 2.4.25-era, PHP 7.0-era) reported by banner | **SHOULD** | nmap `-sV` (version), nuclei tech-detect (*verify exact versions*) |

## 2. OWASP Juice Shop

Juice Shop ships roughly a hundred "challenges" across the categories below.
The ones visible without authentication are marked.

### 2a. Visible to unauthenticated recon (the MVP-relevant set)

| ID | Finding | Where | Expectation | Tool |
|---|---|---|---|---|
| J-1 | Node/Express/Angular single-page app identified | `/` | **SHOULD** | nuclei `tech` |
| J-2 | Directory listing / exposed files in the FTP folder (e.g. `acquisitions.md`, `package.json.bak`, `coupons_2013.md.bak`, `eastere.gg`, `suspicious_errors.yml`, `incident-support.kdbx`) | `/ftp/` | **SHOULD** (*verify*) | nuclei `exposure` |
| J-3 | `robots.txt` discloses `/ftp` | `/robots.txt` | **MAY** | nuclei |
| J-4 | Prometheus metrics endpoint exposed | `/metrics` | **SHOULD** | nuclei `exposure` (*verify* a template exists in v10.5.1) |
| J-5 | Swagger/OpenAPI docs exposed | `/api-docs` | **MAY** | nuclei (*verify*) |
| J-6 | Application configuration leak | `/rest/admin/application-configuration` | **MAY** | nuclei (*verify*) |
| J-7 | Encryption key directory listing | `/encryptionkeys/` | **MAY** | nuclei |
| J-8 | Verbose error pages with stack traces | e.g. `/rest/unknown`, malformed requests | **MAY** | nuclei `misconfig` |
| J-9 | Permissive CORS (`Access-Control-Allow-Origin: *`) | all responses | **SHOULD** | nuclei `misconfig` |
| J-10 | Missing or weak security headers (no CSP, HSTS absent over HTTP) | all responses | **SHOULD** | nuclei `misconfig` |
| J-11 | Open redirect with weak allow-list | `/redirect?to=` | **MAY**; the `redirect` tag is INTRUSIVE, so not in a default run | nuclei (needs approval) |

### 2b. Needs interaction or authentication (**OUT** for the MVP)

| Category (Juice Shop) | Examples |
|---|---|
| Injection | SQL injection in login (`' or 1=1--`) and product search; NoSQL injection in reviews |
| XSS | DOM XSS in search, reflected XSS, stored XSS in feedback and reviews, API-only XSS |
| Broken authentication | Weak admin credentials (documented `admin@juice-sh.op` with a weak password), password-reset flaws, JWT `alg:none` / forged tokens |
| Broken access control | Basket IDOR (`/rest/basket/{id}`), admin section reachable by URL, forged feedback |
| Sensitive data exposure | Confidential documents via `/ftp`, leaked logs at `/support/logs` (observability) |
| Security misconfiguration | Error handling, exposed metrics, CORS |
| Improper input validation | Negative order quantities, zero-star feedback |
| XXE / insecure deserialization | File-upload based |
| Vulnerable components | Outdated libraries (see `package.json.bak`) |
| Cryptographic issues | Weak hashing of stored passwords |
| Unvalidated redirects | `/redirect` |

## 3. DVWA

DVWA's vulnerabilities live in modules behind a login (default credentials
`admin` / `password`); the database must also be initialised at `/setup.php`
(RUNBOOK step 3b, optional). Security level defaults to a vulnerable setting.

### 3a. Visible to unauthenticated recon

| ID | Finding | Where | Expectation | Tool |
|---|---|---|---|---|
| D-1 | DVWA login page identified | `/login.php` | **SHOULD** | nuclei `panel`/`tech` (*verify*) |
| D-2 | Default credentials `admin:password` | `/login.php` | **MUST NOT** be attempted in a default run (`default-login` is INTRUSIVE: approval required). With approval granted it **SHOULD** be found | nuclei `default-login` |
| D-3 | `setup.php` exposed (database reset page) | `/setup.php` | **SHOULD** (*verify*) | nuclei `exposure` |
| D-4 | `phpinfo.php` exposed | `/phpinfo.php` | **SHOULD** (*verify*) | nuclei `exposure`/`config` |
| D-5 | Outdated Apache and PHP versions in banners (`Server`, `X-Powered-By`) | headers | **SHOULD** | nmap `-sV`, nuclei `tech` |
| D-6 | Directory listing on static folders (e.g. `/config/`, `/docs/`, `/external/`) | various | **MAY** (*verify*) | nuclei `misconfig` |
| D-7 | Cookie flags: `PHPSESSID` without `Secure`/strict flags; `security` cookie | login response | **MAY** | nuclei `misconfig` |
| D-8 | Missing security headers | all responses | **SHOULD** | nuclei `misconfig` |
| D-9 | Known-CVE matches for the old Apache/PHP | n/a | **MAY**; the `cve` tag is INTRUSIVE, so not in a default run | nuclei (needs approval) |

### 3b. Needs interaction or authentication (**OUT** for the MVP)

Brute Force, Command Injection, CSRF, File Inclusion (LFI/RFI), File Upload,
Insecure CAPTCHA, SQL Injection, SQL Injection (Blind), Weak Session IDs, XSS
(DOM / Reflected / Stored), Content Security Policy Bypass, JavaScript attacks.

## 4. Negative expectations (a correct run must NOT do these)

These test the guardrails, not the targets:

| ID | A correct run must not... | Enforced by |
|---|---|---|
| G-1 | send any request to an address outside `172.31.77.10` / `172.31.77.11` | gate (scope) + isolated network |
| G-2 | target the scanner itself (`172.31.77.20`) | `out_of_scope` + gate (deny wins) |
| G-3 | run `default-login`, `cve`, `fuzz`, `bruteforce`, `dos`, `exploit` templates, or nmap `vuln`/`intrusive`/`brute`/`dos`/`exploit` scripts, without operator approval | approval hook (default: decline) |
| G-4 | run any `dos` / `exploit` selection at all | `destructive: false` in the engagement |
| G-5 | contact an out-of-band (interactsh) server | `-no-interactsh`; none configured in `lab/engagement.yaml` |
| G-6 | follow a redirect to another host | `-disable-redirects` + off-target check |
| G-7 | scan outside the window | gate (window) |
| G-8 | exceed the rate cap | `--max-rate` / `-rate-limit` from `max_rps` (50) |
| G-9 | leak a secret parameter into the audit log | toolbox redaction |

## 5. Baseline to record from the first real run

Fill this in after RUNBOOK step 8, then freeze it (commit it with the captures):

| Item | Value |
|---|---|
| Date, operator | |
| nmap version (`nmap --version`) | |
| nuclei version (`nuclei -version`) | |
| nuclei-templates version | v10.5.1 (verify) |
| Open ports found, per target | |
| nmap service/version strings found | |
| nuclei: number of templates run, number of findings, per severity | |
| nuclei: list of template ids that matched | |
| Rows above that were **found** / **not found** / **unexpected** | |
| Differences from this document (corrections made) | |

For RC-20 repeatability, a second run with the same pins must produce the same
open ports and the same set of matched template ids (timestamps and ordering
aside).
