# wpbugfinder — Wordfence-researcher-aware WordPress plugin bug finder

Automates fetching WordPress plugins from the official wordpress.org directory
and finding **real, evidence-backed signals that a bug exists** — with rules
modeled on the Wordfence Bug Bounty Program criteria so the findings map to
the bug classes, severity model and scope rules professional researchers use.

## How it decides something is a "real signal"

A finding is only emitted when **all** of the following hold:

1. **Attacker-reachable entry point** — the vulnerable callback is registered
   on a hook an attacker can hit: `wp_ajax_nopriv_*`, `wp_ajax_*`,
   `admin_post_*` / `admin_post_nopriv_*`, shortcode, a REST route without
   `permission_callback`, or a frontend hook (`init`, `template_redirect`,
   `the_content`, …).
2. **Taint flow** — request data (`$_GET/$_POST/$_REQUEST/$_COOKIE/$_FILES`,
   `php://input`, HTTP `$_SERVER` keys) propagates into a dangerous sink
   (`$wpdb->query`, `echo`, `unserialize`, `unlink`, `file_put_contents`,
   `wp_redirect`, `update_option`, `wp_remote_get`, `eval`, …) **without**
   sanitization (`esc_*`, `sanitize_*`, `intval`, `absint`, `$wpdb->prepare`,
   int casts, …).
3. **Wordfence scope** — each finding is scored with a true CVSS 3.1 base
   vector (privilege context drives the PR metric) and assessed against the
   program rules: out of scope when exploitation requires
   Administrator/Editor (`PR:H`), when install counts are below the 50-install
   threshold, etc. Vulnerabilities in EOL-software-only code paths are demoted
   (e.g. removed-PHP-API usage scores Low).

## Bug classes (Wordfence Intelligence taxonomy)

| Rule | Class | Typical Wordfence title pattern |
|---|---|---|
| `sqli` | SQL Injection (CWE-89) | "Unauthenticated Time-Based SQL Injection via …" |
| `xss` / `stored_xss` | Cross-Site Scripting (CWE-79) | "Authenticated (Contributor+) Stored Cross-Site Scripting" |
| `missing_authorization` | Missing Authorization (CWE-862) | "Missing Authorization to (Subscriber+) Arbitrary …" |
| `missing_nonce` | Missing Nonce Verification (CWE-352) | "CSRF via missing nonce check" |
| `object_injection` | PHP Object Injection (CWE-502) | "Unauthenticated PHP Object Injection" |
| `rce` | Remote Code Execution (CWE-94) | eval/system/exec with request data |
| `file_upload` | Arbitrary File Upload (CWE-434) | uploads without `wp_check_filetype_and_ext` |
| `file_read` / `file_write` / `file_deletion` | Path Traversal (CWE-22) | unlink/read/file_put_contents on request paths |
| `options_update` | Arbitrary Option Update (CWE-284) | attacker-controlled option names (siteurl/privilege escalation) |
| `shortcode_exec` | Arbitrary Shortcode Execution (CWE-94) | `do_shortcode($_GET[...])` |
| `open_redirect` | Open Redirect (CWE-601) | `wp_redirect($attacker_url)` |
| `ssrf` | SSRF (CWE-918) | `wp_remote_get($attacker_url)` |
| `deprecated_php` | removed/deprecated PHP & WP APIs (CWE-477, low) | fatal errors on modern PHP — compatibility signal |
| `hardening` | missing direct-access guard (low) | no `ABSPATH`/`WPINC` check |

## Install

Requires Python 3.10+. Postgres persistence needs Node.js for `prisma generate`.

```bash
pip install -r requirements.txt
python3 -m prisma generate            # generates the Prisma client
```

## Usage

```bash
# search the wordpress.org directory
./bin/wpbugfinder search "contact form" -n 10

# fetch one plugin (zip -> extracted into .wpbf-cache/plugins/<slug>/<version>)
./bin/wpbugfinder fetch duplicate-post

# scan one plugin (by slug, wordpress.org URL, or a local source dir)
./bin/wpbugfinder scan duplicate-post
./bin/wpbugfinder --min-severity high scan https://wordpress.org/plugins/updraftplus/
./bin/wpbugfinder --json findings.json --markdown report.md scan someplugin

# batch audit: fetch many plugins automatically and scan them all
./bin/wpbugfinder audit --search "woocommerce product table" --top 10
./bin/wpbugfinder audit --browse popular --top 25
./bin/wpbugfinder audit --slugs hello-dolly,akismet,duplicate-post
```

Options: `--min-severity {critical,high,medium,low}`, `--include-out-of-scope`
(show PR:H / off-bounty findings too), `--include-vendor`, `--json`, `--markdown`.

## Postgres persistence (Prisma)

```bash
export DATABASE_URL="postgresql://user:pass@localhost:5432/wpbugfinder"
./bin/wpbugfinder db-init                 # create tables (prisma db push)

./bin/wpbugfinder --db scan duplicate-post   # store every scan + finding
./bin/wpbugfinder audit --db --search "wp quiz" --top 20

./bin/wpbugfinder db-find --severity critical --rule sqli
./bin/wpbugfinder db-stats
```

Findings are stored with their Wordfence-style title, CVSS score/vector, CWEs,
attacker privilege context, taint path, snippet and bounty-scope assessment, so
you can query e.g. all stored in-scope Critical SQL Injections across the
plugins you audited.

### Schema

`Plugin` (slug, name, version, active installs) → `Scan` (files scanned,
counts) → `Finding` (rule, severity enum, CVSS score/vector, attacker context,
file:line, entry hook, taint path, in-scope flag). Sources: `prisma/schema.prisma`.

### Tests

```bash
python3 -m unittest discover -s tests -v
```

Generated Prisma clients are not committed (they bundle platform-specific
engine binaries). Before using `--db` or the DB tests, generate them:

```bash
python3 -m prisma generate                         # main Postgres client
WPBF_DB_MODE=test python3 -m prisma generate \
  --schema tests/prisma-test/schema.prisma         # sqlite twin for tests
```

## Layout

```
bin/wpbugfinder          CLI entry point
wpbugfinder/
  cli.py                 search / fetch / scan / audit / db-* commands
  fetch.py               wordpress.org search, metadata, zip download (zip-slip guarded)
  php.py                 PHP masker (strings/comments/HTML blanked, newlines kept)
  taint.py               sources → sanitizers → sinks taint engine
  context.py             hook → callback → attacker-privilege resolution
  criteria.py            Wordfence taxonomy, CVSS 3.1 calculator, scope rules
  finding.py             finding model (titles, vectors, scope assessment)
  detectors/
    sinks.py             taint-flow sink checks (SQLi, XSS, RCE, file ops, …)
    authorization.py     Missing Authorization / Capability Check / Nonce
    misc.py              file upload, deprecated APIs, hardening
  db.py                  Prisma async client wrapper
  report.py              console / JSON / Markdown reports
prisma/schema.prisma     Postgres schema
tests/                   fixture plugin + tests (sqlite twin client)
```

## Known limitations (documented blind spots)

- Second-order (stored) taint through the DB (`SELECT` → variable → output) is
  not traced cross-request; only direct request→sink flow is scored.
- SQLi that *requires* `wp_magic_quotes` disabled is nominally out of scope in
  the bounty program; static detection of this cannot be fully reliable.
- Callback resolution is name-based within a file; callbacks defined in other
  files are scanned for sinks but not linked to their entry point.
