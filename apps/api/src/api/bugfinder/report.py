"""Console / JSON / Markdown reporting with Wordfence-style sections."""

import json
from collections import Counter

from .criteria import SEVERITY_RANK


def summarize(results: dict, min_severity: str = "Low",
              include_out_of_scope: bool = True) -> dict:
    findings = results["findings"]
    if not include_out_of_scope:
        findings = [f for f in findings if f.in_scope]
    floor = SEVERITY_RANK.get(min_severity.title(), 1)
    findings = [f for f in findings if SEVERITY_RANK[f.severity] >= floor]
    return {**results, "findings": findings}


def to_console(results: dict) -> str:
    findings = results["findings"]
    inst = results.get("active_installs")
    head = f"### {results['plugin']}"
    if results.get("version"):
        head += f" {results['version']}"
    if inst is not None:
        head += f"  —  {inst:,} active installs"
    head += f"  —  {results['files_scanned']} PHP files scanned"
    lines = [head, ""]
    if not findings:
        lines.append("  No in-scope bug signals found.")
        return "\n".join(lines)
    by_sev = Counter(f.severity for f in findings)
    lines.append("  " + ", ".join(
        f"{sev}: {n}" for sev, n in by_sev.most_common()))
    lines.append("")
    for f in findings:
        lines.append("  " + f.row())
        if f.taint_path:
            lines.append(f"             taint: {' -> '.join(f.taint_path)}")
        if f.note:
            lines.append(f"             note: {f.note}")
        lines.append("")
    return "\n".join(lines)


def to_json(results: dict) -> str:
    return json.dumps({
        **{k: v for k, v in results.items() if k != "findings"},
        "findings": [f.to_dict() for f in results["findings"]],
    }, indent=2)


def to_markdown(results: dict) -> str:
    findings = results["findings"]
    inst = results.get("active_installs")
    md = [f"# Bug finder report — {results['plugin']}"
          + (f" {results['version']}" if results.get("version") else ""), ""]
    md.append(f"*Active installs:* {inst if inst is not None else 'unknown'}  ")
    md.append(f"*PHP files scanned:* {results['files_scanned']}  ")
    md.append(f"*Findings:* {len(findings)}")
    md.append("")
    md.append("| Severity | CVSS | Class (Wordfence taxonomy) | Location | "
              "Bounty scope |")
    md.append("|---|---|---|---|---|")
    for f in findings:
        loc = f"{f.file}:{f.line}"
        esc = lambda s: s.replace("|", "\\|")
        md.append(f"| {f.severity} | {f.score} | {esc(f.title)} | "
                  f"`{loc}` | {'✅' if f.in_scope else '—'} |")
    md.append("")
    md.append("## Details")
    md.append("")
    for f in findings:
        md.append(f"### {f.title} ({f.severity}, CVSS {f.score})")
        md.append("")
        md.append(f"- **File:** `{f.file}:{f.line}`")
        md.append(f"- **CWE:** {', '.join(f.cwes)}")
        md.append(f"- **CVSS vector:** `{f.vector}`")
        md.append(f"- **Bug-bounty scope:** {'in scope' if f.in_scope else 'out of scope'} — {f.scope_note}")
        if f.taint_path:
            md.append(f"- **Taint path:** `{' -> '.join(f.taint_path)}`")
        if f.note:
            md.append(f"- **Note:** {f.note}")
        md.append("")
        md.append("```php")
        md.append(f.snippet.strip()[:900])
        md.append("```")
        md.append("")
    return "\n".join(md)
