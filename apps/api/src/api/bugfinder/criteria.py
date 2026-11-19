"""Wordfence-researcher-aware criteria model.

Encodes the Wordfence Bug Bounty Program rules as of its public documentation:
 - Vulnerability classes named the way Wordfence Intelligence names them
 - CVSS v3.1 base score computation (FIRST spec)
 - Scope rules: out of scope when exploitation requires Administrator/Editor
   level permissions (CVSS PR:H), is EOL-software dependent, or depends on
   wp_magic_quotes being disabled.
 - Active-install-count thresholds used by the program.
"""

import math
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# CVSS v3.1 (base metric group)
# ---------------------------------------------------------------------------

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_PR_U = {"N": 0.85, "L": 0.62, "H": 0.27}
_PR_C = {"N": 0.85, "L": 0.68, "H": 0.5}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(x: float) -> float:
    return math.ceil(round(x * 10.0, 5)) / 10.0


def cvss31(vector: str) -> float:
    """Compute a CVSS 3.1 base score from a vector string like
    'AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H'."""
    m = dict(part.split(":", 1) for part in vector.split("/"))
    av, ac, pr, ui = _AV[m["AV"]], _AC[m["AC"]], m["PR"], _UI[m["UI"]]
    c, i, a = _CIA[m["C"]], _CIA[m["I"]], _CIA[m["A"]]
    s = m.get("S", "U")
    iss = 1.0 - (1.0 - c) * (1.0 - i) * (1.0 - a)
    if s == "U":
        impact = 6.42 * iss
        prv = _PR_U[pr]
    else:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
        prv = _PR_C[pr]
    if impact <= 0:
        return 0.0
    expl = 8.22 * av * ac * prv * ui
    score = impact + expl
    if s == "C":
        score = min(1.08 * score, 10.0)
    return _roundup(score)


def severity_of(score: float) -> str:
    if score == 0.0:
        return "None"
    if score < 4.0:
        return "Low"
    if score < 7.0:
        return "Medium"
    if score < 9.0:
        return "High"
    return "Critical"


# ---------------------------------------------------------------------------
# Attacker context (mirrors Wordfence titles like
# "Authenticated (Contributor+) Stored Cross-Site Scripting")
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class AttackerContext:
    privilege: str          # 'unauthenticated' | 'subscriber' | 'contributor' | 'author' | 'admin'
    vector_pr: str          # CVSS PR letter
    label: str              # Wordfence-style label used in titles

    def title_prefix(self) -> str:
        if self.privilege == "unauthenticated":
            return "Unauthenticated"
        return f"Authenticated ({self.label})"


UNAUTHENTICATED = AttackerContext("unauthenticated", "N", "Unauthenticated")
SUBSCRIBER = AttackerContext("subscriber", "L", "Subscriber+")
CONTRIBUTOR = AttackerContext("contributor", "L", "Contributor+")
AUTHOR = AttackerContext("author", "L", "Author+")
ADMIN = AttackerContext("admin", "H", "Administrator+")


# ---------------------------------------------------------------------------
# Vulnerability classes (Wordfence Intelligence naming)
# ---------------------------------------------------------------------------

@dataclass
class VulnClass:
    key: str
    name: str                       # Wordfence-style type name
    cwes: tuple = field(default_factory=tuple)
    # base CVSS vector with {PR} placeholder replaced per attacker context
    vector: str = "AV:N/AC:L/PR:{PR}/UI:N/S:U/C:L/I:L/A:N"
    severity_floor: str = None
    needs_taint: bool = True
    # does this class produce "considerable impact" (bounty relevant)?
    considerable_impact: bool = True


VULN_CLASSES = {
    "sqli": VulnClass("sqli", "SQL Injection", ("CWE-89",),
                      "AV:N/AC:L/PR:{PR}/UI:N/S:U/C:H/I:H/A:H"),
    "xss": VulnClass("xss", "Cross-Site Scripting", ("CWE-79",),
                     "AV:N/AC:L/PR:{PR}/UI:R/S:C/C:L/I:L/A:N"),
    "stored_xss": VulnClass("stored_xss", "Stored Cross-Site Scripting", ("CWE-79",),
                            "AV:N/AC:L/PR:{PR}/UI:N/S:C/C:L/I:L/A:N"),
    "missing_authorization": VulnClass(
        "missing_authorization", "Missing Authorization", ("CWE-862",),
        "AV:N/AC:L/PR:{PR}/UI:N/S:U/C:H/I:H/A:H", needs_taint=False),
    "missing_capability": VulnClass(
        "missing_capability", "Missing Capability Check", ("CWE-862",),
        "AV:N/AC:L/PR:{PR}/UI:N/S:U/C:H/I:H/A:H", needs_taint=False),
    "missing_nonce": VulnClass(
        "missing_nonce", "Missing Nonce Verification", ("CWE-352",),
        "AV:N/AC:L/PR:{PR}/UI:N/S:U/C:L/I:H/A:N", needs_taint=False),
    "object_injection": VulnClass(
        "object_injection", "PHP Object Injection", ("CWE-502",),
        "AV:N/AC:L/PR:{PR}/UI:N/S:U/C:H/I:H/A:H"),
    "rce": VulnClass("rce", "Remote Code Execution", ("CWE-94",),
                     "AV:N/AC:L/PR:{PR}/UI:N/S:U/C:H/I:H/A:H"),
    "file_upload": VulnClass(
        "file_upload", "Arbitrary File Upload", ("CWE-434",),
        "AV:N/AC:L/PR:{PR}/UI:N/S:U/C:H/I:H/A:H", needs_taint=False),
    "file_read": VulnClass("file_read", "Path Traversal / Arbitrary File Read",
                           ("CWE-22", "CWE-200"),
                           "AV:N/AC:L/PR:{PR}/UI:N/S:U/C:H/I:N/A:N"),
    "file_write": VulnClass("file_write", "Arbitrary File Write", ("CWE-22",),
                            "AV:N/AC:L/PR:{PR}/UI:N/S:U/C:N/I:H/A:H"),
    "file_deletion": VulnClass("file_deletion", "Arbitrary File Deletion", ("CWE-22",),
                               "AV:N/AC:L/PR:{PR}/UI:N/S:U/C:N/I:H/A:H"),
    "options_update": VulnClass(
        "options_update", "Arbitrary Option Update", ("CWE-284",),
        "AV:N/AC:L/PR:{PR}/UI:N/S:C/C:H/I:H/A:H"),
    "shortcode_exec": VulnClass(
        "shortcode_exec", "Arbitrary Shortcode Execution", ("CWE-94",),
        "AV:N/AC:L/PR:{PR}/UI:N/S:U/C:H/I:H/A:H"),
    "open_redirect": VulnClass("open_redirect", "Open Redirect", ("CWE-601",),
                               "AV:N/AC:L/PR:{PR}/UI:R/S:U/C:N/I:L/A:N"),
    "ssrf": VulnClass("ssrf", "Server-Side Request Forgery", ("CWE-918",),
                      "AV:N/AC:L/PR:{PR}/UI:N/S:U/C:H/I:N/A:N"),
    "info_exposure": VulnClass(
        "info_exposure", "Sensitive Information Exposure",
        ("CWE-200", "CWE-538"),
        "AV:N/AC:L/PR:{PR}/UI:N/S:U/C:H/I:N/A:N"),
    "idor": VulnClass("idor", "Insecure Direct Object Reference", ("CWE-639",),
                      "AV:N/AC:L/PR:{PR}/UI:N/S:U/C:H/I:H/A:N"),
    "deprecated_php": VulnClass(
        "deprecated_php", "Insecure or Removed PHP API Usage", ("CWE-477",),
        "AV:N/AC:H/PR:{PR}/UI:N/S:U/C:N/I:N/A:L", needs_taint=False,
        considerable_impact=False),
    "hardening": VulnClass(
        "hardening", "Missing Direct-Access Guard", ("CWE-16",),
        "AV:N/AC:L/PR:{PR}/UI:N/S:U/C:N/I:N/A:N", needs_taint=False,
        considerable_impact=False),
}

SEVERITY_RANK = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, "None": 0}


# ---------------------------------------------------------------------------
# Scope rules (Wordfence Bug Bounty Program)
# ---------------------------------------------------------------------------

MIN_IN_SCOPE_INSTALLS = 50       # plugins/themes with >= 50 active installs
INSTALLS_UPDATED_WINDOW_YEARS = 2  # 50-999 installs must be updated within 2y
OUT_OF_SCOPE_NOTES = (
    ("Vulnerabilities only exploitable on configurations running EOL versions "
    "of software (PHP, MySQL, Apache, nginx, OpenSSL)."),
    ("Any SQL Injection that requires wp_magic_quotes to be disabled in order "
    "to exploit."),
)


def assess_scope(finding_score: float, privilege: str,
                 active_installs: int | None = None) -> tuple:
    """Return (in_scope: bool, note: str) per Wordfence program rules."""
    reasons = []
    if privilege == "admin":
        reasons.append(
            "out of scope: exploitation requires Administrator/Editor level "
            "permissions (CVSSv3.1 PR:H)")
    if active_installs is not None and active_installs < MIN_IN_SCOPE_INSTALLS:
        reasons.append(
            f"active install count ({active_installs}) is below the program's "
            f"{MIN_IN_SCOPE_INSTALLS}-install threshold")
    if finding_score > 0 and finding_score < 4.0 and active_installs == 0:
        reasons.append("low-severity finding without measurable footprint")
    if reasons:
        return False, "; ".join(reasons)
    return True, (
        f"in scope: impact is exploitable without admin/editor permissions and "
        f"{f'active installs ({active_installs}) >= {MIN_IN_SCOPE_INSTALLS}' if active_installs is not None else 'install count unknown'}")


# ---------------------------------------------------------------------------
# WordPress privilege → CVSS PR mapping helper
# ---------------------------------------------------------------------------

def context_for_privilege(privilege: str) -> AttackerContext:
    return {
        "unauthenticated": UNAUTHENTICATED,
        "subscriber": SUBSCRIBER,
        "contributor": CONTRIBUTOR,
        "author": AUTHOR,
        "admin": ADMIN,
    }.get(privilege, SUBSCRIBER)
