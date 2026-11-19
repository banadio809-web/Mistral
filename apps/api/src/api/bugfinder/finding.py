"""Finding model: Wordfence-style titles, CVSS vector computation and
scope assessment per finding."""

from dataclasses import dataclass, field, fields

from .criteria import (
    VULN_CLASSES,
    assess_scope,
    context_for_privilege,
    cvss31,
    severity_of,
)


@dataclass
class Finding:
    rule: str                     # vuln class key
    attacker: str                 # 'unauthenticated' | 'subscriber' | ...
    file: str
    line: int
    snippet: str
    entry: dict = field(default_factory=dict)
    taint_path: list = field(default_factory=list)
    note: str = ""
    active_installs: int = None
    version: str = None
    plugin_slug: str = None
    vector: str = ""
    score: float = 0.0
    severity: str = "None"
    title: str = ""
    cwes: list = field(default_factory=list)
    in_scope: bool = False
    scope_note: str = ""

    def finalize(self) -> "Finding":
        cls = VULN_CLASSES[self.rule]
        ctx = context_for_privilege(self.attacker)
        self.vector = cls.vector.replace("{PR}", ctx.vector_pr)
        self.score = cvss31(self.vector)
        self.severity = severity_of(self.score)
        via = f" via '{self.entry['hook']}'" if self.entry.get("hook") else ""
        self.title = f"{ctx.title_prefix()} {cls.name}{via}"
        self.cwes = list(cls.cwes)
        self.in_scope, self.scope_note = assess_scope(
            self.score, self.attacker, self.active_installs)
        return self

    def to_dict(self) -> dict:
        return {f.name: getattr(self, f.name) for f in fields(self)}

    def row(self) -> str:
        scope = "IN-SCOPE" if self.in_scope else "OUT-OF-SCOPE"
        sn = self.snippet.strip().replace("\n", "\n             ")[:200]
        return (f"[{self.severity.upper():8}] CVSS {self.score:<4} | {self.title}\n"
                f"           {self.file}:{self.line}  ({scope}; {self.scope_note})\n"
                f"             > {sn}")
