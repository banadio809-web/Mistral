import { useCallback, useEffect, useState } from "react";
import { createFileRoute, redirect } from "@tanstack/react-router";

import { env } from "../env";

type SearchHit = {
  slug: string;
  name: string;
  version: string;
  active_installs: number | null;
  author: string;
  short_description: string;
};

type StoredFinding = {
  id: number;
  scan_id: number;
  plugin_slug: string;
  rule: string;
  severity: string;
  score: number;
  title: string;
  vector: string;
  attacker: string;
  cwe: string[];
  file: string;
  line: number;
  snippet: string;
  taint_path: string[];
  in_scope: boolean;
  scope_note: string;
};

type StoredPlugin = { slug: string; name: string; version: string; active_installs: number | null };

type ScanResponse = {
  scan_id: number;
  plugin_slug: string;
  version: string;
  files_scanned: number;
  findings_count: number;
  in_scope_count: number;
  max_score: number;
  max_severity: string;
  findings: StoredFinding[];
};

const SEVERITY_CLASS: Record<string, string> = {
  critical: "bg-red-600/15 text-red-400 border-red-600/40",
  high: "bg-orange-500/15 text-orange-400 border-orange-500/40",
  medium: "bg-amber-400/15 text-amber-300 border-amber-400/40",
  low: "bg-sky-500/15 text-sky-400 border-sky-500/40",
};

const api = (path: string, init?: RequestInit) =>
  fetch(`${env.VITE_API_URL}/api/v1${path}`, {
    ...init,
    headers: { "Content-Type": "application/json", ...init?.headers },
  });

function SeverityChip({ severity, score }: { severity: string; score: number }) {
  return (
    <span
      className={`inline-flex items-center gap-1 rounded border px-2 py-0.5 text-xs font-medium uppercase ${
        SEVERITY_CLASS[severity] ?? "bg-neutral-500/15 text-neutral-400 border-neutral-500/40"
      }`}
    >
      {severity || "info"} {score ? `· ${score.toFixed(1)}` : ""}
    </span>
  );
}

function FindingCard({ finding }: { finding: StoredFinding }) {
  return (
    <li className="rounded-lg border border-neutral-800 bg-neutral-900/60 p-4 text-sm">
      <div className="mb-1 flex flex-wrap items-center gap-2">
        <SeverityChip severity={finding.severity} score={finding.score} />
        {finding.in_scope ? (
          <span className="rounded border border-emerald-600/40 bg-emerald-600/10 px-2 py-0.5 text-xs text-emerald-400">
            in Wordfence scope
          </span>
        ) : (
          <span className="rounded border border-neutral-700 px-2 py-0.5 text-xs text-neutral-500">
            out of scope — {finding.scope_note}
          </span>
        )}
        <span className="text-xs text-neutral-500">{finding.vector}</span>
      </div>
      <p className="font-medium text-neutral-100">{finding.title}</p>
      <p className="mt-1 text-neutral-400">
        <code className="text-xs">{finding.file}:{finding.line}</code>
        {" · "}
        {finding.rule} · attacker: {finding.attacker || "n/a"}
        {finding.cwe.length > 0 ? ` · ${finding.cwe.join(", ")}` : ""}
      </p>
      {finding.snippet ? (
        <pre className="mt-2 overflow-x-auto rounded bg-black/40 p-2 text-xs text-neutral-400">
          {finding.snippet}
        </pre>
      ) : null}
      {finding.taint_path.length > 0 ? (
        <p className="mt-1 text-xs text-neutral-500">taint: {finding.taint_path.join(" → ")}</p>
      ) : null}
    </li>
  );
}

function Dashboard() {
  const [target, setTarget] = useState("");
  const [query, setQuery] = useState("");
  const [hits, setHits] = useState<SearchHit[]>([]);
  const [lastScan, setLastScan] = useState<ScanResponse | null>(null);
  const [plugins, setPlugins] = useState<StoredPlugin[]>([]);
  const [findings, setFindings] = useState<StoredFinding[]>([]);
  const [severity, setSeverity] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const loadFindings = useCallback(async () => {
    const params = new URLSearchParams();
    if (severity) params.set("severity", severity);
    if (target) params.set("plugin_slug", target.split("/").pop() || "");
    const res = await api(`/findings?${params.toString()}`);
    if (res.ok) setFindings((await res.json()).findings);
  }, [severity, target]);

  const loadPlugins = useCallback(async () => {
    const res = await api("/plugins");
    if (res.ok) setPlugins((await res.json()).plugins);
  }, []);

  useEffect(() => {
    void loadPlugins();
  }, [loadPlugins]);

  const runScan = async (scanTarget: string) => {
    if (!scanTarget) return;
    setBusy(true);
    setError("");
    try {
      const res = await api("/scans", { method: "POST", body: JSON.stringify({ target: scanTarget }) });
      if (!res.ok) {
        const detail = ((await res.json()) as { detail?: string }).detail ?? res.statusText;
        throw new Error(detail);
      }
      setLastScan(await res.json());
      setTarget(scanTarget);
      await Promise.all([loadFindings(), loadPlugins()]);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const runSearch = async () => {
    if (!query) return;
    setBusy(true);
    setError("");
    try {
      const res = await api(`/search?q=${encodeURIComponent(query)}&limit=10`);
      if (!res.ok) throw new Error(res.statusText);
      setHits((await res.json()).hits);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className="mx-auto min-h-full max-w-5xl p-8 text-neutral-200">
      <h1 className="text-2xl font-semibold">WordPress Plugin Bug Finder</h1>
      <p className="mt-1 text-sm text-neutral-500">
        Static taint analysis of wordpress.org plugins, scored against Wordfence bug-bounty criteria.
        Signals must be verified manually.
      </p>

      <section className="mt-6 flex flex-wrap gap-2">
        <input
          value={target}
          onChange={(e) => setTarget(e.target.value)}
          placeholder="plugin slug, wordpress.org URL, or local path"
          className="min-w-64 flex-1 rounded border border-neutral-700 bg-neutral-900 px-3 py-2 text-sm outline-none focus:border-neutral-500"
        />
        <button
          type="button"
          disabled={busy || !target}
          onClick={() => void runScan(target)}
          className="rounded bg-blue-600 px-4 py-2 text-sm font-medium text-white hover:bg-blue-500 disabled:opacity-50"
        >
          {busy ? "Working…" : "Fetch + scan"}
        </button>
      </section>

      {error ? <p className="mt-3 rounded border border-red-600/40 bg-red-600/10 p-3 text-sm text-red-400">{error}</p> : null}

      {lastScan ? (
        <section className="mt-6 rounded-lg border border-neutral-800 bg-neutral-900/60 p-4">
          <h2 className="text-sm font-semibold">
            Scan #{lastScan.scan_id} — {lastScan.plugin_slug} {lastScan.version} ({lastScan.files_scanned} files)
          </h2>
          <p className="mt-1 text-sm text-neutral-400">
            {lastScan.findings_count} findings · {lastScan.in_scope_count} in Wordfence scope · top CVSS {lastScan.max_score.toFixed(1)} {lastScan.max_severity}
          </p>
          <ul className="mt-3 space-y-2">
            {lastScan.findings.map((f) => (
              <FindingCard key={f.id} finding={f} />
            ))}
          </ul>
        </section>
      ) : null}

      <section className="mt-8">
        <h2 className="text-sm font-semibold text-neutral-300">Search the plugin directory</h2>
        <div className="mt-2 flex gap-2">
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && void runSearch()}
            placeholder="e.g. contact form"
            className="min-w-48 flex-1 rounded border border-neutral-700 bg-neutral-900 px-3 py-2 text-sm outline-none focus:border-neutral-500"
          />
          <button
            type="button"
            disabled={busy || !query}
            onClick={() => void runSearch()}
            className="rounded border border-neutral-700 px-4 py-2 text-sm hover:bg-neutral-800 disabled:opacity-50"
          >
            Search
          </button>
        </div>
        <ul className="mt-3 space-y-2">
          {hits.map((hit) => (
            <li key={hit.slug} className="flex flex-wrap items-center justify-between gap-2 rounded border border-neutral-800 bg-neutral-900/60 p-3 text-sm">
              <div>
                <p className="font-medium">
                  {hit.name} <span className="text-xs text-neutral-500">v{hit.version}</span>
                </p>
                <p className="text-xs text-neutral-500">
                  {hit.slug} · {hit.active_installs?.toLocaleString() ?? "?"} installs · {hit.author}
                </p>
              </div>
              <button
                type="button"
                disabled={busy}
                onClick={() => void runScan(hit.slug)}
                className="rounded border border-neutral-700 px-3 py-1 text-xs hover:bg-neutral-800 disabled:opacity-50"
              >
                Scan
              </button>
            </li>
          ))}
        </ul>
      </section>

      <section className="mt-8 grid gap-4 md:grid-cols-[1fr_2fr]">
        <div>
          <h2 className="text-sm font-semibold text-neutral-300">Scanned plugins</h2>
          <ul className="mt-2 space-y-1 text-sm">
            {plugins.map((p) => (
              <li key={p.slug}>
                <button type="button" onClick={() => void runScan(p.slug)} className="text-left text-blue-400 hover:underline">
                  {p.slug}
                </button>
                <span className="text-xs text-neutral-500">
                  {" "}
                  v{p.version} · {p.active_installs?.toLocaleString() ?? "?"} installs
                </span>
              </li>
            ))}
            {plugins.length === 0 ? <li className="text-neutral-500">Nothing scanned yet.</li> : null}
          </ul>
        </div>
        <div>
          <h2 className="text-sm font-semibold text-neutral-300">Stored findings</h2>
          <select
            value={severity}
            onChange={(e) => setSeverity(e.target.value)}
            className="mt-2 rounded border border-neutral-700 bg-neutral-900 px-2 py-1 text-xs"
          >
            <option value="">any severity</option>
            <option value="critical">critical</option>
            <option value="high">high</option>
            <option value="medium">medium</option>
            <option value="low">low</option>
          </select>
          <ul className="mt-3 space-y-2">
            {findings.map((f) => (
              <FindingCard key={f.id} finding={f} />
            ))}
            {findings.length === 0 ? <li className="text-sm text-neutral-500">No stored findings.</li> : null}
          </ul>
        </div>
      </section>
    </main>
  );
}

export const Route = createFileRoute("/")({
  beforeLoad: ({ context }) => {
    const to = context.landingPath();

    if (to !== undefined && to !== "" && to !== "/") {
      // oxlint-disable-next-line typescript/only-throw-error -- TanStack Router's redirect is thrown, by design
      throw redirect({ href: to });
    }
  },
  component: Dashboard,
});
