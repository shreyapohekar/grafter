import { useCallback, useEffect, useMemo, useState } from "react";

// -----------------------------------------------------------------------------
// Types (kept local so JobsView is standalone; must stay in sync with the
// backend `PocRun` / `LivePocRunListItem` shapes in poc/models.py).
// -----------------------------------------------------------------------------
type PocRunListItem = {
  id: string;
  finding_id: string;
  finding_title?: string | null;
  finding_repo?: string | null;
  category?: string | null;
  claim?: string | null;
  state: string;
  verdict?: string | null;
  started?: number | null;
  finished?: number | null;
  proven_impact: string[];
  workflow_run_url?: string | null;
  mirror_owner?: string | null;
  mirror_repo?: string | null;
};

type PocRunListPage = {
  total: number;
  items: PocRunListItem[];
};

const TERMINAL = new Set(["done", "failed", "cancelled"]);

function fmtElapsed(started?: number | null, finished?: number | null): string {
  if (!started) return "";
  const end = finished ?? Date.now() / 1000;
  const s = Math.max(0, Math.round(end - started));
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  const r = s % 60;
  return `${m}m ${r}s`;
}

function fmtAgo(ts?: number | null): string {
  if (!ts) return "";
  const sec = Math.max(0, Math.round(Date.now() / 1000 - ts));
  if (sec < 60) return `${sec}s ago`;
  if (sec < 3600) return `${Math.floor(sec / 60)}m ago`;
  if (sec < 86400) return `${Math.floor(sec / 3600)}h ago`;
  return `${Math.floor(sec / 86400)}d ago`;
}

function verdictClass(v?: string | null): string {
  if (!v) return "";
  return `poc-verdict-${v.replace(/_/g, "-")}`;
}

// -----------------------------------------------------------------------------
// Props
// -----------------------------------------------------------------------------
export type JobsViewProps = {
  visible: boolean;
  /** Open the finding drawer for the given finding id. */
  onOpenFinding: (findingId: string) => void;
  /** Notified whenever we reload runs, so the parent can update the
   *  set of finding ids with in-flight PoC runs (used to render the
   *  blinking dot on finding cards). */
  onActiveFindingsChange?: (findingIds: string[]) => void;
};

// -----------------------------------------------------------------------------
// Component
// -----------------------------------------------------------------------------
export default function JobsView({ visible, onOpenFinding, onActiveFindingsChange }: JobsViewProps) {
  const [runs, setRuns] = useState<PocRunListItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  const loadRuns = useCallback(async () => {
    setLoading(true);
    try {
      const r = await fetch("/api/live-poc/runs?state=all&limit=200", { credentials: "include" });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const d: PocRunListPage = await r.json();
      const items = d.items || [];
      setRuns(items);
      setErr(null);
      if (onActiveFindingsChange) {
        const activeFids = Array.from(
          new Set(items.filter((it) => !TERMINAL.has(it.state)).map((it) => it.finding_id)),
        );
        onActiveFindingsChange(activeFids);
      }
    } catch (e) {
      setErr(String((e as Error).message || e));
    } finally {
      setLoading(false);
    }
  }, [onActiveFindingsChange]);

  // Initial + interval polling while the tab is visible. Poll faster when
  // there are active runs so the UI feels alive.
  useEffect(() => {
    if (!visible) return;
    void loadRuns();
  }, [visible, loadRuns]);

  useEffect(() => {
    if (!visible) return;
    const activeCount = runs.filter((r) => !TERMINAL.has(r.state)).length;
    const interval = activeCount > 0 ? 2500 : 8000;
    const t = window.setInterval(() => void loadRuns(), interval);
    return () => window.clearInterval(t);
  }, [visible, runs, loadRuns]);

  const { active, history } = useMemo(() => {
    const a = runs.filter((r) => !TERMINAL.has(r.state));
    const h = runs.filter((r) => TERMINAL.has(r.state));
    // Newest first in each section.
    a.sort((x, y) => (y.started ?? 0) - (x.started ?? 0));
    h.sort((x, y) => (y.finished ?? y.started ?? 0) - (x.finished ?? x.started ?? 0));
    return { active: a, history: h };
  }, [runs]);

  async function cancelRun(id: string) {
    if (!window.confirm("Cancel this run? Cleanup will remove the mirror + attacker repos.")) return;
    await fetch(`/api/live-poc/runs/${id}/cancel`, { method: "POST", credentials: "include" });
    void loadRuns();
  }

  async function deleteRun(id: string) {
    if (!window.confirm("Delete this terminal run from history?")) return;
    const r = await fetch(`/api/live-poc/runs/${id}`, { method: "DELETE", credentials: "include" });
    if (r.ok) void loadRuns();
  }

  if (!visible) return null;

  return (
    <div className="jobs-view">
      <div className="jobs-header">
        <h2 className="jobs-title">Live PoC Jobs</h2>
        <div className="jobs-summary">
          <span className="jobs-summary-chip active">
            <span className="jobs-dot jobs-dot-blink" /> {active.length} active
          </span>
          <span className="jobs-summary-chip">{history.length} in history</span>
          <button
            className="btn ghost"
            style={{ padding: "6px 12px", fontSize: 12 }}
            onClick={() => void loadRuns()}
            disabled={loading}
          >
            {loading ? "Refreshing…" : "Refresh"}
          </button>
        </div>
      </div>
      {err && <div className="error" style={{ marginTop: 10 }}>{err}</div>}

      <section className="jobs-section">
        <div className="jobs-section-title">
          Active <span className="jobs-count">{active.length}</span>
        </div>
        {active.length === 0 ? (
          <div className="jobs-empty">
            No Live PoCs are running right now. Start one from any finding's drawer
            (open a finding → Live PoC tab → New PoC).
          </div>
        ) : (
          <JobsTable
            rows={active}
            terminal={false}
            onOpenFinding={onOpenFinding}
            onCancel={cancelRun}
          />
        )}
      </section>

      <section className="jobs-section">
        <div className="jobs-section-title">
          History <span className="jobs-count">{history.length}</span>
        </div>
        {history.length === 0 ? (
          <div className="jobs-empty">No completed runs yet.</div>
        ) : (
          <JobsTable
            rows={history}
            terminal={true}
            onOpenFinding={onOpenFinding}
            onDelete={deleteRun}
          />
        )}
      </section>
    </div>
  );
}

// -----------------------------------------------------------------------------
// JobsTable
// -----------------------------------------------------------------------------
function JobsTable({
  rows,
  terminal,
  onOpenFinding,
  onCancel,
  onDelete,
}: {
  rows: PocRunListItem[];
  terminal: boolean;
  onOpenFinding: (findingId: string) => void;
  onCancel?: (runId: string) => void;
  onDelete?: (runId: string) => void;
}) {
  return (
    <div className="jobs-table" role="table">
      <div className="jobs-thead" role="row">
        <div role="columnheader">Finding</div>
        <div role="columnheader">Category</div>
        <div role="columnheader">Mirror repo</div>
        <div role="columnheader">{terminal ? "Verdict" : "State"}</div>
        <div role="columnheader">{terminal ? "Finished" : "Elapsed"}</div>
        <div role="columnheader" className="jobs-th-actions">Actions</div>
      </div>
      {rows.map((r) => {
        const mirror =
          r.mirror_owner && r.mirror_repo ? `${r.mirror_owner}/${r.mirror_repo}` : null;
        const mirrorUrl = mirror ? `https://github.com/${mirror}` : null;
        return (
          <div key={r.id} className="jobs-row" role="row">
            <div className="jobs-td-finding">
              <div className="jobs-finding-title" title={r.finding_title || r.finding_id}>
                {r.finding_title || r.finding_id.slice(0, 12)}
              </div>
              <div className="jobs-finding-sub">
                <span className="repo">{r.finding_repo || ""}</span>
                <button
                  className="btn ghost jobs-open-finding-btn"
                  onClick={() => onOpenFinding(r.finding_id)}
                  title="Open finding drawer"
                >
                  open ↗
                </button>
              </div>
            </div>
            <div className="jobs-td-cat">
              {r.category ? <span className="badge">{r.category}</span> : <span className="repo">—</span>}
            </div>
            <div className="jobs-td-mirror">
              {mirrorUrl ? (
                <a href={mirrorUrl} target="_blank" rel="noreferrer" className="jobs-mirror-link">
                  {mirror} ↗
                </a>
              ) : (
                <span className="repo">— pending —</span>
              )}
              {r.workflow_run_url && (
                <a
                  href={r.workflow_run_url}
                  target="_blank"
                  rel="noreferrer"
                  className="jobs-mirror-link jobs-workflow-link"
                >
                  workflow run ↗
                </a>
              )}
            </div>
            <div className="jobs-td-state">
              {terminal ? (
                <span className={`badge ${verdictClass(r.verdict)}`}>
                  {(r.verdict || r.state).replace(/_/g, " ")}
                </span>
              ) : (
                <span className="badge jobs-state-active">
                  <span className="jobs-dot jobs-dot-blink" /> {r.state}
                </span>
              )}
            </div>
            <div className="jobs-td-time">
              {terminal
                ? fmtAgo(r.finished ?? r.started)
                : fmtElapsed(r.started, null)}
            </div>
            <div className="jobs-td-actions">
              {!terminal && onCancel && (
                <button
                  className="btn ghost danger"
                  style={{ padding: "4px 10px", fontSize: 12 }}
                  onClick={() => onCancel(r.id)}
                  title="Cancel this run"
                >
                  Cancel
                </button>
              )}
              {terminal && onDelete && (
                <button
                  className="btn ghost"
                  style={{ padding: "4px 10px", fontSize: 12 }}
                  onClick={() => onDelete(r.id)}
                  title="Delete this run from history"
                >
                  Delete
                </button>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}
