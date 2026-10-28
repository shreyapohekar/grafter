import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { redactGitHubLogin } from "./redaction";

// -----------------------------------------------------------------------------
// Types (mirror backend Pydantic models in poc/models.py)
// -----------------------------------------------------------------------------
export type LivePocIdentity = {
  login?: string | null;
  preview?: string | null;
  saved_at?: number | null;
};

export type LivePocCanary = {
  kind?: string | null;
  label?: string | null;
  preview?: string | null;
  history_url?: string | null;
  saved_at?: number | null;
};

export type LivePocTokensInfo = {
  maintainer?: LivePocIdentity | null;
  attacker?: LivePocIdentity | null;
  canary?: LivePocCanary | null;
};

export type LivePocRunSummary = {
  active: number;
  terminal_last_24h: number;
  stuck: number;
};

export type LivePocRunListItem = {
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

export type LivePocRunListPage = {
  total: number;
  items: LivePocRunListItem[];
};

export type PocRunLogLine = {
  ts: number;
  phase: string;
  level: string;
  message: string;
};

export type PocRunSignal = {
  signal_type: string;
  when: number;
  where?: string | null;
  matched_by?: string | null;
  tags: string[];
  details?: Record<string, unknown>;
};

export type PocRun = {
  id: string;
  finding_id: string;
  category?: string | null;
  claim?: string | null;
  impact_class: string[];
  proven_impact: string[];
  success_requirement?: string | null;
  mirror_mode?: string | null;
  mirror_manifest?: Array<{ path: string; reason: string; size: number }> | null;
  state: string;
  verdict?: string | null;
  started?: number | null;
  finished?: number | null;
  marker: string;
  mirror_owner?: string | null;
  mirror_repo?: string | null;
  attacker_owner?: string | null;
  attacker_fork?: string | null;
  workflow_run_id?: number | null;
  workflow_run_url?: string | null;
  logs: PocRunLogLine[];
  evidence: PocRunSignal[];
  opt_in_real_repo: boolean;
  canary_kind?: string | null;
  error?: string | null;
};

export type DriverPreview = {
  category: string;
  claim: string;
  impact_tags: string[];
  success_criteria: string[];
  signals: string[];
  payload_summary: string;
  supports_real_repo_mode: boolean;
};

const PHASES = [
  "queued",
  "preflight",
  "mirror",
  "inject",
  "trigger",
  "watch",
  "verdict",
  "cleanup",
  "done",
];
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
export type LivePocViewProps = {
  visible: boolean;
  initialFindingId: string | null;
  onOpenFinding: (findingId: string) => void;
  onSummaryChange: (summary: LivePocRunSummary) => void;
  refreshTick: number;
  findingFilter?: string | null;
};

// -----------------------------------------------------------------------------
// Component
// -----------------------------------------------------------------------------
export default function LivePocView({
  visible,
  initialFindingId,
  onOpenFinding,
  onSummaryChange,
  refreshTick,
  findingFilter,
}: LivePocViewProps) {
  const [tokens, setTokens] = useState<LivePocTokensInfo>({});
  const [tokensLoading, setTokensLoading] = useState(false);
  const [tokenSaveErr, setTokenSaveErr] = useState<string | null>(null);
  const [maintainerInput, setMaintainerInput] = useState("");
  const [attackerInput, setAttackerInput] = useState("");
  const [canaryInput, setCanaryInput] = useState("");
  const [canaryKind, setCanaryKind] = useState<string>("http");
  const [canaryHistoryUrl, setCanaryHistoryUrl] = useState("");

  const [runs, setRuns] = useState<LivePocRunListItem[]>([]);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [detail, setDetail] = useState<PocRun | null>(null);
  const [detailErr, setDetailErr] = useState<string | null>(null);

  const [drivers, setDrivers] = useState<string[]>([]);

  const [showNewPocForm, setShowNewPocForm] = useState<boolean>(!!initialFindingId);
  const [newPocFindingId, setNewPocFindingId] = useState<string>(initialFindingId ?? "");
  const [newPocPreview, setNewPocPreview] = useState<DriverPreview | null>(null);
  const [newPocErr, setNewPocErr] = useState<string | null>(null);
  const [newPocUseRealRepo, setNewPocUseRealRepo] = useState(false);
  const [newPocRealRepoConfirm, setNewPocRealRepoConfirm] = useState(false);
  const [newPocKeepRepos, setNewPocKeepRepos] = useState(false);
  const [newPocForceMinimal, setNewPocForceMinimal] = useState(false);
  const [newPocStarting, setNewPocStarting] = useState(false);
  const logRef = useRef<HTMLPreElement | null>(null);
  const [autoscroll, setAutoscroll] = useState(true);

  useEffect(() => {
    if (initialFindingId) {
      setShowNewPocForm(true);
      setNewPocFindingId(initialFindingId);
    }
  }, [initialFindingId, refreshTick]);

  // -----------------------------------------------------
  // Fetch helpers
  // -----------------------------------------------------
  const loadTokens = useCallback(async () => {
    setTokensLoading(true);
    try {
      const r = await fetch("/api/live-poc/tokens", { credentials: "include" });
      if (r.ok) setTokens(await r.json());
    } finally {
      setTokensLoading(false);
    }
  }, []);

  const loadDrivers = useCallback(async () => {
    try {
      const r = await fetch("/api/live-poc/drivers", { credentials: "include" });
      if (r.ok) {
        const d = await r.json();
        setDrivers(d.categories || []);
      }
    } catch {
      /* noop */
    }
  }, []);

  const loadRuns = useCallback(async () => {
    try {
      const r = await fetch("/api/live-poc/runs?state=all&limit=100", { credentials: "include" });
      if (r.ok) {
        const d: LivePocRunListPage = await r.json();
        setRuns(d.items || []);
      }
    } catch {
      /* noop */
    }
  }, []);

  const loadSummary = useCallback(async () => {
    try {
      const r = await fetch("/api/live-poc/runs/summary", { credentials: "include" });
      if (r.ok) onSummaryChange(await r.json());
    } catch {
      /* noop */
    }
  }, [onSummaryChange]);

  const loadDetail = useCallback(async (id: string) => {
    try {
      const r = await fetch(`/api/live-poc/runs/${id}`, { credentials: "include" });
      if (r.ok) {
        setDetail(await r.json());
        setDetailErr(null);
      } else {
        setDetail(null);
        setDetailErr(`HTTP ${r.status}`);
      }
    } catch (e) {
      setDetail(null);
      setDetailErr(String(e));
    }
  }, []);

  // Initial load + interval polling while visible.
  useEffect(() => {
    if (!visible) return;
    loadTokens();
    loadDrivers();
    loadRuns();
    loadSummary();
  }, [visible, loadTokens, loadDrivers, loadRuns, loadSummary]);

  useEffect(() => {
    if (!visible) return;
    const activeCount = runs.filter((r) => !TERMINAL.has(r.state)).length;
    const interval = activeCount > 0 ? 2000 : 5000;
    const t = window.setInterval(() => {
      loadRuns();
      loadSummary();
      if (selectedId) loadDetail(selectedId);
    }, interval);
    return () => window.clearInterval(t);
  }, [visible, runs, selectedId, loadRuns, loadSummary, loadDetail]);

  // Auto-select first non-terminal run when nothing is selected.
  useEffect(() => {
    if (selectedId) return;
    const pool = findingFilter ? runs.filter((r) => r.finding_id === findingFilter) : runs;
    if (pool.length === 0) return;
    const activeRun = pool.find((r) => !TERMINAL.has(r.state));
    const pick = activeRun ?? pool[0];
    setSelectedId(pick.id);
  }, [runs, selectedId, findingFilter]);

  useEffect(() => {
    if (selectedId) loadDetail(selectedId);
    else setDetail(null);
  }, [selectedId, loadDetail]);

  // Load driver preview whenever the New PoC finding_id changes.
  const loadPreview = useCallback(async (fid: string) => {
    if (!fid) {
      setNewPocPreview(null);
      return;
    }
    setNewPocErr(null);
    try {
      const r = await fetch(`/api/findings/${fid}/live-poc/preview`, { credentials: "include" });
      if (r.ok) setNewPocPreview(await r.json());
      else {
        const t = await r.text();
        setNewPocPreview(null);
        setNewPocErr(t || `HTTP ${r.status}`);
      }
    } catch (e) {
      setNewPocPreview(null);
      setNewPocErr(String(e));
    }
  }, []);

  useEffect(() => {
    if (showNewPocForm && newPocFindingId) loadPreview(newPocFindingId);
  }, [showNewPocForm, newPocFindingId, loadPreview]);

  // Autoscroll live log tail.
  useEffect(() => {
    if (autoscroll && logRef.current) {
      logRef.current.scrollTop = logRef.current.scrollHeight;
    }
  }, [detail?.logs?.length, autoscroll]);

  // -----------------------------------------------------
  // Token save / forget
  // -----------------------------------------------------
  async function saveTokens(payload: Record<string, string | null>) {
    setTokenSaveErr(null);
    try {
      const r = await fetch("/api/live-poc/tokens", {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      if (!r.ok) throw new Error(await r.text());
      setTokens(await r.json());
      setMaintainerInput("");
      setAttackerInput("");
      setCanaryInput("");
    } catch (e) {
      setTokenSaveErr(String((e as Error).message || e));
    }
  }

  async function forgetTokens() {
    if (!confirm("Forget all Live PoC tokens (maintainer, attacker, canary)?")) return;
    const r = await fetch("/api/live-poc/tokens", { method: "DELETE", credentials: "include" });
    if (r.ok) setTokens(await r.json());
  }

  // -----------------------------------------------------
  // Run actions
  // -----------------------------------------------------
  async function startRun() {
    if (!newPocFindingId) return;
    setNewPocStarting(true);
    setNewPocErr(null);
    try {
      const body = {
        use_real_repo: newPocUseRealRepo && newPocRealRepoConfirm,
        keep_repos: newPocKeepRepos,
        force_minimal_mirror: newPocForceMinimal,
      };
      const r = await fetch(`/api/findings/${newPocFindingId}/live-poc`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      if (!r.ok) throw new Error(await r.text());
      const d = await r.json();
      setShowNewPocForm(false);
      setSelectedId(d.run_id);
      await loadRuns();
    } catch (e) {
      setNewPocErr(String((e as Error).message || e));
    } finally {
      setNewPocStarting(false);
    }
  }

  async function cancelRun(id: string) {
    if (!confirm("Cancel this run? Cleanup will run and any mirror/attacker repos will be deleted.")) return;
    await fetch(`/api/live-poc/runs/${id}/cancel`, { method: "POST", credentials: "include" });
    await loadRuns();
    if (id === selectedId) await loadDetail(id);
  }

  async function deleteRun(id: string) {
    if (!confirm("Delete this terminal run from history?")) return;
    const r = await fetch(`/api/live-poc/runs/${id}`, { method: "DELETE", credentials: "include" });
    if (r.ok) {
      if (id === selectedId) setSelectedId(null);
      await loadRuns();
    }
  }

  const scopedRuns = useMemo(
    () => (findingFilter ? runs.filter((r) => r.finding_id === findingFilter) : runs),
    [runs, findingFilter],
  );
  const active = useMemo(() => scopedRuns.filter((r) => !TERMINAL.has(r.state)), [scopedRuns]);
  const history = useMemo(() => scopedRuns.filter((r) => TERMINAL.has(r.state)), [scopedRuns]);

  if (!visible) return null;

  return (
    <div className="poc-view">
      {/* Left rail: runs list */}
      <aside className="poc-list-rail">
        <div className="poc-list-header">
          <button
            className="btn primary poc-newrun-btn"
            onClick={() => {
              setShowNewPocForm((v) => !v);
              setSelectedId(null);
              setNewPocErr(null);
              setNewPocPreview(null);
              setNewPocFindingId(initialFindingId ?? "");
            }}
          >
            + New PoC
          </button>
        </div>
        <div className="poc-list-section">
          <div className="poc-list-section-title">
            Active <span className="poc-count">{active.length}</span>
          </div>
          {active.length === 0 ? (
            <div className="poc-list-empty">No active runs</div>
          ) : (
            active.map((r) => (
              <RunRow
                key={r.id}
                run={r}
                selected={r.id === selectedId && !showNewPocForm}
                onClick={() => {
                  setShowNewPocForm(false);
                  setSelectedId(r.id);
                }}
              />
            ))
          )}
        </div>
        <div className="poc-list-section">
          <div className="poc-list-section-title">
            History <span className="poc-count">{history.length}</span>
          </div>
          {history.length === 0 ? (
            <div className="poc-list-empty">No completed runs yet</div>
          ) : (
            history.map((r) => (
              <RunRow
                key={r.id}
                run={r}
                selected={r.id === selectedId && !showNewPocForm}
                onClick={() => {
                  setShowNewPocForm(false);
                  setSelectedId(r.id);
                }}
              />
            ))
          )}
        </div>
      </aside>

      {/* Middle pane: either the New PoC form or the run detail */}
      <section className="poc-detail-pane">
        {showNewPocForm ? (
          <NewPocPanel
            findingId={newPocFindingId}
            setFindingId={setNewPocFindingId}
            lockFindingId={!!findingFilter}
            preview={newPocPreview}
            err={newPocErr}
            tokens={tokens}
            drivers={drivers}
            useRealRepo={newPocUseRealRepo}
            setUseRealRepo={setNewPocUseRealRepo}
            realRepoConfirm={newPocRealRepoConfirm}
            setRealRepoConfirm={setNewPocRealRepoConfirm}
            keepRepos={newPocKeepRepos}
            setKeepRepos={setNewPocKeepRepos}
            forceMinimal={newPocForceMinimal}
            setForceMinimal={setNewPocForceMinimal}
            starting={newPocStarting}
            onStart={startRun}
            onCancel={() => setShowNewPocForm(false)}
            /* Token controls */
            maintainerInput={maintainerInput}
            setMaintainerInput={setMaintainerInput}
            attackerInput={attackerInput}
            setAttackerInput={setAttackerInput}
            canaryInput={canaryInput}
            setCanaryInput={setCanaryInput}
            canaryKind={canaryKind}
            setCanaryKind={setCanaryKind}
            canaryHistoryUrl={canaryHistoryUrl}
            setCanaryHistoryUrl={setCanaryHistoryUrl}
            tokensLoading={tokensLoading}
            tokenSaveErr={tokenSaveErr}
            onSaveTokens={saveTokens}
            onForgetTokens={forgetTokens}
          />
        ) : detail ? (
          <RunDetail
            run={detail}
            onCancel={() => cancelRun(detail.id)}
            onDelete={() => deleteRun(detail.id)}
            onOpenFinding={() => onOpenFinding(detail.finding_id)}
            logRef={logRef}
            autoscroll={autoscroll}
            setAutoscroll={setAutoscroll}
          />
        ) : (
          <div className="poc-empty-detail">
            {runs.length === 0
              ? "No Live PoC runs yet. Click + New PoC to start one."
              : "Select a run from the left rail."}
            {detailErr && <div className="error">{detailErr}</div>}
          </div>
        )}
      </section>
    </div>
  );
}

// -----------------------------------------------------------------------------
// RunRow
// -----------------------------------------------------------------------------
function RunRow({
  run,
  selected,
  onClick,
}: {
  run: LivePocRunListItem;
  selected: boolean;
  onClick: () => void;
}) {
  return (
    <div
      className={`poc-run-row ${selected ? "selected" : ""}`}
      onClick={onClick}
      role="button"
    >
      <div className="poc-run-row-title">
        {run.finding_title || run.finding_id.slice(0, 12)}
      </div>
      <div className="poc-run-row-meta">
        <span className="poc-run-row-repo">{run.finding_repo || ""}</span>
        {run.category && <span className="poc-run-row-cat">{run.category}</span>}
      </div>
      <div className="poc-run-row-state">
        {TERMINAL.has(run.state) ? (
          <span className={`badge ${verdictClass(run.verdict)}`}>
            {(run.verdict || run.state).replace(/_/g, " ")}
          </span>
        ) : (
          <span className="poc-run-row-live">
            <span className="poc-spinner" />
            {run.state}
          </span>
        )}
        <span className="poc-run-row-elapsed">
          {fmtElapsed(run.started, run.finished)}
        </span>
      </div>
      {run.proven_impact && run.proven_impact.length > 0 && (
        <div className="poc-run-row-tags">
          {run.proven_impact.map((t) => (
            <span key={t} className="poc-tag">
              {t}
            </span>
          ))}
        </div>
      )}
    </div>
  );
}

// -----------------------------------------------------------------------------
// RunDetail
// -----------------------------------------------------------------------------
function RunDetail({
  run,
  onCancel,
  onDelete,
  onOpenFinding,
  logRef,
  autoscroll,
  setAutoscroll,
}: {
  run: PocRun;
  onCancel: () => void;
  onDelete: () => void;
  onOpenFinding: () => void;
  logRef: React.MutableRefObject<HTMLPreElement | null>;
  autoscroll: boolean;
  setAutoscroll: (v: boolean) => void;
}) {
  const currentIndex = PHASES.indexOf(run.state);
  return (
    <div className="poc-run-detail">
      <header className="poc-run-header">
        <div className="poc-run-header-title-row">
          {TERMINAL.has(run.state) ? (
            <span className={`badge poc-verdict-badge ${verdictClass(run.verdict)}`}>
              {(run.verdict || run.state).replace(/_/g, " ")}
            </span>
          ) : (
            <span className="poc-run-row-live big">
              <span className="poc-spinner" />
              {run.state}
            </span>
          )}
          <span className="poc-run-elapsed">{fmtElapsed(run.started, run.finished)}</span>
          <button className="btn ghost" onClick={onOpenFinding} title="Open the finding in the drawer">
            View finding
          </button>
          {!TERMINAL.has(run.state) ? (
            <button className="btn ghost" onClick={onCancel}>
              Cancel
            </button>
          ) : (
            <button className="btn ghost danger" onClick={onDelete}>
              Delete
            </button>
          )}
        </div>
        {run.claim && <div className="poc-run-claim">{run.claim}</div>}
        {run.success_requirement && (
          <div className="poc-run-req">
            Success requirement:&nbsp;<code>{run.success_requirement}</code>
          </div>
        )}
        {run.impact_class && run.impact_class.length > 0 && (
          <div className="poc-run-impact-row">
            <span>Impact tags:</span>
            {run.impact_class.map((t) => (
              <span
                key={t}
                className={`poc-tag ${run.proven_impact.includes(t) ? "proven" : ""}`}
              >
                {t}
                {run.proven_impact.includes(t) ? " ✓" : ""}
              </span>
            ))}
          </div>
        )}
      </header>

      <div className="poc-timeline">
        {PHASES.map((p, i) => {
          const done = i < currentIndex || run.state === "done";
          const active = i === currentIndex && !TERMINAL.has(run.state);
          const failed = run.state === "failed" && i === currentIndex;
          return (
            <div
              key={p}
              className={`poc-phase ${done ? "done" : ""} ${active ? "active" : ""} ${
                failed ? "failed" : ""
              }`}
            >
              <span className="poc-phase-dot" />
              <span className="poc-phase-label">{p}</span>
            </div>
          );
        })}
      </div>

      <div className="poc-artifacts">
        {run.mirror_owner && run.mirror_repo && (
          <a
            href={`https://github.com/${run.mirror_owner}/${run.mirror_repo}`}
            target="_blank"
            rel="noreferrer"
            className="poc-artifact"
          >
            Mirror repo → {run.mirror_owner}/{run.mirror_repo}
          </a>
        )}
        {run.attacker_owner && run.attacker_fork && (
          <a
            href={`https://github.com/${run.attacker_owner}/${run.attacker_fork}`}
            target="_blank"
            rel="noreferrer"
            className="poc-artifact"
          >
            Attacker fork → {run.attacker_owner}/{run.attacker_fork}
          </a>
        )}
        {run.workflow_run_url && (
          <a
            href={run.workflow_run_url}
            target="_blank"
            rel="noreferrer"
            className="poc-artifact"
          >
            Workflow run ↗
          </a>
        )}
        {run.mirror_mode && (
          <span className="poc-artifact static">
            mirror mode: <code>{run.mirror_mode}</code>
          </span>
        )}
        <span className="poc-artifact static">marker: <code>{run.marker}</code></span>
      </div>

      {run.error && (
        <div className="error poc-error">Error: {run.error}</div>
      )}

      {run.evidence && run.evidence.length > 0 && (
        <div className="poc-evidence">
          <div className="poc-evidence-title">Observed signals ({run.evidence.length})</div>
          <ul>
            {run.evidence.map((s, i) => (
              <li key={i}>
                <span className="poc-tag">{s.signal_type}</span>
                <span>{s.matched_by || "(no description)"}</span>
                {s.where && (
                  <a href={s.where} target="_blank" rel="noreferrer" className="poc-evidence-where">
                    ↗
                  </a>
                )}
                {s.tags && s.tags.length > 0 && (
                  <span className="poc-evidence-tags">
                    {s.tags.map((t) => (
                      <span key={t} className="poc-tag mini">
                        {t}
                      </span>
                    ))}
                  </span>
                )}
              </li>
            ))}
          </ul>
        </div>
      )}

      <div className="poc-log-header">
        <span>Live log</span>
        <label>
          <input
            type="checkbox"
            checked={autoscroll}
            onChange={(e) => setAutoscroll(e.target.checked)}
          />
          Autoscroll
        </label>
      </div>
      <pre className="poc-log" ref={logRef}>
        {run.logs
          .map(
            (l) =>
              `[${new Date(l.ts * 1000).toLocaleTimeString()}] ${l.phase.padEnd(10)} ${
                l.level.toUpperCase().padEnd(5)
              } ${l.message}`
          )
          .join("\n")}
      </pre>
    </div>
  );
}

// -----------------------------------------------------------------------------
// NewPocPanel
// -----------------------------------------------------------------------------
type NewPocPanelProps = {
  findingId: string;
  setFindingId: (v: string) => void;
  lockFindingId?: boolean;
  preview: DriverPreview | null;
  err: string | null;
  tokens: LivePocTokensInfo;
  drivers: string[];
  useRealRepo: boolean;
  setUseRealRepo: (v: boolean) => void;
  realRepoConfirm: boolean;
  setRealRepoConfirm: (v: boolean) => void;
  keepRepos: boolean;
  setKeepRepos: (v: boolean) => void;
  forceMinimal: boolean;
  setForceMinimal: (v: boolean) => void;
  starting: boolean;
  onStart: () => void;
  onCancel: () => void;
  maintainerInput: string;
  setMaintainerInput: (v: string) => void;
  attackerInput: string;
  setAttackerInput: (v: string) => void;
  canaryInput: string;
  setCanaryInput: (v: string) => void;
  canaryKind: string;
  setCanaryKind: (v: string) => void;
  canaryHistoryUrl: string;
  setCanaryHistoryUrl: (v: string) => void;
  tokensLoading: boolean;
  tokenSaveErr: string | null;
  onSaveTokens: (payload: Record<string, string | null>) => Promise<void>;
  onForgetTokens: () => Promise<void>;
};

function NewPocPanel(props: NewPocPanelProps) {
  const {
    findingId,
    setFindingId,
    lockFindingId,
    preview,
    err,
    tokens,
    drivers,
    useRealRepo,
    setUseRealRepo,
    realRepoConfirm,
    setRealRepoConfirm,
    keepRepos,
    setKeepRepos,
    forceMinimal,
    setForceMinimal,
    starting,
    onStart,
    onCancel,
    maintainerInput,
    setMaintainerInput,
    attackerInput,
    setAttackerInput,
    canaryInput,
    setCanaryInput,
    canaryKind,
    setCanaryKind,
    canaryHistoryUrl,
    setCanaryHistoryUrl,
    tokensLoading,
    tokenSaveErr,
    onSaveTokens,
    onForgetTokens,
  } = props;

  const canStart = !!preview && !!tokens.maintainer && !!tokens.attacker && !starting;

  return (
    <div className="poc-new-pane">
      <div className="poc-new-header">
        <h2>New Live PoC run</h2>
        <button className="btn ghost" onClick={onCancel}>
          Cancel
        </button>
      </div>

      {/* Step 1: Tokens */}
      <section className="poc-new-section">
        <h3>1. Credentials</h3>
        <div className="poc-tokens-grid">
          <TokenSlot
            label="Maintainer PAT"
            help="Owns the private mirror. Needs scopes: repo, workflow, delete_repo."
            info={tokens.maintainer}
            input={maintainerInput}
            setInput={setMaintainerInput}
            onSave={() =>
              onSaveTokens({ maintainer_token: maintainerInput || null })
            }
          />
          <TokenSlot
            label="Attacker PAT"
            help="Forks the mirror + opens PR/issue/comment. Needs scope: repo."
            info={tokens.attacker}
            input={attackerInput}
            setInput={setAttackerInput}
            onSave={() =>
              onSaveTokens({ attacker_token: attackerInput || null })
            }
          />
          <div className="poc-token-slot">
            <div className="poc-token-slot-label">Canary token (optional)</div>
            <div className="poc-token-slot-help">
              canarytokens.org token that phones home when used. Enables{" "}
              <code>secrets_exposure</code> proof.
            </div>
            {tokens.canary?.preview && (
              <div className="poc-token-slot-saved">
                Saved: <code>{tokens.canary.preview}</code> · kind{" "}
                <code>{tokens.canary.kind}</code>
                {tokens.canary.history_url && (
                  <>
                    {" "}·{" "}
                    <a href={tokens.canary.history_url} target="_blank" rel="noreferrer">
                      history ↗
                    </a>
                  </>
                )}
              </div>
            )}
            <input
              type="password"
              placeholder="Canary token…"
              value={canaryInput}
              onChange={(e) => setCanaryInput(e.target.value)}
            />
            <div className="poc-token-canary-inline">
              <select value={canaryKind} onChange={(e) => setCanaryKind(e.target.value)}>
                <option value="http">http</option>
                <option value="aws">aws</option>
                <option value="dns">dns</option>
              </select>
              <input
                type="text"
                placeholder="History URL (optional)"
                value={canaryHistoryUrl}
                onChange={(e) => setCanaryHistoryUrl(e.target.value)}
              />
              <button
                className="btn ghost"
                disabled={!canaryInput || tokensLoading}
                onClick={() =>
                  onSaveTokens({
                    canary_token: canaryInput || null,
                    canary_kind: canaryKind,
                    canary_history_url: canaryHistoryUrl || null,
                  })
                }
              >
                Save
              </button>
            </div>
          </div>
        </div>
        {tokenSaveErr && <div className="error">{tokenSaveErr}</div>}
        <div className="poc-tokens-actions">
          <button className="btn ghost danger" onClick={onForgetTokens}>
            Forget all Live PoC tokens
          </button>
        </div>
      </section>

      {/* Step 2: Finding */}
      <section className="poc-new-section">
        <h3>2. Finding</h3>
        <input
          type="text"
          placeholder="Finding id (paste from the drawer, or click Live PoC → on a finding)"
          value={findingId}
          onChange={(e) => setFindingId(e.target.value)}
          readOnly={!!lockFindingId}
          title={lockFindingId ? "Live PoC in the drawer is scoped to the finding you opened." : undefined}
        />
        <div className="poc-new-hint">
          {lockFindingId
            ? "This Live PoC will verify the finding currently open in the drawer."
            : `Supported categories: ${drivers.length > 0 ? drivers.join(", ") : "loading…"}`}
        </div>
      </section>

      {/* Step 3: Preview */}
      <section className="poc-new-section">
        <h3>3. Preview</h3>
        {err && <div className="error">{err}</div>}
        {!preview ? (
          <div className="poc-new-hint">
            Paste a finding id above to see the Claim, payload, and success requirement.
          </div>
        ) : (
          <div className="poc-preview">
            <div className="poc-preview-claim">
              <strong>Claim:</strong> {preview.claim}
            </div>
            <div className="poc-preview-tags">
              <strong>Impact tags:</strong>{" "}
              {preview.impact_tags.map((t) => (
                <span key={t} className="poc-tag">
                  {t}
                </span>
              ))}
            </div>
            <div className="poc-preview-signals">
              <strong>We will confirm this when we observe:</strong>
              <ul>
                {preview.success_criteria.map((c, i) => (
                  <li key={i}>{c}</li>
                ))}
              </ul>
            </div>
            <div className="poc-preview-payload">
              <strong>Payload:</strong> {preview.payload_summary}
            </div>
          </div>
        )}
      </section>

      {/* Step 4: Options */}
      <section className="poc-new-section">
        <h3>4. Options</h3>
        <label className="poc-checkbox">
          <input
            type="checkbox"
            checked={keepRepos}
            onChange={(e) => setKeepRepos(e.target.checked)}
          />
          Keep mirror + fork repos after the run (for debugging)
        </label>
        <label className="poc-checkbox">
          <input
            type="checkbox"
            checked={forceMinimal}
            onChange={(e) => setForceMinimal(e.target.checked)}
          />
          Force minimal-mirror mode (workflow + relevant files only)
        </label>
        <label className={`poc-checkbox ${preview?.supports_real_repo_mode ? "" : "disabled"}`}>
          <input
            type="checkbox"
            checked={useRealRepo}
            disabled={!preview?.supports_real_repo_mode}
            onChange={(e) => {
              setUseRealRepo(e.target.checked);
              if (!e.target.checked) setRealRepoConfirm(false);
            }}
          />
          Run against the real target repo (not the mirror){" "}
          {!preview?.supports_real_repo_mode && (
            <span className="poc-new-hint">— not supported by this driver</span>
          )}
        </label>
        {useRealRepo && (
          <label className="poc-checkbox warn">
            <input
              type="checkbox"
              checked={realRepoConfirm}
              onChange={(e) => setRealRepoConfirm(e.target.checked)}
            />
            I own / have explicit permission to test this repo.
          </label>
        )}
      </section>

      <div className="poc-new-actions">
        <button className="btn primary" disabled={!canStart} onClick={onStart}>
          {starting ? "Starting…" : "Start Live PoC"}
        </button>
        {!tokens.maintainer && (
          <span className="poc-new-hint">Missing maintainer PAT</span>
        )}
        {!tokens.attacker && (
          <span className="poc-new-hint">Missing attacker PAT</span>
        )}
      </div>
    </div>
  );
}

function TokenSlot({
  label,
  help,
  info,
  input,
  setInput,
  onSave,
}: {
  label: string;
  help: string;
  info: LivePocIdentity | null | undefined;
  input: string;
  setInput: (v: string) => void;
  onSave: () => void;
}) {
  return (
    <div className="poc-token-slot">
      <div className="poc-token-slot-label">{label}</div>
      <div className="poc-token-slot-help">{help}</div>
      {info?.login ? (
        <div className="poc-token-slot-saved">
          Saved: <strong>{redactGitHubLogin(info.login)}</strong> · <code>{info.preview}</code>
        </div>
      ) : (
        <div className="poc-token-slot-empty">Not saved</div>
      )}
      <div className="poc-token-slot-input">
        <input
          type="password"
          placeholder="Paste PAT to save…"
          value={input}
          onChange={(e) => setInput(e.target.value)}
        />
        <button className="btn ghost" disabled={!input} onClick={onSave}>
          Save
        </button>
      </div>
    </div>
  );
}
