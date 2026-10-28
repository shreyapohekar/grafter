import { useCallback, useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import GitHubQuota, { type TokenPoolQuota } from "./GitHubQuota";
import { redactGitHubLogin } from "./redaction";

export type ScanJob = TokenPoolQuota & {
  id: string;
  scan_id: string;
  org: string;
  state: string;
  priority: number;
  created_at: number;
  updated_at: number;
  started_at?: number | null;
  finished_at?: number | null;
  next_attempt_at?: number | null;
  retry_count: number;
  max_retries: number;
  repos_total: number;
  repos_completed: number;
  repos_failed: number;
  workflows_scanned: number;
  findings_count?: number;
  rate_limit_limit?: number | null;
  rate_limit_remaining?: number | null;
  rate_limit_reset?: number | null;
  error?: string | null;
  all_rules: boolean;
  selected_rules: string[];
  selected_rule_count: number;
  selected_rule_labels: string[];
  activity?: string | null;
  activity_updated_at?: number | null;
  active_repositories?: number;
  requests_queued?: number;
  requests_in_flight?: number;
  requests_completed?: number;
  requests_backing_off?: number;
  last_response_at?: number | null;
  token_pool_size?: number;
  token_rotations?: number;
  rate_limit_warning?: string | null;
};

type ScanJobPage = {
  total: number;
  items: ScanJob[];
};

export type QueueSummary = {
  pending: number;
  running: number;
  waiting_rate_limit: number;
  completed: number;
  failed: number;
  cancelled: number;
};

type QueueViewProps = {
  visible: boolean;
  focusJobId?: string | null;
  onOpenScan: (scanId: string) => void;
  onSummaryChange?: (summary: QueueSummary) => void;
};

const ACTIVE = new Set(["pending", "starting", "running", "waiting_rate_limit"]);
const TERMINAL = new Set(["completed", "failed", "cancelled"]);

function fmtTime(value?: number | null): string {
  return value ? new Date(value * 1000).toLocaleString() : "—";
}

function fmtCountdown(value?: number | null): string {
  if (!value) return "waiting for quota";
  const seconds = Math.max(0, Math.ceil(value - Date.now() / 1000));
  if (seconds < 60) return `${seconds}s`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ${seconds % 60}s`;
  return `${Math.floor(minutes / 60)}h ${minutes % 60}m`;
}

function fmtAge(value: number): string {
  const seconds = Math.max(0, Math.floor(Date.now() / 1000 - value));
  if (seconds < 60) return `${seconds}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s ago`;
  return `${Math.floor(seconds / 3600)}h ${Math.floor((seconds % 3600) / 60)}m ago`;
}

async function apiAction(url: string, init?: RequestInit): Promise<void> {
  const response = await fetch(url, { credentials: "include", ...init });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || `HTTP ${response.status}`);
  }
}

export default function QueueView({
  visible,
  focusJobId,
  onOpenScan,
  onSummaryChange,
}: QueueViewProps) {
  const [jobs, setJobs] = useState<ScanJob[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [busyId, setBusyId] = useState<string | null>(null);
  const [, setClock] = useState(0);
  const hasActive = jobs.some((job) => ACTIVE.has(job.state));

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [jobsResponse, summaryResponse] = await Promise.all([
        fetch("/api/scan-jobs?limit=500", { credentials: "include" }),
        fetch("/api/scan-jobs/summary", { credentials: "include" }),
      ]);
      if (!jobsResponse.ok) throw new Error(`Queue HTTP ${jobsResponse.status}`);
      if (!summaryResponse.ok) throw new Error(`Summary HTTP ${summaryResponse.status}`);
      const page: ScanJobPage = await jobsResponse.json();
      const summary: QueueSummary = await summaryResponse.json();
      setJobs(page.items || []);
      onSummaryChange?.(summary);
      setError(null);
    } catch (err) {
      setError(String((err as Error).message || err));
    } finally {
      setLoading(false);
    }
  }, [onSummaryChange]);

  useEffect(() => {
    if (!visible) return;
    void load();
  }, [visible, load]);

  useEffect(() => {
    if (!visible) return;
    const interval = window.setInterval(() => void load(), hasActive ? 2500 : 8000);
    return () => window.clearInterval(interval);
  }, [visible, hasActive, load]);

  useEffect(() => {
    if (!visible || !hasActive) return;
    const interval = window.setInterval(() => setClock((value) => value + 1), 1000);
    return () => window.clearInterval(interval);
  }, [visible, hasActive]);

  useEffect(() => {
    if (!visible || !focusJobId) return;
    document.getElementById(`scan-job-${focusJobId}`)?.scrollIntoView({ block: "center" });
  }, [visible, focusJobId, jobs]);

  const groups = useMemo(() => ({
    running: jobs.filter((job) => job.state === "running" || job.state === "starting"),
    waiting: jobs.filter((job) => job.state === "waiting_rate_limit"),
    pending: jobs.filter((job) => job.state === "pending"),
    history: jobs.filter((job) => TERMINAL.has(job.state)),
  }), [jobs]);

  async function act(jobId: string, action: "cancel" | "retry" | "delete" | "up" | "down") {
    if (action === "delete" && !window.confirm("Delete this terminal queue record? Scan findings are preserved.")) {
      return;
    }
    setBusyId(jobId);
    try {
      if (action === "delete") {
        await apiAction(`/api/scan-jobs/${jobId}`, { method: "DELETE" });
      } else if (action === "up" || action === "down") {
        await apiAction(`/api/scan-jobs/${jobId}/move`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ direction: action }),
        });
      } else {
        await apiAction(`/api/scan-jobs/${jobId}/${action}`, { method: "POST" });
      }
      await load();
    } catch (err) {
      setError(String((err as Error).message || err));
    } finally {
      setBusyId(null);
    }
  }

  if (!visible) return null;

  return (
    <div className="queue-view">
      <div className="queue-header">
        <div>
          <h2>Scan Queue</h2>
          <div className="note">Rate-limited scans resume from the first unfinished repository.</div>
        </div>
        <button className="btn ghost" onClick={() => void load()} disabled={loading}>
          {loading ? "Refreshing…" : "Refresh"}
        </button>
      </div>
      {error && <div className="error">{error}</div>}

      <QueueSection title="Running" jobs={groups.running}>
        {(job) => <QueueRow key={job.id} job={job} busy={busyId === job.id} onOpenScan={onOpenScan} onAction={act} />}
      </QueueSection>
      <QueueSection title="Waiting for GitHub rate limit" jobs={groups.waiting}>
        {(job) => <QueueRow key={job.id} job={job} busy={busyId === job.id} onOpenScan={onOpenScan} onAction={act} />}
      </QueueSection>
      <QueueSection title="Pending" jobs={groups.pending}>
        {(job) => <QueueRow key={job.id} job={job} busy={busyId === job.id} onOpenScan={onOpenScan} onAction={act} />}
      </QueueSection>
      <QueueSection title="History" jobs={groups.history}>
        {(job) => <QueueRow key={job.id} job={job} busy={busyId === job.id} onOpenScan={onOpenScan} onAction={act} />}
      </QueueSection>
    </div>
  );
}

function QueueSection({
  title,
  jobs,
  children,
}: {
  title: string;
  jobs: ScanJob[];
  children: (job: ScanJob) => ReactNode;
}) {
  return (
    <section className="queue-section">
      <div className="queue-section-title">{title} <span>{jobs.length}</span></div>
      {jobs.length === 0 ? <div className="queue-empty">No jobs in this state.</div> : jobs.map(children)}
    </section>
  );
}

function QueueRow({
  job,
  busy,
  onOpenScan,
  onAction,
}: {
  job: ScanJob;
  busy: boolean;
  onOpenScan: (scanId: string) => void;
  onAction: (jobId: string, action: "cancel" | "retry" | "delete" | "up" | "down") => void;
}) {
  const complete = job.repos_completed + job.repos_failed;
  const progress = job.repos_total ? Math.min(100, Math.round((complete / job.repos_total) * 100)) : 0;
  const hasLiveProgress = job.requests_queued != null && job.requests_in_flight != null;
  return (
    <article id={`scan-job-${job.id}`} className={`queue-row ${job.state}`}>
      <div className="queue-row-main">
        <div>
          <strong>{job.org}</strong>
          <span className={`queue-state ${job.state}`}>{job.state.replace(/_/g, " ")}</span>
        </div>
        <div className="queue-meta">
          {job.repos_completed} completed · {job.repos_failed} failed · {Math.max(0, job.repos_total - complete)} unfinished / {job.repos_total || "?"} repos
          {" · "}{job.workflows_scanned} workflow downloads (includes retries)
          {job.findings_count != null && ` · ${job.findings_count} unique findings saved`}
          {" · "}created {fmtTime(job.created_at)}
        </div>
        <div
          className="queue-rule-scope"
          title={job.all_rules ? "All scanner rules" : job.selected_rule_labels.join("\n")}
        >
          {job.all_rules
            ? `All rules (${job.selected_rule_count})`
            : `${job.selected_rule_count} selected rule${job.selected_rule_count === 1 ? "" : "s"}`}
          {!job.all_rules && job.selected_rule_labels.length > 0 && (
            <span> · {job.selected_rule_labels.join(", ")}</span>
          )}
        </div>
        <div className="queue-progress"><span style={{ width: `${progress}%` }} /></div>
        {(job.state === "running" || job.state === "starting") && (
          <div className="queue-activity" role="status">
            <div>{job.activity || (hasLiveProgress
              ? "Preparing scan and loading saved repository checkpoints..."
              : "Live activity unavailable: the backend must restart to load the queue update.")}</div>
            <div>
              <GitHubQuota quota={job} />
              {hasLiveProgress
                ? ` · ${(job.requests_queued ?? 0) + (job.requests_in_flight ?? 0)} pending (${job.requests_queued} queued, ${job.requests_in_flight} in flight) · ${job.requests_completed ?? 0} responses received`
                : " · live request counters unavailable"}
            </div>
            <div className={job.requests_backing_off ? "queue-backoff" : ""}>
              {!hasLiveProgress
                ? `Last saved progress ${fmtAge(job.updated_at)}; quota shown is the last saved snapshot`
                : job.requests_backing_off
                ? `${job.requests_backing_off} requests backing off before retrying GitHub`
                : `${job.active_repositories ?? 0} active repositories`}
              {job.last_response_at
                ? ` · last GitHub response ${fmtAge(job.last_response_at)}`
                : job.activity_updated_at ? ` · phase started ${fmtAge(job.activity_updated_at)}` : ""}
              {(job.token_pool_size ?? 1) > 1 && ` · ${job.token_pool_size} tokens, ${job.token_rotations ?? 0} rotations`}
              {(job.pool_accounts?.length ?? 0) > 1 && ` · accounts: ${job.pool_accounts!.map(
                (account) => `${redactGitHubLogin(account.account)} ${account.remaining}/${account.limit}`
              ).join(" + ")}`}
              {job.repos_failed > 0 && ` · ${job.repos_failed} repositories failed; Retry will revisit them when this attempt finishes`}
              {job.rate_limit_warning && ` · ${job.rate_limit_warning}`}
            </div>
          </div>
        )}
        {job.state === "pending" && (
          <div className="queue-meta">Waiting for a scan worker slot. This job will start automatically.</div>
        )}
        {job.state === "waiting_rate_limit" && (
          <div className="queue-wait">
            Resumes in {fmtCountdown(job.next_attempt_at)}
            {" · "}<GitHubQuota quota={job} />
            {(job.token_pool_size ?? 1) > 1 && ` · ${job.token_rotations ?? 0} token rotations`}
            {` · retry ${job.retry_count}/${job.max_retries}`}
            {" · Completed repositories and findings are saved; interrupted repositories restart from their beginning."}
          </div>
        )}
        {job.error && <div className="queue-error">{job.error}</div>}
      </div>
      <div className="queue-actions">
        <button className="btn ghost" disabled={busy} onClick={() => onOpenScan(job.scan_id)}>Findings</button>
        {job.state === "pending" && (
          <>
            <button className="btn ghost" disabled={busy} onClick={() => onAction(job.id, "up")}>↑</button>
            <button className="btn ghost" disabled={busy} onClick={() => onAction(job.id, "down")}>↓</button>
          </>
        )}
        {ACTIVE.has(job.state) && (
          <button className="btn ghost" disabled={busy} onClick={() => onAction(job.id, "cancel")}>Cancel</button>
        )}
        {(job.state === "failed" || job.state === "cancelled") && (
          <button className="btn" disabled={busy} onClick={() => onAction(job.id, "retry")}>Retry</button>
        )}
        {TERMINAL.has(job.state) && (
          <button className="btn ghost" disabled={busy} onClick={() => onAction(job.id, "delete")}>Delete</button>
        )}
      </div>
    </article>
  );
}
