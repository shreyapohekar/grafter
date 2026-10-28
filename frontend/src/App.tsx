import { useCallback, useEffect, useRef, useState, type FormEvent, type MouseEvent } from "react";
import { createPortal } from "react-dom";
import LivePocView from "./LivePocView";
import JobsView from "./JobsView";
import QueueView, { type QueueSummary } from "./QueueView";
import GitHubQuota, { type TokenPoolQuota } from "./GitHubQuota";
import { redactGitHubLogin } from "./redaction";

type Finding = {
  id: string;
  scan_id?: string | null;
  repo: string;
  repo_url: string;
  workflow_path: string;
  workflow_url: string;
  job?: string;
  step?: string;
  trigger: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  exploitability: string;
  confidence: number;
  title: string;
  why: string[];
  evidence: string[];
  remediation: string[];
  snippet: string;
  category?: string | null;
  created_at?: number | null;
  manual_verdict?: "true_positive" | "false_positive" | "true_positive_severity_overstated" | null;
  manual_verdict_at?: number | null;
  gates_detected?: string[];
  tainted_expression?: string | null;
  detected_sink_line?: string | null;
  line_number?: number | null;
  archived_state?: "fixed" | "deleted" | "modified" | "live" | null;
  archived_at?: number | null;
  archived_reason?: string | null;
  last_recheck_at?: number | null;
  last_recheck_head_sha?: string | null;
};

type FindingListItem = Omit<Finding, "why" | "evidence" | "remediation" | "snippet" | "tainted_expression" | "detected_sink_line" | "line_number" | "last_recheck_head_sha">;

type ScanStatus = TokenPoolQuota & {
  id: string;
  state: "running" | "done" | "error" | "pending" | "starting" | "waiting_rate_limit" | "cancelled";
  progress: number;
  repos_total: number;
  repos_scanned: number;
  workflows_scanned: number;
  findings: Finding[];
  error?: string | null;
  rate_limit_limit?: number | null;
  rate_limit_remaining?: number | null;
  rate_limit_reset?: number | null;
  rate_limit_warning?: string | null;
  token_pool_size?: number | null;
  token_rotations?: number | null;
  job_id?: string | null;
  queue_state?: string | null;
  all_rules?: boolean;
  selected_rules?: string[];
  selected_rule_count?: number;
};

type FindingsPage = {
  total: number;
  page: number;
  page_size: number;
  items: FindingListItem[];
};

type TrendItem = {
  day: string;
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  true_positive: number;
  false_positive: number;
  true_positive_severity_overstated?: number;
  unreviewed: number;
};

type BugBountyReport = {
  title: string;
  severity: string;
  cvss_estimate: string;
  cvss_vector: string | null;
  cvss_score: number | null;
  summary: string;
  root_cause: string;
  vulnerable_line: string;
  tainted_expression?: string | null;
  detected_sink_line?: string | null;
  affected_asset: string;
  vulnerability_class: string;
  impact: string;
  steps_to_reproduce: string[];
  proof_of_concept: string;
  fix_diff: string;
  remediation: string[];
  references: string[];
  markdown: string;
};

type RecheckResult = {
  id: string;
  archived_state: "fixed" | "deleted" | "modified" | "live" | null;
  archived_reason: string | null;
  last_recheck_at: number | null;
  last_recheck_head_sha: string | null;
  finding: Finding;
};

type ScanListItem = {
  id: string;
  org: string;
  state: string;
  started: number | null;
  finished: number | null;
  repos_total: number;
  repos_scanned: number;
  workflows_scanned: number;
  findings_count: number;
  error: string | null;
  all_rules: boolean;
  selected_rules: string[];
  selected_rule_count: number;
};

type DiffScanRef = {
  id: string;
  org: string;
  state: string;
  started: number | null;
  finished: number | null;
  all_rules: boolean;
  selected_rules: string[];
  selected_rule_count: number;
};

type FindingChangeItem = FindingListItem & {
  previous_severity: string | null;
  previous_confidence: number | null;
  severity_delta: "up" | "down" | "same" | null;
  confidence_delta: number | null;
};

type DiffResult = {
  current: DiffScanRef;
  previous: DiffScanRef | null;
  summary: {
    new: number;
    persistent: number;
    fixed: number;
    severity_changed: number;
  };
  new: FindingListItem[];
  persistent: FindingChangeItem[];
  fixed: FindingListItem[];
  severity_changed: FindingChangeItem[];
  compared_rules: string[];
  scope_warning?: string | null;
};

type RuleCatalogItem = {
  key: string;
  label: string;
};

type AskAIEvidenceRef = {
  file: string;
  lines: string;
  reason: string;
};

type AskAIResponse = {
  verdict: string;
  final_severity: string;
  confidence: string;
  attacker_can_exploit: boolean;
  summary: string;
  blocking_gates: string[];
  severity_lowering_factors: string[];
  attacker_model: string;
  required_preconditions: string[];
  realistic_exploit_path: string[];
  ease_of_exploit: string;
  reliability: string;
  real_impact: string;
  why_overstated?: string | null;
  evidence: AskAIEvidenceRef[];
  recommendation: string;
};

type SavedTokenInfo = {
  saved: boolean;
  login?: string | null;
  saved_at?: number | null;
  token_preview?: string | null;
};

type SavedTokenEntry = {
  login?: string | null;
  saved_at?: number | null;
  token_preview: string;
};

type SavedTokenPool = {
  tokens: SavedTokenEntry[];
};

type AuthInfo = {
  authenticated: boolean;
  username?: string | null;
};

const PAGE_SIZE = 50;
const RULE_SELECTION_STORAGE_KEY = "grafter.selected-rules.v1";

export default function App() {
  const [authChecked, setAuthChecked] = useState(false);
  const [authenticated, setAuthenticated] = useState(false);
  const [authUser, setAuthUser] = useState<string | null>(null);
  const [loginUser, setLoginUser] = useState("admin");
  const [loginPassword, setLoginPassword] = useState("");
  const [loginError, setLoginError] = useState<string | null>(null);
  const [loginBusy, setLoginBusy] = useState(false);
  const [loginShowPw, setLoginShowPw] = useState(false);

  const [org, setOrg] = useState("");
  const [token, setToken] = useState("");
  const [githubFieldsLocked, setGithubFieldsLocked] = useState(true);
  const [includeForks, setIncludeForks] = useState(false);
  const [maxRepos, setMaxRepos] = useState(200);
  const [availableRules, setAvailableRules] = useState<RuleCatalogItem[]>([]);
  const [selectedRules, setSelectedRules] = useState<Set<string>>(new Set());
  const [rulesLoading, setRulesLoading] = useState(false);
  const [rulesError, setRulesError] = useState<string | null>(null);
  const [rulesReloadVersion, setRulesReloadVersion] = useState(0);
  const [ruleMenuOpen, setRuleMenuOpen] = useState(false);
  const [ruleSearch, setRuleSearch] = useState("");
  const ruleMenuRef = useRef<HTMLDivElement | null>(null);
  const ruleMenuButtonRef = useRef<HTMLButtonElement | null>(null);
  const [status, setStatus] = useState<ScanStatus | null>(null);
  const [scanId, setScanId] = useState<string | null>(null);
  const [selected, setSelected] = useState<Finding | null>(null);
  const [selectedLoading, setSelectedLoading] = useState(false);
  const [report, setReport] = useState<BugBountyReport | null>(null);
  const [reportLoading, setReportLoading] = useState(false);
  const [askAI, setAskAI] = useState<AskAIResponse | null>(null);
  const [askAILoading, setAskAILoading] = useState(false);
  const [askAIError, setAskAIError] = useState<string | null>(null);
  const [manualVerdictSaving, setManualVerdictSaving] = useState(false);
  const [manualVerdictError, setManualVerdictError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [reportMenuOpen, setReportMenuOpen] = useState(false);
  const reportMenuRef = useRef<HTMLDivElement | null>(null);
  const [drawerTab, setDrawerTab] = useState<"details" | "graph" | "live-poc">("details");

  const [filterRepo, setFilterRepo] = useState("");
  const [filterSev, setFilterSev] = useState("ALL");
  const [filterExp, setFilterExp] = useState("ALL");
  const [filterCat, setFilterCat] = useState("ALL");
  const [filterState, setFilterState] = useState<"live" | "archived" | "all">("live");
  const [sinkSourceSearch, setSinkSourceSearch] = useState("");
  const [sortBy, setSortBy] = useState<"severity" | "newest" | "oldest">("severity");
  const [categories, setCategories] = useState<{ key: string; label: string; count: number }[]>([]);
  const [trend, setTrend] = useState<TrendItem[]>([]);
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [bulkBusy, setBulkBusy] = useState(false);
  const [deleteAllBusy, setDeleteAllBusy] = useState(false);
  const [findingsLoading, setFindingsLoading] = useState(false);
  const [recheckBusy, setRecheckBusy] = useState(false);
  const [recheckMessage, setRecheckMessage] = useState<string | null>(null);
  const [scanFilter, setScanFilter] = useState<"this" | "all">("all");
  const [exportMenuOpen, setExportMenuOpen] = useState(false);
  const [exportMenuRect, setExportMenuRect] = useState<{ top: number; right: number } | null>(null);
  const exportMenuRef = useRef<HTMLDivElement | null>(null);
  const exportMenuBtnRef = useRef<HTMLButtonElement | null>(null);
  const [catMenuOpen, setCatMenuOpen] = useState(false);
  const [catSearch, setCatSearch] = useState("");
  const [catMenuRect, setCatMenuRect] = useState<{ top: number; left: number; width: number } | null>(null);
  const catMenuRef = useRef<HTMLDivElement | null>(null);
  const catMenuBtnRef = useRef<HTMLButtonElement | null>(null);
  const catSearchInputRef = useRef<HTMLInputElement | null>(null);
  const [mainView, setMainView] = useState<"findings" | "diff" | "rules" | "jobs" | "queue">("findings");
  const [livePocRefresh, setLivePocRefresh] = useState<number>(0);
  const [activeLivePocFindings, setActiveLivePocFindings] = useState<Set<string>>(new Set());
  const [queueSummary, setQueueSummary] = useState<QueueSummary>({
    pending: 0,
    running: 0,
    waiting_rate_limit: 0,
    completed: 0,
    failed: 0,
    cancelled: 0,
  });
  const [queueFocusJobId, setQueueFocusJobId] = useState<string | null>(null);
  const [diffData, setDiffData] = useState<DiffResult | null>(null);
  const [diffLoading, setDiffLoading] = useState(false);
  const [diffError, setDiffError] = useState<string | null>(null);
  const [diffScanId, setDiffScanId] = useState<string | null>(null);
  const [diffAgainstId, setDiffAgainstId] = useState<string>("previous");
  const [diffScanList, setDiffScanList] = useState<ScanListItem[]>([]);
  const [diffPersistentFilter, setDiffPersistentFilter] = useState<"all" | "changed">("all");
  const [page, setPage] = useState(1);
  const [pageData, setPageData] = useState<FindingsPage>({
    total: 0,
    page: 1,
    page_size: PAGE_SIZE,
    items: [],
  });
  const [counts, setCounts] = useState<Record<string, number>>({
    CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0,
  });
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState<SavedTokenInfo>({ saved: false });
  const [tokenPool, setTokenPool] = useState<SavedTokenEntry[]>([]);
  const [poolTokenInput, setPoolTokenInput] = useState("");
  const [poolBusy, setPoolBusy] = useState(false);
  const [poolError, setPoolError] = useState<string | null>(null);
  const [poolExpanded, setPoolExpanded] = useState(false);

  const effectiveScanId = scanFilter === "this" ? scanId : null;

  useEffect(() => {
    if (!authenticated) return;
    let cancelled = false;
    setRulesLoading(true);
    setRulesError(null);
    void fetch("/api/rules", { credentials: "include" })
      .then(async (response) => {
        if (!response.ok) throw new Error(`Rules HTTP ${response.status}`);
        return await response.json() as RuleCatalogItem[];
      })
      .then((rules) => {
        if (cancelled) return;
        const validKeys = new Set(rules.map((rule) => rule.key));
        let next = new Set(validKeys);
        try {
          const stored = JSON.parse(localStorage.getItem(RULE_SELECTION_STORAGE_KEY) || "null");
          if (stored && stored.all === false && Array.isArray(stored.rules)) {
            next = new Set(
              stored.rules
                .map((key: unknown) => String(key))
                .filter((key: string) => validKeys.has(key)),
            );
          }
        } catch {
          next = new Set(validKeys);
        }
        setAvailableRules(rules);
        setSelectedRules(next);
      })
      .catch((err) => {
        if (!cancelled) setRulesError(String((err as Error).message || err));
      })
      .finally(() => {
        if (!cancelled) setRulesLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [authenticated, rulesReloadVersion]);

  useEffect(() => {
    if (availableRules.length === 0) return;
    const allSelected = selectedRules.size === availableRules.length;
    localStorage.setItem(
      RULE_SELECTION_STORAGE_KEY,
      JSON.stringify({
        all: allSelected,
        rules: allSelected ? [] : Array.from(selectedRules),
      }),
    );
  }, [availableRules, selectedRules]);

  useEffect(() => {
    if (!ruleMenuOpen) return;
    function closeRuleMenu(event: globalThis.MouseEvent | PointerEvent) {
      const target = event.target as Node | null;
      if (
        target
        && !ruleMenuRef.current?.contains(target)
        && !ruleMenuButtonRef.current?.contains(target)
      ) {
        setRuleMenuOpen(false);
      }
    }
    function onKey(event: KeyboardEvent) {
      if (event.key === "Escape") setRuleMenuOpen(false);
    }
    document.addEventListener("mousedown", closeRuleMenu);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", closeRuleMenu);
      document.removeEventListener("keydown", onKey);
    };
  }, [ruleMenuOpen]);

  const reloadFindings = useCallback(async () => {
    if (!authenticated) return;
    setFindingsLoading(true);
    try {
      const params = new URLSearchParams();
      params.set("page", String(page));
      params.set("page_size", String(PAGE_SIZE));
      if (filterRepo.trim()) params.set("repo", filterRepo.trim());
      if (filterSev !== "ALL") params.set("severity", filterSev);
      if (filterExp !== "ALL") params.set("exploitability", filterExp);
      if (filterCat !== "ALL") params.set("category", filterCat);
      if (sinkSourceSearch.trim()) params.set("q", sinkSourceSearch.trim());
      if (effectiveScanId) params.set("scan_id", effectiveScanId);
      params.set("sort", sortBy);
      params.set("state", filterState);

      const countsQs = `state=${filterState}${effectiveScanId ? `&scan_id=${effectiveScanId}` : ""}`;
      const [r1, r2, r3, r4] = await Promise.all([
        fetch(`/api/findings?${params.toString()}`),
        fetch(`/api/findings/counts?${countsQs}`),
        fetch(`/api/findings/categories?${countsQs}`),
        fetch(
          `/api/findings/trend?days=30${effectiveScanId ? `&scan_id=${effectiveScanId}` : ""}`
        ),
      ]);
      if (r1.status === 401 || r2.status === 401 || r3.status === 401 || r4.status === 401) {
        setAuthenticated(false);
        setAuthUser(null);
        setPageData({ total: 0, page: 1, page_size: PAGE_SIZE, items: [] });
        return;
      }
      if (r1.ok) setPageData(await r1.json());
      if (r2.ok) {
        const data = await r2.json();
        setCounts(data.counts ?? counts);
      }
      if (r3.ok) {
        const data = await r3.json();
        setCategories(data.categories ?? []);
      }
      if (r4.ok) {
        const data = await r4.json();
        setTrend(data.items ?? []);
      }
    } catch (e: any) {
      setError(String(e));
    } finally {
      setFindingsLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [authenticated, page, filterRepo, filterSev, filterExp, filterCat, filterState, sinkSourceSearch, effectiveScanId, sortBy]);

  // Check dashboard auth session on mount.
  useEffect(() => {
    (async () => {
      try {
        const r = await fetch("/api/auth/session");
        if (r.ok) {
          const data: AuthInfo = await r.json();
          setAuthenticated(data.authenticated);
          setAuthUser(data.username ?? null);
        }
      } catch {
        /* ignore */
      } finally {
        setAuthChecked(true);
      }
    })();
  }, []);

  // Load locally saved token info only after dashboard authentication.
  useEffect(() => {
    if (!authenticated) return;
    (async () => {
      try {
        const r = await fetch("/api/token");
        if (r.status === 401) {
          setAuthenticated(false);
          setAuthUser(null);
          return;
        }
        if (r.ok) setSaved(await r.json());
      } catch {
        /* ignore */
      }
      try {
        const p = await fetch("/api/tokens");
        if (p.ok) {
          const data: SavedTokenPool = await p.json();
          setTokenPool(data.tokens || []);
        }
      } catch {
        /* ignore */
      }
    })();
  }, [authenticated]);

  useEffect(() => {
    void reloadFindings();
  }, [reloadFindings]);

  // ---- Diff view data loaders ----
  const reloadScanList = useCallback(async () => {
    if (!authenticated) return;
    try {
      const r = await fetch(`/api/scans?limit=200`);
      if (!r.ok) return;
      const items: ScanListItem[] = await r.json();
      setDiffScanList(items);
    } catch {
      /* ignore */
    }
  }, [authenticated]);

  const reloadDiff = useCallback(async () => {
    if (!authenticated || mainView !== "diff") return;
    // Resolve the scan to diff against: the user's explicit picker
    // (diffScanId) or, failing that, the most recent scan visible in the
    // list.
    let target = diffScanId;
    if (!target) {
      if (diffScanList.length > 0) {
        target = diffScanList[0].id;
      } else if (scanId) {
        target = scanId;
      }
    }
    if (!target) {
      setDiffData(null);
      return;
    }
    setDiffLoading(true);
    setDiffError(null);
    try {
      const qs = new URLSearchParams({ against: diffAgainstId || "previous" });
      const r = await fetch(`/api/scans/${target}/diff?${qs.toString()}`);
      if (r.status === 401) {
        setAuthenticated(false);
        setAuthUser(null);
        return;
      }
      if (!r.ok) throw new Error(await r.text());
      const data: DiffResult = await r.json();
      setDiffData(data);
    } catch (e: any) {
      setDiffError(e?.message ?? String(e));
      setDiffData(null);
    } finally {
      setDiffLoading(false);
    }
  }, [authenticated, mainView, diffScanId, diffScanList, scanId, diffAgainstId]);

  useEffect(() => {
    if (mainView === "diff") {
      void reloadScanList();
    }
  }, [mainView, reloadScanList]);

  useEffect(() => {
    void reloadDiff();
  }, [reloadDiff]);

  // Poll active Live PoC runs so we know which finding cards should show
  // the blinking yellow dot. Fast poll when any run is active, slow poll
  // otherwise. Pause when the browser tab is hidden.
  useEffect(() => {
    if (!authenticated) return;
    let cancelled = false;
    let intervalMs = 8000;
    const poll = async () => {
      if (document.visibilityState === "hidden") return;
      try {
        const r = await fetch("/api/live-poc/runs?state=active&limit=200", { credentials: "include" });
        if (!r.ok) return;
        const j = await r.json();
        const items: Array<{ finding_id: string; state: string }> = j.items || [];
        const fids = new Set<string>();
        for (const it of items) {
          if (it.finding_id && !["done", "failed", "cancelled"].includes(it.state)) {
            fids.add(it.finding_id);
          }
        }
        if (!cancelled) {
          setActiveLivePocFindings(fids);
          intervalMs = fids.size > 0 ? 3000 : 8000;
        }
      } catch { /* noop */ }
    };
    void poll();
    let t = window.setInterval(poll, intervalMs);
    const restart = () => { window.clearInterval(t); t = window.setInterval(poll, intervalMs); };
    // Re-arm interval when adaptive interval changes
    const armCheck = window.setInterval(() => { restart(); }, 15000);
    const onVis = () => { if (document.visibilityState === "visible") void poll(); };
    document.addEventListener("visibilitychange", onVis);
    return () => {
      cancelled = true;
      window.clearInterval(t);
      window.clearInterval(armCheck);
      document.removeEventListener("visibilitychange", onVis);
    };
  }, [authenticated]);

  useEffect(() => {
    if (!authenticated) return;
    let wasRunning = false;
    const poll = async () => {
      if (document.visibilityState === "hidden") return;
      try {
        const response = await fetch("/api/scan-jobs/summary", { credentials: "include" });
        if (response.ok) {
          const summary: QueueSummary = await response.json();
          setQueueSummary(summary);
          if (summary.running > 0 || wasRunning) void reloadFindings();
          wasRunning = summary.running > 0;
        }
      } catch {
        // QueueView shows actionable errors when opened.
      }
    };
    void poll();
    const timer = window.setInterval(poll, 8000);
    return () => window.clearInterval(timer);
  }, [authenticated, reloadFindings]);

  // Poll scan status while running; refresh findings as new ones land.
  useEffect(() => {
    if (!scanId || !["running", "starting", "pending", "waiting_rate_limit"].includes(status?.state || "")) return;
    const t = setInterval(async () => {
      try {
        const r = await fetch(`/api/scan/${scanId}`);
        if (!r.ok) throw new Error(await r.text());
        const data: ScanStatus = await r.json();
        setStatus(data);
        void reloadFindings();
        if (["running", "starting"].includes(status?.state || "")
          && (data.state === "waiting_rate_limit" || data.state === "pending")) {
          setQueueFocusJobId(data.job_id ?? null);
          setMainView("queue");
        }
        if (!["running", "starting", "pending", "waiting_rate_limit"].includes(data.state)) clearInterval(t);
      } catch (e: any) {
        setError(String(e));
        clearInterval(t);
      }
    }, 1500);
    return () => clearInterval(t);
  }, [scanId, status?.state, reloadFindings]);

  // Close the export kebab menu when the user clicks outside it or presses Escape.
  useEffect(() => {
    if (!exportMenuOpen && !reportMenuOpen && !catMenuOpen) return;
    function onDocDown(e: PointerEvent | globalThis.MouseEvent) {
      const target = e.target as Node | null;
      if (exportMenuOpen && target) {
        const insideMenu = exportMenuRef.current && exportMenuRef.current.contains(target);
        const insideBtn = exportMenuBtnRef.current && exportMenuBtnRef.current.contains(target);
        if (!insideMenu && !insideBtn) setExportMenuOpen(false);
      }
      if (reportMenuOpen && reportMenuRef.current && target && !reportMenuRef.current.contains(target)) {
        setReportMenuOpen(false);
      }
      if (catMenuOpen && target) {
        const insideMenu = catMenuRef.current && catMenuRef.current.contains(target);
        const insideBtn = catMenuBtnRef.current && catMenuBtnRef.current.contains(target);
        if (!insideMenu && !insideBtn) setCatMenuOpen(false);
      }
    }
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") {
        setExportMenuOpen(false);
        setReportMenuOpen(false);
        setCatMenuOpen(false);
      }
    }
    document.addEventListener("mousedown", onDocDown);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDocDown);
      document.removeEventListener("keydown", onKey);
    };
  }, [exportMenuOpen, reportMenuOpen, catMenuOpen]);

  // Pin the export menu to its trigger button. The menu is portalled to
  // <body> to escape the toolbar's `backdrop-filter` stacking context, so it
  // needs explicit viewport coordinates. Right-anchored to keep the menu's
  // original right-aligned look. Re-position on scroll/resize.
  useEffect(() => {
    if (!exportMenuOpen) {
      setExportMenuRect(null);
      return;
    }
    function reposition() {
      const btn = exportMenuBtnRef.current;
      if (!btn) return;
      const r = btn.getBoundingClientRect();
      setExportMenuRect({
        top: r.bottom + 8,
        right: Math.max(12, window.innerWidth - r.right),
      });
    }
    reposition();
    window.addEventListener("resize", reposition);
    window.addEventListener("scroll", reposition, true);
    return () => {
      window.removeEventListener("resize", reposition);
      window.removeEventListener("scroll", reposition, true);
    };
  }, [exportMenuOpen]);

  // When the category menu opens, focus the search input, clear stale text,
  // and pin the portal to the trigger button. Re-position on scroll/resize
  // so the menu stays anchored to the button while it's open.
  useEffect(() => {
    if (!catMenuOpen) {
      setCatMenuRect(null);
      return;
    }
    setCatSearch("");
    requestAnimationFrame(() => catSearchInputRef.current?.focus());
    function reposition() {
      const btn = catMenuBtnRef.current;
      if (!btn) return;
      const r = btn.getBoundingClientRect();
      setCatMenuRect({ top: r.bottom + 8, left: r.left, width: r.width });
    }
    reposition();
    window.addEventListener("resize", reposition);
    window.addEventListener("scroll", reposition, true);
    return () => {
      window.removeEventListener("resize", reposition);
      window.removeEventListener("scroll", reposition, true);
    };
  }, [catMenuOpen]);

  async function login(e?: FormEvent) {
    e?.preventDefault();
    setLoginBusy(true);
    setLoginError(null);
    try {
      const r = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username: loginUser, password: loginPassword }),
      });
      if (!r.ok) throw new Error("Invalid username or password");
      const data: AuthInfo = await r.json();
      setAuthenticated(data.authenticated);
      setAuthUser(data.username ?? loginUser);
      setLoginPassword("");
      setGithubFieldsLocked(true);
      setPage(1);
    } catch (e: any) {
      setLoginError(e?.message ?? String(e));
    } finally {
      setLoginBusy(false);
      setAuthChecked(true);
    }
  }

  async function logout() {
    await fetch("/api/auth/logout", { method: "POST" });
    setAuthenticated(false);
    setAuthUser(null);
    setSelected(null);
    setReport(null);
    setAskAI(null);
    setAskAIError(null);
    setManualVerdictError(null);
    setStatus(null);
    setGithubFieldsLocked(true);
    setPageData({ total: 0, page: 1, page_size: PAGE_SIZE, items: [] });
  }

  async function startScan() {
    setError(null);
    setSelected(null);
    setReport(null);
    setAskAI(null);
    setAskAIError(null);
    try {
      const r = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          org,
          token: token || undefined,
          include_forks: includeForks,
          max_repos: Number(maxRepos),
          remember: true,
          selected_rules:
            selectedRules.size === availableRules.length
              ? null
              : Array.from(selectedRules),
        }),
      });
      if (!r.ok) {
        if (r.status === 409) {
          const conflict = await r.json();
          const detail = conflict.detail || {};
          setQueueFocusJobId(detail.job_id ?? null);
          setScanId(detail.scan_id ?? null);
          setMainView("queue");
          throw new Error(detail.message || "An equivalent scan is already queued or running.");
        }
        throw new Error(await r.text());
      }
      const data: ScanStatus = await r.json();
      setStatus(data);
      setScanId(data.id);
      setQueueFocusJobId(data.job_id ?? null);
      if (data.queue_state === "pending" || data.queue_state === "waiting_rate_limit") {
        setMainView("queue");
      }
      setPage(1);
      setToken("");
      try {
        const s = await fetch("/api/token");
        if (s.ok) setSaved(await s.json());
      } catch {
        /* ignore */
      }
      void reloadTokenPool();
    } catch (e: any) {
      setError(String(e));
    }
  }

  async function forgetToken() {
    try {
      await fetch("/api/token", { method: "DELETE" });
      setSaved({ saved: false });
      setTokenPool([]);
    } catch (e: any) {
      setError(String(e));
    }
  }

  async function reloadTokenPool() {
    try {
      const p = await fetch("/api/tokens");
      if (p.ok) {
        const data: SavedTokenPool = await p.json();
        setTokenPool(data.tokens || []);
      }
    } catch {
      /* ignore */
    }
  }

  async function addPoolToken() {
    const value = poolTokenInput.trim();
    if (!value) return;
    setPoolBusy(true);
    setPoolError(null);
    try {
      const r = await fetch("/api/tokens", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ token: value }),
      });
      if (!r.ok) throw new Error(await r.text());
      const data: SavedTokenPool = await r.json();
      setTokenPool(data.tokens || []);
      setPoolTokenInput("");
      // Keep the single-token badge in sync too — the newest saved token
      // is treated as the primary one for backward-compat callers.
      try {
        const s = await fetch("/api/token");
        if (s.ok) setSaved(await s.json());
      } catch {
        /* ignore */
      }
    } catch (e: any) {
      setPoolError(String(e));
    } finally {
      setPoolBusy(false);
    }
  }

  async function removePoolToken(login?: string | null) {
    if (!login) return;
    if (!confirm(`Remove the saved token for @${redactGitHubLogin(login)} from the rotation pool?`)) return;
    setPoolBusy(true);
    setPoolError(null);
    try {
      const r = await fetch(`/api/tokens/${encodeURIComponent(login)}`, { method: "DELETE" });
      if (!r.ok) throw new Error(await r.text());
      const data: SavedTokenPool = await r.json();
      setTokenPool(data.tokens || []);
      try {
        const s = await fetch("/api/token");
        if (s.ok) setSaved(await s.json());
      } catch {
        /* ignore */
      }
    } catch (e: any) {
      setPoolError(String(e));
    } finally {
      setPoolBusy(false);
    }
  }

  async function deleteFinding(id: string, e?: MouseEvent) {
    e?.stopPropagation();
    if (!confirm("Delete this finding from the database?")) return;
    try {
      const r = await fetch(`/api/findings/${id}`, { method: "DELETE" });
      if (!r.ok) throw new Error(await r.text());
      if (selected?.id === id) {
        setSelected(null);
        setReport(null);
        setAskAI(null);
        setAskAIError(null);
        setManualVerdictError(null);
      }
      await reloadFindings();
    } catch (err: any) {
      setError(String(err));
    }
  }

  async function loadReport(f: Finding) {
    setReport(null);
    setReportLoading(true);
    try {
      const r = await fetch(`/api/findings/${f.id}/bug-bounty`);
      if (!r.ok) throw new Error(await r.text());
      setReport(await r.json());
    } catch (e: any) {
      setError(String(e));
    } finally {
      setReportLoading(false);
    }
  }

  async function saveManualVerdict(verdict: "true_positive" | "false_positive" | "true_positive_severity_overstated" | null) {
    if (!selected) return;
    const previous = selected;
    const optimistic = { ...selected, manual_verdict: verdict, manual_verdict_at: verdict ? Date.now() / 1000 : null };
    setSelected(optimistic);
    setPageData((current) => ({
      ...current,
      items: current.items.map((item) =>
        item.id === selected.id
          ? { ...item, manual_verdict: optimistic.manual_verdict, manual_verdict_at: optimistic.manual_verdict_at }
          : item
      ),
    }));
    setManualVerdictSaving(true);
    setManualVerdictError(null);
    try {
      const r = await fetch(`/api/findings/${selected.id}/manual-verdict`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ manual_verdict: verdict }),
      });
      if (!r.ok) throw new Error(await r.text());
      const savedFinding: Finding = await r.json();
      setSelected(savedFinding);
      setPageData((current) => ({
        ...current,
        items: current.items.map((item) =>
          item.id === savedFinding.id
            ? {
                ...item,
                manual_verdict: savedFinding.manual_verdict,
                manual_verdict_at: savedFinding.manual_verdict_at,
              }
            : item
        ),
      }));
    } catch (e: any) {
      setSelected(previous);
      setManualVerdictError(e?.message ?? String(e));
    } finally {
      setManualVerdictSaving(false);
    }
  }

  async function openFinding(fOrId: FindingListItem | string) {
    const fid = typeof fOrId === "string" ? fOrId : fOrId.id;
    setSelectedLoading(true);
    setSelected(null);
    setReport(null);
    setAskAI(null);
    setAskAIError(null);
    setManualVerdictError(null);
    setCopied(false);
    setDrawerTab("details");
    try {
      const r = await fetch(`/api/findings/${fid}`);
      if (!r.ok) throw new Error(await r.text());
      const full: Finding = await r.json();
      setSelected(full);
      void loadReport(full);
    } catch (e: any) {
      setError(String(e));
    } finally {
      setSelectedLoading(false);
    }
  }

  async function askAIValidate() {
    if (!selected) return;
    setAskAILoading(true);
    setAskAIError(null);
    setAskAI(null);
    try {
      const r = await fetch(`/api/findings/${selected.id}/ask-ai`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ include_support_files: false, max_files: 4 }),
      });
      if (!r.ok) throw new Error(await r.text());
      setAskAI(await r.json());
    } catch (e: any) {
      setAskAIError(e?.message ?? String(e));
    } finally {
      setAskAILoading(false);
    }
  }

  async function copyReport() {
    if (!report) return;
    try {
      await navigator.clipboard.writeText(report.markdown);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      /* ignore */
    }
  }

  function downloadReport() {
    if (!report || !selected) return;
    const blob = new Blob([report.markdown], { type: "text/markdown" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `bug-bounty-${selected.repo.replace("/", "_")}-${selected.id.slice(0, 8)}.md`;
    a.click();
    URL.revokeObjectURL(url);
  }

  function downloadSelectedSarif() {
    if (!selected) return;
    window.location.href = `/api/findings/${selected.id}/sarif`;
  }

  const items = pageData.items;
  const totalPages = Math.max(1, Math.ceil(pageData.total / PAGE_SIZE));
  const allVisibleSelected = items.length > 0 && items.every((f) => selectedIds.has(f.id));
  const reviewedTotal = trend.reduce((sum, row) => sum + Number(row.true_positive || 0) + Number(row.false_positive || 0) + Number(row.true_positive_severity_overstated || 0), 0);
  const trendTotal = trend.reduce((sum, row) => sum + Number(row.total || 0), 0);
  const trendLatest = trend[trend.length - 1];

  function toggleSelected(id: string) {
    setSelectedIds((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  function toggleAllVisible() {
    setSelectedIds((current) => {
      const next = new Set(current);
      if (allVisibleSelected) {
        items.forEach((f) => next.delete(f.id));
      } else {
        items.forEach((f) => next.add(f.id));
      }
      return next;
    });
  }

  async function bulkSetManualVerdict(verdict: "true_positive" | "false_positive" | "true_positive_severity_overstated" | null) {
    const ids = Array.from(selectedIds);
    if (ids.length === 0) return;
    setBulkBusy(true);
    setError(null);
    try {
      const r = await fetch("/api/findings/manual-verdict/bulk", {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ finding_ids: ids, manual_verdict: verdict }),
      });
      if (!r.ok) throw new Error(await r.text());
      setSelectedIds(new Set());
      await reloadFindings();
    } catch (e: any) {
      setError(e?.message ?? String(e));
    } finally {
      setBulkBusy(false);
    }
  }

  async function bulkDeleteSelected() {
    const ids = Array.from(selectedIds);
    if (ids.length === 0) return;
    if (!confirm(`Delete ${ids.length} selected findings from the database?`)) return;
    setBulkBusy(true);
    setError(null);
    try {
      const r = await fetch("/api/findings/bulk-delete", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ finding_ids: ids }),
      });
      if (!r.ok) throw new Error(await r.text());
      if (selected && selectedIds.has(selected.id)) {
        setSelected(null);
        setReport(null);
        setAskAI(null);
        setAskAIError(null);
      }
      setSelectedIds(new Set());
      await reloadFindings();
    } catch (e: any) {
      setError(e?.message ?? String(e));
    } finally {
      setBulkBusy(false);
    }
  }

  async function deleteAllFindings() {
    const total = pageData.total;
    if (total === 0) return;
    if (!confirm(`Delete ALL ${total} findings from the database? This cannot be undone.`)) return;
    const typed = prompt(`Type DELETE to permanently remove all ${total} findings.`);
    if (typed !== "DELETE") return;
    setDeleteAllBusy(true);
    setError(null);
    try {
      const r = await fetch("/api/findings", { method: "DELETE" });
      if (!r.ok) throw new Error(await r.text());
      setSelectedIds(new Set());
      setSelected(null);
      setReport(null);
      setAskAI(null);
      setAskAIError(null);
      setPage(1);
      await reloadFindings();
    } catch (e: any) {
      setError(e?.message ?? String(e));
    } finally {
      setDeleteAllBusy(false);
    }
  }

  async function recheckFinding() {
    if (!selected) return;
    setRecheckBusy(true);
    setRecheckMessage(null);
    try {
      const r = await fetch(`/api/findings/${selected.id}/recheck`, { method: "POST" });
      if (!r.ok) throw new Error(await r.text());
      const data: RecheckResult = await r.json();
      const finding = data.finding;
      setSelected(finding);
      // Reflect the state change in the visible list without a full reload.
      setPageData((current) => ({
        ...current,
        items: current.items.map((item) =>
          item.id === finding.id
            ? {
                ...item,
                archived_state: finding.archived_state,
                archived_at: finding.archived_at,
                archived_reason: finding.archived_reason,
                last_recheck_at: finding.last_recheck_at,
              }
            : item
        ),
      }));
      if (data.archived_state === "fixed") {
        setRecheckMessage("Fixed at HEAD — the scanner no longer produces this finding. Moved to Archived.");
      } else if (data.archived_state === "deleted") {
        setRecheckMessage("Workflow file no longer exists at HEAD. Moved to Archived.");
      } else {
        setRecheckMessage(`Still live at HEAD (rechecked ${new Date((finding.last_recheck_at || 0) * 1000).toLocaleString()}).`);
      }
      // Refresh counts so the sidebar reflects the new state.
      void reloadFindings();
    } catch (e: any) {
      setRecheckMessage(`Recheck failed: ${e?.message ?? String(e)}`);
    } finally {
      setRecheckBusy(false);
    }
  }

  async function bulkRecheck() {
    const ids = Array.from(selectedIds);
    if (ids.length === 0) return;
    setBulkBusy(true);
    setError(null);
    try {
      const r = await fetch("/api/findings/recheck/bulk", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ finding_ids: ids }),
      });
      if (!r.ok) throw new Error(await r.text());
      const data = await r.json();
      setRecheckMessage(
        `Rechecked ${data.total}: ${data.live} live, ${data.fixed} fixed, ${data.deleted} deleted${data.errors ? `, ${data.errors} errors` : ""}.`
      );
      setSelectedIds(new Set());
      await reloadFindings();
    } catch (e: any) {
      setError(e?.message ?? String(e));
    } finally {
      setBulkBusy(false);
    }
  }

  function exportReviewed(format: "json" | "csv") {
    window.location.href = `/api/findings/export-reviewed?format=${format}`;
  }

  function exportFilteredSarif() {
    // Mirror the current dashboard filters so what the user *sees* is what
    // they export. `state` matters — SARIF consumers (GitHub code scanning
    // especially) will treat every entry as an active finding unless
    // `baselineState=absent`, so exporting only live findings is the sane
    // default.
    const params = new URLSearchParams({ format: "sarif", state: filterState });
    if (filterRepo.trim()) params.set("repo", filterRepo.trim());
    if (filterSev !== "ALL") params.set("severity", filterSev);
    if (filterExp !== "ALL") params.set("exploitability", filterExp);
    if (filterCat !== "ALL") params.set("category", filterCat);
    if (sinkSourceSearch.trim()) params.set("q", sinkSourceSearch.trim());
    if (effectiveScanId) params.set("scan_id", effectiveScanId);
    window.location.href = `/api/findings/export?${params.toString()}`;
  }

  function exportTriageJson(overrideSeverity?: string) {
    // `overrideSeverity` lets the severity shortcut chips ship a scoped
    // export without touching the dashboard's severity filter. Falls back
    // to the currently-selected filter.
    const sev = overrideSeverity ?? filterSev;
    const params = new URLSearchParams({ format: "triage", state: filterState });
    if (filterRepo.trim()) params.set("repo", filterRepo.trim());
    if (sev && sev !== "ALL") params.set("severity", sev);
    if (filterExp !== "ALL") params.set("exploitability", filterExp);
    if (filterCat !== "ALL") params.set("category", filterCat);
    if (sinkSourceSearch.trim()) params.set("q", sinkSourceSearch.trim());
    if (effectiveScanId) params.set("scan_id", effectiveScanId);
    window.location.href = `/api/findings/export?${params.toString()}`;
  }

  if (!authChecked) {
    return (
      <div className="app">
        <main className="main">
          <div className="empty">Checking dashboard session…</div>
        </main>
      </div>
    );
  }

  if (!authenticated) {
    return (
      <div className="login-shell">
        <div className="login-aurora" aria-hidden />
        <div className="login-card">
          <aside className="login-brand-side">
            <div className="brand-mark">
              <span className="brand-mark-glyph" aria-hidden />
              <div>
                <div className="brand-name">Grafter</div>
                <div className="brand-tagline">
                  GitHub Actions trust-boundary scanner
                </div>
              </div>
            </div>
            <ul className="brand-highlights">
              <li>
                <span className="hl-tick" aria-hidden>✓</span>
                Detects exploitable <code>pull_request_target</code> and
                <code> workflow_run</code> bugs
              </li>
              <li>
                <span className="hl-tick" aria-hidden>✓</span>
                Agentic workflow injection — 10 rule classes
              </li>
              <li>
                <span className="hl-tick" aria-hidden>✓</span>
                Live secret validation across 14 providers
              </li>
              <li>
                <span className="hl-tick" aria-hidden>✓</span>
                SARIF 2.1.0 export for GitHub code scanning
              </li>
            </ul>
            <div className="brand-footer">
              <span className="pulse" aria-hidden /> Local · in-memory · zero
              telemetry
            </div>
          </aside>

          <form className="login-form" onSubmit={login} noValidate>
            <div className="login-header">
              <h1>Welcome back</h1>
              <p>Sign in to review findings and start new scans.</p>
            </div>

            <label className="login-field">
              <span className="login-field-label">Username</span>
              <div className="login-input-wrap">
                <svg
                  className="login-input-icon"
                  viewBox="0 0 24 24"
                  aria-hidden
                >
                  <path
                    fill="currentColor"
                    d="M12 12a4 4 0 1 0-4-4 4 4 0 0 0 4 4Zm0 2c-3.5 0-7 1.8-7 5.3V21h14v-1.7c0-3.5-3.5-5.3-7-5.3Z"
                  />
                </svg>
                <input
                  value={loginUser}
                  onChange={(e) => setLoginUser(e.target.value)}
                  autoComplete="username"
                  spellCheck={false}
                  placeholder="admin"
                />
              </div>
            </label>

            <label className="login-field">
              <span className="login-field-label">Password</span>
              <div className="login-input-wrap">
                <svg
                  className="login-input-icon"
                  viewBox="0 0 24 24"
                  aria-hidden
                >
                  <path
                    fill="currentColor"
                    d="M18 8h-1V6a5 5 0 0 0-10 0v2H6a2 2 0 0 0-2 2v10a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V10a2 2 0 0 0-2-2Zm-6 9a2 2 0 1 1 2-2 2 2 0 0 1-2 2Zm3-9H9V6a3 3 0 0 1 6 0Z"
                  />
                </svg>
                <input
                  type={loginShowPw ? "text" : "password"}
                  value={loginPassword}
                  onChange={(e) => setLoginPassword(e.target.value)}
                  autoComplete="current-password"
                  autoFocus
                  placeholder="••••••••"
                />
                <button
                  type="button"
                  className="login-input-reveal"
                  onClick={() => setLoginShowPw((v) => !v)}
                  aria-label={loginShowPw ? "Hide password" : "Show password"}
                  tabIndex={-1}
                >
                  {loginShowPw ? "Hide" : "Show"}
                </button>
              </div>
            </label>

            {loginError && (
              <div className="login-error" role="alert">
                <svg viewBox="0 0 24 24" aria-hidden>
                  <path
                    fill="currentColor"
                    d="M12 2 1 22h22L12 2Zm0 6.5 6.5 12h-13L12 8.5Zm-1 4v4h2v-4Zm0 5v2h2v-2Z"
                  />
                </svg>
                <span>{loginError}</span>
              </div>
            )}

            <button
              className="login-submit"
              type="submit"
              disabled={loginBusy || !loginUser || !loginPassword}
            >
              {loginBusy ? (
                <>
                  <span className="login-spinner" aria-hidden />
                  Signing in…
                </>
              ) : (
                <>
                  Sign in
                  <svg viewBox="0 0 24 24" aria-hidden>
                    <path
                      fill="currentColor"
                      d="M13 5v6H4v2h9v6l7-7Z"
                    />
                  </svg>
                </>
              )}
            </button>

            <p className="login-hint">
              Default admin credentials are in the project README. Once signed
              in you'll add a GitHub PAT to run scans.
            </p>
          </form>
        </div>
      </div>
    );
  }

  const availableRuleKeys = new Set(availableRules.map((rule) => rule.key));
  const selectedRuleCount = selectedRules.size;
  const allRulesSelected = (
    availableRules.length > 0
    && selectedRuleCount === availableRules.length
  );
  const ruleSelectionLabel = rulesLoading
    ? "Loading rules…"
    : allRulesSelected
    ? `All rules (${availableRules.length})`
    : selectedRuleCount === 0
    ? "No rules selected"
    : `${selectedRuleCount} of ${availableRules.length} rules`;
  const ruleQuery = ruleSearch.trim().toLowerCase();
  const selectableRuleFamilies = RULES_CATALOG.map((family) => ({
    ...family,
    categories: family.categories.filter((category) => (
      availableRuleKeys.has(category.key)
      && (
        !ruleQuery
        || category.label.toLowerCase().includes(ruleQuery)
        || category.key.toLowerCase().includes(ruleQuery)
        || category.summary.toLowerCase().includes(ruleQuery)
      )
    )),
  })).filter((family) => family.categories.length > 0);

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <span className="dot" />
          <div>
            Grafter <br />
            <small>GitHub Actions trust-boundary scanner</small>
          </div>
        </div>

        <div className="note">
          Signed in as <span className="kbd">{authUser ?? "admin"}</span>{" "}
          <a
            className="link"
            href="#"
            onClick={(e) => {
              e.preventDefault();
              void logout();
            }}
          >
            sign out
          </a>
        </div>

        <div className="field">
          <label>GitHub organization or user</label>
          <input
            name="grafter-scan-owner"
            placeholder="e.g. octocat"
            value={org}
            onChange={(e) => setOrg(e.target.value)}
            onFocus={() => setGithubFieldsLocked(false)}
            readOnly={githubFieldsLocked}
            autoComplete="off"
            data-lpignore="true"
            data-1p-ignore="true"
            data-form-type="other"
            spellCheck={false}
          />
        </div>

        <div className="field">
          <label>
            GitHub PAT {saved.saved ? "(saved locally)" : "(stored locally on submit)"}
          </label>
          <input
            name="grafter-github-token"
            type="password"
            placeholder={
              saved.saved
                ? `Using saved token ${saved.token_preview ?? ""} — leave blank to reuse`
                : "ghp_… or github_pat_…"
            }
            value={token}
            onChange={(e) => setToken(e.target.value)}
            onFocus={() => setGithubFieldsLocked(false)}
            readOnly={githubFieldsLocked}
            autoComplete="new-password"
            data-lpignore="true"
            data-1p-ignore="true"
            data-form-type="other"
            spellCheck={false}
          />
          {saved.saved ? (
            <div className="note">
              Saved as <span className="kbd">@{redactGitHubLogin(saved.login)}</span>
              {saved.saved_at && (
                <> · {new Date(saved.saved_at * 1000).toLocaleString()}</>
              )}
              {" · "}
              <a
                className="link"
                href="#"
                onClick={(e) => {
                  e.preventDefault();
                  forgetToken();
                }}
              >
                forget token
              </a>
            </div>
          ) : (
            <div className="note">
              Token will be saved to{" "}
              <span className="kbd">~/.grafter/tokens.json</span> for reuse. Required
              scopes: <span className="kbd">repo</span> + <span className="kbd">read:org</span>.
            </div>
          )}
        </div>

        <div className="field">
          <div
            style={{ display: "flex", alignItems: "center", gap: 6, cursor: "pointer" }}
            onClick={() => setPoolExpanded((v) => !v)}
          >
            <label style={{ margin: 0, cursor: "pointer" }}>
              Token rotation pool {tokenPool.length > 0 ? `(${tokenPool.length} saved)` : ""}
            </label>
            <span className="link" style={{ fontSize: 11 }}>
              {poolExpanded ? "▲ hide" : "▼ manage"}
            </span>
          </div>
          {poolExpanded && (
            <div style={{ marginTop: 6 }}>
              <div className="note" style={{ marginBottom: 8 }}>
                Save several PATs (from different accounts) here. When a scan's active
                token gets low on quota, Grafter automatically rotates to the next saved
                token with headroom instead of failing — so you can run multiple scans
                back-to-back without waiting on a single token's hourly rate-limit reset.
              </div>
              {tokenPool.length > 0 && (
                <div style={{ display: "flex", flexDirection: "column", gap: 4, marginBottom: 8 }}>
                  {tokenPool.map((t, i) => (
                    <div
                      key={`${t.login}-${i}`}
                      style={{
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "space-between",
                        fontSize: 12,
                        padding: "4px 8px",
                        border: "1px solid var(--border, #333)",
                        borderRadius: 6,
                      }}
                    >
                      <span>
                        <span className="kbd">@{redactGitHubLogin(t.login)}</span>{" "}
                        <span style={{ color: "var(--muted)" }}>{t.token_preview}</span>
                        {t.saved_at && (
                          <span style={{ color: "var(--muted)" }}>
                            {" "}
                            · {new Date(t.saved_at * 1000).toLocaleDateString()}
                          </span>
                        )}
                      </span>
                      <a
                        className="link"
                        href="#"
                        onClick={(e) => {
                          e.preventDefault();
                          if (!poolBusy) removePoolToken(t.login);
                        }}
                      >
                        remove
                      </a>
                    </div>
                  ))}
                </div>
              )}
              <div style={{ display: "flex", gap: 6 }}>
                <input
                  type="password"
                  placeholder="Add another PAT to the pool (ghp_… or github_pat_…)"
                  value={poolTokenInput}
                  onChange={(e) => setPoolTokenInput(e.target.value)}
                  autoComplete="new-password"
                  data-lpignore="true"
                  data-1p-ignore="true"
                  spellCheck={false}
                  style={{ flex: 1 }}
                  disabled={poolBusy}
                />
                <button
                  type="button"
                  className="btn"
                  disabled={poolBusy || !poolTokenInput.trim()}
                  onClick={() => addPoolToken()}
                >
                  {poolBusy ? "Adding…" : "Add"}
                </button>
              </div>
              {poolError && (
                <div className="note" style={{ borderLeftColor: "var(--crit)", color: "var(--crit)", marginTop: 6 }}>
                  {poolError}
                </div>
              )}
            </div>
          )}
        </div>

        <div className="row">
          <div className="field">
            <label>Max repos</label>
            <input
              type="number"
              min={1}
              max={2000}
              value={maxRepos}
              onChange={(e) => setMaxRepos(parseInt(e.target.value || "0", 10))}
            />
          </div>
          <div className="field">
            <label>Forks</label>
            <select
              value={includeForks ? "yes" : "no"}
              onChange={(e) => setIncludeForks(e.target.value === "yes")}
            >
              <option value="no">Skip</option>
              <option value="yes">Include</option>
            </select>
          </div>
        </div>

        <div className="field rule-selector-field">
          <label>Rules to run</label>
          <button
            ref={ruleMenuButtonRef}
            type="button"
            className={`rule-selector-trigger ${ruleMenuOpen ? "is-open" : ""}`}
            onClick={() => setRuleMenuOpen((open) => !open)}
            disabled={rulesLoading || !!rulesError}
            aria-haspopup="dialog"
            aria-expanded={ruleMenuOpen}
          >
            <span>{ruleSelectionLabel}</span>
            <span aria-hidden>{ruleMenuOpen ? "▲" : "▼"}</span>
          </button>
          {ruleMenuOpen && (
            <div ref={ruleMenuRef} className="rule-selector-menu" role="dialog" aria-label="Select scanner rules">
              <div className="rule-selector-actions">
                <button
                  type="button"
                  className="link-button"
                  onClick={() => setSelectedRules(new Set(availableRules.map((rule) => rule.key)))}
                >
                  Select all
                </button>
                <button
                  type="button"
                  className="link-button"
                  onClick={() => setSelectedRules(new Set())}
                >
                  Deselect all
                </button>
              </div>
              <input
                className="rule-selector-search"
                type="search"
                value={ruleSearch}
                onChange={(event) => setRuleSearch(event.target.value)}
                placeholder="Search rules…"
                aria-label="Search scanner rules"
              />
              <div className="rule-selector-list">
                {selectableRuleFamilies.map((family) => (
                  <div className="rule-selector-family" key={family.id}>
                    <div className="rule-selector-family-name">{family.name}</div>
                    {family.categories.map((rule) => (
                      <label className="rule-selector-option" key={rule.key} title={rule.summary}>
                        <input
                          type="checkbox"
                          checked={selectedRules.has(rule.key)}
                          onChange={() => {
                            setSelectedRules((current) => {
                              const next = new Set(current);
                              if (next.has(rule.key)) next.delete(rule.key);
                              else next.add(rule.key);
                              return next;
                            });
                          }}
                        />
                        <span>
                          <strong>{rule.label}</strong>
                          <small>{rule.key}</small>
                        </span>
                      </label>
                    ))}
                  </div>
                ))}
                {selectableRuleFamilies.length === 0 && (
                  <div className="rule-selector-empty">No matching rules.</div>
                )}
              </div>
            </div>
          )}
          {rulesError && (
            <div className="note" style={{ borderLeftColor: "var(--crit)", color: "var(--crit)" }}>
              Could not load scanner rules: {rulesError}.{" "}
              <button
                type="button"
                className="link-button"
                onClick={() => setRulesReloadVersion((version) => version + 1)}
              >
                Retry
              </button>
            </div>
          )}
          {!rulesLoading && !rulesError && selectedRuleCount === 0 && (
            <div className="note" style={{ borderLeftColor: "var(--warn, #d97706)" }}>
              Select at least one rule before starting a scan.
            </div>
          )}
          <div className="note">Workflow and policy parse errors are always reported.</div>
        </div>

        <button
          className="btn"
          disabled={
            !org
            || (!token && !saved.saved)
            || rulesLoading
            || !!rulesError
            || selectedRuleCount === 0
            || status?.state === "running"
            || status?.state === "starting"
          }
          onClick={startScan}
        >
          {status?.state === "running" || status?.state === "starting" ? "Scanning…" : "Start scan"}
        </button>

        {status && (
          <div className="progress">
            <div style={{ fontSize: 12, color: "var(--muted)", marginBottom: 4 }}>
              {status.state === "running" || status.state === "starting"
                ? `Scanning ${status.repos_scanned}/${status.repos_total} repos · ${status.workflows_scanned} workflows`
                : status.state === "waiting_rate_limit" || status.state === "pending"
                ? `Queued · resumes after GitHub rate limit reset`
                : status.state === "done"
                ? `Done · ${status.repos_scanned} repos · ${status.workflows_scanned} workflows · ${pageData.total} findings`
                : status.state === "cancelled"
                ? "Cancelled"
                : `Error: ${status.error}`}
            </div>
            <div className="track">
              <div className="fill" style={{ width: `${Math.round((status.progress || 0) * 100)}%` }} />
            </div>
            {status.rate_limit_remaining != null && status.rate_limit_limit != null && (
              <div
                className="rate-limit-badge"
                style={{
                  fontSize: 11,
                  marginTop: 4,
                  color:
                    (status.pool_rate_limit_remaining ?? status.rate_limit_remaining) === 0
                      ? "var(--crit)"
                      : (status.pool_rate_limit_remaining ?? status.rate_limit_remaining) < (status.pool_rate_limit_limit ?? status.rate_limit_limit) * 0.1
                      ? "var(--warn, #d97706)"
                      : "var(--muted)",
                }}
              >
                <GitHubQuota quota={status} />
                {status.token_pool_size && status.token_pool_size > 1 ? (
                  <>
                    {" "}· {status.token_pool_size} tokens in rotation pool
                    {status.token_rotations ? ` (rotated ${status.token_rotations}×)` : ""}
                  </>
                ) : null}
              </div>
            )}
            {status.rate_limit_warning && status.state === "running" && (
              <div className="note" style={{ borderLeftColor: "var(--warn, #d97706)", color: "var(--warn, #d97706)", marginTop: 6 }}>
                {status.rate_limit_warning}
              </div>
            )}
          </div>
        )}

        {error && (
          <div className="note" style={{ borderLeftColor: "var(--crit)", color: "var(--crit)" }}>
            {error}
          </div>
        )}

        <div className="note">
          Dashboard shows high-confidence findings, including medium/low visibility issues for org owners.
          Rules cover privileged GitHub Actions trust-boundary bugs, CI/CD artifact/cache poisoning,
          self-hosted runner exposure, cloud OIDC abuse, release/publish compromise paths, and
          agentic workflow injection where untrusted PR/comment/issue/review/dispatch or artifact
          content can steer AI agents and workflow-referenced helper scripts with repo-write tools.
          Normal GitHub-hosted pull_request builds are suppressed unless a
          real privilege/runner risk exists. Raw secrets are masked and never shown.
        </div>
      </aside>

      <main className="main">
        <div className="stats">
          <Stat label="Critical" value={counts.CRITICAL} color="var(--crit)" />
          <Stat label="High" value={counts.HIGH} color="var(--high)" />
          <Stat label="Medium" value={counts.MEDIUM} color="var(--med)" />
          <Stat label="Low" value={counts.LOW} color="var(--low)" />
          <Stat label="Info" value={counts.INFO} color="var(--info)" />
        </div>

        <div className="trend-panel">
          <div>
            <div className="graph-kicker">Trend over time</div>
            <strong>Last 30 days: {trendTotal} findings</strong>
            {trendLatest && <span className="repo"> · latest day {trendLatest.day}: {trendLatest.total}</span>}
          </div>
          <div className="trend-bars" aria-label="Findings trend over the last 30 days">
            {trend.length === 0 ? (
              <span className="repo">No trend data yet</span>
            ) : trend.map((row) => {
              const max = Math.max(1, ...trend.map((r) => r.total));
              return (
                <div
                  key={row.day}
                  className="trend-bar"
                  title={`${row.day}: ${row.total} total, ${row.true_positive} TP, ${row.true_positive_severity_overstated ?? 0} TP-overstated, ${row.false_positive} FP`}
                  style={{ height: `${Math.max(6, (row.total / max) * 52)}px` }}
                />
              );
            })}
          </div>
          <div className="trend-review">
            Reviewed: <strong>{reviewedTotal}</strong>
          </div>
        </div>

        <div className="view-tabs" role="tablist" aria-label="Main view">
          <button
            role="tab"
            aria-selected={mainView === "findings"}
            className={`view-tab ${mainView === "findings" ? "active" : ""}`}
            onClick={() => setMainView("findings")}
          >
            <svg viewBox="0 0 24 24" aria-hidden><path fill="currentColor" d="M3 6h18v2H3zm0 5h18v2H3zm0 5h18v2H3z"/></svg>
            Findings
          </button>
          <button
            role="tab"
            aria-selected={mainView === "diff"}
            className={`view-tab ${mainView === "diff" ? "active" : ""}`}
            onClick={() => setMainView("diff")}
            title="Compare the selected scan against the previous scan of the same org"
          >
            <svg viewBox="0 0 24 24" aria-hidden><path fill="currentColor" d="M9 3v18l-6-6zm12 6H10v2h11zm-2 4H10v2h9zm-4 4h-5v2h5z"/></svg>
            Diff
            {diffData?.summary && (diffData.summary.new + diffData.summary.fixed + diffData.summary.severity_changed) > 0 && (
              <span className="view-tab-badge">
                {diffData.summary.new + diffData.summary.fixed + diffData.summary.severity_changed}
              </span>
            )}
          </button>
          <button
            role="tab"
            aria-selected={mainView === "rules"}
            className={`view-tab ${mainView === "rules" ? "active" : ""}`}
            onClick={() => setMainView("rules")}
            title="Browse every detection Grafter runs, grouped by attacker primitive"
          >
            <svg viewBox="0 0 24 24" aria-hidden><path fill="currentColor" d="M4 6h16v2H4Zm0 5h16v2H4Zm0 5h10v2H4Zm12 0h4v2h-4Zm2-11L14 3h6v2ZM6 3l-4 4V3Z"/></svg>
            Rules
            <span className="view-tab-badge">
              {RULES_CATALOG.reduce((n, f) => n + f.categories.length, 0)}
            </span>
          </button>
          <button
            role="tab"
            aria-selected={mainView === "queue"}
            className={`view-tab ${mainView === "queue" ? "active" : ""}`}
            onClick={() => setMainView("queue")}
            title="See organization and user scans waiting for GitHub quota or currently running"
          >
            <svg viewBox="0 0 24 24" aria-hidden><path fill="currentColor" d="M4 5h12v2H4Zm0 6h12v2H4Zm0 6h8v2H4Zm14-5h2v7h-2Zm-3 3h8v2h-8Z"/></svg>
            Queue
            {(queueSummary.pending + queueSummary.running + queueSummary.waiting_rate_limit) > 0 && (
              <span className="view-tab-badge">
                {queueSummary.pending + queueSummary.running + queueSummary.waiting_rate_limit}
              </span>
            )}
          </button>
          <button
            role="tab"
            aria-selected={mainView === "jobs"}
            className={`view-tab ${mainView === "jobs" ? "active" : ""}`}
            onClick={() => setMainView("jobs")}
            title="See every Live PoC currently running and full history"
          >
            <svg viewBox="0 0 24 24" aria-hidden><path fill="currentColor" d="M4 5h16v2H4Zm0 6h16v2H4Zm0 6h10v2H4Zm14-4h4v6h-4z"/></svg>
            Jobs
            {activeLivePocFindings.size > 0 && (
              <span className="view-tab-badge jobs-badge-live">
                <span className="jobs-dot jobs-dot-blink" style={{ marginRight: 4 }} />
                {activeLivePocFindings.size}
              </span>
            )}
          </button>
        </div>

        {mainView === "findings" && (
        <>
        <div className="toolbar">
          <input
            placeholder="Filter by repo…"
            value={filterRepo}
            onChange={(e) => { setFilterRepo(e.target.value); setPage(1); }}
          />
          <input
            placeholder="Search source/sink, docker, gh pr, azure/login, true positive, false positive, unreviewed…"
            value={sinkSourceSearch}
            onChange={(e) => { setSinkSourceSearch(e.target.value); setPage(1); }}
            title={
              "Free-text search across title, category, trigger, workflow path, evidence, remediation, and snippets. " +
              "Verdict tags — 'true positive', 'false positive', 'verdict:tp', 'verdict:fp', 'unreviewed' — filter by " +
              "manual verdict. Combine both (e.g. 'false positive script injection')."
            }
          />
          {(() => {
            const totalCount = categories.reduce((a, c) => a + c.count, 0);
            const selectedLabel =
              filterCat === "ALL"
                ? `All categories (${totalCount})`
                : (categories.find((c) => c.key === filterCat)?.label ?? filterCat);
            const q = catSearch.trim().toLowerCase();
            const filtered = q
              ? categories.filter(
                  (c) =>
                    c.label.toLowerCase().includes(q) ||
                    c.key.toLowerCase().includes(q),
                )
              : categories;
            return (
              <div className="cat-menu-wrap">
                <button
                  type="button"
                  ref={catMenuBtnRef}
                  className={`cat-menu-btn ${catMenuOpen ? "is-open" : ""}`}
                  onClick={() => setCatMenuOpen((v) => !v)}
                  aria-haspopup="listbox"
                  aria-expanded={catMenuOpen}
                  title="Filter by vulnerability category"
                >
                  <span className="cat-menu-btn-label">{selectedLabel}</span>
                  <svg viewBox="0 0 24 24" aria-hidden className={`cat-menu-btn-caret ${catMenuOpen ? "is-open" : ""}`}>
                    <path d="M7 10l5 5 5-5" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                  </svg>
                </button>
                {catMenuOpen && catMenuRect && createPortal(
                  <div
                    ref={catMenuRef}
                    className="cat-menu cat-menu-portal"
                    role="listbox"
                    aria-label="Vulnerability category"
                    style={{
                      top: catMenuRect.top,
                      left: catMenuRect.left,
                      minWidth: Math.max(catMenuRect.width, 320),
                    }}
                  >
                    <div className="cat-menu-search">
                      <svg viewBox="0 0 24 24" aria-hidden className="cat-menu-search-icon">
                        <circle cx="11" cy="11" r="7" fill="none" stroke="currentColor" strokeWidth="2" />
                        <path d="M20 20l-3.5-3.5" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
                      </svg>
                      <input
                        ref={catSearchInputRef}
                        type="text"
                        value={catSearch}
                        onChange={(e) => setCatSearch(e.target.value)}
                        placeholder="Search categories…"
                        aria-label="Search categories"
                        onKeyDown={(e) => {
                          if (e.key === "Enter" && filtered.length > 0) {
                            const first = filtered[0];
                            setFilterCat(first.key);
                            setPage(1);
                            setCatMenuOpen(false);
                          }
                        }}
                      />
                      {catSearch && (
                        <button
                          type="button"
                          className="cat-menu-search-clear"
                          onClick={() => setCatSearch("")}
                          aria-label="Clear search"
                          title="Clear"
                        >×</button>
                      )}
                    </div>
                    <div className="cat-menu-list">
                      <button
                        type="button"
                        role="option"
                        aria-selected={filterCat === "ALL"}
                        className={`cat-menu-item ${filterCat === "ALL" ? "is-selected" : ""}`}
                        onClick={() => { setFilterCat("ALL"); setPage(1); setCatMenuOpen(false); }}
                      >
                        <span className="cat-menu-item-label">All categories</span>
                        <span className="cat-menu-item-count">{totalCount}</span>
                      </button>
                      {filtered.length === 0 ? (
                        <div className="cat-menu-empty">No categories match “{catSearch}”</div>
                      ) : (
                        filtered.map((c) => (
                          <button
                            key={c.key}
                            type="button"
                            role="option"
                            aria-selected={filterCat === c.key}
                            className={`cat-menu-item ${filterCat === c.key ? "is-selected" : ""}`}
                            onClick={() => { setFilterCat(c.key); setPage(1); setCatMenuOpen(false); }}
                            title={c.key}
                          >
                            <span className="cat-menu-item-label">{c.label}</span>
                            <span className="cat-menu-item-count">{c.count}</span>
                          </button>
                        ))
                      )}
                    </div>
                  </div>,
                  document.body,
                )}
              </div>
            );
          })()}
          <select
            value={filterSev}
            onChange={(e) => { setFilterSev(e.target.value); setPage(1); }}
          >
            <option value="ALL">All severities</option>
            <option>CRITICAL</option>
            <option>HIGH</option>
            <option>MEDIUM</option>
            <option>LOW</option>
            <option>INFO</option>
          </select>
          <select
            value={filterExp}
            onChange={(e) => { setFilterExp(e.target.value); setPage(1); }}
          >
            <option value="ALL">All exploitability</option>
            <option value="HIGHLY_EXPLOITABLE">Highly exploitable</option>
            <option value="REALISTIC">Realistic</option>
            <option value="CONDITIONAL">Conditional</option>
            <option value="BLOCKED">Blocked</option>
            <option value="HARDENED">Hardened</option>
          </select>
          <select
            value={filterState}
            onChange={(e) => { setFilterState(e.target.value as "live" | "archived" | "all"); setPage(1); }}
            title="Live findings are those still producible against HEAD. Archived means fixed or deleted."
          >
            <option value="live">Live only</option>
            <option value="archived">Archived (fixed / deleted)</option>
            <option value="all">All findings</option>
          </select>
          {scanId && (
            <select
              value={scanFilter}
              onChange={(e) => { setScanFilter(e.target.value as "this" | "all"); setPage(1); }}
            >
              <option value="all">All scans (DB)</option>
              <option value="this">Current scan only</option>
            </select>
          )}
          <select
            value={sortBy}
            onChange={(e) => { setSortBy(e.target.value as "severity" | "newest" | "oldest"); setPage(1); }}
            title="Sort findings"
          >
            <option value="severity">Sort: severity</option>
            <option value="newest">Sort: newest first</option>
            <option value="oldest">Sort: oldest first</option>
          </select>
          <div className="spacer" />
          <div className="export-menu-wrap">
            <button
              type="button"
              ref={exportMenuBtnRef}
              className={`export-btn ${exportMenuOpen ? "is-open" : ""}`}
              onClick={() => setExportMenuOpen((v) => !v)}
              aria-haspopup="menu"
              aria-expanded={exportMenuOpen}
              title="Download findings as SARIF, triage JSON, or reviewed CSV/JSON"
            >
              <svg viewBox="0 0 24 24" aria-hidden>
                <path fill="currentColor" d="M12 3v10.6l3.3-3.3 1.4 1.4L12 16.4 7.3 11.7l1.4-1.4L12 13.6V3zm-7 15h14v2H5z"/>
              </svg>
              <span>Export</span>
              <svg viewBox="0 0 24 24" aria-hidden className={`export-btn-caret ${exportMenuOpen ? "is-open" : ""}`}>
                <path fill="currentColor" d="M7 10l5 5 5-5z"/>
              </svg>
            </button>
            {exportMenuOpen && exportMenuRect && createPortal(
              <>
                <div className="export-menu-backdrop" onClick={() => setExportMenuOpen(false)} aria-hidden />
                <div
                  ref={exportMenuRef}
                  className="kebab-menu export-menu-forward export-menu-portal"
                  role="menu"
                  style={{ top: exportMenuRect.top, right: exportMenuRect.right }}
                >
                  <div className="kebab-menu-title">Export findings</div>
                <button
                  type="button"
                  role="menuitem"
                  className="kebab-item"
                  onClick={() => { setExportMenuOpen(false); exportFilteredSarif(); }}
                >
                  <span className="kebab-item-icon" aria-hidden>
                    <svg viewBox="0 0 24 24"><path fill="currentColor" d="M5 3h11l4 4v14a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1Zm10 2v4h4Zm-3 6h-2v4H8l4 4 4-4h-2v-4Z"/></svg>
                  </span>
                  <span className="kebab-item-body">
                    <span className="kebab-item-title">Export SARIF</span>
                    <span className="kebab-item-sub">Current filters · GitHub code scanning / DefectDojo / GitLab SAST</span>
                  </span>
                </button>
                <div className="kebab-item kebab-item-static">
                  <span className="kebab-item-icon" aria-hidden>
                    <svg viewBox="0 0 24 24"><path fill="currentColor" d="M12 2a5 5 0 0 0-5 5c0 1.9 1.05 3.55 2.6 4.4L9 13l-2 2v3l-2 2v2h14v-2l-2-2v-3l-2-2-.6-1.6A5 5 0 0 0 17 7a5 5 0 0 0-5-5Zm0 2a3 3 0 0 1 3 3 3 3 0 0 1-6 0 3 3 0 0 1 3-3Z"/></svg>
                  </span>
                  <div className="kebab-item-body">
                    <button
                      type="button"
                      role="menuitem"
                      className="kebab-item-primary"
                      onClick={() => { setExportMenuOpen(false); exportTriageJson(); }}
                    >
                      <span className="kebab-item-title">Export for triage (JSON)</span>
                      <span className="kebab-item-sub">
                        Compact per-finding JSON — severity, GitHub link, title, description, evidence. Feed to an LLM triage agent. Respects current filters.
                      </span>
                    </button>
                    <div className="kebab-sev-shortcuts" aria-label="Quick severity export">
                      <span className="kebab-sev-label">Quick:</span>
                      {(["CRITICAL", "HIGH", "MEDIUM", "LOW", "ALL"] as const).map((sev) => (
                        <button
                          key={sev}
                          type="button"
                          className={`kebab-sev-chip sev-${sev}`}
                          onClick={() => { setExportMenuOpen(false); exportTriageJson(sev); }}
                          title={
                            sev === "ALL"
                              ? "Export all severities as triage JSON"
                              : `Export only ${sev} findings as triage JSON`
                          }
                        >
                          {sev === "ALL" ? "All" : sev.charAt(0) + sev.slice(1).toLowerCase()}
                        </button>
                      ))}
                    </div>
                  </div>
                </div>
                <button
                  type="button"
                  role="menuitem"
                  className="kebab-item"
                  onClick={() => { setExportMenuOpen(false); exportReviewed("json"); }}
                >
                  <span className="kebab-item-icon" aria-hidden>
                    <svg viewBox="0 0 24 24"><path fill="currentColor" d="M9 3h6v6h6v12a2 2 0 0 1-2 2H9a2 2 0 0 1-2-2v-6H3v-2h4V5a2 2 0 0 1 2-2Zm-4 8v6h4v-6Zm12-6v4h4Z"/></svg>
                  </span>
                  <span className="kebab-item-body">
                    <span className="kebab-item-title">Reviewed as JSON</span>
                    <span className="kebab-item-sub">TP / FP verdicts with full evidence</span>
                  </span>
                </button>
                <button
                  type="button"
                  role="menuitem"
                  className="kebab-item"
                  onClick={() => { setExportMenuOpen(false); exportReviewed("csv"); }}
                >
                  <span className="kebab-item-icon" aria-hidden>
                    <svg viewBox="0 0 24 24"><path fill="currentColor" d="M4 4h16v3H4Zm0 5h16v3H4Zm0 5h16v3H4Zm0 5h16v3H4Z"/></svg>
                  </span>
                  <span className="kebab-item-body">
                    <span className="kebab-item-title">Reviewed as CSV</span>
                    <span className="kebab-item-sub">Spreadsheet-friendly, one row per finding</span>
                  </span>
                </button>
                </div>
              </>,
              document.body
            )}
          </div>
          <button
            type="button"
            className="export-btn delete-all-btn"
            disabled={deleteAllBusy || pageData.total === 0}
            onClick={deleteAllFindings}
            title="Permanently delete every finding in the database, ignoring current filters"
          >
            <svg viewBox="0 0 24 24" aria-hidden>
              <path fill="currentColor" d="M9 3h6l1 2h4v2H4V5h4Zm-3 6h12l-1 12H7Zm3 2v8h2v-8Zm4 0v8h2v-8Z"/>
            </svg>
            <span>{deleteAllBusy ? "Deleting…" : "Delete All"}</span>
          </button>
          <span className="toolbar-count">
            {pageData.total} findings · page {pageData.page}/{totalPages}
          </span>
        </div>

        <div className="bulk-bar">
          <label className="bulk-check">
            <input type="checkbox" checked={allVisibleSelected} onChange={toggleAllVisible} />
            <span>Select visible</span>
          </label>
          <span className="bulk-count">{selectedIds.size} selected</span>
          <div className="bulk-spacer" />
          <button
            className="pill-btn pill-tp"
            disabled={bulkBusy || selectedIds.size === 0}
            onClick={() => bulkSetManualVerdict("true_positive")}
            title="Mark selected findings as true positives"
          >
            <svg viewBox="0 0 24 24" aria-hidden><path fill="currentColor" d="m9 16.2-3.5-3.5L4 14.2 9 19 20 8l-1.5-1.5Z"/></svg>
            Mark TP
          </button>
          <button
            className="pill-btn pill-tp-overstated"
            disabled={bulkBusy || selectedIds.size === 0}
            onClick={() => bulkSetManualVerdict("true_positive_severity_overstated")}
            title="Mark selected findings as true positives whose severity is inflated relative to real-world exploitability"
          >
            <svg viewBox="0 0 24 24" aria-hidden><path fill="currentColor" d="M12 3 2 21h20L12 3zm0 6 6.5 11h-13L12 9zm-1 4v4h2v-4h-2zm0 5v2h2v-2h-2z"/></svg>
            Mark TP · overstated
          </button>
          <button
            className="pill-btn pill-fp"
            disabled={bulkBusy || selectedIds.size === 0}
            onClick={() => bulkSetManualVerdict("false_positive")}
            title="Mark selected findings as false positives"
          >
            <svg viewBox="0 0 24 24" aria-hidden><path fill="currentColor" d="M18.3 5.7 12 12l6.3 6.3-1.4 1.4L10.6 13.4 4.3 19.7l-1.4-1.4L9.2 12 2.9 5.7l1.4-1.4L10.6 10.6l6.3-6.3Z"/></svg>
            Mark FP
          </button>
          <button
            className="pill-btn pill-neutral"
            disabled={bulkBusy || selectedIds.size === 0}
            onClick={() => bulkSetManualVerdict(null)}
            title="Clear the manual verdict on the selected findings"
          >
            <svg viewBox="0 0 24 24" aria-hidden><path fill="currentColor" d="M6 11h12v2H6z"/></svg>
            Clear verdict
          </button>
          <button
            className="pill-btn pill-danger"
            disabled={bulkBusy || selectedIds.size === 0}
            onClick={bulkDeleteSelected}
            title="Delete selected findings from the database"
          >
            <svg viewBox="0 0 24 24" aria-hidden><path fill="currentColor" d="M9 3h6l1 2h4v2H4V5h4Zm-3 6h12l-1 12H7Zm3 2v8h2v-8Zm4 0v8h2v-8Z"/></svg>
            Delete
          </button>
          <button
            className="pill-btn pill-primary"
            disabled={bulkBusy || selectedIds.size === 0}
            onClick={bulkRecheck}
            title="Fetch each workflow at HEAD and re-run the scanner. Fixed / deleted findings are moved to Archived."
          >
            <svg viewBox="0 0 24 24" aria-hidden><path fill="currentColor" d="M12 5V2L7 7l5 5V8a5 5 0 0 1 5 5 5 5 0 0 1-5 5 5 5 0 0 1-4.9-4H5.1A7 7 0 1 0 12 5Z"/></svg>
            Recheck at HEAD
          </button>
        </div>
        {recheckMessage && (
          <div className="note" style={{ borderLeftColor: "var(--info)", marginBottom: 8 }}>
            {recheckMessage}
          </div>
        )}

        {findingsLoading && items.length === 0 ? (
          <div className="empty findings-loading">
            <span className="spinner" aria-hidden />
            <span>Loading findings…</span>
          </div>
        ) : items.length === 0 ? (
          <div className="empty">
            {status?.state === "done" || pageData.total === 0
              ? "No matching findings."
              : "Run a scan to see findings here."}
          </div>
        ) : (
          <>
            <div className="findings">
              {items.map((f) => (
                <div key={f.id} className="finding" onClick={() => openFinding(f)}>
                  <div className="top">
                    <input
                      type="checkbox"
                      checked={selectedIds.has(f.id)}
                      onClick={(e) => e.stopPropagation()}
                      onChange={() => toggleSelected(f.id)}
                      aria-label={`Select finding ${f.title}`}
                    />
                    {activeLivePocFindings.has(f.id) && (
                      <span
                        className="jobs-dot jobs-dot-blink finding-live-poc-dot"
                        title="Live PoC is running for this finding"
                        aria-label="Live PoC is running for this finding"
                      />
                    )}
                    <span className={`badge ${f.severity}`}>{f.severity}</span>
                    <span className="badge">{f.exploitability.replace(/_/g, " ")}</span>
                    {f.category && <span className="badge" title={f.category}>{f.category.replace(/-/g, " ")}</span>}
                    {f.manual_verdict && (
                      <span
                        className={`badge verdict-${f.manual_verdict}`}
                        title={
                          f.manual_verdict === "true_positive_severity_overstated"
                            ? "Real finding, but the assigned severity is inflated relative to real-world exploitability."
                            : undefined
                        }
                      >
                        {f.manual_verdict === "true_positive"
                          ? "True positive"
                          : f.manual_verdict === "false_positive"
                            ? "False positive"
                            : "TP · sev overstated"}
                      </span>
                    )}
                    {f.archived_state && f.archived_state !== "live" && (
                      <span
                        className={`badge archived-${f.archived_state}`}
                        title={f.archived_reason || ""}
                      >
                        {f.archived_state === "fixed" ? "Fixed" : f.archived_state === "deleted" ? "File deleted" : "Archived"}
                      </span>
                    )}
                    <div className="title">{f.title}</div>
                  </div>
                  <div className="row2">
                    <span className="repo">{f.repo}</span>
                    <span className="repo">·</span>
                    <span className="repo">{f.workflow_path}</span>
                    {f.job && <span className="repo">· job: {f.job}</span>}
                    <span className="repo">· trigger: {f.trigger}</span>
                    {f.created_at && (
                      <span
                        className="repo"
                        title={new Date(f.created_at * 1000).toLocaleString()}
                      >
                        · first seen: {new Date(f.created_at * 1000).toLocaleDateString()}
                      </span>
                    )}
                    <div className="spacer" style={{ flex: 1 }} />
                    <span className="repo">Confidence {f.confidence}%</span>
                    <div className="bar">
                      <div style={{ width: `${f.confidence}%` }} />
                    </div>
                    <button
                      className="btn ghost"
                      style={{ padding: "4px 10px", fontSize: 12 }}
                      onClick={(e) => deleteFinding(f.id, e)}
                      title="Delete this finding"
                    >
                      Delete
                    </button>
                  </div>
                </div>
              ))}
            </div>

            <div className="toolbar" style={{ marginTop: 14, justifyContent: "center" }}>
              <button
                className="btn ghost"
                disabled={page <= 1}
                onClick={() => setPage((p) => Math.max(1, p - 1))}
              >
                ← Prev
              </button>
              <span style={{ color: "var(--muted)", fontSize: 13 }}>
                Page {pageData.page} of {totalPages}
              </span>
              <button
                className="btn ghost"
                disabled={page >= totalPages}
                onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
              >
                Next →
              </button>
            </div>
          </>
        )}
        </>
        )}

        {mainView === "diff" && (
          <DiffView
            data={diffData}
            loading={diffLoading}
            error={diffError}
            scans={diffScanList}
            scanId={diffScanId}
            setScanId={setDiffScanId}
            againstId={diffAgainstId}
            setAgainstId={setDiffAgainstId}
            persistentFilter={diffPersistentFilter}
            setPersistentFilter={setDiffPersistentFilter}
            onOpenFinding={openFinding}
          />
        )}

        {mainView === "rules" && (
          <RulesView
            categories={categories}
            onOpenFinding={(cat) => {
              // Route the click to the Findings view with the category
              // filter pinned. Users can drill straight from the catalog
              // into every finding of that class.
              setFilterCat(cat);
              setPage(1);
              setMainView("findings");
            }}
          />
        )}

        <JobsView
          visible={mainView === "jobs"}
          onOpenFinding={(fid) => { void openFinding(fid); }}
          onActiveFindingsChange={(fids) => setActiveLivePocFindings(new Set(fids))}
        />
        <QueueView
          visible={mainView === "queue"}
          focusJobId={queueFocusJobId}
          onSummaryChange={setQueueSummary}
          onOpenScan={async (id) => {
            setScanId(id);
            setScanFilter("this");
            setPage(1);
            setMainView("findings");
            try {
              const response = await fetch(`/api/scan/${id}`);
              if (!response.ok) throw new Error(await response.text());
              setStatus(await response.json());
            } catch (err) {
              setError(String(err));
            }
          }}
        />
      </main>

      {(selected || selectedLoading) && (
        <div className="drawer-mask" onClick={() => { setSelected(null); setSelectedLoading(false); setAskAI(null); setAskAIError(null); setManualVerdictError(null); }}>
          <div className="drawer" onClick={(e) => e.stopPropagation()}>
            {selectedLoading && !selected ? (
              <div className="note">Loading finding details…</div>
            ) : selected && (
              <>
            <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
              <span className={`badge ${selected.severity}`}>{selected.severity}</span>
              <span className="badge">{selected.exploitability.replace(/_/g, " ")}</span>
              <span className="badge">Confidence {selected.confidence}%</span>
              {selected.archived_state && selected.archived_state !== "live" && (
                <span
                  className={`badge archived-${selected.archived_state}`}
                  title={selected.archived_reason || ""}
                >
                  {selected.archived_state === "fixed" ? "Fixed at HEAD" : selected.archived_state === "deleted" ? "File deleted at HEAD" : "Archived"}
                </span>
              )}
              <div className="spacer" style={{ flex: 1 }} />
              <button
                className="btn ghost"
                style={{ padding: "6px 12px" }}
                onClick={recheckFinding}
                disabled={recheckBusy}
                title="Fetch the workflow at HEAD and re-run the scanner rule for this finding."
              >
                {recheckBusy ? "Rechecking…" : "Recheck at HEAD"}
              </button>
              {selected.severity !== "LOW" && selected.severity !== "INFO" && (
                <button
                  className="btn ghost"
                  style={{ padding: "6px 12px" }}
                  onClick={() => {
                    setLivePocRefresh((v) => v + 1);
                    setDrawerTab("live-poc");
                  }}
                  title="Open the Live PoC tab to verify this finding live"
                >
                  Live PoC →
                </button>
              )}
              <button
                className="btn ghost"
                style={{ padding: "6px 12px" }}
                onClick={(e) => deleteFinding(selected.id, e)}
              >
                Delete finding
              </button>
            </div>
            {recheckMessage && (
              <div className="note" style={{ marginTop: 8 }}>{recheckMessage}</div>
            )}
            {selected.archived_state && selected.archived_state !== "live" && selected.archived_reason && (
              <div className="note" style={{ marginTop: 8, borderLeftColor: "var(--muted)" }}>
                <strong>Archived reason:</strong> {selected.archived_reason}
                {selected.last_recheck_at && (
                  <> · <span className="repo">rechecked {new Date(selected.last_recheck_at * 1000).toLocaleString()}</span></>
                )}
              </div>
            )}
            <h2 style={{ marginTop: 10 }}>{selected.title}</h2>
            <div
              className="finding-id"
              title="Click to copy this finding ID"
              onClick={async () => {
                try {
                  await navigator.clipboard.writeText(selected.id);
                  setCopied(true);
                  setTimeout(() => setCopied(false), 1600);
                } catch { /* clipboard blocked — fall through */ }
              }}
            >
              <span className="finding-id-label">id</span>
              <span className="finding-id-value">{selected.id}</span>
              <span className="finding-id-copy">{copied ? "copied" : "copy"}</span>
            </div>
            <div style={{ color: "var(--muted)" }}>
              <a className="link" href={selected.workflow_url} target="_blank" rel="noreferrer">
                {selected.repo} / {selected.workflow_path}
              </a>
              {selected.job && <> · job <span className="kbd">{selected.job}</span></>}
              {selected.step && <> · step <span className="kbd">{selected.step}</span></>}
              <> · trigger <span className="kbd">{selected.trigger}</span></>
            </div>

            <div className="manual-verdict" role="group" aria-label="Manual finding verdict">
              <div className="manual-verdict-header">
                <div className="manual-verdict-title">Manual analysis verdict</div>
                <div className="manual-verdict-help">
                  Mark this after review; it autosaves and can be used later to improve scanner precision.
                </div>
              </div>
              <div className="manual-verdict-choices">
                <label>
                  <input
                    type="radio"
                    name={`manual-verdict-${selected.id}`}
                    checked={selected.manual_verdict === "true_positive"}
                    disabled={manualVerdictSaving}
                    onChange={() => saveManualVerdict("true_positive")}
                  />
                  True positive
                </label>
                <label title="Real finding, but the assigned severity is inflated relative to real-world exploitability.">
                  <input
                    type="radio"
                    name={`manual-verdict-${selected.id}`}
                    checked={selected.manual_verdict === "true_positive_severity_overstated"}
                    disabled={manualVerdictSaving}
                    onChange={() => saveManualVerdict("true_positive_severity_overstated")}
                  />
                  TP · sev overstated
                </label>
                <label>
                  <input
                    type="radio"
                    name={`manual-verdict-${selected.id}`}
                    checked={selected.manual_verdict === "false_positive"}
                    disabled={manualVerdictSaving}
                    onChange={() => saveManualVerdict("false_positive")}
                  />
                  False positive
                </label>
                {selected.manual_verdict && (
                  <button className="btn ghost manual-verdict-clear" disabled={manualVerdictSaving} onClick={() => saveManualVerdict(null)}>
                    Clear
                  </button>
                )}
                <span className="manual-verdict-status">
                  {manualVerdictSaving ? "Saving..." : selected.manual_verdict ? "Saved" : "Not marked"}
                </span>
              </div>
            </div>
            {manualVerdictError && (
              <div className="error" style={{ marginTop: 10 }}>{manualVerdictError}</div>
            )}

            {selected.gates_detected && selected.gates_detected.length > 0 && (
              <div className="gates-detected">
                <div className="gates-detected-title">Detected gates (auto-downgrade rationale)</div>
                <ul>
                  {selected.gates_detected.map((g, i) => {
                    const m = g.match(/^\[(strong|medium|weak)\]\s*(.+)$/i);
                    const strength = m ? m[1].toLowerCase() : "info";
                    const label = m ? m[2] : g;
                    return (
                      <li key={i}>
                        <span className={`badge gate-${strength}`}>{strength}</span>
                        <span style={{ marginLeft: 8 }}>{label}</span>
                      </li>
                    );
                  })}
                </ul>
              </div>
            )}

            <div className="drawer-tabs" role="tablist" aria-label="Finding views">
              <button
                className={`tab ${drawerTab === "details" ? "active" : ""}`}
                role="tab"
                aria-selected={drawerTab === "details"}
                onClick={() => setDrawerTab("details")}
              >
                Details & report
              </button>
              <button
                className={`tab ${drawerTab === "graph" ? "active" : ""}`}
                role="tab"
                aria-selected={drawerTab === "graph"}
                onClick={() => setDrawerTab("graph")}
              >
                Exploitability graph
              </button>
              <button
                className={`tab ${drawerTab === "live-poc" ? "active" : ""}`}
                role="tab"
                aria-selected={drawerTab === "live-poc"}
                onClick={() => {
                  setLivePocRefresh((v) => v + 1);
                  setDrawerTab("live-poc");
                }}
                title="Reproduce this finding end-to-end in a private mirror"
              >
                Live PoC
              </button>
            </div>

            {drawerTab === "details" ? (
              <>
            <h3>Why exploitation is possible</h3>
            <ul>
              {selected.why.map((w, i) => (
                <li key={i}>{w}</li>
              ))}
            </ul>

            <h3>Evidence</h3>
            <ul>
              {selected.evidence.map((e, i) => (
                <li key={i}><code>{e}</code></li>
              ))}
            </ul>

            <h3>Workflow snippet</h3>
            <pre>{selected.snippet}</pre>

            <h3>Remediation</h3>
            <ul>
              {selected.remediation.map((r, i) => (
                <li key={i}>{r}</li>
              ))}
            </ul>

            <h3 style={{ display: "flex", alignItems: "center", gap: 8 }}>
              Ask AI exploitability check
              <span style={{ flex: 1 }} />
              <button
                className="btn"
                style={{ padding: "6px 12px", fontSize: 12 }}
                onClick={askAIValidate}
                disabled={askAILoading}
              >
                {askAILoading ? "Validating..." : "Ask AI"}
              </button>
            </h3>
            <div className="note">
              Sends only this workflow YAML to local Ollama, plus dependent workflow YAML only when
              this workflow references it, then checks whether gates make the issue not worth pursuing.
            </div>
            {askAILoading && (
              <div className="note">Fetching repository context and validating exploitability...</div>
            )}
            {askAIError && (
              <div className="error" style={{ marginTop: 10 }}>{askAIError}</div>
            )}
            {askAI && (
              <div style={{ marginTop: 10 }}>
                <div style={{ display: "flex", gap: 8, flexWrap: "wrap", alignItems: "center" }}>
                  <span className="badge">{askAI.verdict}</span>
                  <span className="badge">{askAI.final_severity}</span>
                  <span className="badge">AI confidence {askAI.confidence}</span>
                  <span className="badge">{askAI.attacker_can_exploit ? (askAI.blocking_gates.length > 0 ? "Attacker can exploit with conditions" : "Attacker can exploit") : "Exploit not confirmed"}</span>
                </div>
                <div className="note" style={{ marginTop: 10 }}>
                  <strong>Recommendation:</strong> {askAI.recommendation}
                </div>
                <h4 style={{ marginTop: 14, marginBottom: 4 }}>Summary</h4>
                <div>{askAI.summary}</div>
                <h4 style={{ marginTop: 14, marginBottom: 4 }}>Can attacker actually exploit it?</h4>
                <div>{askAI.attacker_can_exploit ? (askAI.blocking_gates.length > 0 ? "Yes, but only under the listed gates/caveats." : "Yes, based on the provided workflow context.") : "Not confirmed from the provided workflow context."}</div>
                {askAI.blocking_gates.length > 0 && (
                  <>
                    <h4 style={{ marginTop: 14, marginBottom: 4 }}>Blocking gates / caveats</h4>
                    <ul>{askAI.blocking_gates.map((g, i) => <li key={i}>{g}</li>)}</ul>
                  </>
                )}
                {askAI.severity_lowering_factors.length > 0 && (
                  <>
                    <h4 style={{ marginTop: 14, marginBottom: 4 }}>What lowers severity</h4>
                    <ul>{askAI.severity_lowering_factors.map((g, i) => <li key={i}>{g}</li>)}</ul>
                  </>
                )}
                <h4 style={{ marginTop: 14, marginBottom: 4 }}>Attacker model</h4>
                <div>{askAI.attacker_model}</div>
                <h4 style={{ marginTop: 14, marginBottom: 4 }}>Required preconditions</h4>
                <ul>{askAI.required_preconditions.map((p, i) => <li key={i}>{p}</li>)}</ul>
                <h4 style={{ marginTop: 14, marginBottom: 4 }}>Realistic exploit path</h4>
                <ol>{askAI.realistic_exploit_path.map((s, i) => <li key={i}>{s}</li>)}</ol>
                <div style={{ marginTop: 10 }}>
                  <strong>Ease:</strong> {askAI.ease_of_exploit} · <strong>Reliability:</strong> {askAI.reliability}
                </div>
                <h4 style={{ marginTop: 14, marginBottom: 4 }}>Real impact</h4>
                <div>{askAI.real_impact}</div>
                {askAI.why_overstated && (
                  <>
                    <h4 style={{ marginTop: 14, marginBottom: 4 }}>Why the scanner claim may be overstated</h4>
                    <div>{askAI.why_overstated}</div>
                  </>
                )}
                <h4 style={{ marginTop: 14, marginBottom: 4 }}>Evidence references</h4>
                <ul>
                  {askAI.evidence.map((e, i) => (
                    <li key={i}>
                      <code>{e.file}:{e.lines}</code> — {e.reason}
                    </li>
                  ))}
                </ul>
              </div>
            )}

            <h3 className="drawer-report-head">
              <span>Bug bounty report</span>
              <span className="drawer-report-spacer" />
              <div className="export-menu-wrap" ref={reportMenuRef}>
                <button
                  type="button"
                  className={`kebab-btn ${reportMenuOpen ? "is-open" : ""}`}
                  onClick={() => setReportMenuOpen((v) => !v)}
                  aria-haspopup="menu"
                  aria-expanded={reportMenuOpen}
                  aria-label="Report actions"
                  title="Report actions"
                  disabled={!report}
                >
                  <svg viewBox="0 0 24 24" aria-hidden>
                    <circle cx="12" cy="5"  r="1.75" fill="currentColor" />
                    <circle cx="12" cy="12" r="1.75" fill="currentColor" />
                    <circle cx="12" cy="19" r="1.75" fill="currentColor" />
                  </svg>
                </button>
                {reportMenuOpen && report && (
                  <div className="kebab-menu" role="menu">
                    <div className="kebab-menu-title">Report</div>
                    <button
                      type="button"
                      role="menuitem"
                      className="kebab-item"
                      onClick={() => { setReportMenuOpen(false); void copyReport(); }}
                    >
                      <span className="kebab-item-icon" aria-hidden>
                        <svg viewBox="0 0 24 24"><path fill="currentColor" d="M16 1H4a2 2 0 0 0-2 2v14h2V3h12Zm3 4H8a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h11a2 2 0 0 0 2-2V7a2 2 0 0 0-2-2Zm0 16H8V7h11Z"/></svg>
                      </span>
                      <span className="kebab-item-body">
                        <span className="kebab-item-title">{copied ? "Copied!" : "Copy markdown"}</span>
                        <span className="kebab-item-sub">Paste into a disclosure ticket / bug-bounty portal</span>
                      </span>
                    </button>
                    <button
                      type="button"
                      role="menuitem"
                      className="kebab-item"
                      onClick={() => { setReportMenuOpen(false); downloadReport(); }}
                    >
                      <span className="kebab-item-icon" aria-hidden>
                        <svg viewBox="0 0 24 24"><path fill="currentColor" d="M5 3h11l4 4v14a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1Zm10 2v4h4ZM8 13v2h8v-2Zm0 4v2h5v-2Z"/></svg>
                      </span>
                      <span className="kebab-item-body">
                        <span className="kebab-item-title">Download Markdown</span>
                        <span className="kebab-item-sub">Full report as <code>.md</code></span>
                      </span>
                    </button>
                    <button
                      type="button"
                      role="menuitem"
                      className="kebab-item"
                      onClick={() => { setReportMenuOpen(false); downloadSelectedSarif(); }}
                    >
                      <span className="kebab-item-icon" aria-hidden>
                        <svg viewBox="0 0 24 24"><path fill="currentColor" d="M5 3h11l4 4v14a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1V4a1 1 0 0 1 1-1Zm10 2v4h4Zm-3 6h-2v4H8l4 4 4-4h-2v-4Z"/></svg>
                      </span>
                      <span className="kebab-item-body">
                        <span className="kebab-item-title">Download SARIF</span>
                        <span className="kebab-item-sub">SARIF 2.1.0 · GitHub code scanning / DefectDojo / GitLab SAST</span>
                      </span>
                    </button>
                  </div>
                )}
              </div>
            </h3>
            {reportLoading && (
              <div className="note">Generating bug-bounty summary…</div>
            )}
            {report && (
              <>
                <div className="note">
                  Ready to copy or download for a disclosure report. Validate against the program's
                  scope and never run destructive PoCs against production.
                </div>
                <div style={{ marginTop: 10 }}>
                  <div><strong>Title:</strong> {report.title}</div>
                  <div>
                    <strong>Severity:</strong> {report.severity}
                    {" · "}
                    <strong>CVSS:</strong> {report.cvss_score != null ? report.cvss_score.toFixed(1) : report.cvss_estimate}
                    {report.cvss_vector && <> <code>{report.cvss_vector}</code></>}
                  </div>
                  <div><strong>Class:</strong> {report.vulnerability_class}</div>
                  <div><strong>Asset:</strong> {report.affected_asset}</div>
                  {report.tainted_expression && (
                    <div>
                      <strong>Tainted expression:</strong>{" "}
                      <code>{report.tainted_expression}</code>
                    </div>
                  )}
                  {report.detected_sink_line && (
                    <div>
                      <strong>Sink line:</strong>{" "}
                      <code>{report.detected_sink_line}</code>
                    </div>
                  )}
                </div>
                <h4 style={{ marginTop: 14, marginBottom: 4 }}>Summary</h4>
                <div>{report.summary}</div>
                <h4 style={{ marginTop: 14, marginBottom: 4 }}>Root cause</h4>
                <pre style={{ whiteSpace: "pre-wrap" }}>{report.root_cause}</pre>
                <h4 style={{ marginTop: 14, marginBottom: 4 }}>Vulnerable line</h4>
                <pre style={{ whiteSpace: "pre-wrap" }}>{report.vulnerable_line}</pre>
                <h4 style={{ marginTop: 14, marginBottom: 4 }}>Impact</h4>
                <div>{report.impact}</div>
                <h4 style={{ marginTop: 14, marginBottom: 4 }}>Steps to replicate</h4>
                <ol>
                  {report.steps_to_reproduce.map((s, i) => <li key={i}>{s}</li>)}
                </ol>
                <h4 style={{ marginTop: 14, marginBottom: 4 }}>Proof of concept</h4>
                <pre style={{ whiteSpace: "pre-wrap" }}>{report.proof_of_concept}</pre>
                <h4 style={{ marginTop: 14, marginBottom: 4 }}>Fix (unified diff)</h4>
                <pre style={{ whiteSpace: "pre-wrap" }} className="fix-diff">{report.fix_diff}</pre>
                <h4 style={{ marginTop: 14, marginBottom: 4 }}>References</h4>
                <ul>
                  {report.references.map((r, i) => <li key={i}><code>{r}</code></li>)}
                </ul>
              </>
            )}
              </>
            ) : drawerTab === "graph" ? (
              <ExploitabilityGraph finding={selected} />
            ) : (
              <div className="drawer-live-poc">
                <LivePocView
                  visible
                  initialFindingId={selected.id}
                  findingFilter={selected.id}
                  refreshTick={livePocRefresh}
                  onOpenFinding={() => { /* already viewing this finding */ }}
                  onSummaryChange={() => { /* no dashboard badge to update */ }}
                />
              </div>
            )}

            <div style={{ marginTop: 18 }}>
              <button className="btn ghost" onClick={() => { setSelected(null); setReport(null); setAskAI(null); setAskAIError(null); }}>
                Close
              </button>
            </div>
              </>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

function Stat({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className="stat">
      <div className="lbl">{label}</div>
      <div className="val" style={{ color }}>{value}</div>
    </div>
  );
}

// ============================================================================
// Rules catalog — grouped view of every detection Grafter runs, so users
// understand the coverage surface before drilling into individual findings.
// Nine families, ~45 categories. Family accents come from the severity
// palette so the visual weight matches the average severity of the family.
// ============================================================================
type RuleEntry = {
  key: string;      // matches the `category` field returned by /api/findings
  label: string;    // short human-readable name
  summary: string;  // 1-2 sentence description of what triggers it
};

type RuleFamily = {
  id: string;
  name: string;
  intro: string;
  accent: "crit" | "high" | "med" | "low" | "info" | "accent";
  categories: RuleEntry[];
};

const RULES_CATALOG: RuleFamily[] = [
  {
    id: "untrusted-code-exec",
    name: "Untrusted code execution",
    accent: "crit",
    intro:
      "Attacker-controlled code — from a fork PR, an issue comment, an issue-triggered PR-ref pivot, or a Dockerfile inside a PR checkout — reaches an execution sink on the workflow's runner. This is the highest-impact family; it's how CI/CD compromises usually start.",
    categories: [
      { key: "checkout-untrusted", label: "Untrusted code checkout", summary: "`actions/checkout` resolves to attacker-controlled PR head in a privileged trigger (`pull_request_target`, `workflow_run`, `issues`, `issue_comment`) followed by a build/install/test sink." },
      { key: "pr-code-execution-risk", label: "PR-controlled code execution risk", summary: "A `pull_request` job on a self-hosted runner or with cloud/OIDC credentials in scope executes checked-out fork code. Even without `pull_request_target` this is impactful." },
      { key: "pull-request-ci-code-execution", label: "pull_request CI executes contributor code", summary: "Hosted-runner PR CI that ends up running attacker code. Usually visibility, but escalates when the same job holds an id-token or registry PAT." },
      { key: "pull-request-authenticated-code-execution", label: "Fork PR code after approved environment login", summary: "Plain fork `pull_request` runs receive no repository/org secrets or usable OIDC. This conditional rule fires only when a maintainer-approved environment may release environment credentials before PR-controlled code executes." },
      { key: "pr-controlled-dockerfile-build", label: "PR-controlled Dockerfile build", summary: "`docker build` / `docker/build-push-action` / `buildah` executes the attacker's Dockerfile `RUN` instructions on the runner after PR checkout." },
      { key: "reusable-local-action-untrusted", label: "Local/reusable action from checkout", summary: "Post-checkout `uses: ./local/action` runs the attacker's `action.yml` with the caller job's permissions." },
      { key: "comment-command-pr-checkout", label: "Issue/comment command checks out PR", summary: "An `issues` or `issue_comment` workflow checks out the referenced PR head (`refs/pull/<n>/head`) and executes it under base-repo secrets." },
      { key: "pull-request-auto-merge-untrusted", label: "Untrusted PR can trigger auto-merge", summary: "A PR-reachable workflow enables or performs merge based on attacker-controlled or insufficiently trusted input. Branch protection may limit impact, but weak approval gates can turn this into default-branch compromise." },
      { key: "living-off-the-pipeline", label: "Living Off The Pipeline (LOTP)", summary: "A tool the workflow treats as a read-only check — linter, formatter, test runner, doc builder, build wrapper — loads a config file from the PR checkout and executes code from it at start-up. `conftest.py`, `.pre-commit-config.yaml`, `build.gradle`, `.mvn/extensions.xml`, `build.rs`, `eslint.config.js`, `Dangerfile`, `Directory.Build.props` and friends. No explicit build step required." },
    ],
  },
  {
    id: "injection",
    name: "Injection primitives",
    accent: "high",
    intro:
      "Attacker-controlled strings (PR title/body, issue title, comment body, branch name, commit author) are interpolated into shell / JavaScript / config sinks without escaping. Small primitives that combine into full RCE when a token is in scope.",
    categories: [
      { key: "script-injection", label: "Script injection via ${{ github.event.* }}", summary: "Untrusted event data interpolated directly into `run:`, `github-script`'s `script:`, or a wrapper action's shell field. Includes the env-indirection variant." },
      { key: "runner-control-injection", label: "Runner/container/shell field injection", summary: "Untrusted input flows into `runs-on:`, `container:`, `services:`, `shell:`, or matrix fields — attacker can redirect execution to unsafe runners/images." },
      { key: "deprecated-commands", label: "Deprecated / smuggle workflow commands", summary: "`::set-env`, `::add-path`, `::stop-commands::`, `::add-mask::` — command-channel smuggling primitives. Modern runners block most, but `::stop-commands::` still works." },
      { key: "bypassable-actor-allowlist-gate", label: "Bypassable actor allowlist gate", summary: "A trust decision uses substring, prefix/suffix, or another loose actor-name comparison instead of exact identity or permission checks, allowing lookalike usernames to pass." },
      { key: "filename-collision-download", label: "Untrusted download consumed by filename", summary: "An attacker-controlled URL or artifact is saved under a predictable trusted filename that a later step executes, installs, imports, or publishes without validating its source or digest." },
    ],
  },
  {
    id: "trust-boundary",
    name: "Cross-workflow trust-boundary leaks",
    accent: "crit",
    intro:
      "`workflow_run` and label-persistence bugs let untrusted context reach privileged jobs indirectly. Data an attacker writes in one workflow becomes trusted input in another; labels applied on one PR event carry across to a subsequent malicious push.",
    categories: [
      { key: "workflow_run-privileged", label: "Privileged workflow_run job", summary: "A `workflow_run` job runs with elevated permissions and consumes artifacts/metadata from an upstream fork-reachable workflow." },
      { key: "artifact-to-github-env", label: "Artifact content piped to $GITHUB_ENV / $GITHUB_PATH", summary: "Downloaded artifact content is written to env files; a newline in the attacker's content injects arbitrary env vars (LD_PRELOAD, NODE_OPTIONS)." },
      { key: "artifact-extraction-poisoning", label: "Untrusted artifact extraction", summary: "Zip/tarball artifacts extracted with insufficient validation — zip-slip / executable planting into runner paths." },
      { key: "cache-poisoning", label: "CI cache poisoning across trust boundary", summary: "Reports untrusted jobs only when cache writes are actually permitted. GitHub's low-trust default and explicit `cache-mode: read|none` are suppressed; explicit `write|write-only` overrides are flagged when risky executable paths or attacker-influenced keys can reach later trusted builds." },
      { key: "pull-request-target-label-persistence", label: "pull_request_target label persistence bypass", summary: "`types: [labeled, synchronize]` keeps the label on subsequent pushes — attacker earns the label with a benign push, then pushes the exploit." },
    ],
  },
  {
    id: "data-exfil",
    name: "Data exfiltration",
    accent: "crit",
    intro:
      "Direct paths for an attacker to pull secrets, credentials, or private repo content out of the CI environment.",
    categories: [
      { key: "upload-artifact-exfil", label: "Artifact path exfiltration", summary: "`actions/upload-artifact` with an attacker-controlled `path:` or `name:` — attacker uploads `~/.aws/credentials`, `~/.docker/config.json`, `.git/config` (with the workflow token) as a downloadable artifact." },
      { key: "verified-secret", label: "Verified live secret/API-key exposure", summary: "A provider-recognised credential in the repo was validated live via a read-only probe. Currently covers GitHub, OpenAI, Anthropic, AWS, GCP, Slack, Discord, npm, Stripe, SendGrid, HuggingFace, DockerHub, GitLab, and PEM private keys." },
      { key: "secrets-context-wholesale", label: "Whole `secrets` context serialised", summary: "`${{ toJSON(secrets) }}` or a bare `${{ secrets }}` reference expands every repository, organisation, and environment secret into one value. The in-workflow equivalent of `secrets: inherit` — masking does not contain it, and every step and third-party action in the job inherits the blob." },
      { key: "secret-echoed-to-log", label: "Unmasked secret confirmed in Actions logs", summary: "Grafter checks recent downloadable workflow logs and reports this only when a secret-shaped value actually survives GitHub's `***` masking. Evidence includes the run URL and a redacted preview/fingerprint, never the full value." },
    ],
  },
  {
    id: "runner-compromise",
    name: "Runner & infrastructure compromise",
    accent: "crit",
    intro:
      "Self-hosted / on-prem / GPU / 1ES runners have persistent state, IMDS access, cloud IAM roles, and internal network reach. Compromise here is often far worse than any hosted-runner bug.",
    categories: [
      { key: "self-hosted-runner-untrusted", label: "Untrusted workflow on self-hosted runner", summary: "Fork PR or comment-triggered workflow lands on a self-hosted runner — RCE on the runner host, IMDS reachable, workspace persistence." },
      { key: "self-hosted-runner-exposure", label: "Self-hosted runner exposed to untrusted trigger", summary: "Visibility variant — the runner is reachable from a PR-style trigger even if no direct source→sink was proven." },
      { key: "docker-runner-compromise", label: "Docker/socket runner compromise", summary: "Docker socket mount (`/var/run/docker.sock`), `--privileged` container, or host network exposure from a PR-triggered job." },
      { key: "pr-submodules-recursive", label: "PR-controlled .gitmodules (SSRF + token exfil)", summary: "`actions/checkout` with `submodules: true|recursive` — attacker's `.gitmodules` becomes outbound HTTP with the workflow token in the Authorization header." },
    ],
  },
  {
    id: "cloud-registry",
    name: "Cloud & registry abuse",
    accent: "high",
    intro:
      "OIDC federated identity, published packages, published images, and cloud logins are the exit routes from a compromised CI job to the rest of the org's infrastructure.",
    categories: [
      { key: "oidc-cloud-credential-abuse", label: "OIDC/cloud credential exposure from untrusted workflow", summary: "`id-token: write` on a fork-reachable trigger — attacker mints an OIDC JWT, exchanges for cloud credentials if the trust policy admits PR context." },
      { key: "oidc-cloud-credential-visibility", label: "OIDC credential exposure visibility", summary: "Weaker variant — the workflow grants `id-token: write` without a direct exploit path, but org owners should verify the trust policy." },
      { key: "release-publish-poisoning", label: "Release/package/container publish poisoning", summary: "Untrusted input reaches a release/publish step (`npm publish`, `gh release`, `docker push`, `pypa/gh-action-pypi-publish`) — attacker ships a poisoned artifact to downstream consumers." },
    ],
  },
  {
    id: "supply-chain",
    name: "Supply chain",
    accent: "med",
    intro:
      "Actions, reusable workflows, and installer scripts brought in from outside the repo. Compromise of an upstream = compromise of every job that consumed it since the tag last moved.",
    categories: [
      { key: "third-party-action-supply-chain", label: "Mutable third-party action in privileged job", summary: "External action pinned by moving tag/branch in a job that holds secrets or write scopes — a hijacked upstream is a one-shot org compromise." },
      { key: "mutable-action-reference", label: "Mutable or unpinned action reference", summary: "Any action pinned by tag / branch rather than a 40-char commit SHA. Hygiene finding; escalates in privileged contexts." },
      { key: "remote-script-installer", label: "Remote script installer (curl | bash)", summary: "`curl -fsSL … | bash`, `wget | sh`, or similar patterns that execute remote code at workflow runtime." },
      { key: "reusable-workflow-secret-inheritance", label: "Reusable workflow `secrets: inherit`", summary: "Caller forwards every secret to a reusable workflow instead of naming the required ones — the callee sees more than it needs." },
    ],
  },
  {
    id: "agentic",
    name: "Agentic workflow injection (AI / LLM)",
    accent: "high",
    intro:
      "AI agents (Claude, Codex, Aider, GPT-based bots, github-models, azure-openai, MCP integrations) that consume untrusted PR/issue/comment/review text and then have write access to the repo. Prompt-injection turns into direct commits, PRs, comments, or tool execution.",
    categories: [
      { key: "agentic-workflow-injection", label: "Agentic workflow injection", summary: "Untrusted PR/issue/comment text feeds an AI agent that can write to the repo (open/edit PRs, push commits, post comments/checks/releases)." },
      { key: "agentic-code-context-poisoning", label: "Agentic code/context poisoning", summary: "PR diff / uploaded artifact / referenced files become the agent's code context — attacker steers reasoning by planting instructions in `AGENTS.md`, README, or diff comments." },
      { key: "agentic-tool-execution", label: "LLM output drives tool or command execution", summary: "The model's output pipes into `bash`, `eval`, `git apply`, `patch -p1`, `apply_patch`, or `>> $GITHUB_ENV` — arbitrary shell execution." },
      { key: "agentic-comment-command", label: "Comment/review command invokes privileged AI agent", summary: "`/fix`, `/review`, or similar comment triggers an agent with write scope — any external commenter can invoke it." },
      { key: "agentic-workflow-run-poisoning", label: "workflow_run feeds untrusted data to agent", summary: "A privileged `workflow_run` job downloads artifacts from a fork-reachable upstream and pipes them into the agent's prompt/context." },
      { key: "agentic-prompt-file-poisoning", label: "Agent loads PR-controlled prompt files", summary: "`--prompt-file AGENTS.md`, `--instructions-file`, `--system-prompt` etc. where the referenced file is checked out from the attacker's PR." },
      { key: "agentic-mcp-config-poisoning", label: "Agent loads PR-controlled MCP config", summary: "`.mcp.json`, `mcp_settings.json`, or `--mcp-config` points at a PR-checked-out file — attacker defines the tool set." },
      { key: "agentic-secrets-to-ai-context", label: "Secrets exposed to AI on untrusted input", summary: "`${{ secrets.X }}` is passed into an agent prompt / API call whose other input is attacker-controlled. Model may leak the secret back into the response." },
      { key: "agentic-output-auto-apply", label: "LLM output auto-applied or executed", summary: "`--yes`, `--auto`, `--dangerously`, `--permission-mode acceptEdits` flags disable human review; agent's output is committed / pushed directly." },
      { key: "agentic-verdict-authorization", label: "LLM verdict authorises privileged action", summary: "Agent's yes/no verdict decides whether a privileged step runs (auto-approve PR, auto-merge, auto-deploy). Prompt injection = authorisation bypass." },
    ],
  },
  {
    id: "hygiene",
    name: "Hygiene & visibility",
    accent: "info",
    intro:
      "Organisational-visibility findings — usually not directly exploitable on their own, but org owners want to see them for hardening. Many are pre-conditions that turn other findings CRITICAL when they co-occur.",
    categories: [
      { key: "permissions-not-pinned", label: "GITHUB_TOKEN permissions not explicitly pinned", summary: "Workflow inherits repo-default permissions (usually broader than needed). Set `permissions:` explicitly at the workflow or job level." },
      { key: "excessive-token-permissions", label: "Broad GITHUB_TOKEN permissions", summary: "`contents: write`, `packages: write`, `id-token: write`, or `write-all` — write scopes on a `pull_request_target` job are the multiplier for other primitives." },
      { key: "checkout-credential-persistence", label: "Checkout credentials persisted in workspace", summary: "`actions/checkout` without `persist-credentials: false` — the workflow token stays in `.git/config` and can be read by any later step." },
      { key: "pull-request-target-metadata-write", label: "pull_request_target metadata write scope", summary: "The job can write PR/issue/label/check/status metadata even without a direct code-execution primitive." },
      { key: "comment-trigger-write-scope", label: "Comment/review-triggered job with write scope", summary: "Comment/review/discussion-comment workflows hold write-capable token scopes — external users can potentially trigger those writes." },
      { key: "artifact-retention-or-scope", label: "Broad artifact upload or long retention", summary: "Wide `path:`, hidden files included, or long retention — CI data leakage hygiene." },
      { key: "cache-restore-key-fallback", label: "Broad cache restore-key fallback", summary: "Wide `restore-keys:` prefixes — cache confusion risk between untrusted PR jobs and trusted release/deploy jobs." },
      { key: "security-step-continue-on-error", label: "Security check allowed to fail", summary: "`continue-on-error: true` on security-scanning steps hides findings from required status checks." },
      { key: "workflow-parse-error", label: "Workflow YAML failed to parse", summary: "Grafter couldn't parse the workflow YAML. Usually a syntax bug; occasionally a sign the file was edited to look like broken YAML on purpose." },
      { key: "policy-file-unauth-mutation", label: "Unauthenticated issue-ops policy mutation", summary: "A `.github/policies` task responds to an issue, PR, or comment event with labels, closure, approval, merge, review dismissal, or branch mutation without validating sender permission or association." },
      { key: "policy-file-parse-error", label: "Issue-ops policy YAML failed to parse", summary: "Grafter could not parse a `.github/policies` file. This usually indicates broken automation, but may also disable a label-removal or authorization control relied on by another workflow." },
    ],
  },
];

type RulesViewProps = {
  categories: { key: string; label: string; count: number }[];
  onOpenFinding: (category: string) => void;
};

function RulesView({ categories, onOpenFinding }: RulesViewProps) {
  const countByKey = new Map<string, number>();
  for (const c of categories) countByKey.set(c.key, c.count);
  const totalCategoriesInCatalog = RULES_CATALOG.reduce((n, f) => n + f.categories.length, 0);
  const activeFindings = categories.reduce((n, c) => n + c.count, 0);

  return (
    <div className="rules-view">
      <div className="rules-header">
        <div>
          <div className="graph-kicker">Detection catalog</div>
          <h2 className="rules-title">
            {RULES_CATALOG.length} families · {totalCategoriesInCatalog} categories
          </h2>
          <p className="rules-subtitle">
            Every detection Grafter runs, grouped by attacker primitive. Click any
            category to filter Findings to only that class. Live-scan count on the
            right shows how many findings currently match your dashboard filters.
          </p>
        </div>
        <div className="rules-active-count">
          <span className="rules-active-val">{activeFindings}</span>
          <span className="rules-active-lbl">Active findings across all categories</span>
        </div>
      </div>

      {RULES_CATALOG.map((family) => (
        <section key={family.id} className={`rule-family family-accent-${family.accent}`}>
          <header className="rule-family-header">
            <div className="rule-family-marker" aria-hidden />
            <div>
              <h3 className="rule-family-name">{family.name}</h3>
              <p className="rule-family-intro">{family.intro}</p>
            </div>
            <span className="rule-family-count">
              {family.categories.length} categor{family.categories.length === 1 ? "y" : "ies"}
            </span>
          </header>
          <div className="rule-family-body">
            {family.categories.map((cat) => {
              const n = countByKey.get(cat.key) ?? 0;
              return (
                <button
                  key={cat.key}
                  type="button"
                  className={`rule-card ${n > 0 ? "has-findings" : ""}`}
                  onClick={() => onOpenFinding(cat.key)}
                  title={`Filter Findings to ${cat.label}`}
                >
                  <div className="rule-card-top">
                    <span className="rule-card-name">{cat.label}</span>
                    <span className={`rule-card-count ${n > 0 ? "has-findings" : ""}`}>
                      {n > 0 ? `${n} finding${n === 1 ? "" : "s"}` : "0"}
                    </span>
                  </div>
                  <p className="rule-card-summary">{cat.summary}</p>
                  <code className="rule-card-slug">{cat.key}</code>
                </button>
              );
            })}
          </div>
        </section>
      ))}
    </div>
  );
}

type DiffViewProps = {
  data: DiffResult | null;
  loading: boolean;
  error: string | null;
  scans: ScanListItem[];
  scanId: string | null;
  setScanId: (id: string | null) => void;
  againstId: string;
  setAgainstId: (id: string) => void;
  persistentFilter: "all" | "changed";
  setPersistentFilter: (f: "all" | "changed") => void;
  onOpenFinding: (f: FindingListItem) => void;
};

function _fmtScanLabel(s: ScanListItem | DiffScanRef | null | undefined): string {
  if (!s) return "—";
  const ts = (("finished" in s ? s.finished : null) as number | null) ?? (("started" in s ? s.started : null) as number | null);
  const stamp = ts ? new Date(ts * 1000).toLocaleString() : "unknown time";
  const shortId = s.id.slice(0, 8);
  return `${s.org} · ${shortId} · ${stamp}`;
}

function _deltaLabel(delta: number | null | undefined): string {
  if (delta === null || delta === undefined || delta === 0) return "";
  return delta > 0 ? `+${delta}` : `${delta}`;
}

function DiffFindingCard({
  f,
  onOpen,
  showDelta,
  showPreviousBadge,
}: {
  f: FindingListItem | FindingChangeItem;
  onOpen: () => void;
  showDelta?: boolean;
  showPreviousBadge?: boolean;
}) {
  const change = f as FindingChangeItem;
  const sevChanged = showDelta && change.severity_delta && change.severity_delta !== "same";
  const confChanged = showDelta && change.confidence_delta && change.confidence_delta !== 0;
  return (
    <div className="diff-finding" onClick={onOpen}>
      <div className="diff-finding-top">
        <span className={`badge ${f.severity}`}>{f.severity}</span>
        {showPreviousBadge && change.previous_severity && change.previous_severity !== f.severity && (
          <span className="badge diff-prev-sev" title="Severity in previous scan">
            was {change.previous_severity}
          </span>
        )}
        {sevChanged && (
          <span className={`delta-badge delta-${change.severity_delta}`}>
            severity {change.severity_delta}
          </span>
        )}
        {confChanged && (
          <span className={`delta-badge delta-${(change.confidence_delta ?? 0) > 0 ? "up" : "down"}`}>
            confidence {_deltaLabel(change.confidence_delta)}
          </span>
        )}
        {f.category && (
          <span className="badge" title={f.category}>
            {f.category.replace(/-/g, " ")}
          </span>
        )}
        <div className="diff-finding-title">{f.title}</div>
      </div>
      <div className="diff-finding-meta">
        <span className="repo">{f.repo}</span>
        <span className="repo">·</span>
        <span className="repo">{f.workflow_path}</span>
        {f.job && <span className="repo">· job {f.job}</span>}
        <span className="repo">· trigger {f.trigger}</span>
      </div>
    </div>
  );
}

function DiffView({
  data, loading, error, scans, scanId, setScanId, againstId, setAgainstId,
  persistentFilter, setPersistentFilter, onOpenFinding,
}: DiffViewProps) {
  const currentScan = data?.current;
  const previousScan = data?.previous;
  const selectedId = scanId ?? currentScan?.id ?? "";

  if (error) {
    return (
      <div className="diff-view">
        <div className="diff-empty diff-error-block">{error}</div>
      </div>
    );
  }

  if (loading && !data) {
    return (
      <div className="diff-view">
        <div className="diff-empty">Loading diff…</div>
      </div>
    );
  }

  if (!currentScan) {
    return (
      <div className="diff-view">
        <div className="diff-empty">
          Run a scan first — the diff view compares two scans of the same organisation.
        </div>
      </div>
    );
  }

  const filteredPersistent = data
    ? persistentFilter === "changed"
      ? data.persistent.filter(
          (p) =>
            (p.severity_delta && p.severity_delta !== "same") ||
            (p.confidence_delta ?? 0) !== 0
        )
      : data.persistent
    : [];

  return (
    <div className="diff-view">
      <div className="diff-header">
        <div className="diff-header-scans">
          <div className="diff-scan-picker">
            <label>
              <span>Compare scan</span>
              <select
                value={selectedId}
                onChange={(e) => setScanId(e.target.value || null)}
              >
                {scans.length === 0 && (
                  <option value={selectedId}>{_fmtScanLabel(currentScan)}</option>
                )}
                {scans.map((s) => (
                  <option key={s.id} value={s.id}>
                    {_fmtScanLabel(s)} — {s.findings_count} findings
                  </option>
                ))}
              </select>
            </label>
            <span className="diff-arrow" aria-hidden>↔</span>
            <label>
              <span>Against</span>
              <select
                value={againstId}
                onChange={(e) => setAgainstId(e.target.value)}
              >
                <option value="previous">Previous scan of the same org</option>
                {scans
                  .filter((s) => s.id !== selectedId)
                  .map((s) => (
                    <option key={s.id} value={s.id}>
                      {_fmtScanLabel(s)}
                    </option>
                  ))}
              </select>
            </label>
          </div>
          <div className="diff-scan-note">
            <strong>Current:</strong> {_fmtScanLabel(currentScan)}
            <br />
            <strong>Baseline:</strong> {previousScan ? _fmtScanLabel(previousScan) : (
              <em>none (this looks like the first scan for the org)</em>
            )}
          </div>
        </div>
        <div className="diff-counters">
          <div className="diff-counter diff-counter-new">
            <span className="diff-counter-val">+{data?.summary.new ?? 0}</span>
            <span className="diff-counter-lbl">New</span>
          </div>
          <div className="diff-counter diff-counter-changed">
            <span className="diff-counter-val">~{data?.summary.severity_changed ?? 0}</span>
            <span className="diff-counter-lbl">Updated</span>
          </div>
          <div className="diff-counter diff-counter-persistent">
            <span className="diff-counter-val">≈{data?.summary.persistent ?? 0}</span>
            <span className="diff-counter-lbl">Persistent</span>
          </div>
          <div className="diff-counter diff-counter-fixed">
            <span className="diff-counter-val">−{data?.summary.fixed ?? 0}</span>
            <span className="diff-counter-lbl">Fixed</span>
          </div>
        </div>
      </div>
      {data?.scope_warning && (
        <div className="note diff-scope-warning">
          {data.scope_warning} Comparing {data.compared_rules.length} security rule
          {data.compared_rules.length === 1 ? "" : "s"}.
        </div>
      )}

      <div className="diff-columns">
        <section className="diff-col diff-col-new">
          <header className="diff-col-header">
            <h3>New</h3>
            <span className="diff-col-count">{data?.new.length ?? 0}</span>
          </header>
          <div className="diff-col-body">
            {(!data || data.new.length === 0) && (
              <div className="diff-col-empty">No new findings in this scan.</div>
            )}
            {data?.new.map((f) => (
              <DiffFindingCard key={f.id} f={f} onOpen={() => onOpenFinding(f)} />
            ))}
          </div>
        </section>

        <section className="diff-col diff-col-persistent">
          <header className="diff-col-header">
            <h3>Persistent</h3>
            <span className="diff-col-count">{filteredPersistent.length}</span>
            <div className="diff-col-actions">
              <button
                className={`chip ${persistentFilter === "all" ? "active" : ""}`}
                onClick={() => setPersistentFilter("all")}
              >
                All
              </button>
              <button
                className={`chip ${persistentFilter === "changed" ? "active" : ""}`}
                onClick={() => setPersistentFilter("changed")}
                title="Only findings whose severity or confidence changed between the two scans"
              >
                Updated only ({data?.summary.severity_changed ?? 0})
              </button>
            </div>
          </header>
          <div className="diff-col-body">
            {filteredPersistent.length === 0 && (
              <div className="diff-col-empty">
                {persistentFilter === "changed"
                  ? "No persistent findings had a severity or confidence change."
                  : "No persistent findings shared between both scans."}
              </div>
            )}
            {filteredPersistent.map((f) => (
              <DiffFindingCard
                key={f.id}
                f={f}
                onOpen={() => onOpenFinding(f)}
                showDelta
                showPreviousBadge
              />
            ))}
          </div>
        </section>

        <section className="diff-col diff-col-fixed">
          <header className="diff-col-header">
            <h3>Fixed</h3>
            <span className="diff-col-count">{data?.fixed.length ?? 0}</span>
          </header>
          <div className="diff-col-body">
            {(!data || data.fixed.length === 0) && (
              <div className="diff-col-empty">
                {previousScan
                  ? "No findings from the baseline scan are missing here."
                  : "Baseline unavailable — no fixed findings to show."}
              </div>
            )}
            {data?.fixed.map((f) => (
              <DiffFindingCard key={f.id} f={f} onOpen={() => onOpenFinding(f)} />
            ))}
          </div>
        </section>
      </div>
    </div>
  );
}

type GraphNode = {
  label: string;
  detail: string;
  kind: "source" | "context" | "gate" | "sink" | "impact";
};

function ExploitabilityGraph({ finding }: { finding: Finding }) {
  const nodes = buildExploitabilityGraph(finding);
  const gateNodes = nodes.filter((n) => n.kind === "gate");
  const mainNodes = nodes.filter((n) => n.kind !== "gate");

  return (
    <div className="graph-view">
      <div className="graph-summary">
        <div>
          <div className="graph-kicker">Attack path</div>
          <h3>{finding.category?.replace(/-/g, " ") ?? "exploitability chain"}</h3>
        </div>
        <div className="graph-score">
          <span className={`badge ${finding.severity}`}>{finding.severity}</span>
          <span className="badge">{finding.exploitability.replace(/_/g, " ")}</span>
          <span className="badge">Confidence {finding.confidence}%</span>
        </div>
      </div>

      <div className="attack-graph" aria-label="Exploitability graph">
        {mainNodes.map((node, index) => (
          <div className="graph-step-wrap" key={`${node.kind}-${index}`}>
            <div className={`graph-node ${node.kind}`}>
              <div className="graph-node-label">{node.label}</div>
              <div className="graph-node-detail">{node.detail}</div>
            </div>
            {index < mainNodes.length - 1 && <div className="graph-edge">→</div>}
          </div>
        ))}
      </div>

      {gateNodes.length > 0 && (
        <div className="gate-strip">
          <div className="graph-kicker">Gates / complexity reducers</div>
          {gateNodes.map((node, index) => (
            <div className="gate-card" key={`${node.kind}-${index}`}>
              <strong>{node.label}</strong>
              <span>{node.detail}</span>
            </div>
          ))}
        </div>
      )}

      <div className="graph-grid">
        <GraphPanel title="Source evidence" items={finding.evidence.filter((e) => /source|trigger|event|PR-controlled|untrusted|checkout|workflow_run|comment|prompt/i.test(e)).slice(0, 5)} fallback={finding.trigger} />
        <GraphPanel title="Sink evidence" items={finding.evidence.filter((e) => /sink|permission|write|token|mutat|exec|deploy|publish|push|merge|apply|cloud|artifact|runner/i.test(e)).slice(0, 5)} fallback={finding.evidence[0] ?? "No sink evidence was recorded."} />
        <GraphPanel title="Why this matters" items={finding.why.slice(0, 5)} fallback={finding.title} />
        <GraphPanel title="Fix strategy" items={finding.remediation.slice(0, 5)} fallback="Apply least privilege and break the source-to-sink chain." />
      </div>
    </div>
  );
}

function GraphPanel({ title, items, fallback }: { title: string; items: string[]; fallback: string }) {
  const values = items.length > 0 ? items : [fallback];
  return (
    <div className="graph-panel">
      <h4>{title}</h4>
      <ul>
        {values.map((item, index) => (
          <li key={index}>{item}</li>
        ))}
      </ul>
    </div>
  );
}

function buildExploitabilityGraph(finding: Finding): GraphNode[] {
  const category = finding.category ?? "";
  const allText = [...finding.why, ...finding.evidence, finding.title, category].join("\n");
  const source = sourceNode(finding, allText);
  const context = contextNode(finding, allText);
  const gates = gateNodes(allText);
  const sink = sinkNode(finding, allText);
  const impact = impactNode(finding, allText);
  return [source, context, ...gates, sink, impact];
}

function sourceNode(finding: Finding, text: string): GraphNode {
  if (/issue_comment|discussion_comment|pull_request_review|comment/i.test(finding.trigger + text)) {
    return {
      kind: "source",
      label: "Attacker-controlled comment/review",
      detail: `${finding.trigger} can carry attacker text into workflow logic.`,
    };
  }
  if (/workflow_run|artifact/i.test(finding.trigger + text)) {
    return {
      kind: "source",
      label: "Untrusted upstream artifact/context",
      detail: "A fork-reachable upstream run can feed metadata, logs, or artifacts downstream.",
    };
  }
  if (/pull_request_target|pull_request|PR-controlled|head\.sha|head code/i.test(finding.trigger + text)) {
    return {
      kind: "source",
      label: "Fork PR-controlled input/code",
      detail: `${finding.trigger} exposes PR metadata, branch, files, or head SHA to the workflow.`,
    };
  }
  if (/dispatch|client_payload|inputs/i.test(finding.trigger + text)) {
    return {
      kind: "source",
      label: "Dispatch/input payload",
      detail: "Workflow input or dispatch payload can influence execution.",
    };
  }
  return {
    kind: "source",
    label: "Workflow trigger",
    detail: `${finding.trigger || "unknown"} starts the chain.`,
  };
}

function contextNode(finding: Finding, text: string): GraphNode {
  if (/agentic|LLM|AI|MCP|prompt|claude|aider|openai|gemini|copilot/i.test(finding.category + text)) {
    return {
      kind: "context",
      label: "AI/agent interpretation layer",
      detail: "Untrusted context is interpreted by an LLM/agent before a privileged action.",
    };
  }
  if (/checkout|local action|npm|pip|test|build|script/i.test(finding.category + text)) {
    return {
      kind: "context",
      label: "Code execution layer",
      detail: "Workflow executes checked-out code, build scripts, tests, or local actions.",
    };
  }
  if (/artifact|cache|workflow_run/i.test(finding.category + text)) {
    return {
      kind: "context",
      label: "Cross-workflow data handoff",
      detail: "Artifact/cache/workflow_run data crosses from one trust boundary into another.",
    };
  }
  return {
    kind: "context",
    label: "Workflow job context",
    detail: finding.job ? `Job ${finding.job} processes the source data.` : "The workflow processes source data.",
  };
}

function gateNodes(text: string): GraphNode[] {
  const gates: GraphNode[] = [];
  const gateChecks: Array<[RegExp, string, string]> = [
    [/environment|approval|deployment protection/i, "Environment approval", "Protected environments can require maintainer approval before sensitive steps."],
    [/author_association|MEMBER|OWNER|COLLABORATOR|actor allowlist|github\.actor/i, "Actor or membership gate", "Execution depends on trusted actor, author association, or allowlist checks."],
    [/label|labeled|safe-to-test/i, "Label gate", "A maintainer/triager may need to apply a label before the risky path runs."],
    [/head\.repo\.full_name == github\.repository|fork == false|source repo/i, "Source-repository gate", "The workflow checks whether the PR came from the same repository or a trusted source."],
    [/read-only|contents: read|permissions are explicit read-only/i, "Read-only permissions", "Token permissions may limit impact even if source reaches a sink."],
  ];
  for (const [pattern, label, detail] of gateChecks) {
    if (pattern.test(text)) gates.push({ kind: "gate", label, detail });
  }
  return gates.slice(0, 4);
}

function sinkNode(finding: Finding, text: string): GraphNode {
  if (/merge|review|label|comment|pull-requests: write|issues: write|checks: write|statuses: write/i.test(text)) {
    return {
      kind: "sink",
      label: "GitHub metadata write sink",
      detail: "The chain can affect PRs, issues, labels, checks, reviews, comments, or statuses.",
    };
  }
  if (/git push|contents: write|commit|tag|release|publish|package|docker push/i.test(text)) {
    return {
      kind: "sink",
      label: "Repository/release write sink",
      detail: "The chain can modify repository contents, tags, releases, packages, or images.",
    };
  }
  if (/id-token|OIDC|cloud|azure|aws|gcloud|deploy/i.test(text)) {
    return {
      kind: "sink",
      label: "Cloud/deployment credential sink",
      detail: "The workflow can mint cloud credentials or reach deployment tooling.",
    };
  }
  if (/shell|command|exec|bash|git apply|patch|GITHUB_ENV|tool execution|MCP/i.test(text)) {
    return {
      kind: "sink",
      label: "Command/tool execution sink",
      detail: "The chain can execute shell, patch, environment, MCP, or other tools.",
    };
  }
  return {
    kind: "sink",
    label: "Sensitive workflow sink",
    detail: finding.evidence[0] ?? "The finding records a sensitive action or permission boundary.",
  };
}

function impactNode(finding: Finding, text: string): GraphNode {
  if (/secret|token|credential|exfil/i.test(text)) {
    return {
      kind: "impact",
      label: "Secret or credential exposure",
      detail: `${finding.severity} impact if sensitive data becomes observable or usable.`,
    };
  }
  if (/cloud|deploy|OIDC|id-token/i.test(text)) {
    return {
      kind: "impact",
      label: "Cloud or deployment compromise",
      detail: `${finding.severity} impact depending on cloud trust policy and environment gates.`,
    };
  }
  if (/release|publish|package|docker/i.test(text)) {
    return {
      kind: "impact",
      label: "Supply-chain compromise",
      detail: `${finding.severity} impact through release, package, artifact, or container poisoning.`,
    };
  }
  return {
    kind: "impact",
    label: "Practical impact",
    detail: `${finding.severity} / ${finding.exploitability.replace(/_/g, " ")} with ${finding.confidence}% scanner confidence.`,
  };
}
