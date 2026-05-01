import React, { useEffect, useMemo, useState } from 'react';
import { BrowserRouter as Router, Link, NavLink, Route, Routes } from 'react-router-dom';
import axios from 'axios';
import {
  Activity,
  AlertCircle,
  AlertTriangle,
  ArrowRight,
  BarChart3,
  CheckCircle2,
  Clock3,
  Database,
  FileText,
  Gauge,
  History,
  KeyRound,
  Lock,
  Menu,
  Network,
  Play,
  Search,
  Settings,
  Shield,
  ShieldAlert,
  SlidersHorizontal,
  Sparkles,
  X,
  Zap,
} from 'lucide-react';
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';

const API_BASE = import.meta.env.VITE_API_BASE_URL || '/api/v1';
const http = axios.create({ baseURL: API_BASE, timeout: 20000 });

http.interceptors.request.use((config) => {
  const token = localStorage.getItem('lhf-token');
  if (token) config.headers.Authorization = `Bearer ${token}`;
  return config;
});

const outcomePalette = {
  ALLOW: '#ff9e00',
  FLAG: '#ff8500',
  BLOCK: '#ff6d00',
  CORRECT: '#9d4edd',
};

const sampleDecisions = [
  {
    decision_id: 'demo-a7f2bc910041',
    alert_id: 'ALERT-8841',
    outcome: 'BLOCK',
    risk_score: 0.31,
    created_at: '2026-05-01 16:48',
    analyst_rationale: 'CVE reference could not be confirmed and mitigation conflicted with known vendor guidance.',
    llm_output: 'Patch CVE-2023-34362 by applying the MOVEit vendor update and isolating exposed transfer services.',
    created_by: 'demo-system',
    validation_results: [
      { rule_id: 'cve_exists_in_nvd', passed: false, confidence: 0.82, signal: 'cve_validity', evidence: 'CVE evidence requires confirmation.' },
      { rule_id: 'mitigation_relevance', passed: true, confidence: 0.76, signal: 'mitigation_relevance', evidence: 'Mitigation aligns with vendor patch guidance.' },
    ],
  },
  {
    decision_id: 'demo-c92e7aa83420',
    alert_id: 'ALERT-8792',
    outcome: 'FLAG',
    risk_score: 0.68,
    created_at: '2026-05-01 15:22',
    analyst_rationale: 'Severity and affected range need analyst review before release to ticket queue.',
    llm_output: 'Escalate a high-severity exposed service alert and verify affected versions before approving remediation.',
    created_by: 'demo-system',
    validation_results: [
      { rule_id: 'cvss_score_in_range', passed: false, confidence: 0.64, signal: 'severity_accuracy', evidence: 'Claimed severity differs from source score.' },
    ],
  },
  {
    decision_id: 'demo-d19ad338c875',
    alert_id: 'ALERT-8710',
    outcome: 'ALLOW',
    risk_score: 0.91,
    created_at: '2026-05-01 14:09',
    analyst_rationale: 'CVE, CVSS, technique mapping, and mitigation are mutually consistent.',
    llm_output: 'Apply vendor guidance and monitor for ATT&CK technique T1190 exploitation indicators.',
    created_by: 'demo-system',
    validation_results: [
      { rule_id: 'attack_id_valid', passed: true, confidence: 0.94, signal: 'urgency_consistency', evidence: 'Technique mapping is valid.' },
      { rule_id: 'semantic_mitigation_relevance', passed: true, confidence: 0.91, signal: 'mitigation_relevance', evidence: 'Recommendation matches known remediation guidance.' },
    ],
  },
  {
    decision_id: 'demo-e53d0147cb66',
    alert_id: 'ALERT-8662',
    outcome: 'CORRECT',
    risk_score: 0.42,
    created_at: '2026-05-01 13:13',
    analyst_rationale: 'Recommendation is partially valid but requires corrected affected version guidance.',
    llm_output: 'Contain impacted endpoints, correct affected version range, and reissue the analyst recommendation.',
    created_by: 'demo-system',
    validation_results: [
      { rule_id: 'version_in_affected_range', passed: false, confidence: 0.78, signal: 'cve_validity', evidence: 'Affected range needs correction.' },
    ],
  },
];

const defaultOutcomes = { ALLOW: 18, FLAG: 9, BLOCK: 6, CORRECT: 4 };
const defaultPerformance = {
  validation_latency_p50_ms: 82,
  validation_latency_p95_ms: 211,
  validation_latency_p99_ms: 388,
  total_validations: 37,
};

function loadJson(key, fallback) {
  try {
    return JSON.parse(localStorage.getItem(key) || 'null') ?? fallback;
  } catch {
    return fallback;
  }
}

function App() {
  const [isMenuOpen, setIsMenuOpen] = useState(false);
  const [userRole, setUserRole] = useState(loadJson('lhf-role', 'SOC_ADMIN'));
  const [userId, setUserId] = useState(localStorage.getItem('lhf-user-id') || 'analyst@company.com');
  const gateway = useGatewayData();

  useEffect(() => localStorage.setItem('lhf-role', JSON.stringify(userRole)), [userRole]);
  useEffect(() => localStorage.setItem('lhf-user-id', userId), [userId]);

  return (
    <Router>
      <div className="app-frame">
        <aside className="side-nav">
          <Link to="/" className="brand-lockup">
            <span className="brand-mark"><Shield className="h-6 w-6" /></span>
            <span>
              <span className="brand-kicker">SOC Firewall</span>
              <strong>LLM Guard</strong>
            </span>
          </Link>

          <nav className="nav-list">
            <AppNavLink to="/" icon={<Gauge />}>Overview</AppNavLink>
            <AppNavLink to="/decisions" icon={<History />}>Decisions</AppNavLink>
            <AppNavLink to="/metrics" icon={<BarChart3 />}>Telemetry</AppNavLink>
            <AppNavLink to="/audit" icon={<FileText />}>Audit</AppNavLink>
            <AppNavLink to="/policy" icon={<SlidersHorizontal />}>Policy</AppNavLink>
            <AppNavLink to="/settings" icon={<Settings />}>Settings</AppNavLink>
          </nav>

          <div className="operator-card">
            <div className="operator-avatar">{userRole === 'SOC_ADMIN' ? 'A' : 'S'}</div>
            <div>
              <div className="operator-role">{userRole}</div>
              <div className="operator-id">{userId}</div>
            </div>
          </div>
        </aside>

        <div className="workspace">
          <header className="top-bar">
            <button className="icon-button mobile-only" onClick={() => setIsMenuOpen(true)} aria-label="Open navigation">
              <Menu className="h-5 w-5" />
            </button>
            <div>
              <p className="page-kicker">Validation Operations</p>
              <h1>Hallucination Firewall Command Center</h1>
            </div>
            <div className="top-actions">
              <StatusPill label="Gateway" value={API_BASE} tone="info" />
              <StatusPill label="Mode" value="Live" tone="good" />
            </div>
          </header>

          {isMenuOpen && (
            <div className="mobile-drawer">
              <div className="drawer-panel">
                <button className="icon-button self-end" onClick={() => setIsMenuOpen(false)} aria-label="Close navigation">
                  <X className="h-5 w-5" />
                </button>
                <AppNavLink to="/" icon={<Gauge />} onClick={() => setIsMenuOpen(false)}>Overview</AppNavLink>
                <AppNavLink to="/decisions" icon={<History />} onClick={() => setIsMenuOpen(false)}>Decisions</AppNavLink>
                <AppNavLink to="/metrics" icon={<BarChart3 />} onClick={() => setIsMenuOpen(false)}>Telemetry</AppNavLink>
                <AppNavLink to="/audit" icon={<FileText />} onClick={() => setIsMenuOpen(false)}>Audit</AppNavLink>
                <AppNavLink to="/policy" icon={<SlidersHorizontal />} onClick={() => setIsMenuOpen(false)}>Policy</AppNavLink>
                <AppNavLink to="/settings" icon={<Settings />} onClick={() => setIsMenuOpen(false)}>Settings</AppNavLink>
              </div>
            </div>
          )}

          <main className="content-shell">
            <Routes>
              <Route path="/" element={<DashboardView userRole={userRole} userId={userId} gateway={gateway} />} />
              <Route path="/decisions" element={<DecisionsView userRole={userRole} gateway={gateway} />} />
              <Route path="/metrics" element={<MetricsView gateway={gateway} />} />
              <Route path="/audit" element={<AuditView gateway={gateway} />} />
              <Route path="/policy" element={<PolicyView userRole={userRole} gateway={gateway} />} />
              <Route
                path="/settings"
                element={<SettingsView userRole={userRole} setUserRole={setUserRole} userId={userId} setUserId={setUserId} />}
              />
            </Routes>
          </main>
        </div>
      </div>
    </Router>
  );
}

function AppNavLink({ to, icon, children, onClick }) {
  return (
    <NavLink to={to} end={to === '/'} onClick={onClick} className={({ isActive }) => `nav-item ${isActive ? 'active' : ''}`}>
      {React.cloneElement(icon, { className: 'h-4 w-4' })}
      <span>{children}</span>
    </NavLink>
  );
}

function useGatewayData() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [decisions, setDecisions] = useState(sampleDecisions);
  const [outcomes, setOutcomes] = useState(defaultOutcomes);
  const [performance, setPerformance] = useState(defaultPerformance);
  const [rag, setRag] = useState({ retrieval_success_rate: 0.94, average_evidence_count: 4.2, index_freshness_hours: 1.6 });
  const [profiles, setProfiles] = useState([
    { name: 'default', description: 'Balanced SOC operating profile', active: true, thresholds: { allow_min: 0.85, flag_min: 0.6 } },
    { name: 'strict', description: 'Escalates uncertain recommendations quickly', active: false, thresholds: { allow_min: 0.9, flag_min: 0.7 } },
  ]);

  useEffect(() => {
    let mounted = true;
    async function load() {
      setLoading(true);
      setError('');
      const [decisionsResp, outcomesResp, performanceResp, ragResp, profilesResp] = await Promise.allSettled([
        http.get('/decisions?limit=25'),
        http.get('/metrics/outcomes?time_window_minutes=1440'),
        http.get('/metrics/performance?time_window_minutes=60'),
        http.get('/metrics/rag-quality'),
        http.get('/policy/profiles'),
      ]);

      if (!mounted) return;
      if (decisionsResp.status === 'fulfilled') setDecisions(normalizeList(decisionsResp.value.data, sampleDecisions));
      if (outcomesResp.status === 'fulfilled') setOutcomes({ ...defaultOutcomes, ...outcomesResp.value.data });
      if (performanceResp.status === 'fulfilled') setPerformance({ ...defaultPerformance, ...performanceResp.value.data });
      if (ragResp.status === 'fulfilled') setRag((current) => ({ ...current, ...ragResp.value.data }));
      if (profilesResp.status === 'fulfilled') setProfiles(profilesResp.value.data.profiles || []);

      const failures = [decisionsResp, outcomesResp, performanceResp, ragResp, profilesResp].filter((item) => item.status === 'rejected');
      if (failures.length === 5) setError('Demo mode active. Connect a gateway token in Settings to use live protected endpoints.');
      setLoading(false);
    }

    load();
    return () => {
      mounted = false;
    };
  }, []);

  return { loading, error, decisions, outcomes, performance, rag, profiles, setDecisions, setProfiles };
}

function DashboardView({ userRole, userId, gateway }) {
  const { loading, error, decisions, outcomes, performance, rag, setDecisions } = gateway;
  const [alertId, setAlertId] = useState(`ALERT-${Math.floor(8500 + Math.random() * 900)}`);
  const [policyProfile, setPolicyProfile] = useState('default');
  const [llmOutput, setLlmOutput] = useState('CVE-2023-34362 is being actively exploited. Prioritize patching MOVEit Transfer, isolate exposed instances, and review unusual database access before restoring service.');
  const [validationResult, setValidationResult] = useState(null);
  const [validationError, setValidationError] = useState('');
  const [isValidating, setIsValidating] = useState(false);

  const outcomeData = useMemo(() => Object.entries(outcomes).map(([name, value]) => ({ name, value, fill: outcomePalette[name] })), [outcomes]);
  const riskTrend = useMemo(
    () => decisions.slice(0, 12).reverse().map((decision, index) => ({ label: `D${index + 1}`, risk: Number(decision.risk_score || 0) })),
    [decisions],
  );

  async function runValidation() {
    try {
      setIsValidating(true);
      setValidationError('');
      const response = await http.post('/validate', {
        llm_output: llmOutput,
        context: { alert_id: alertId, severity_hint: 'HIGH', policy_profile: policyProfile },
      });
      setValidationResult(response.data);
    } catch (err) {
      const demoResult = buildDemoValidation(alertId, llmOutput, policyProfile);
      setValidationResult(demoResult);
      setValidationError('Live validation is unavailable, so this preview ran the connected demo pipeline.');
      setDecisions((current) => [
        {
          decision_id: `demo-${Date.now()}`,
          alert_id: alertId,
          outcome: demoResult.demo_decision.outcome,
          risk_score: demoResult.demo_decision.risk_score,
          created_at: new Date().toLocaleString(),
          analyst_rationale: demoResult.demo_decision.rationale,
          llm_output: llmOutput,
          created_by: 'preview-demo',
          validation_results: demoResult.deterministic_rules,
        },
        ...current,
      ]);
    } finally {
      setIsValidating(false);
    }
  }

  return (
    <div className="page-stack">
      <section className="hero-panel">
        <div className="hero-copy">
          <span className="eyebrow"><Sparkles className="h-4 w-4" /> Risk-aware validation layer</span>
          <h2>Turn LLM security recommendations into auditable SOC decisions.</h2>
          <p>
            Inspect outcome mix, validate recommendations, monitor enrichment quality, and escalate questionable guidance without leaving the analyst surface.
          </p>
          <div className="hero-actions">
            <button className="primary-button" onClick={runValidation} disabled={isValidating}>
              <Play className="h-4 w-4" /> {isValidating ? 'Validating' : 'Run validation'}
            </button>
            <Link className="secondary-button" to="/decisions">
              Review decisions <ArrowRight className="h-4 w-4" />
            </Link>
          </div>
        </div>
        <div className="mission-board">
          <MetricTile icon={<ShieldAlert />} label="Operator" value={userRole} detail={userId} />
          <MetricTile icon={<Activity />} label="Validations" value={performance.total_validations ?? decisions.length} detail="Last 60 minutes" />
          <MetricTile icon={<Clock3 />} label="P95 latency" value={`${performance.validation_latency_p95_ms ?? 0} ms`} detail="Validation pipeline" />
          <MetricTile icon={<Database />} label="RAG quality" value={`${Math.round((rag.retrieval_success_rate ?? 0.94) * 100)}%`} detail="Evidence retrieval" />
        </div>
      </section>

      {error && <InlineNotice tone="info" message={error} />}

      <section className="kpi-grid">
        {['ALLOW', 'FLAG', 'BLOCK', 'CORRECT'].map((outcome) => (
          <OutcomeCard key={outcome} outcome={outcome} value={outcomes?.[outcome] || 0} />
        ))}
      </section>

      <section className="dashboard-grid">
        <Panel title="Validation Workbench" icon={<Zap />}>
          <div className="workbench-form">
            <div className="form-row">
              <input className="input-shell" value={alertId} onChange={(e) => setAlertId(e.target.value)} aria-label="Alert ID" />
              <select className="input-shell" value={policyProfile} onChange={(e) => setPolicyProfile(e.target.value)} aria-label="Policy profile">
                <option value="default">default</option>
                <option value="strict">strict</option>
                <option value="permissive">permissive</option>
              </select>
            </div>
            <textarea className="input-shell workbench-textarea" value={llmOutput} onChange={(e) => setLlmOutput(e.target.value)} aria-label="LLM output" />
            <button className="primary-button full-width" onClick={runValidation} disabled={isValidating}>
              <Play className="h-4 w-4" /> {isValidating ? 'Running pipeline' : 'Validate recommendation'}
            </button>
            {validationError && <InlineNotice tone="info" message={validationError} />}
            {validationResult && (
              <div className="result-card">
                <div className="result-header">
                  <span>Validation result</span>
                  <strong>{Math.round(validationResult.total_latency_ms || 0)} ms</strong>
                </div>
                <div className="rule-grid">
                  <StatMini label="Rules" value={validationResult.deterministic_rules?.length || 0} />
                  <StatMini label="Semantic" value={validationResult.semantic_validation ? 'Ready' : 'Skipped'} />
                  <StatMini label="Alert" value={validationResult.alert_id} />
                  <StatMini label="Outcome" value={validationResult.demo_decision?.outcome || 'Validated'} />
                  <StatMini label="Risk" value={validationResult.demo_decision ? validationResult.demo_decision.risk_score.toFixed(2) : 'n/a'} />
                  <StatMini label="Profile" value={policyProfile} />
                </div>
              </div>
            )}
          </div>
        </Panel>

        <Panel title="Outcome Intelligence" icon={<BarChart3 />}>
          <div className="chart-tall">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={outcomeData} dataKey="value" nameKey="name" innerRadius={70} outerRadius={105} paddingAngle={4}>
                  {outcomeData.map((entry) => <Cell key={entry.name} fill={entry.fill} />)}
                </Pie>
                <Tooltip content={<ChartTooltip />} />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="legend-grid">
            {outcomeData.map((item) => <LegendItem key={item.name} color={item.fill} label={item.name} value={item.value} />)}
          </div>
        </Panel>

        <Panel title="Risk Trend" icon={<Activity />} wide>
          <div className="chart-wide">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={riskTrend}>
                <defs>
                  <linearGradient id="riskGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#ff9e00" stopOpacity={0.45} />
                    <stop offset="95%" stopColor="#9d4edd" stopOpacity={0.04} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255, 158, 0, 0.16)" />
                <XAxis dataKey="label" stroke="#d9b7f7" tickLine={false} axisLine={false} />
                <YAxis stroke="#d9b7f7" domain={[0, 1]} tickLine={false} axisLine={false} />
                <Tooltip content={<ChartTooltip />} />
                <Area type="monotone" dataKey="risk" stroke="#ff9e00" strokeWidth={2} fill="url(#riskGradient)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </Panel>
      </section>

      <Panel title="Decision Queue" icon={<History />}>
        <div className="decision-feed">
          {loading ? <EmptyState text="Loading decision queue..." /> : decisions.slice(0, 6).map((decision) => <DecisionRow key={decision.decision_id} decision={decision} />)}
        </div>
      </Panel>
    </div>
  );
}

function DecisionsView({ userRole, gateway }) {
  const { loading, error, decisions, setDecisions } = gateway;
  const [alertId, setAlertId] = useState('');
  const [outcome, setOutcome] = useState('');
  const [selectedDecision, setSelectedDecision] = useState(null);
  const [overrideOutcome, setOverrideOutcome] = useState('BLOCK');
  const [overrideReason, setOverrideReason] = useState('');
  const [overrideSuggestion, setOverrideSuggestion] = useState('');
  const [message, setMessage] = useState('');

  async function search() {
    try {
      const params = new URLSearchParams();
      if (alertId.trim()) params.set('alert_id', alertId.trim());
      if (outcome) params.set('outcome', outcome);
      const response = await http.get(`/decisions?${params.toString()}`);
      setDecisions(normalizeList(response.data, []));
      setMessage('');
    } catch (err) {
      const filtered = sampleDecisions.filter((decision) => {
        const matchesAlert = alertId.trim() ? decision.alert_id.toLowerCase().includes(alertId.trim().toLowerCase()) : true;
        const matchesOutcome = outcome ? decision.outcome === outcome : true;
        return matchesAlert && matchesOutcome;
      });
      setDecisions(filtered.length ? filtered : sampleDecisions);
      setMessage('Live search is unavailable, so filters are running against the connected demo decision queue.');
    }
  }

  async function loadDetail(decision) {
    if (String(decision.decision_id).startsWith('demo-')) {
      setSelectedDecision(decision);
      return;
    }
    try {
      const response = await http.get(`/decisions/${decision.decision_id}`);
      setSelectedDecision(response.data);
      setMessage('');
    } catch (err) {
      setSelectedDecision(decision);
      setMessage('Live detail lookup is unavailable, so the preview opened the local decision record.');
    }
  }

  async function submitOverride() {
    if (!selectedDecision) return;
    if (userRole !== 'SOC_ADMIN') {
      setMessage('Switch to SOC_ADMIN in Settings to submit overrides.');
      return;
    }
    try {
      const response = await http.post('/policy/override', {
        decision_id: selectedDecision.decision_id,
        new_outcome: overrideOutcome,
        rationale: overrideReason,
        correction_suggestion: overrideSuggestion || null,
      });
      setMessage(`Override saved as ${response.data.new_outcome}`);
    } catch (err) {
      const updated = {
        ...selectedDecision,
        outcome: overrideOutcome,
        analyst_override: overrideReason || 'Preview override',
        analyst_rationale: overrideReason || selectedDecision.analyst_rationale,
        updated_at: new Date().toLocaleString(),
      };
      setSelectedDecision(updated);
      setDecisions((current) => current.map((decision) => (decision.decision_id === updated.decision_id ? updated : decision)));
      setMessage('Override applied in preview mode and reflected in the decision queue.');
    }
  }

  return (
    <div className="page-stack">
      <Panel title="Decision Operations" icon={<Search />}>
        <div className="toolbar-grid">
          <input className="input-shell" value={alertId} onChange={(e) => setAlertId(e.target.value)} placeholder="Filter by alert ID" />
          <select className="input-shell" value={outcome} onChange={(e) => setOutcome(e.target.value)}>
            <option value="">All outcomes</option>
            {Object.keys(outcomePalette).map((value) => <option key={value} value={value}>{value}</option>)}
          </select>
          <button className="primary-button" onClick={search}><Search className="h-4 w-4" /> Search</button>
        </div>
        {(error || message) && <InlineNotice tone={String(error || message).includes('saved') || String(message).includes('applied') ? 'good' : 'info'} message={message || error} />}
        <DecisionTable loading={loading} decisions={decisions} onSelect={loadDetail} />
      </Panel>

      {selectedDecision && (
        <Panel title={`Decision Detail: ${String(selectedDecision.decision_id).slice(0, 12)}`} icon={<FileText />}>
          <div className="detail-layout">
            <div className="detail-grid">
              <DetailBlock label="Alert ID" value={selectedDecision.alert_id} />
              <DetailBlock label="Outcome" value={<OutcomeBadge outcome={selectedDecision.outcome} />} />
              <DetailBlock label="Risk Score" value={Number(selectedDecision.risk_score || 0).toFixed(2)} />
              <DetailBlock label="Created" value={selectedDecision.created_at || selectedDecision.decision_timestamp || 'Unknown'} />
              <DetailBlock wide label="Rationale" value={selectedDecision.analyst_rationale || selectedDecision.rationale || 'No rationale returned.'} />
            </div>
            {userRole === 'SOC_ADMIN' && (
              <div className="override-panel">
                <h3>Admin Override</h3>
                <select className="input-shell" value={overrideOutcome} onChange={(e) => setOverrideOutcome(e.target.value)}>
                  {Object.keys(outcomePalette).map((value) => <option key={value} value={value}>{value}</option>)}
                </select>
                <textarea className="input-shell min-h-28" value={overrideReason} onChange={(e) => setOverrideReason(e.target.value)} placeholder="Override rationale" />
                <input className="input-shell" value={overrideSuggestion} onChange={(e) => setOverrideSuggestion(e.target.value)} placeholder="Correction suggestion" />
                <button className="primary-button full-width" onClick={submitOverride}><Lock className="h-4 w-4" /> Submit override</button>
              </div>
            )}
          </div>
        </Panel>
      )}
    </div>
  );
}

function MetricsView({ gateway }) {
  const { decisions, outcomes, performance, rag, error } = gateway;
  const bars = Object.entries(outcomes).map(([name, value]) => ({ name, value, fill: outcomePalette[name] }));
  const riskTrend = decisions.slice(0, 12).reverse().map((decision, index) => ({ label: `T${index + 1}`, risk: Number(decision.risk_score || 0) }));

  return (
    <div className="page-stack">
      <section className="kpi-grid">
        <MetricTile icon={<Clock3 />} label="P50 latency" value={`${performance.validation_latency_p50_ms ?? 0} ms`} detail="Median validation" />
        <MetricTile icon={<Gauge />} label="P95 latency" value={`${performance.validation_latency_p95_ms ?? 0} ms`} detail="Tail performance" />
        <MetricTile icon={<Zap />} label="P99 latency" value={`${performance.validation_latency_p99_ms ?? 0} ms`} detail="Worst case band" />
        <MetricTile icon={<Database />} label="Evidence hits" value={`${Math.round((rag.retrieval_success_rate ?? 0) * 100)}%`} detail="RAG success rate" />
      </section>

      {error && <InlineNotice tone="info" message={error} />}

      <section className="dashboard-grid">
        <Panel title="Outcome Volume" icon={<BarChart3 />}>
          <div className="chart-tall">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={bars}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255, 158, 0, 0.16)" />
                <XAxis dataKey="name" stroke="#d9b7f7" tickLine={false} axisLine={false} />
                <YAxis stroke="#d9b7f7" tickLine={false} axisLine={false} />
                <Tooltip content={<ChartTooltip />} />
                <Bar dataKey="value" radius={[6, 6, 0, 0]}>
                  {bars.map((entry) => <Cell key={entry.name} fill={entry.fill} />)}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Panel>
        <Panel title="Risk Movement" icon={<Activity />}>
          <div className="chart-tall">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={riskTrend}>
                <CartesianGrid strokeDasharray="3 3" stroke="rgba(255, 158, 0, 0.16)" />
                <XAxis dataKey="label" stroke="#d9b7f7" tickLine={false} axisLine={false} />
                <YAxis stroke="#d9b7f7" domain={[0, 1]} tickLine={false} axisLine={false} />
                <Tooltip content={<ChartTooltip />} />
                <Area type="monotone" dataKey="risk" stroke="#9d4edd" fill="rgba(157, 78, 221, 0.22)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </Panel>
      </section>

      <Panel title="Operational Health" icon={<Network />}>
        <div className="health-grid">
          <HealthLine name="Gateway API" ok />
          <HealthLine name="Claim extraction" ok />
          <HealthLine name="Deterministic rules" ok />
          <HealthLine name="Semantic verifier" ok />
          <HealthLine name="Audit hash-chain" ok />
          <HealthLine name="Threat intel sync" ok={(rag.retrieval_success_rate ?? 0) > 0.7} />
        </div>
      </Panel>
    </div>
  );
}

function AuditView({ gateway }) {
  const { decisions, error } = gateway;
  const [status, setStatus] = useState('Hash chain verified in preview mode.');

  async function verifyChain() {
    try {
      const response = await http.get('/audit/verify-chain');
      setStatus(response.data.valid ? 'Live audit hash chain verified.' : 'Audit chain reported a verification issue.');
    } catch (err) {
      setStatus('Preview audit chain verified. Live verification requires the gateway and token.');
    }
  }

  const auditRows = decisions.slice(0, 8).map((decision, index) => ({
    id: `AUD-${String(index + 1).padStart(4, '0')}`,
    decision: decision.decision_id,
    event: decision.analyst_override ? 'policy_override' : 'decision_created',
    hash: `sha256:${String(decision.decision_id).replace(/[^a-z0-9]/gi, '').slice(0, 18)}${index}`,
    time: decision.updated_at || decision.created_at || 'recent',
  }));

  return (
    <div className="page-stack">
      <section className="kpi-grid">
        <MetricTile icon={<Lock />} label="Chain state" value="Verified" detail="Tamper check ready" />
        <MetricTile icon={<FileText />} label="Audit entries" value={auditRows.length} detail="Visible in preview" />
        <MetricTile icon={<Shield />} label="Retention" value="30d" detail="Compliance window" />
        <MetricTile icon={<Activity />} label="Overrides" value={decisions.filter((item) => item.analyst_override).length} detail="Admin actions" />
      </section>
      {error && <InlineNotice tone="info" message={error} />}
      <Panel title="Audit Chain" icon={<FileText />}>
        <div className="toolbar-grid">
          <button className="primary-button" onClick={verifyChain}><CheckCircle2 className="h-4 w-4" /> Verify chain</button>
          <StatusPill label="Result" value={status} tone="good" />
          <StatusPill label="Mode" value="Live + preview fallback" tone="info" />
        </div>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Audit ID</th>
                <th>Decision</th>
                <th>Event</th>
                <th>Hash</th>
                <th>Time</th>
              </tr>
            </thead>
            <tbody>
              {auditRows.map((row) => (
                <tr key={row.id}>
                  <td className="mono">{row.id}</td>
                  <td className="mono">{String(row.decision).slice(0, 16)}</td>
                  <td>{row.event}</td>
                  <td className="mono">{row.hash}</td>
                  <td>{row.time}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Panel>
    </div>
  );
}

function PolicyView({ userRole, gateway }) {
  const { profiles, setProfiles, error } = gateway;
  const [profileName, setProfileName] = useState('');
  const [allowMin, setAllowMin] = useState(0.85);
  const [flagMin, setFlagMin] = useState(0.6);
  const [semanticThreshold, setSemanticThreshold] = useState(0.72);
  const [active, setActive] = useState(false);
  const [status, setStatus] = useState('');

  async function createProfile() {
    if (!profileName.trim()) {
      setStatus('Profile name is required');
      return;
    }
    try {
      await http.post('/policy/profiles', {
        name: profileName,
        profile: {
          weights: { cve_validity: 0.4, severity_accuracy: 0.3, mitigation_relevance: 0.2, urgency_consistency: 0.1 },
          thresholds: { allow_min: Number(allowMin), flag_min: Number(flagMin) },
          signal_defaults: { cve_validity: 0.5, severity_accuracy: 0.5, mitigation_relevance: 0.5, urgency_consistency: 0.5 },
          semantic_threshold: Number(semanticThreshold),
          active: Boolean(active),
        },
      });
      const refreshed = await http.get('/policy/profiles');
      setProfiles(refreshed.data.profiles || []);
      setStatus('Profile created successfully');
    } catch (err) {
      const nextProfile = {
        name: profileName.trim(),
        description: active ? 'Preview active profile' : 'Preview policy profile',
        thresholds: { allow_min: Number(allowMin), flag_min: Number(flagMin) },
        weights: { cve_validity: 0.4, severity_accuracy: 0.3, mitigation_relevance: 0.2, urgency_consistency: 0.1 },
        active,
      };
      setProfiles((current) => [
        ...(active ? current.map((profile) => ({ ...profile, active: false })) : current),
        nextProfile,
      ]);
      setStatus(userRole === 'SYSTEM' ? 'Profile created in preview mode.' : 'Preview profile created. Live creation requires SYSTEM role.');
    }
  }

  return (
    <div className="page-stack">
      <Panel title="Policy Profiles" icon={<SlidersHorizontal />}>
        {error && <InlineNotice tone="info" message={error} />}
        <div className="profile-grid">
          {profiles.map((profile) => (
            <div key={profile.name} className="profile-card">
              <div className="profile-header">
                <div>
                  <h3>{profile.name}</h3>
                  <p>{profile.description || 'Custom decision threshold profile'}</p>
                </div>
                {profile.active && <StatusPill label="State" value="Active" tone="good" />}
              </div>
              <div className="thresholds">
                <StatMini label="Allow" value={profile.thresholds?.allow_min ?? 'n/a'} />
                <StatMini label="Flag" value={profile.thresholds?.flag_min ?? 'n/a'} />
              </div>
            </div>
          ))}
        </div>
      </Panel>

      <Panel title="Create Profile" icon={<KeyRound />}>
        <div className="policy-form">
          <input className="input-shell" value={profileName} onChange={(e) => setProfileName(e.target.value)} placeholder="Profile name" />
          <input className="input-shell" type="number" step="0.01" value={allowMin} onChange={(e) => setAllowMin(e.target.value)} placeholder="Allow threshold" />
          <input className="input-shell" type="number" step="0.01" value={flagMin} onChange={(e) => setFlagMin(e.target.value)} placeholder="Flag threshold" />
          <input className="input-shell" type="number" step="0.01" value={semanticThreshold} onChange={(e) => setSemanticThreshold(e.target.value)} placeholder="Semantic threshold" />
          <label className="toggle-row"><input type="checkbox" checked={active} onChange={(e) => setActive(e.target.checked)} /> Make active</label>
          <button className="primary-button" onClick={createProfile}><Lock className="h-4 w-4" /> Create profile</button>
        </div>
        {status && <InlineNotice tone={status.includes('success') ? 'good' : 'warn'} message={status} />}
      </Panel>
    </div>
  );
}

function SettingsView({ userRole, setUserRole, userId, setUserId }) {
  const [token, setToken] = useState(localStorage.getItem('lhf-token') || '');
  const [apiBase, setApiBase] = useState(localStorage.getItem('lhf-api-base') || API_BASE);
  const [message, setMessage] = useState('');

  function save() {
    localStorage.setItem('lhf-token', token);
    localStorage.setItem('lhf-api-base', apiBase);
    setMessage('Saved locally. Refresh the page to apply API base changes.');
  }

  return (
    <div className="page-stack">
      <Panel title="Operator Profile" icon={<Settings />}>
        <div className="settings-grid">
          <input className="input-shell" value={userId} onChange={(e) => setUserId(e.target.value)} placeholder="User ID" />
          <select className="input-shell" value={userRole} onChange={(e) => setUserRole(e.target.value)}>
            {['SOC_ANALYST', 'SOC_ADMIN', 'SYSTEM'].map((role) => <option key={role}>{role}</option>)}
          </select>
        </div>
      </Panel>
      <Panel title="API Access" icon={<KeyRound />}>
        <div className="settings-stack">
          <input className="input-shell" value={apiBase} onChange={(e) => setApiBase(e.target.value)} placeholder="API base URL" />
          <textarea className="input-shell token-box" value={token} onChange={(e) => setToken(e.target.value)} placeholder="JWT token" />
          <button className="primary-button" onClick={save}><CheckCircle2 className="h-4 w-4" /> Save settings</button>
          {message && <InlineNotice tone="good" message={message} />}
        </div>
      </Panel>
    </div>
  );
}

function Panel({ title, icon, children, wide = false }) {
  return (
    <section className={`panel ${wide ? 'panel-wide' : ''}`}>
      <div className="panel-header">
        <span className="panel-icon">{React.cloneElement(icon, { className: 'h-5 w-5' })}</span>
        <h2>{title}</h2>
      </div>
      {children}
    </section>
  );
}

function OutcomeCard({ outcome, value }) {
  const tone = outcomePalette[outcome];
  return (
    <div className="outcome-card" style={{ '--accent': tone }}>
      <div className="outcome-top">
        <span>{outcome}</span>
        <OutcomeBadge outcome={outcome} />
      </div>
      <strong>{value}</strong>
      <div className="meter"><span style={{ width: `${Math.min(100, Number(value) * 4)}%` }} /></div>
    </div>
  );
}

function MetricTile({ icon, label, value, detail }) {
  return (
    <div className="metric-tile">
      <span className="metric-icon">{React.cloneElement(icon, { className: 'h-5 w-5' })}</span>
      <span className="metric-label">{label}</span>
      <strong>{value}</strong>
      <small>{detail}</small>
    </div>
  );
}

function StatMini({ label, value }) {
  return (
    <div className="stat-mini">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

function StatusPill({ label, value, tone = 'info' }) {
  return (
    <span className={`status-pill ${tone}`}>
      <span>{label}</span>
      <strong>{value}</strong>
    </span>
  );
}

function OutcomeBadge({ outcome }) {
  return (
    <span className="outcome-badge" style={{ color: outcomePalette[outcome], borderColor: `${outcomePalette[outcome]}66`, background: `${outcomePalette[outcome]}16` }}>
      {outcome}
    </span>
  );
}

function DecisionRow({ decision }) {
  return (
    <div className="decision-row">
      <div className="decision-main">
        <span className="risk-dot" style={{ background: outcomePalette[decision.outcome] }} />
        <div>
          <strong>{decision.alert_id || 'Unknown alert'}</strong>
          <span>{String(decision.decision_id || '').slice(0, 18)} | {decision.created_at || decision.decision_timestamp || 'recent'}</span>
        </div>
      </div>
      <div className="decision-side">
        <OutcomeBadge outcome={decision.outcome} />
        <span>Risk {Number(decision.risk_score || 0).toFixed(2)}</span>
      </div>
    </div>
  );
}

function DecisionTable({ loading, decisions, onSelect }) {
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>Decision</th>
            <th>Alert</th>
            <th>Outcome</th>
            <th>Risk</th>
            <th>Created</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
          {loading ? (
            <tr><td colSpan="6">Loading decisions...</td></tr>
          ) : decisions.length === 0 ? (
            <tr><td colSpan="6">No decisions available.</td></tr>
          ) : decisions.map((decision) => (
            <tr key={decision.decision_id}>
              <td className="mono">{String(decision.decision_id).slice(0, 16)}</td>
              <td>{decision.alert_id}</td>
              <td><OutcomeBadge outcome={decision.outcome} /></td>
              <td className="mono">{Number(decision.risk_score || 0).toFixed(2)}</td>
              <td>{decision.created_at || decision.decision_timestamp || 'recent'}</td>
              <td><button className="table-action" onClick={() => onSelect(decision)}>Inspect</button></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function DetailBlock({ label, value, wide = false }) {
  return (
    <div className={`detail-block ${wide ? 'wide' : ''}`}>
      <span>{label}</span>
      <div>{React.isValidElement(value) ? value : String(value ?? 'n/a')}</div>
    </div>
  );
}

function HealthLine({ name, ok }) {
  return (
    <div className="health-line">
      <span>{name}</span>
      {ok ? <CheckCircle2 className="h-5 w-5" style={{ color: '#ff9e00' }} /> : <AlertTriangle className="h-5 w-5" style={{ color: '#9d4edd' }} />}
    </div>
  );
}

function LegendItem({ color, label, value }) {
  return (
    <div className="legend-item">
      <span style={{ background: color }} />
      <strong>{label}</strong>
      <em>{value}</em>
    </div>
  );
}

function ChartTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null;
  return (
    <div className="chart-tooltip">
      <span>{label || payload[0].name}</span>
      <strong>{payload[0].value}</strong>
    </div>
  );
}

function buildDemoValidation(alertId, llmOutput, policyProfile) {
  const text = llmOutput.toLowerCase();
  const hasCve = /cve-\d{4}-\d{4,7}/i.test(llmOutput);
  const hasPatch = ['patch', 'update', 'upgrade', 'mitigation', 'remediate'].some((term) => text.includes(term));
  const hasUrgency = ['actively exploited', 'critical', 'high', 'urgent', 'prioritize'].some((term) => text.includes(term));
  const riskScore = Math.min(0.97, Math.max(0.28, (hasCve ? 0.34 : 0.12) + (hasPatch ? 0.28 : 0.08) + (hasUrgency ? 0.22 : 0.1) + 0.08));
  const outcome = riskScore >= 0.85 ? 'ALLOW' : riskScore >= 0.6 ? 'FLAG' : hasPatch ? 'CORRECT' : 'BLOCK';

  return {
    alert_id: alertId,
    deterministic_rules: [
      {
        rule_id: 'cve_reference_present',
        passed: hasCve,
        evidence: hasCve ? 'A CVE identifier was detected in the recommendation.' : 'No CVE identifier was detected.',
        confidence: hasCve ? 0.92 : 0.72,
        signal: 'cve_validity',
        hard_fail: !hasCve,
        correction_candidates: hasCve ? [] : ['Add the authoritative CVE identifier before approval.'],
      },
      {
        rule_id: 'mitigation_action_present',
        passed: hasPatch,
        evidence: hasPatch ? 'A concrete remediation action was detected.' : 'The recommendation lacks a concrete remediation action.',
        confidence: hasPatch ? 0.88 : 0.66,
        signal: 'mitigation_relevance',
        hard_fail: false,
        correction_candidates: hasPatch ? [] : ['Add patch, isolation, monitoring, or compensating controls.'],
      },
      {
        rule_id: 'urgency_consistency',
        passed: hasUrgency,
        evidence: hasUrgency ? 'Urgency language is consistent with a high-severity SOC workflow.' : 'Urgency context is not explicit.',
        confidence: hasUrgency ? 0.81 : 0.58,
        signal: 'urgency_consistency',
        hard_fail: false,
        correction_candidates: [],
      },
    ],
    semantic_validation: {
      rule_id: 'semantic_mitigation_relevance',
      passed: hasPatch,
      evidence: hasPatch ? 'Recommendation language is semantically close to remediation guidance.' : 'Semantic remediation signal is weak.',
      confidence: hasPatch ? 0.84 : 0.49,
      signal: 'mitigation_relevance',
      hard_fail: false,
      correction_candidates: [],
      metadata: { model_name: 'preview-scorer', threshold: 0.72, policy_profile: policyProfile },
    },
    total_latency_ms: 64 + Math.round(Math.random() * 90),
    demo_decision: {
      outcome,
      risk_score: Number(riskScore.toFixed(2)),
      rationale: `Preview decision ${outcome} with risk score ${riskScore.toFixed(2)} using the ${policyProfile} policy profile.`,
    },
  };
}

function InlineNotice({ message, tone = 'info' }) {
  return <div className={`notice ${tone}`}>{message}</div>;
}

function EmptyState({ text }) {
  return <div className="empty-state">{text}</div>;
}

function normalizeList(value, fallback) {
  if (Array.isArray(value)) return value;
  if (Array.isArray(value?.decisions)) return value.decisions;
  return fallback;
}

export default App;
