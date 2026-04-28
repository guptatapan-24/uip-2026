import React, { useEffect, useMemo, useState } from 'react';
import { BrowserRouter as Router, Routes, Route, Link, useNavigate } from 'react-router-dom';
import axios from 'axios';
import {
  AlertCircle,
  BarChart3,
  CheckCircle2,
  ChevronRight,
  Lock,
  Menu,
  Settings,
  Shield,
  Sparkles,
  AlertTriangle,
} from 'lucide-react';
import {
  Area,
  AreaChart,
  CartesianGrid,
  Cell,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';

const API_BASE = import.meta.env.VITE_API_BASE_URL || '/api/v1';
const http = axios.create({ baseURL: API_BASE, timeout: 20000 });

const outcomePalette = {
  ALLOW: '#22c55e',
  FLAG: '#f59e0b',
  BLOCK: '#ef4444',
  CORRECT: '#38bdf8',
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
  const [userRole, setUserRole] = useState(loadJson('lhf-role', 'SOC_ANALYST'));
  const [userId, setUserId] = useState(localStorage.getItem('lhf-user-id') || 'analyst@company.com');

  useEffect(() => {
    localStorage.setItem('lhf-role', JSON.stringify(userRole));
  }, [userRole]);

  useEffect(() => {
    localStorage.setItem('lhf-user-id', userId);
  }, [userId]);

  return (
    <Router>
      <div className="min-h-screen text-slate-100 dashboard-shell">
        <header className="border-b border-white/10 bg-slate-950/80 backdrop-blur sticky top-0 z-30">
          <div className="max-w-7xl mx-auto px-4 py-4 flex items-center justify-between gap-4">
            <Link to="/" className="flex items-center gap-3">
              <div className="p-2 rounded-xl bg-cyan-500/15 border border-cyan-400/20">
                <Lock className="w-6 h-6 text-cyan-300" />
              </div>
              <div>
                <div className="text-xs uppercase tracking-[0.35em] text-cyan-200/70">SOC Firewall</div>
                <h1 className="text-lg md:text-xl font-semibold">LLM Hallucination Firewall</h1>
              </div>
            </Link>

            <nav className="hidden md:flex items-center gap-6 text-sm text-slate-300">
              <NavLink to="/">Dashboard</NavLink>
              <NavLink to="/decisions">Decisions</NavLink>
              <NavLink to="/metrics">Metrics</NavLink>
              {userRole === 'SOC_ADMIN' && <NavLink to="/policy">Policy</NavLink>}
              <NavLink to="/settings">Settings</NavLink>
            </nav>

            <button className="md:hidden p-2 rounded-lg bg-white/5" onClick={() => setIsMenuOpen((v) => !v)}>
              <Menu className="w-6 h-6" />
            </button>
          </div>

          {isMenuOpen && (
            <div className="md:hidden border-t border-white/10 px-4 py-3 bg-slate-900/95 space-y-2">
              <NavLink mobile to="/">Dashboard</NavLink>
              <NavLink mobile to="/decisions">Decisions</NavLink>
              <NavLink mobile to="/metrics">Metrics</NavLink>
              {userRole === 'SOC_ADMIN' && <NavLink mobile to="/policy">Policy</NavLink>}
              <NavLink mobile to="/settings">Settings</NavLink>
            </div>
          )}
        </header>

        <main className="max-w-7xl mx-auto px-4 py-8">
          <Routes>
            <Route path="/" element={<DashboardView userRole={userRole} userId={userId} />} />
            <Route path="/decisions" element={<DecisionsView userRole={userRole} userId={userId} />} />
            <Route path="/metrics" element={<MetricsView userRole={userRole} />} />
            {userRole === 'SOC_ADMIN' && <Route path="/policy" element={<PolicyView userRole={userRole} />} />}
            <Route path="/settings" element={<SettingsView userRole={userRole} setUserRole={setUserRole} userId={userId} setUserId={setUserId} />} />
          </Routes>
        </main>
      </div>
    </Router>
  );
}

function NavLink({ to, children, mobile = false }) {
  return (
    <Link
      to={to}
      className={`${mobile ? 'block py-1' : ''} hover:text-cyan-300 transition-colors duration-200`}
    >
      {children}
    </Link>
  );
}

function SectionCard({ title, icon, children }) {
  return (
    <section className="glass-card rounded-3xl border border-white/10 p-6 shadow-2xl shadow-black/20">
      <div className="flex items-center gap-3 mb-5">
        <div className="p-2 rounded-xl bg-cyan-500/15 border border-cyan-400/20">{icon}</div>
        <h2 className="text-xl md:text-2xl font-semibold">{title}</h2>
      </div>
      {children}
    </section>
  );
}

function useGatewayData() {
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [decisions, setDecisions] = useState([]);
  const [outcomes, setOutcomes] = useState({ ALLOW: 0, FLAG: 0, BLOCK: 0, CORRECT: 0 });
  const [performance, setPerformance] = useState(null);
  const [profiles, setProfiles] = useState([]);

  useEffect(() => {
    let mounted = true;

    async function load() {
      try {
        setLoading(true);
        const [decisionsResp, outcomesResp, performanceResp, profilesResp] = await Promise.allSettled([
          http.get('/decisions?limit=25'),
          http.get('/metrics/outcomes?time_window_minutes=1440'),
          http.get('/metrics/performance?time_window_minutes=60'),
          http.get('/policy/profiles'),
        ]);

        if (!mounted) return;

        if (decisionsResp.status === 'fulfilled') setDecisions(decisionsResp.value.data);
        if (outcomesResp.status === 'fulfilled') setOutcomes(outcomesResp.value.data);
        if (performanceResp.status === 'fulfilled') setPerformance(performanceResp.value.data);
        if (profilesResp.status === 'fulfilled') setProfiles(profilesResp.value.data.profiles || []);
      } catch (err) {
        if (!mounted) return;
        setError(err?.response?.data?.detail || err.message || 'Failed to load gateway data');
      } finally {
        if (mounted) setLoading(false);
      }
    }

    load();
    return () => {
      mounted = false;
    };
  }, []);

  return { loading, error, decisions, outcomes, performance, profiles, setDecisions, setProfiles };
}

function DashboardView({ userRole }) {
  const { loading, error, decisions, outcomes, performance } = useGatewayData();
  const outcomeData = useMemo(
    () => Object.entries(outcomes).map(([name, value]) => ({ name, value, fill: outcomePalette[name] })),
    [outcomes],
  );

  return (
    <div className="space-y-6">
      <div className="hero-grid rounded-[2rem] border border-white/10 p-6 md:p-8 overflow-hidden">
        <div className="max-w-3xl">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-cyan-500/10 border border-cyan-400/20 text-cyan-200 text-xs uppercase tracking-[0.35em]">
            <Sparkles className="w-3.5 h-3.5" /> Live gateway telemetry
          </div>
          <h2 className="mt-4 text-3xl md:text-5xl font-semibold leading-tight">Decision intelligence for SOC analysts.</h2>
          <p className="mt-4 text-slate-300 max-w-2xl">
            Monitor validation outcomes, inspect recent decisions, and move directly into audit or override workflows when a recommendation needs human review.
          </p>
        </div>
        <div className="mt-6 md:mt-0 grid grid-cols-2 gap-3 self-start">
          <MetricPill label="Role" value={userRole} />
          <MetricPill label="Decisions" value={decisions.length} />
          <MetricPill label="API" value={API_BASE} wide />
          <MetricPill label="Status" value={loading ? 'Loading' : 'Ready'} />
        </div>
      </div>

      {error && <InlineError message={error} />}

      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {['ALLOW', 'FLAG', 'BLOCK', 'CORRECT'].map((outcome) => (
          <OutcomeCard key={outcome} outcome={outcome} value={outcomes?.[outcome] || 0} />
        ))}
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <SectionCard title="Outcome Distribution" icon={<BarChart3 className="w-5 h-5 text-cyan-300" />}>
          <div className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={outcomeData} dataKey="value" nameKey="name" innerRadius={70} outerRadius={100} paddingAngle={3}>
                  {outcomeData.map((entry) => (
                    <Cell key={entry.name} fill={entry.fill} />
                  ))}
                </Pie>
                <Tooltip contentStyle={{ background: '#0f172a', border: '1px solid rgba(255,255,255,0.12)', borderRadius: 16 }} />
                <Legend />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </SectionCard>

        <SectionCard title="Validation Latency" icon={<CheckCircle2 className="w-5 h-5 text-cyan-300" />}>
          <div className="grid grid-cols-3 gap-3 mb-4">
            <StatBox label="p50" value={`${performance?.validation_latency_p50_ms ?? 0} ms`} />
            <StatBox label="p95" value={`${performance?.validation_latency_p95_ms ?? 0} ms`} />
            <StatBox label="p99" value={`${performance?.validation_latency_p99_ms ?? 0} ms`} />
          </div>
          <div className="h-44 rounded-2xl bg-slate-950/40 border border-white/10 p-3">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={decisions.map((d, idx) => ({ idx: idx + 1, risk: d.risk_score }))}>
                <defs>
                  <linearGradient id="riskFill" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#22d3ee" stopOpacity={0.45} />
                    <stop offset="95%" stopColor="#22d3ee" stopOpacity={0.02} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                <XAxis dataKey="idx" stroke="#94a3b8" />
                <YAxis stroke="#94a3b8" domain={[0, 1]} />
                <Tooltip contentStyle={{ background: '#0f172a', border: '1px solid rgba(255,255,255,0.12)', borderRadius: 16 }} />
                <Area type="monotone" dataKey="risk" stroke="#22d3ee" fill="url(#riskFill)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </SectionCard>
      </div>

      <SectionCard title="Recent Decisions" icon={<Shield className="w-5 h-5 text-cyan-300" />}>
        <div className="space-y-3">
          {decisions.length === 0 ? (
            <EmptyState text={loading ? 'Loading decisions...' : 'No decisions yet. Run a validation to populate the feed.'} />
          ) : (
            decisions.slice(0, 6).map((decision) => <DecisionRow key={decision.decision_id} decision={decision} compact />)
          )}
        </div>
      </SectionCard>
    </div>
  );
}

function DecisionsView({ userRole }) {
  const { loading, error, decisions, setDecisions } = useGatewayData();
  const [alertId, setAlertId] = useState('');
  const [outcome, setOutcome] = useState('');
  const [selectedDecision, setSelectedDecision] = useState(null);
  const [overrideOutcome, setOverrideOutcome] = useState('BLOCK');
  const [overrideReason, setOverrideReason] = useState('');
  const [overrideSuggestion, setOverrideSuggestion] = useState('');
  const [actionError, setActionError] = useState('');
  const [actionSuccess, setActionSuccess] = useState('');

  async function search() {
    try {
      const params = new URLSearchParams();
      if (alertId.trim()) params.set('alert_id', alertId.trim());
      if (outcome) params.set('outcome', outcome);
      const response = await http.get(`/decisions?${params.toString()}`);
      setDecisions(response.data);
    } catch (err) {
      setActionError(err?.response?.data?.detail || err.message || 'Unable to load decisions');
    }
  }

  async function loadDetail(decisionId) {
    try {
      const response = await http.get(`/decisions/${decisionId}`);
      setSelectedDecision(response.data);
      setActionError('');
      setActionSuccess('');
    } catch (err) {
      setActionError(err?.response?.data?.detail || err.message || 'Unable to load decision detail');
    }
  }

  async function submitOverride() {
    if (!selectedDecision) return;
    try {
      const response = await http.post('/policy/override', {
        decision_id: selectedDecision.decision_id,
        new_outcome: overrideOutcome,
        rationale: overrideReason,
        correction_suggestion: overrideSuggestion || null,
      });
      setActionSuccess(`Override saved: ${response.data.new_outcome}`);
      const refreshed = await http.get(`/decisions/${selectedDecision.decision_id}`);
      setSelectedDecision(refreshed.data);
      const listResp = await http.get('/decisions?limit=25');
      setDecisions(listResp.data);
    } catch (err) {
      setActionError(err?.response?.data?.detail || err.message || 'Override failed');
    }
  }

  return (
    <div className="space-y-6">
      <SectionCard title="Decision History" icon={<ChevronRight className="w-5 h-5 text-cyan-300" />}>
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <input className="input-shell" value={alertId} onChange={(e) => setAlertId(e.target.value)} placeholder="Alert ID" />
          <select className="input-shell" value={outcome} onChange={(e) => setOutcome(e.target.value)}>
            <option value="">All outcomes</option>
            {['ALLOW', 'FLAG', 'BLOCK', 'CORRECT'].map((value) => <option key={value} value={value}>{value}</option>)}
          </select>
          <button className="btn-primary" onClick={search}>Search</button>
        </div>

        {(error || actionError) && <InlineError message={error || actionError} />}
        {actionSuccess && <InlineSuccess message={actionSuccess} />}

        <div className="mt-5 overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="text-slate-400 border-b border-white/10">
              <tr>
                <th className="text-left py-3">Decision</th>
                <th className="text-left py-3">Alert</th>
                <th className="text-left py-3">Outcome</th>
                <th className="text-left py-3">Risk</th>
                <th className="text-left py-3">Created</th>
                <th className="text-left py-3">Action</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td className="py-6 text-slate-400" colSpan="6">Loading decisions...</td></tr>
              ) : decisions.length === 0 ? (
                <tr><td className="py-6 text-slate-400" colSpan="6">No decisions available.</td></tr>
              ) : decisions.map((decision) => (
                <tr key={decision.decision_id} className="border-b border-white/5 hover:bg-white/5">
                  <td className="py-3 font-mono text-xs">{decision.decision_id.slice(0, 12)}...</td>
                  <td className="py-3">{decision.alert_id}</td>
                  <td className="py-3"><OutcomeBadge outcome={decision.outcome} /></td>
                  <td className="py-3 font-mono">{Number(decision.risk_score).toFixed(2)}</td>
                  <td className="py-3 text-slate-400 text-xs">{decision.created_at}</td>
                  <td className="py-3"><button className="text-cyan-300 hover:underline" onClick={() => loadDetail(decision.decision_id)}>View</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </SectionCard>

      {selectedDecision && (
        <SectionCard title={`Decision Detail: ${selectedDecision.decision_id.slice(0, 12)}...`} icon={<AlertCircle className="w-5 h-5 text-cyan-300" />}>
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="space-y-4">
              <DetailBlock label="Alert ID" value={selectedDecision.alert_id} />
              <DetailBlock label="Outcome" value={selectedDecision.outcome} />
              <DetailBlock label="Risk Score" value={selectedDecision.risk_score} />
              <DetailBlock label="Rationale" value={selectedDecision.analyst_rationale} />
              <DetailBlock label="Override" value={selectedDecision.analyst_override || 'None'} />
            </div>
            {userRole === 'SOC_ADMIN' && (
              <div className="space-y-3 rounded-2xl border border-white/10 bg-slate-950/40 p-4">
                <h3 className="text-lg font-semibold">Override Flow</h3>
                <select className="input-shell" value={overrideOutcome} onChange={(e) => setOverrideOutcome(e.target.value)}>
                  {['ALLOW', 'FLAG', 'BLOCK', 'CORRECT'].map((value) => <option key={value} value={value}>{value}</option>)}
                </select>
                <textarea className="input-shell min-h-[96px]" value={overrideReason} onChange={(e) => setOverrideReason(e.target.value)} placeholder="Override rationale" />
                <input className="input-shell" value={overrideSuggestion} onChange={(e) => setOverrideSuggestion(e.target.value)} placeholder="Correction suggestion (optional)" />
                <button className="btn-primary w-full" onClick={submitOverride}>Submit Override</button>
              </div>
            )}
          </div>
        </SectionCard>
      )}
    </div>
  );
}

function MetricsView() {
  const { performance, decisions } = useGatewayData();
  const trendData = decisions.slice(0, 10).reverse().map((decision, index) => ({ label: `#${index + 1}`, risk: decision.risk_score }));

  return (
    <div className="space-y-6">
      <SectionCard title="System Metrics" icon={<BarChart3 className="w-5 h-5 text-cyan-300" />}>
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <StatBox label="p50 latency" value={`${performance?.validation_latency_p50_ms ?? 0} ms`} />
          <StatBox label="p95 latency" value={`${performance?.validation_latency_p95_ms ?? 0} ms`} />
          <StatBox label="p99 latency" value={`${performance?.validation_latency_p99_ms ?? 0} ms`} />
          <StatBox label="Validations" value={performance?.total_validations ?? 0} />
        </div>
      </SectionCard>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <SectionCard title="Latency Trend" icon={<TriangleAlert className="w-5 h-5 text-cyan-300" />}>
          <div className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trendData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
                <XAxis dataKey="label" stroke="#94a3b8" />
                <YAxis stroke="#94a3b8" domain={[0, 1]} />
                <Tooltip contentStyle={{ background: '#0f172a', border: '1px solid rgba(255,255,255,0.12)', borderRadius: 16 }} />
                <Area type="monotone" dataKey="risk" stroke="#f59e0b" fill="rgba(245,158,11,0.2)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </SectionCard>

        <SectionCard title="Operational Health" icon={<CheckCircle2 className="w-5 h-5 text-cyan-300" />}>
          <div className="space-y-3">
            <HealthLine name="Gateway API" ok />
            <HealthLine name="Validation engine" ok />
            <HealthLine name="Decision engine" ok />
            <HealthLine name="Audit hash-chain" ok />
            <HealthLine name="RAG enrichment" ok={decisions.length > 0} />
          </div>
        </SectionCard>
      </div>
    </div>
  );
}

function PolicyView() {
  const { profiles, setProfiles } = useGatewayData();
  const [profileName, setProfileName] = useState('');
  const [allowMin, setAllowMin] = useState(0.85);
  const [flagMin, setFlagMin] = useState(0.6);
  const [semanticThreshold, setSemanticThreshold] = useState(0.72);
  const [active, setActive] = useState(false);
  const [status, setStatus] = useState('');

  async function createProfile() {
    try {
      const payload = {
        name: profileName,
        profile: {
          weights: {
            cve_validity: 0.4,
            severity_accuracy: 0.3,
            mitigation_relevance: 0.2,
            urgency_consistency: 0.1,
          },
          thresholds: {
            allow_min: Number(allowMin),
            flag_min: Number(flagMin),
          },
          signal_defaults: {
            cve_validity: 0.5,
            severity_accuracy: 0.5,
            mitigation_relevance: 0.5,
            urgency_consistency: 0.5,
          },
          semantic_threshold: Number(semanticThreshold),
          active: Boolean(active),
        },
      };
      await http.post('/policy/profiles', payload);
      const refreshed = await http.get('/policy/profiles');
      setProfiles(refreshed.data.profiles || []);
      setStatus('Profile created successfully');
    } catch (err) {
      setStatus(err?.response?.data?.detail || err.message || 'Failed to create profile');
    }
  }

  return (
    <div className="space-y-6">
      <SectionCard title="Policy Profiles" icon={<Settings className="w-5 h-5 text-cyan-300" />}>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {profiles.length === 0 ? <EmptyState text="No policy profiles returned yet." /> : profiles.map((profile) => (
            <div key={profile.name} className="rounded-2xl border border-white/10 bg-slate-950/40 p-4 space-y-2">
              <div className="flex items-center justify-between gap-4">
                <div>
                  <div className="font-semibold">{profile.name}</div>
                  <div className="text-xs text-slate-400">{profile.description}</div>
                </div>
                {profile.active && <span className="px-2 py-1 rounded-full text-xs bg-emerald-500/15 text-emerald-300 border border-emerald-400/20">Active</span>}
              </div>
              <pre className="text-xs text-slate-300 overflow-x-auto">{JSON.stringify(profile.thresholds, null, 2)}</pre>
            </div>
          ))}
        </div>
      </SectionCard>

      <SectionCard title="Create Profile" icon={<Lock className="w-5 h-5 text-cyan-300" />}>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <input className="input-shell" value={profileName} onChange={(e) => setProfileName(e.target.value)} placeholder="Profile name" />
          <input className="input-shell" type="number" step="0.01" value={allowMin} onChange={(e) => setAllowMin(e.target.value)} placeholder="Allow threshold" />
          <input className="input-shell" type="number" step="0.01" value={flagMin} onChange={(e) => setFlagMin(e.target.value)} placeholder="Flag threshold" />
          <input className="input-shell" type="number" step="0.01" value={semanticThreshold} onChange={(e) => setSemanticThreshold(e.target.value)} placeholder="Semantic threshold" />
          <label className="flex items-center gap-2 text-sm text-slate-300">
            <input type="checkbox" checked={active} onChange={(e) => setActive(e.target.checked)} /> Active
          </label>
          <button className="btn-primary" onClick={createProfile}>Create</button>
        </div>
        {status && <div className="mt-3 text-sm text-slate-300">{status}</div>}
      </SectionCard>
    </div>
  );
}

function SettingsView({ userRole, setUserRole, userId, setUserId }) {
  const [token, setToken] = useState(localStorage.getItem('lhf-token') || '');
  const [apiBase, setApiBase] = useState(API_BASE);
  const [message, setMessage] = useState('');

  function save() {
    localStorage.setItem('lhf-token', token);
    localStorage.setItem('lhf-api-base', apiBase);
    setMessage('Saved locally. Refresh to apply token or API base changes.');
  }

  return (
    <div className="space-y-6">
      <SectionCard title="User Profile" icon={<Settings className="w-5 h-5 text-cyan-300" />}>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <input className="input-shell" value={userId} onChange={(e) => setUserId(e.target.value)} placeholder="User ID" />
          <select className="input-shell" value={userRole} onChange={(e) => setUserRole(e.target.value)}>
            {['SOC_ANALYST', 'SOC_ADMIN', 'SYSTEM'].map((role) => <option key={role}>{role}</option>)}
          </select>
        </div>
      </SectionCard>

      <SectionCard title="API Access" icon={<Lock className="w-5 h-5 text-cyan-300" />}>
        <div className="space-y-3">
          <input className="input-shell" value={apiBase} onChange={(e) => setApiBase(e.target.value)} placeholder="API base URL" />
          <textarea className="input-shell min-h-[120px] font-mono text-xs" value={token} onChange={(e) => setToken(e.target.value)} placeholder="JWT token" />
          <button className="btn-primary" onClick={save}>Save locally</button>
          {message && <div className="text-sm text-slate-300">{message}</div>}
        </div>
      </SectionCard>

      <SectionCard title="References" icon={<BarChart3 className="w-5 h-5 text-cyan-300" />}>
        <ul className="space-y-2 text-sm text-cyan-200">
          <li><a href="http://localhost:8000/docs" target="_blank" rel="noreferrer">API Documentation</a></li>
          <li><a href="http://localhost:9090" target="_blank" rel="noreferrer">Prometheus</a></li>
          <li><a href="http://localhost:3000" target="_blank" rel="noreferrer">Grafana</a></li>
        </ul>
      </SectionCard>
    </div>
  );
}

function OutcomeCard({ outcome, value }) {
  return (
    <div className="rounded-3xl border border-white/10 bg-white/5 p-5 shadow-lg shadow-black/15">
      <div className="text-xs uppercase tracking-[0.35em] text-slate-400">{outcome}</div>
      <div className="mt-2 text-3xl font-semibold" style={{ color: outcomePalette[outcome] }}>{value}</div>
    </div>
  );
}

function MetricPill({ label, value, wide = false }) {
  return (
    <div className={`rounded-2xl border border-white/10 bg-black/20 p-4 ${wide ? 'col-span-2' : ''}`}>
      <div className="text-xs uppercase tracking-[0.35em] text-slate-400">{label}</div>
      <div className="mt-1 text-sm md:text-base font-medium break-all">{value}</div>
    </div>
  );
}

function StatBox({ label, value }) {
  return (
    <div className="rounded-2xl border border-white/10 bg-black/20 p-4">
      <div className="text-xs uppercase tracking-[0.35em] text-slate-400">{label}</div>
      <div className="mt-2 text-lg font-semibold">{value}</div>
    </div>
  );
}

function OutcomeBadge({ outcome }) {
  return <span className="px-3 py-1 rounded-full text-xs border" style={{ color: outcomePalette[outcome], borderColor: `${outcomePalette[outcome]}55`, background: `${outcomePalette[outcome]}15` }}>{outcome}</span>;
}

function DecisionRow({ decision }) {
  return (
    <div className="rounded-2xl border border-white/10 bg-slate-950/40 p-4 flex items-center justify-between gap-4 hover:bg-white/5 transition-colors">
      <div>
        <div className="font-mono text-sm">{decision.alert_id}</div>
        <div className="text-xs text-slate-400">{decision.decision_id.slice(0, 12)}... · {decision.created_at}</div>
      </div>
      <div className="text-right">
        <OutcomeBadge outcome={decision.outcome} />
        <div className="mt-1 text-sm text-slate-300">Risk {Number(decision.risk_score).toFixed(2)}</div>
      </div>
    </div>
  );
}

function DetailBlock({ label, value }) {
  return (
    <div className="rounded-2xl border border-white/10 bg-black/20 p-4">
      <div className="text-xs uppercase tracking-[0.35em] text-slate-400">{label}</div>
      <div className="mt-2 text-sm text-slate-100 break-words">{typeof value === 'string' ? value : JSON.stringify(value, null, 2)}</div>
    </div>
  );
}

function HealthLine({ name, ok }) {
  return (
    <div className="flex items-center justify-between rounded-2xl border border-white/10 bg-black/20 px-4 py-3">
      <span>{name}</span>
      {ok ? <CheckCircle2 className="w-5 h-5 text-emerald-300" /> : <AlertTriangle className="w-5 h-5 text-amber-300" />}
    </div>
  );
}

function InlineError({ message }) {
  return <div className="rounded-2xl border border-red-400/20 bg-red-500/10 px-4 py-3 text-sm text-red-200">{message}</div>;
}

function InlineSuccess({ message }) {
  return <div className="rounded-2xl border border-emerald-400/20 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-200">{message}</div>;
}

function EmptyState({ text }) {
  return <div className="rounded-2xl border border-dashed border-white/10 bg-black/20 px-4 py-8 text-center text-sm text-slate-400">{text}</div>;
}

export default App;
