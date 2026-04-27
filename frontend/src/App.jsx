import { useEffect, useState } from "react";
import DecisionCard from "./components/DecisionCard";
import MetricsPanel from "./components/MetricsPanel";

const API_BASE = "http://127.0.0.1:8000";

export default function App() {
  const [scenarios, setScenarios] = useState([]);
  const [selectedId, setSelectedId] = useState("");
  const [input, setInput] = useState("");
  const [claims, setClaims] = useState({ cves: [], attack_mappings: [], mitigations: [] });
  const [result, setResult] = useState(null);
  const [metrics, setMetrics] = useState(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    async function bootstrap() {
      const [scenarioResponse, metricsResponse] = await Promise.all([
        fetch(`${API_BASE}/demo-scenarios`),
        fetch(`${API_BASE}/metrics`)
      ]);
      const scenarioData = await scenarioResponse.json();
      const metricsData = await metricsResponse.json();
      setScenarios(scenarioData);
      setMetrics(metricsData);
      if (scenarioData.length) {
        selectScenario(scenarioData[0]);
      }
    }

    bootstrap().catch(() => {
      setMetrics(null);
    });
  }, []);

  function selectScenario(scenario) {
    setSelectedId(scenario.id);
    setInput(scenario.prompt);
    setClaims(scenario.claims);
  }

  async function submitValidation(payload) {
    setLoading(true);
    const response = await fetch(`${API_BASE}/validate`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    const data = await response.json();
    setResult(data);
    setMetrics(data.metrics);
    setLoading(false);
  }

  async function runValidation() {
    const scenario = scenarios.find((item) => item.id === selectedId);
    await submitValidation({
      raw_recommendation: input,
      source: "react-ui",
      scenario_id: selectedId || null,
      expected_decision: scenario?.expected_decision ?? null,
      claims
    });
  }

  async function runScenario(scenario) {
    selectScenario(scenario);
    await submitValidation({
      raw_recommendation: scenario.prompt,
      source: "react-ui-demo-button",
      scenario_id: scenario.id,
      expected_decision: scenario.expected_decision,
      claims: scenario.claims
    });
  }

  return (
    <main className="app-shell">
      <section className="hero">
        <p className="eyebrow">Person B Deliverables</p>
        <h1>Hallucination Firewall Control Center</h1>
        <p>
          Demo the middleware flow from recommendation input to risk-aware decision,
          reasoning, and live operational metrics.
        </p>
      </section>

      <section className="layout">
        <section className="panel">
          <h2>One-click demos</h2>
          <div className="quick-actions">
            {scenarios.map((scenario) => (
              <button
                key={scenario.id}
                className="ghost-button"
                onClick={() => runScenario(scenario)}
                disabled={loading}
              >
                {scenario.title}
              </button>
            ))}
          </div>

          <h2>Demo Scenario</h2>
          <select value={selectedId} onChange={(event) => {
            const next = scenarios.find((item) => item.id === event.target.value);
            if (next) {
              selectScenario(next);
            }
          }}>
            {scenarios.map((scenario) => (
              <option key={scenario.id} value={scenario.id}>
                {scenario.title}
              </option>
            ))}
          </select>

          <h3>Recommendation</h3>
          <textarea value={input} onChange={(event) => setInput(event.target.value)} rows={8} />

          <h3>Claims Payload</h3>
          <textarea
            value={JSON.stringify(claims, null, 2)}
            onChange={(event) => {
              try {
                setClaims(JSON.parse(event.target.value));
              } catch {
                // Keep current claims until valid JSON is entered.
              }
            }}
            rows={16}
          />

          <button onClick={runValidation} disabled={loading}>
            {loading ? "Validating..." : "Run /validate"}
          </button>
        </section>

        <div className="stack">
          <DecisionCard result={result} />
          <MetricsPanel metrics={metrics} />
        </div>
      </section>
    </main>
  );
}
