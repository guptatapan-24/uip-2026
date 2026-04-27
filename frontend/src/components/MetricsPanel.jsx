export default function MetricsPanel({ metrics }) {
  if (!metrics) {
    return (
      <section className="panel">
        <h2>Metrics</h2>
        <p>Run a scenario to populate dashboard counters.</p>
      </section>
    );
  }

  const decisions = Object.entries(metrics.decision_counts || {});

  return (
    <section className="panel">
      <h2>Metrics Dashboard</h2>
      <div className="grid">
        <article className="stat">
          <span>Total requests</span>
          <strong>{metrics.total_requests}</strong>
        </article>
        <article className="stat">
          <span>Mean latency</span>
          <strong>{metrics.mean_latency_ms} ms</strong>
        </article>
        <article className="stat">
          <span>Cache hit rate</span>
          <strong>{metrics.cache_hit_rate}%</strong>
        </article>
        <article className="stat">
          <span>FAR / FBR</span>
          <strong>{metrics.far}% / {metrics.fbr}%</strong>
        </article>
      </div>

      <h3>Decision counts</h3>
      <ul>
        {decisions.length ? decisions.map(([key, value]) => <li key={key}>{key}: {value}</li>) : <li>No decisions yet</li>}
      </ul>
    </section>
  );
}
