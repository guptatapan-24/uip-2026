const decisionTone = {
  allow: "tone-allow",
  flag: "tone-flag",
  block: "tone-block",
  correct: "tone-correct"
};

export default function DecisionCard({ result }) {
  if (!result) {
    return (
      <section className="panel">
        <h2>Decision</h2>
        <p>No validation has been run yet.</p>
      </section>
    );
  }

  return (
    <section className={`panel ${decisionTone[result.decision]}`}>
      <div className="split">
        <div>
          <h2>{result.decision.toUpperCase()}</h2>
          <p>Confidence: {(result.confidence * 100).toFixed(0)}%</p>
          <p>Risk score: {result.risk_score}</p>
        </div>
        <div className="badge">{result.metrics.total_requests} checks</div>
      </div>

      <h3>Reasoning</h3>
      <ul>
        {result.reasoning.map((item) => (
          <li key={item}>{item}</li>
        ))}
      </ul>

      <h3>Failed rules</h3>
      <ul>
        {result.failed_rules.length ? result.failed_rules.map((item) => <li key={item}>{item}</li>) : <li>None</li>}
      </ul>

      <h3>Corrections</h3>
      <ul>
        {result.corrections.length ? result.corrections.map((item) => <li key={item}>{item}</li>) : <li>None</li>}
      </ul>
    </section>
  );
}
