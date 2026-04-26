# Demo Scenarios

## Scenario 1: Real CVE, unsafe remediation

- Expected decision: `block`
- Why it demos well: grounded vulnerability, but the mitigation is too broad and risky.

## Scenario 2: Fabricated CVE

- Expected decision: `block`
- Why it demos well: easy to explain hallucination prevention.

## Scenario 3: Grounded patch recommendation

- Expected decision: `allow`
- Why it demos well: proves the firewall is not blocking everything.

## Speaking line

"The model recommendation enters the middleware, the claims are checked, the decision engine assigns a risk-aware outcome, and the dashboard records measurable trust metrics."
