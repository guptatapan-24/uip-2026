Kubernetes manifests for `llm-hallucination-firewall`

These manifests are a minimal, opinionated starting point for deploying the system to a Kubernetes cluster.

Files:
- `deployment.yaml` — `Deployment` for the API gateway (set `image` to your registry image).
- `service.yaml` — `ClusterIP` service exposing the gateway inside the cluster.
- `configmap.yaml` — Non-sensitive configuration values.
- `secret.yaml` — Template for sensitive values; *edit before `kubectl apply`*.
- `postgres-statefulset.yaml` — Example `StatefulSet` for an on-cluster Postgres (for testing only).
- `redis-deployment.yaml` — Redis `Deployment` for on-cluster cache (testing only).

Usage (example):

```bash
# Update `secret.yaml` with real secrets or create a k8s secret via CLI:
# kubectl create secret generic llm-firewall-secrets --from-literal=POSTGRES_PASSWORD=pass ...

kubectl apply -f infra/k8s/configmap.yaml
kubectl apply -f infra/k8s/secret.yaml      # or create via kubectl create secret
kubectl apply -f infra/k8s/postgres-statefulset.yaml
kubectl apply -f infra/k8s/redis-deployment.yaml
kubectl apply -f infra/k8s/deployment.yaml
kubectl apply -f infra/k8s/service.yaml
```

Notes:
- For production, prefer managed Postgres/Redis and replace `postgres-statefulset.yaml`.
- Use `imagePullSecrets` and a proper CI pipeline to push images to your registry before deploying.
- Add `HorizontalPodAutoscaler`, `NetworkPolicy`, `Ingress`/`Gateway` and resource quotas as needed.
