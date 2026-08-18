# Zero-Trust Kubernetes Policy Audit Engine

> Automated detection of over-permissive Kubernetes NetworkPolicies, backed by PostgreSQL for audit trails and Prometheus for real-time observability.

## Overview

Modern Kubernetes clusters default to flat networks — any pod can talk to any other pod. That's convenient for development, but it's a security disaster in production. If an attacker compromises a single frontend container, they can pivot laterally to databases, credential stores, and internal APIs without any resistance.

The Zero-Trust Policy Audit Engine fixes this blind spot. It connects to your cluster's API, pulls every NetworkPolicy, and evaluates each one against a strict set of zero-trust rules. Policies that allow wildcard ingress (`0.0.0.0/0`) or unrestricted egress (`[{}]`) are flagged immediately, persisted to PostgreSQL for compliance records, and surfaced through Prometheus counters so your alerting pipeline can catch regressions the moment they happen.

This repository also includes a complete set of zero-trust baseline policies for a sample three-tier application (frontend → backend → database), along with an attack simulation report that proves the policies actually block unauthorized traffic.

## Architecture

```
┌──────────────────────────────────┐      ┌───────────────────────────────┐
│       Kubernetes Cluster         │      │   Audit Infrastructure        │
│                                  │      │   (Docker Compose)            │
│  ┌───────────┐                   │      │                               │
│  │ frontend  │───(8080)──►┐      │      │  ┌─────────────────────────┐  │
│  └───────────┘            │      │      │  │  Audit Service (FastAPI)│  │
│                    ┌──────┴──┐   │ ◄────┤  │  :8080                  │  │
│                    │ backend │   │ K8s  │  └──────────┬──────────────┘  │
│                    └────┬────┘   │ API  │             │                 │
│                         │        │      │  ┌──────────▼──────────────┐  │
│                  ┌──────▼─────┐  │      │  │  PostgreSQL :5432       │  │
│                  │  database  │  │      │  │  (violations & history) │  │
│                  └────────────┘  │      │  └─────────────────────────┘  │
│                                  │      │                               │
│  NetworkPolicies enforce         │      │  ┌─────────────────────────┐  │
│  zero-trust between pods         │      │  │  Prometheus :9090       │  │
│                                  │      │  │  (scrapes /metrics)     │  │
└──────────────────────────────────┘      │  └─────────────────────────┘  │
                                          └───────────────────────────────┘
```

## Prerequisites

- **Docker & Docker Compose** — for running the audit infrastructure
- **kubectl** — configured for your local cluster
- **kind** (or minikube) — with a CNI that enforces NetworkPolicies (Calico recommended)
- **Python 3.11+** — only needed if you want to run the service outside Docker

## Quick Start

### 1. Clone and Configure

```bash
git clone <repository-url>
cd network-audit
cp .env.example .env
# Review .env and change credentials if you'd like
```

### 2. Set Up a Local Kubernetes Cluster (kind + Calico)

The default kind CNI doesn't enforce NetworkPolicies. You need Calico.

```bash
# Create the cluster with default CNI disabled
cat <<EOF | kind create cluster --config=-
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
networking:
  disableDefaultCNI: true
  podSubnet: 192.168.0.0/16
EOF

# Install Calico
kubectl apply -f https://raw.githubusercontent.com/projectcalico/calico/v3.26.1/manifests/calico.yaml

# Wait until Calico is ready
kubectl wait --for=condition=ready pod -l k8s-app=calico-node -n kube-system --timeout=120s
```

### 3. Deploy the Target Application

```bash
kubectl apply -f deploy/k8s/namespaces.yml
kubectl apply -f deploy/k8s/services.yml
kubectl apply -f deploy/k8s/network-policies/default-deny-all.yml
kubectl apply -f deploy/k8s/network-policies/allow-frontend-to-backend.yml
```

To test the audit engine's violation detection, also apply the intentionally insecure policies:

```bash
kubectl apply -f deploy/k8s/network-policies/test-bad-policies.yml
```

### 4. Start the Audit Infrastructure

```bash
docker-compose up --build -d
```

Verify everything is healthy:

```bash
docker-compose ps
```

You should see `audit-engine-service`, `audit-engine-db`, and `audit-engine-prometheus` all running and healthy.

## API Reference

### `GET /health`

Service health check. Returns database connectivity status.

```bash
curl http://localhost:8080/health
```
```json
{
  "status": "healthy",
  "database": "connected"
}
```

### `GET /api/v1/policies/live`

Fetch all NetworkPolicies currently applied in the cluster.

```bash
curl http://localhost:8080/api/v1/policies/live
```
```json
{
  "policies": [
    {
      "name": "default-deny-all",
      "namespace": "frontend",
      "spec": {
        "podSelector": {},
        "policyTypes": ["Ingress", "Egress"],
        "ingress": [],
        "egress": []
      }
    }
  ]
}
```

### `POST /api/v1/policies/evaluate`

Triggers an on-demand audit. Fetches policies, evaluates them, persists results, and returns any violations found.

```bash
curl -X POST http://localhost:8080/api/v1/policies/evaluate
```
```json
{
  "violations": [
    {
      "policy_name": "allow-all-ingress-wildcard",
      "namespace": "default",
      "violation_type": "wildcard_cidr",
      "severity": "high",
      "severity_score": 5
    },
    {
      "policy_name": "allow-all-egress",
      "namespace": "default",
      "violation_type": "unrestricted_egress",
      "severity": "medium",
      "severity_score": 3
    }
  ],
  "summary": {
    "total_policies_scanned": 10,
    "violations_found": 2,
    "risk_level": "critical"
  }
}
```

### `GET /api/v1/violations`

Retrieve all historical violations from the database.

```bash
curl http://localhost:8080/api/v1/violations
```
```json
{
  "violations": [
    {
      "id": "a1b2c3d4-...",
      "policy_id": "e5f6g7h8-...",
      "policy_name": "allow-all-ingress-wildcard",
      "namespace": "default",
      "violation_type": "wildcard_cidr",
      "severity": "high",
      "severity_score": 5,
      "detected_at": "2026-08-16T12:00:00"
    }
  ]
}
```

### `GET /metrics`

Prometheus scrape target. Returns counters in the standard exposition format.

```bash
curl http://localhost:8080/metrics
```
```text
# HELP policy_violations_total Total number of detected network policy violations
# TYPE policy_violations_total counter
policy_violations_total 2.0
# HELP blocked_connections_total Total blocked connection attempts
# TYPE blocked_connections_total counter
blocked_connections_total 1.0
# HELP unexpected_egress_attempts_total Total unexpected egress attempts detected
# TYPE unexpected_egress_attempts_total counter
unexpected_egress_attempts_total 1.0
```

## Project Structure

```
network-audit/
├── cmd/
│   └── audit-service/
│       └── main.py                 # FastAPI entry point (uvicorn)
├── internal/
│   ├── k8s/
│   │   ├── client.py               # Kubernetes API client setup
│   │   └── parser.py               # NetworkPolicy → dict serialization
│   ├── policy/
│   │   ├── evaluator.py            # Zero-trust rule checks
│   │   └── risk_scoring.py         # Severity scoring and risk aggregation
│   └── api/
│       └── handlers.py             # All REST endpoints and Prometheus metrics
├── migrations/
│   ├── V1__init_schema.sql         # Initial tables (network_policies, policy_violations)
│   └── V2__add_severity_score.sql  # Adds severity_score column
├── deploy/
│   └── k8s/
│       ├── namespaces.yml          # frontend, backend, database namespaces
│       ├── services.yml            # Sample deployments and services
│       └── network-policies/
│           ├── default-deny-all.yml           # Zero-trust baseline
│           ├── allow-frontend-to-backend.yml  # Explicit allow rules
│           └── test-bad-policies.yml          # Intentionally insecure (for testing)
├── docs/
│   ├── flow-matrix.md              # Authorized traffic matrix
│   └── incident-report.md          # Attack simulation results
├── .env.example                    # Environment variable template
├── docker-compose.yml              # Orchestrates all services
├── Dockerfile                      # Containerizes the audit service
├── prometheus.yml                  # Prometheus scrape config
├── requirements.txt                # Python dependencies
└── README.md                       # This file
```

## Attack Simulation

To verify the zero-trust policies are working, see the detailed [incident report](docs/incident-report.md). The key tests:

1. **Frontend → Database (direct)** — should time out (blocked by default-deny)
2. **Frontend → Database (by IP)** — should time out (policies work at the network layer)
3. **Frontend → External internet** — should fail (no egress to public IPs)
4. **Frontend → Backend** — should succeed (explicitly allowed on port 8080)

## Security Considerations

- The audit service container runs as a **non-root user** (`appuser`)
- **No secrets** in the repository — `.env.example` has placeholder values only
- The service needs **read-only** access to the Kubernetes API (`get`, `list` on NetworkPolicies)
- For production, deploy inside the cluster with a dedicated **ServiceAccount** and a **ClusterRole** scoped to `networking.k8s.io/networkpolicies`

## License

MIT
