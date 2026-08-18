# Network Traffic Flow Matrix

This document serves as the single source of truth for all allowed network communication within the cluster. We operate on a strict zero-trust model: any traffic not explicitly listed here is denied by default.

| Source Service | Destination Service | Destination Port | Protocol | Reason |
| :--- | :--- | :--- | :--- | :--- |
| frontend | backend | 8080 | TCP | Web UI forwards API requests to the backend service |
| backend | database | 5432 | TCP | Backend reads and writes application data |
| frontend | kube-dns | 53 | UDP/TCP | DNS resolution for service discovery |
| backend | kube-dns | 53 | UDP/TCP | DNS resolution for service discovery |
| prometheus | audit-service | 8080 | TCP | Scrapes application metrics from the /metrics endpoint |

## Denied by Default

To illustrate the boundaries of this policy, here are examples of explicitly blocked flows:

- **frontend → database**: Direct database access bypasses the backend API, violating the principle of least privilege.
- **frontend → external internet**: No egress to public IPs is permitted to prevent data exfiltration.
- **database → any**: The database should only accept connections and never initiate them.
- **any → any across namespaces**: Unless explicitly listed in the matrix above, cross-namespace communication is blocked.

> **Note:** This matrix is enforced directly by the NetworkPolicy manifests located in `deploy/k8s/network-policies/`.
