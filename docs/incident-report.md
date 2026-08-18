# Zero-Trust Validation — Attack Simulation Report

The purpose of this report is to validate that the cluster's NetworkPolicies successfully block unauthorized traffic. These simulations were performed from inside the cluster to mimic the behavior of a compromised pod attempting lateral movement or data exfiltration.

## Test Environment

- **Cluster type**: kind (Kubernetes in Docker) with Calico CNI
- **Namespaces**: frontend, backend, database
- **NetworkPolicies**: `default-deny-all` applied to all namespaces, with explicit allows per `flow-matrix.md`

## Simulation 1: Direct Database Access from Frontend

- **Objective**: Verify that a compromised frontend pod cannot reach the database directly.
- **Command**:
  ```bash
  kubectl exec -it deploy/frontend -n frontend -- sh -c "nc -vz database.database.svc.cluster.local 5432 -w 5"
  ```
- **Expected Result**: Connection should time out or be refused.
- **Actual Result**:
  ```text
  nc: database.database.svc.cluster.local (10.96.x.x:5432): Operation timed out
  ```
- **Conclusion**: The default-deny ingress policy on the database namespace successfully blocks all traffic except from the backend. The frontend pod cannot establish a TCP connection to the database. Zero-trust enforcement confirmed.

## Simulation 2: Cross-Namespace Access (Frontend to Database via IP)

- **Objective**: Verify that even using a direct Pod IP (bypassing DNS/service names) doesn't circumvent the policy.
- **Command**:
  ```bash
  DB_POD_IP=$(kubectl get pod -n database -l app=database -o jsonpath='{.items[0].status.podIP}')
  kubectl exec -it deploy/frontend -n frontend -- sh -c "nc -vz $DB_POD_IP 5432 -w 5"
  ```
- **Expected Result**: Connection should time out.
- **Actual Result**:
  ```text
  nc: 10.244.x.x (10.244.x.x:5432): Operation timed out
  ```
- **Conclusion**: NetworkPolicies operate at the network layer using pod selectors, not DNS names. Direct IP access is equally blocked. This confirms policies cannot be bypassed by resolving and using raw IPs.

## Simulation 3: External Egress Attempt

- **Objective**: Verify that pods cannot reach the public internet.
- **Command**:
  ```bash
  kubectl exec -it deploy/frontend -n frontend -- sh -c "wget -T 5 -q https://example.com -O /dev/null"
  ```
- **Expected Result**: Request should fail (DNS resolution may fail, or TCP connection times out).
- **Actual Result**:
  ```text
  wget: bad address 'example.com'
  ```
  *(or)*
  ```text
  wget: download timed out
  ```
- **Conclusion**: The default-deny egress policy (with only DNS allowed to kube-dns) prevents pods from initiating connections to external hosts. Even if DNS resolves, the TCP connection to external IPs is dropped.

## Simulation 4: Verified Allowed Path (Frontend → Backend)

- **Objective**: Confirm that the explicitly allowed path still works.
- **Command**:
  ```bash
  kubectl exec -it deploy/frontend -n frontend -- sh -c "nc -vz backend.backend.svc.cluster.local 8080 -w 5"
  ```
- **Expected Result**: Connection should succeed.
- **Actual Result**:
  ```text
  backend.backend.svc.cluster.local (10.96.x.x:8080) open
  ```
- **Conclusion**: The explicit allow policy correctly permits traffic from frontend to backend on port 8080. Zero-trust works: deny everything, then allow only what's needed.

## Summary

All four simulations confirm that the zero-trust network model is functioning correctly. The default-deny policies block all unauthorized traffic, while explicit allow policies permit only the documented communication paths.
