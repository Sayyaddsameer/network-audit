import os
import json
import logging
from fastapi import APIRouter, HTTPException, Response
import psycopg2
from psycopg2.extras import RealDictCursor
from prometheus_client import Counter, generate_latest, CONTENT_TYPE_LATEST

from internal.k8s.client import get_k8s_client, fetch_all_network_policies
from internal.k8s.parser import parse_policies
from internal.policy.evaluator import evaluate_all_policies
from internal.policy.risk_scoring import calculate_aggregate_risk

logger = logging.getLogger(__name__)

router = APIRouter()

# ── Prometheus metrics ──────────────────────────────────────────────
# These counters survive across requests and get scraped by Prometheus.
policy_violations_total = Counter(
    'policy_violations_total',
    'Total number of detected network policy violations'
)
blocked_connections_total = Counter(
    'blocked_connections_total',
    'Total blocked connection attempts'
)
unexpected_egress_attempts_total = Counter(
    'unexpected_egress_attempts_total',
    'Total unexpected egress attempts detected'
)


def get_db_connection():
    """
    Opens a fresh psycopg2 connection using the DATABASE_URL env var.
    Returns None (rather than crashing) if the connection can't be made.
    """
    db_url = os.environ.get('DATABASE_URL')
    if not db_url:
        logger.error("DATABASE_URL environment variable is not set")
        return None

    try:
        conn = psycopg2.connect(db_url)
        return conn
    except psycopg2.OperationalError as e:
        logger.error(f"Failed to connect to database: {e}")
        return None


# ── Health ──────────────────────────────────────────────────────────

@router.get("/health")
def health_check():
    """
    Quick health probe. Tries to touch the database and reports status.
    Used by Docker's HEALTHCHECK and any upstream load balancer.
    """
    conn = get_db_connection()
    if conn:
        conn.close()
        return {"status": "healthy", "database": "connected"}

    return Response(
        content=json.dumps({"status": "degraded", "database": "disconnected"}),
        status_code=503,
        media_type="application/json"
    )


# ── Live policies from the cluster ─────────────────────────────────

@router.get("/api/v1/policies/live")
def get_live_policies():
    """
    Fetches all NetworkPolicies currently applied in the cluster
    and returns them as JSON. This proves real-time connectivity
    to the Kubernetes API.
    """
    api_client = get_k8s_client()
    if not api_client:
        raise HTTPException(status_code=503, detail="Could not connect to the Kubernetes API")

    raw_policies = fetch_all_network_policies(api_client)
    parsed = parse_policies(raw_policies)

    return {"policies": parsed}


# ── On-demand evaluation ───────────────────────────────────────────

@router.post("/api/v1/policies/evaluate")
def evaluate_policies():
    """
    The main audit workflow:
    1. Pull every NetworkPolicy from the cluster
    2. Run each one through the zero-trust evaluator
    3. Persist both the policy snapshot and any violations to PostgreSQL
    4. Bump the Prometheus counters so alerting stays current
    5. Return the violations (and a quick summary) to the caller
    """
    # Step 1 — fetch and parse
    api_client = get_k8s_client()
    if not api_client:
        raise HTTPException(status_code=503, detail="Could not connect to the Kubernetes API")

    raw_policies = fetch_all_network_policies(api_client)
    parsed_policies = parse_policies(raw_policies)

    # Step 2 — evaluate
    violations = evaluate_all_policies(parsed_policies)
    risk = calculate_aggregate_risk(violations)

    # Step 3 — persist
    conn = get_db_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection failed")

    try:
        with conn.cursor() as cur:
            for policy in parsed_policies:
                # Store a snapshot of the policy as we saw it right now
                cur.execute(
                    """
                    INSERT INTO network_policies (policy_name, namespace, spec_json)
                    VALUES (%s, %s, %s)
                    RETURNING id
                    """,
                    (
                        policy.get('name'),
                        policy.get('namespace'),
                        json.dumps(policy.get('spec', {}))
                    )
                )
                policy_id = cur.fetchone()[0]

                # Link any violations back to this policy record
                policy_violations = [
                    v for v in violations
                    if v.get('policy_name') == policy.get('name')
                    and v.get('namespace') == policy.get('namespace')
                ]

                for violation in policy_violations:
                    cur.execute(
                        """
                        INSERT INTO policy_violations
                            (policy_id, violation_type, severity, severity_score)
                        VALUES (%s, %s, %s, %s)
                        """,
                        (
                            policy_id,
                            violation.get('violation_type'),
                            violation.get('severity'),
                            violation.get('severity_score')
                        )
                    )

        conn.commit()
    except Exception as e:
        conn.rollback()
        logger.error(f"Database transaction failed during evaluation: {e}")
        raise HTTPException(status_code=500, detail="Failed to persist evaluation results")
    finally:
        conn.close()

    # Step 4 — update Prometheus counters
    if violations:
        policy_violations_total.inc(len(violations))

        # Also bump the more specific counters for dashboard breakdowns
        for v in violations:
            if v.get('violation_type') == 'unrestricted_egress':
                unexpected_egress_attempts_total.inc()
            if v.get('violation_type') == 'wildcard_cidr':
                blocked_connections_total.inc()

    # Step 5 — respond
    return {
        "violations": violations,
        "summary": {
            "total_policies_scanned": len(parsed_policies),
            "violations_found": len(violations),
            "risk_level": risk.get('risk_level', 'low')
        }
    }


# ── Historical violations ──────────────────────────────────────────

@router.get("/api/v1/violations")
def get_violations():
    """
    Returns every violation we've ever recorded, newest first.
    Joins against network_policies so each row carries the
    policy name and namespace for context.
    """
    conn = get_db_connection()
    if not conn:
        raise HTTPException(status_code=500, detail="Database connection failed")

    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                """
                SELECT
                    v.id,
                    v.policy_id,
                    p.policy_name,
                    p.namespace,
                    v.violation_type,
                    v.severity,
                    v.severity_score,
                    v.detected_at
                FROM policy_violations v
                JOIN network_policies p ON v.policy_id = p.id
                ORDER BY v.detected_at DESC
                """
            )
            rows = cur.fetchall()

            # UUIDs and timestamps aren't JSON-serializable out of the box
            for row in rows:
                if row.get('id'):
                    row['id'] = str(row['id'])
                if row.get('policy_id'):
                    row['policy_id'] = str(row['policy_id'])
                if row.get('detected_at'):
                    row['detected_at'] = row['detected_at'].isoformat()

            return {"violations": rows}
    except Exception as e:
        logger.error(f"Database error fetching violations: {e}")
        raise HTTPException(status_code=500, detail="Failed to retrieve violations")
    finally:
        conn.close()


# ── Prometheus metrics endpoint ────────────────────────────────────

@router.get("/metrics")
def get_metrics():
    """
    Standard Prometheus scrape target. Returns all registered
    counters in the text exposition format.
    """
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)
