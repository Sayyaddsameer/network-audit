import logging
from internal.policy.risk_scoring import get_severity_score

logger = logging.getLogger(__name__)


def evaluate_policy(parsed_policy):
    """
    Evaluates a single parsed NetworkPolicy against zero-trust rules.
    Returns a list of violation dicts (empty if the policy looks clean).

    Two checks are performed:
      1. Wildcard CIDR — ingress from 0.0.0.0/0 is essentially no firewall
      2. Unrestricted Egress — egress: [{}] lets pods talk to the entire internet
    """
    violations = []
    name = parsed_policy.get('name', 'unknown')
    namespace = parsed_policy.get('namespace', 'unknown')
    spec = parsed_policy.get('spec') or {}

    # ── Check 1: Wildcard CIDR in ingress rules ────────────────────
    # A rule that allows 0.0.0.0/0 effectively lets any IP on the internet
    # reach the pod. This is almost never intentional in a zero-trust setup.
    ingress_rules = spec.get('ingress') or []
    for rule in ingress_rules:
        if rule is None:
            continue
        from_entries = rule.get('from') or []
        for entry in from_entries:
            if entry is None:
                continue
            ip_block = entry.get('ipBlock') or entry.get('ip_block')
            if ip_block and ip_block.get('cidr') == '0.0.0.0/0':
                violations.append({
                    'policy_name': name,
                    'namespace': namespace,
                    'violation_type': 'wildcard_cidr',
                    'severity': 'high',
                    'severity_score': get_severity_score('wildcard_cidr')
                })

    # ── Check 2: Unrestricted egress ───────────────────────────────
    # In the K8s API, if policyTypes includes "Egress" and the egress array
    # contains an empty object [{}], it means "allow traffic to everywhere."
    # An empty list [] means "deny all egress" — very different semantics.
    policy_types = spec.get('policyTypes') or spec.get('policy_types') or []
    if 'Egress' in policy_types:
        egress_rules = spec.get('egress')
        if egress_rules is not None and isinstance(egress_rules, list):
            for rule in egress_rules:
                # An empty dict {} or None entry means "match all destinations"
                if rule is None or (isinstance(rule, dict) and len(rule) == 0):
                    violations.append({
                        'policy_name': name,
                        'namespace': namespace,
                        'violation_type': 'unrestricted_egress',
                        'severity': 'medium',
                        'severity_score': get_severity_score('unrestricted_egress')
                    })
                    break  # One violation per policy is enough

    return violations


def evaluate_all_policies(policies):
    """
    Runs the evaluator across every policy and collects all violations.
    """
    all_violations = []
    for policy in policies:
        try:
            all_violations.extend(evaluate_policy(policy))
        except Exception as e:
            logger.error(f"Error evaluating policy '{policy.get('name', '?')}': {e}")
    return all_violations
