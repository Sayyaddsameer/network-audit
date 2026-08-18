SEVERITY_SCORES = {
    'wildcard_cidr': 5,
    'unrestricted_egress': 3
}

def get_severity_score(violation_type):
    """
    Returns score from the mapping, defaults to 1 for unknown types.
    """
    return SEVERITY_SCORES.get(violation_type, 1)

def calculate_aggregate_risk(violations):
    """
    Sums all severity_score values and determines overall risk level.
    """
    total_score = sum(v.get('severity_score', 1) for v in violations)
    violation_count = len(violations)
    
    if total_score >= 10:
        risk_level = 'critical'
    elif total_score >= 5:
        risk_level = 'high'
    elif total_score >= 3:
        risk_level = 'medium'
    else:
        risk_level = 'low'
        
    return {
        'total_score': total_score,
        'violation_count': violation_count,
        'risk_level': risk_level
    }
