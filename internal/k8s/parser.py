import logging
from kubernetes.client import ApiClient

logger = logging.getLogger(__name__)

# A shared ApiClient instance used solely for serialization.
# sanitize_for_serialization converts Kubernetes model objects into
# plain Python dicts with proper camelCase keys matching the K8s API spec.
_serializer = ApiClient()


def _k8s_object_to_dict(obj):
    """
    Converts a Kubernetes model object into a plain Python dict.
    Uses the official client's serializer so that keys come out in camelCase
    (e.g. 'podSelector', 'policyTypes', 'ipBlock') — matching the actual
    Kubernetes API JSON representation.
    """
    try:
        return _serializer.sanitize_for_serialization(obj)
    except Exception:
        # If serialization fails, fall back to to_dict() and hope for the best
        if hasattr(obj, 'to_dict'):
            return obj.to_dict()
        return obj


def parse_policy(raw_policy):
    """
    Takes a Kubernetes V1NetworkPolicy object and returns a clean dict
    with 'name', 'namespace', and 'spec' fields ready for evaluation.
    """
    try:
        serialized = _k8s_object_to_dict(raw_policy)

        metadata = serialized.get('metadata', {})
        spec = serialized.get('spec', {})

        return {
            'name': metadata.get('name', 'unknown'),
            'namespace': metadata.get('namespace', 'default'),
            'spec': spec
        }
    except Exception as e:
        logger.error(f"Error parsing policy: {e}")
        raise


def parse_policies(raw_policies):
    """
    Maps parse_policy over a list of raw K8s policy objects.
    Skips and logs any individual policies that fail to parse —
    one bad policy shouldn't tank the entire scan.
    """
    parsed = []
    for policy in raw_policies:
        try:
            parsed.append(parse_policy(policy))
        except Exception as e:
            name = 'unknown'
            if hasattr(policy, 'metadata') and hasattr(policy.metadata, 'name'):
                name = policy.metadata.name
            logger.warning(f"Skipping policy '{name}' due to parse error: {e}")

    return parsed
