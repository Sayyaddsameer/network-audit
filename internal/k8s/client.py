import logging
from kubernetes import client, config
from kubernetes.client.rest import ApiException
from kubernetes.config.config_exception import ConfigException

logger = logging.getLogger(__name__)

def get_k8s_client():
    """
    Returns a Kubernetes NetworkingV1Api client.
    Attempts to load in-cluster config first, then falls back to kube-config.
    """
    try:
        config.load_incluster_config()
        logger.info("Loaded in-cluster Kubernetes config.")
    except ConfigException:
        try:
            config.load_kube_config()
            logger.info("Loaded local kube-config.")
        except ConfigException as e:
            logger.error(f"Failed to load Kubernetes config: {e}")
            return None
    
    return client.NetworkingV1Api()

def fetch_all_network_policies(api_client):
    """
    Fetches all network policies across all namespaces.
    Returns an empty list on failure instead of crashing.
    """
    if not api_client:
        logger.error("No API client provided.")
        return []
    
    try:
        response = api_client.list_network_policy_for_all_namespaces()
        return response.items
    except ApiException as e:
        logger.error(f"Kubernetes API exception when fetching policies: {e}")
        return []
    except Exception as e:
        logger.error(f"Unexpected error when fetching policies: {e}")
        return []
