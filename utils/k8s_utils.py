import logging
from kubernetes import client
from datetime import datetime, timezone

def update_crd_status(
    k8s_custom_objects_api: client.CustomObjectsApi,
    crd_group: str,
    crd_version: str,
    crd_plural: str,
    namespace: str,
    name: str,
    status_data: dict,
    logger: logging.Logger
) -> bool:
    """
    Update the status of a DomainCertificate CRD

    Args:
        k8s_custom_objects_api: Initialized Kubernetes CustomObjectsApi client.
        crd_group: The API group of the CRD.
        crd_version: The API version of the CRD.
        crd_plural: The plural name of the CRD.
        namespace: Namespace of the CRD.
        name: Name of the CRD.
        status_data: Dictionary containing status fields to update.
        logger: Logger instance.

    Returns:
        bool: True if successful, False otherwise.
    """
    if not k8s_custom_objects_api:
        logger.warning(f"Kubernetes client not initialized, skipping status update for {namespace}/{name}")
        return False

    try:
        # Ensure lastTransitionTime is set for conditions if not present
        if "conditions" in status_data and isinstance(status_data["conditions"], list):
            now_utc = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')
            for condition in status_data["conditions"]:
                if "lastTransitionTime" not in condition:
                    condition["lastTransitionTime"] = now_utc

        # Create the status patch
        status_patch = {
            "status": status_data
        }

        # Update the CRD status
        k8s_custom_objects_api.patch_namespaced_custom_object_status(
            group=crd_group,
            version=crd_version,
            namespace=namespace,
            plural=crd_plural,
            name=name,
            body=status_patch
        )

        logger.info(f"Updated status for DomainCertificate {namespace}/{name} to {status_data.get('state', 'Unknown')}")
        return True
    except Exception as e:
        logger.error(f"Failed to update status for DomainCertificate {namespace}/{name}: {e}")
        return False

