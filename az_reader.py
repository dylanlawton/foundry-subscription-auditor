from azure.identity import InteractiveBrowserCredential
from azure.mgmt.resource import ResourceManagementClient
import os

def list_resource_groups(subscription_id):
    credential = InteractiveBrowserCredential(tenant_id=os.getenv("AZURE_TENANT_ID"))
    client = ResourceManagementClient(credential, subscription_id)
    groups = client.resource_groups.list()

    result = []
    for g in groups:
        result.append({
            "name": g.name,
            "location": g.location,
            "tags": g.tags or {},
            "resource_count": 0  # You can update this to count actual resources later
        })
    return result
