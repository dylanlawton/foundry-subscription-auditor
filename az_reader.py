# az_reader.py
from azure.identity import AzureCliCredential
from azure.mgmt.resource import ResourceManagementClient

def list_resource_groups(subscription_id: str):
    credential = AzureCliCredential()
    client = ResourceManagementClient(credential, subscription_id)
    groups = client.resource_groups.list()

    group_details = []
    for g in groups:
        # Count the number of resources in the group
        resource_count = len(list(client.resources.list_by_resource_group(g.name)))
        
        group_details.append({
            "name": g.name,
            "location": g.location,
            "tags": g.tags or {},
            "resource_count": resource_count
        })

    return group_details
