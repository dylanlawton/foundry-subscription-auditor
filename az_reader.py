# az_reader.py
from azure.identity import AzureCliCredential
from azure.mgmt.resource import ResourceManagementClient

def list_resource_groups(subscription_id: str):
    credential = AzureCliCredential()
    client = ResourceManagementClient(credential, subscription_id)
    groups = client.resource_groups.list()

    group_data = []
    for group in groups:
        resources = list(client.resources.list_by_resource_group(group.name))
        tags = group.tags if group.tags else {}

        group_data.append({
            "name": group.name,
            "location": group.location,
            "resource_count": len(resources),
            "tags": tags
        })

    return group_data
