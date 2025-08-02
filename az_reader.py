from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import ResourceManagementClient

def list_resource_groups(subscription_id: str):
    credential = DefaultAzureCredential()
    client = ResourceManagementClient(credential, subscription_id)
    groups = client.resource_groups.list()
    return [g.name for g in groups]
