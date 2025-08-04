# rg_reader.py

from azure.mgmt.resource import ResourceManagementClient
from ai_analyzer import analyze_resource_group

def audit_resource_groups(subscription_id, credential):
    client = ResourceManagementClient(credential, subscription_id)
    groups = client.resource_groups.list()

    print("Auditing Resource Groups:\n")

    for g in groups:
        # Count all resources in this resource group
        resources = list(client.resources.list_by_resource_group(g.name))
        resource_count = len(resources)

        group_info = {
            "name": g.name,
            "location": g.location,
            "tags": g.tags or {},
            "resource_count": resource_count
        }

        # Print basic info
        print(f"Resource Group: {group_info['name']}")
        print(f"  Location: {group_info['location']}")
        print(f"  Resource Count: {group_info['resource_count']}")
        print(f"  Tags: {group_info['tags']}")

        # AI Analysis
        ai_summary = analyze_resource_group(group_info)
        print(f"  AI Analysis: {ai_summary}\n")
