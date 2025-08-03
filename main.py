# main.py
from az_reader import list_resource_groups
import json

# Replace with your actual subscription ID
sub_id = "b61bf20a-1409-4e92-8675-a41b2fadb9b1"

print(f"Checking resource groups in subscription: {sub_id}\n")

group_data = list_resource_groups(sub_id)

for group in group_data:
    print(f"Resource Group: {group['name']}")
    print(f"  Location: {group['location']}")
    print(f"  Resource Count: {group['resource_count']}")
    print(f"  Tags: {json.dumps(group['tags'], indent=2)}\n")
