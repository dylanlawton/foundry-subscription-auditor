# main.py

from dotenv import load_dotenv
import os
from az_reader import list_resource_groups
from ai_analyzer import analyze_resource_group

# Load environment variables from .env file
load_dotenv()

# Get Azure subscription ID from environment
subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID")

# Confirm subscription ID is set
if not subscription_id:
    raise ValueError("AZURE_SUBSCRIPTION_ID not found in environment variables.")

print(f"Checking resource groups in subscription: {subscription_id}\n")

# Get list of resource groups
group_data = list_resource_groups(subscription_id)

# Output and analyze each group
for group in group_data:
    print(f"Resource Group: {group['name']}")
    print(f"  Location: {group['location']}")
    print(f"  Resource Count: {group['resource_count']}")
    print(f"  Tags: {group['tags']}")

    # AI-generated analysis
    ai_summary = analyze_resource_group(group)
    print(f"  AI Analysis: {ai_summary}\n")
