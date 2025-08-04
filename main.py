# main.py

from dotenv import load_dotenv
import os
from azure.identity import InteractiveBrowserCredential

from rg_reader import audit_resource_groups
from network_reader import audit_virtual_networks

# Load environment variables
load_dotenv()

subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID")
tenant_id = os.getenv("AZURE_TENANT_ID")

if not subscription_id or not tenant_id:
    raise ValueError("Missing AZURE_SUBSCRIPTION_ID or AZURE_TENANT_ID in environment variables.")

# Authenticate once
credential = InteractiveBrowserCredential(tenant_id=tenant_id)

print(f"\nAuditing Azure Subscription: {subscription_id}\n")

# Run audits
audit_resource_groups(subscription_id, credential)
audit_virtual_networks(subscription_id, credential)
