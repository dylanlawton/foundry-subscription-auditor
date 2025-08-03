# main.py
import os
import json
from dotenv import load_dotenv
from az_reader import list_resource_groups
from openai import AzureOpenAI

# Load environment variables
load_dotenv()

subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID")
openai_endpoint = os.getenv("AZURE_OPENAI_ENDPOINT")
openai_key = os.getenv("AZURE_OPENAI_API_KEY")
deployment = os.getenv("AZURE_OPENAI_DEPLOYMENT")

client = AzureOpenAI(
    api_key=openai_key,
    api_version="2024-02-15-preview",
    base_url=f"{openai_endpoint}openai/deployments/{deployment}/",
)

def analyze_resource_group(group):
    # Build a prompt
    prompt = f"""
You are a cloud governance expert. Review this Azure resource group:

Name: {group['name']}
Location: {group['location']}
Resource Count: {group['resource_count']}
Tags: {json.dumps(group['tags'])}

Provide a short best practice recommendation based on:
- Naming convention
- Resource count (highlight if 0)
- Use of tags
- Whether this aligns with Azure Landing Zone guidance
"""

    response = client.chat.completions.create(
        model=deployment,
        messages=[
            {"role": "system", "content": "You are a helpful assistant for Azure subscription governance."},
            {"role": "user", "content": prompt},
        ],
    )
    return response.choices[0].message.content.strip()

print(f"Checking resource groups in subscription: {subscription_id}\n")

group_data = list_resource_groups(subscription_id)

for group in group_data:
    print(f"Resource Group: {group['name']}")
    print(f"  Location: {group['location']}")
    print(f"  Resource Count: {group['resource_count']}")
    print(f"  Tags: {json.dumps(group['tags'], indent=2)}")

    ai_summary = analyze_resource_group(group)
    print(f"  AI Recommendation: {ai_summary}\n")
