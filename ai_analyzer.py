# ai_analyzer.py

import os
from openai import AzureOpenAI

# Store client and deployment as globals (but don't initialize yet)
client = None
deployment = None

def _ensure_client():
    global client, deployment
    if client is None:
        api_key = os.getenv("AZURE_OPENAI_API_KEY")
        endpoint = os.getenv("AZURE_OPENAI_ENDPOINT")
        deployment = os.getenv("AZURE_OPENAI_DEPLOYMENT")

        if not api_key or not endpoint or not deployment:
            raise ValueError("OpenAI credentials or deployment not configured in environment variables.")

        client = AzureOpenAI(
            api_key=api_key,
            api_version="2024-02-15-preview",
            azure_endpoint=endpoint
        )

def analyze_resource_group(group):
    _ensure_client()

    prompt = (
        f"You are an expert in Azure architecture and governance. "
        f"Evaluate whether the following Azure resource group follows best practices or good practices.\n\n"
        f"Name: {group['name']}\n"
        f"Location: {group['location']}\n"
        f"Resource Count: {group['resource_count']}\n"
        f"Tags: {group['tags']}\n\n"
        f"Please include in your summary:\n"
        f"- If the name uses a good or best practice naming convention\n"
        f"- Whether the tag usage is appropriate or lacking\n"
        f"- If the resource count suggests this is a live or staging group\n"
        f"- Any governance recommendations based on the above\n"
        f"Keep your summary concise and clear."
    )

    return _call_openai(prompt)

def analyze_virtual_network(vnet):
    _ensure_client()

    prompt = (
        f"You are an Azure networking expert. Analyze the following virtual network configuration:\n\n"
        f"Name: {vnet['name']}\n"
        f"Location: {vnet['location']}\n"
        f"Address Space: {vnet['address_space']}\n\n"
        f"Please include in your summary:\n"
        f"- If the name follows Azure naming conventions\n"
        f"- Whether the address space looks typical or overly broad\n"
        f"- Any governance, security, or segmentation considerations\n"
        f"- Is this typical of good/best practice in enterprise Azure networking\n"
        f"Keep your feedback concise and clear."
    )

    return _call_openai(prompt)

def _call_openai(prompt):
    response = client.chat.completions.create(
        model=deployment,
        messages=[
            {"role": "system", "content": "You are an expert in Azure architecture, networking, and governance."},
            {"role": "user", "content": prompt}
        ]
    )
    return response.choices[0].message.content.strip()
