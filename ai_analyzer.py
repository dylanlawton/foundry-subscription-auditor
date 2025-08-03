# ai_analyzer.py

import os
from openai import AzureOpenAI

def analyze_resource_group(group):
    client = AzureOpenAI(
        api_key=os.getenv("AZURE_OPENAI_API_KEY"),
        api_version="2024-02-15-preview",
        azure_endpoint=os.getenv("AZURE_OPENAI_ENDPOINT")
    )

    deployment = os.getenv("AZURE_OPENAI_DEPLOYMENT")
    if not deployment:
        return "OpenAI deployment not configured."

    prompt = (
        f"Analyze the following Azure resource group:\n"
        f"Name: {group['name']}\n"
        f"Location: {group['location']}\n"
        f"Resource Count: {group['resource_count']}\n"
        f"Tags: {group['tags']}\n\n"
        f"Provide a short summary including:\n"
        f"- Whether the name follows best practices\n"
        f"- If the tag usage is appropriate\n"
        f"- Whether an empty group (if applicable) is a concern\n"
    )

    response = client.chat.completions.create(
        model=deployment,
        messages=[
            {"role": "system", "content": "You are an expert in Azure resource governance."},
            {"role": "user", "content": prompt}
        ]
    )

    return response.choices[0].message.content.strip()
