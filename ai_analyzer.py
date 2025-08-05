import os
from openai import AzureOpenAI

# Store client and deployment as globals
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

def _call_openai(prompt):
    response = client.chat.completions.create(
        model=deployment,
        messages=[
            {"role": "system", "content": "You are an expert in Azure architecture, networking, and governance."},
            {"role": "user", "content": prompt}
        ]
    )
    return response.choices[0].message.content.strip()


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


def analyze_virtual_network_detailed(vnet_details):
    _ensure_client()

    subnet_details = "\n".join([
        f"    - {sn['name']}: NSG = {sn['nsg']}, UDR = {sn['udr']}"
        for sn in vnet_details['subnets']
    ]) or "None"

    prompt = (
        f"Analyze this Azure Virtual Network configuration for best practices and governance:\n\n"
        f"Name: {vnet_details['name']}\n"
        f"Location: {vnet_details['location']}\n"
        f"Address Space: {vnet_details['address_space']}\n"
        f"Peered: {vnet_details['peered']}\n"
        f"Subnets:\n{subnet_details}\n"
        f"Has Azure Firewall: {vnet_details['has_firewall']}\n"
        f"Has ExpressRoute: {vnet_details['expressroute']}\n"
        f"Has Gateway: {vnet_details['has_gateway']}\n"
        f"Site-to-Site VPN: {vnet_details['site_to_site_vpn']}\n\n"
        f"Please comment on:\n"
        f"- Naming convention and address space size\n"
        f"- Whether NSGs and UDRs are appropriately applied\n"
        f"- Whether segmentation, routing, and peering follow best practice\n"
        f"- Whether the presence or absence of ExpressRoute, Gateway, or Firewall aligns with good enterprise design\n"
        f"- Any risks or recommendations for improvement\n"
        f"Provide a clear and concise summary."
    )

    return _call_openai(prompt)
