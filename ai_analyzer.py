# ai_analyzer.py

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

def _call_openai(prompt: str) -> str:
    response = client.chat.completions.create(
        model=deployment,
        messages=[
            {"role": "system", "content": "You are an expert in ... write concise, executive-friendly summaries with concrete, defensible inferences."},
            {"role": "user", "content": prompt}
        ]
    )
    return response.choices[0].message.content.strip()

# ---------------- Existing analyzers (RG + VNET) ----------------

def analyze_resource_group(group: dict) -> str:
    _ensure_client()
    prompt = (
        f"You are an expert in Azure architecture and governance. "
        f"Evaluate whether the following Azure resource group follows best practices or good practices.\n\n"
        f"Name: {group['name']}\n"
        f"Location: {group['location']}\n"
        f"Resource Count: {group['resource_count']}\n"
        f"Tags: {group.get('tags', {})}\n"
        f"Resources by Region: {group.get('resource_regions', {})}\n"
        f"Resources by Type: {group.get('resource_types', {})}\n"
        f"Tag Usage Across Resources: {group.get('tag_usage', {})}\n\n"
        f"Please include in your summary:\n"
        f"- If the name uses a good or best practice naming convention\n"
        f"- Whether the tag usage (both at group and resource level) is appropriate and consistent\n"
        f"- If the resource types suggest an unusual or inconsistent grouping\n"
        f"- If resources are spread across inconsistent regions, or if that's expected\n"
        f"- Any anomalies, governance issues, or optimisation opportunities\n"
        f"Keep your summary clear, concise, and actionable."
    )
    return _call_openai(prompt)

def analyze_virtual_network_detailed(vnet_details: dict) -> str:
    _ensure_client()
    name = vnet_details.get("name","")
    rg = vnet_details.get("resource_group","")
    location = vnet_details.get("location","")
    addr = ", ".join(vnet_details.get("address_space",[]) or [])
    subnets = vnet_details.get("subnets",[])
    peered = "Yes" if vnet_details.get("peered") else "No"
    peer_count = vnet_details.get("peerings_count",0)
    has_gw = "Yes" if vnet_details.get("has_gateway") else "No"
    has_fw = "Yes" if vnet_details.get("has_firewall") else "No"

    prompt = (
        "You are an expert Azure network architect. Provide a tight, 1–2 paragraph analysis of the following VNet.\n\n"
        f"VNet Name: {name}\n"
        f"Resource Group: {rg}\n"
        f"Location: {location}\n"
        f"Address Space: {addr}\n"
        f"Subnets: {len(subnets)}\n"
        f"Peered: {peered} (Peerings: {peer_count})\n"
        f"Virtual Network Gateway: {has_gw}\n"
        f"Azure Firewall: {has_fw}\n\n"
        "Guidance:\n"
        "- Comment on address space sizing, subnetting discipline (e.g., segregation for tiers / zones), and route/security posture.\n"
        "- If peered, infer hub/spoke or flat mesh patterns, and any potential transitive routing or DNS concerns.\n"
        "- If gateway/firewall missing or present, infer likely connectivity or security posture.\n"
        "- Avoid bullets; produce cohesive prose, actionable for a design review."
    )
    return _call_openai(prompt)

def analyze_virtual_networks_overview(vnets_summary: dict) -> str:
    _ensure_client()
    total = vnets_summary.get("total_vnets", 0)
    subnets = vnets_summary.get("total_subnets", 0)
    peered = vnets_summary.get("peered_vnets", 0)
    gw = vnets_summary.get("vnets_with_gateway", 0)
    fw = vnets_summary.get("vnets_with_firewall", 0)
    regions = ", ".join(vnets_summary.get("regions", [])[:8])

    prompt = (
        "Write a short executive overview of the networking estate.\n\n"
        f"Total VNets: {total}, Total Subnets: {subnets}\n"
        f"Peered VNets: {peered}, VNets with Gateways: {gw}, VNets with Azure Firewall: {fw}\n"
        f"Regions: {regions}\n\n"
        "Guidance:\n"
        "- Comment on likely topology (hub/spoke, flat, or mixed) and segmentation maturity.\n"
        "- Note any high-level risks or natural next steps for hygiene (address-space planning, peering standardisation, firewall centralisation, etc.).\n"
        "- Avoid bullets; concise prose."
    )
    return _call_openai(prompt)

# ---------------- Inventory/Subscription analyzers ----------------

def analyze_subscription_resources_overview(stats: dict) -> str:
    _ensure_client()
    total = stats.get("total",0)
    regions = ", ".join(stats.get("regions",[])[:8])
    types = ", ".join(stats.get("top_types",[])[:8])
    tag_cov = stats.get("tag_coverage",{})

    prompt = (
        "Create an executive summary of the subscription asset inventory based on Azure Resource Graph findings.\n\n"
        f"Total resources: {total}\n"
        f"Regions represented: {regions}\n"
        f"Top resource types: {types}\n"
        f"Tag coverage: {tag_cov}\n\n"
        "Guidance:\n"
        "- Interpret whether the environment looks consolidated or fragmented (by region/type).\n"
        "- Comment on tagging maturity and lifecycle separation hints (dev/test/prod naming or RG splits).\n"
        "- Call out hygiene/standardisation opportunities.\n"
        "- No bullet lists; tight cohesive prose."
    )
    return _call_openai(prompt)

def describe_resource_types(type_rows: list) -> str:
    _ensure_client()
    preview = "\n".join([f"- {r['type']}: {r['count']} (sample: {', '.join(r.get('samples', [])[:3])})" for r in type_rows[:10]])
    prompt = (
        "Write a short descriptive note on the following Azure resource type distribution.\n\n"
        f"{preview}\n\n"
        "Guidance: Focus on what these types suggest about the workload mix (IaaS/PaaS), and any common pitfalls or optimisations. "
        "Avoid long lists; cohesive narrative only."
    )
    return _call_openai(prompt)

# ---------------- VM / Storage / RG overviews ----------------

def analyze_vm_section(vm_data: dict) -> str:
    _ensure_client()
    vms = vm_data.get("vms", [])
    regions = list({v.get("location","") for v in vms})
    sizes = list({v.get("size","") for v in vms})
    spot = sum(1 for v in vms if v.get("priority","").lower()=="spot")
    gen2 = sum(1 for v in vms if v.get("hyperv_gen","").lower()=="v2")
    zrs = sum(1 for v in vms if v.get("zone",""))

    prompt = (
        "Provide a compact, 1–2 paragraph overview of the VM estate suitable for a CIO dashboard.\n\n"
        f"VMs: {len(vms)} | Regions: {', '.join(regions[:8])} | Common sizes: {', '.join(sizes[:8])}\n"
        f"Spot VMs: {spot} | Gen2: {gen2} | Zonal placement count: {zrs}\n\n"
        "Guidance: comment on consolidation, resiliency (zones), modernisation (Gen2), and cost levers (Spot, right-sizing). "
        "Avoid bullets."
    )
    return _call_openai(prompt)

def analyze_storage_section(storage_data: dict) -> str:
    _ensure_client()
    accts = storage_data.get("accounts", [])
    s = storage_data.get("summary", {}) or {}
    kinds = s.get("kinds", {})
    skus = s.get("skus", {})
    pe_total = s.get("private_endpoint_accounts", 0)
    public_allowed = s.get("public_allowed_accounts", 0)
    ver_on = s.get("versioning_enabled_accounts", 0)
    web_on = s.get("static_website_accounts", 0)
    est_gb = s.get("est_total_used_gb", 0.0)

    prompt = (
        "Write an executive-summary style 1–2 paragraph assessment of the Azure Storage estate.\n\n"
        f"Accounts: {len(accts)}\n"
        f"Kinds: {kinds}\n"
        f"SKUs: {skus}\n"
        f"Private Endpoint accounts (total): {pe_total}\n"
        f"Public allowed accounts (approx): {public_allowed}\n"
        f"Versioning enabled accounts: {ver_on}\n"
        f"Static website accounts: {web_on}\n"
        f"Estimated total used (GB): {est_gb}\n\n"
        "Guidance: infer workload mix (blob-heavy, file-heavy, premium vs standard), exposure posture (public/PE), "
        "and governance signals (versioning, immutability). Avoid lists."
    )
    return _call_openai(prompt)

def analyze_rg_section(rg_data: dict) -> str:
    _ensure_client()
    rgs = rg_data.get("rgs", [])
    regions = list({r.get("location","") for r in rgs})
    prompt = (
        "Summarise the Resource Group layout in 1–2 paragraphs.\n\n"
        f"RGs: {len(rgs)} | Regions: {', '.join(regions[:8])}\n\n"
        "Comment on lifecycle separation (dev/test/prod), naming hygiene, and governance clues (policies/tags)."
    )
    return _call_openai(prompt)

def analyze_network_section(net_data: dict) -> str:
    _ensure_client()
    vnets = net_data.get("vnets", [])
    subnets = sum(len(v.get("subnets",[]) or []) for v in vnets)
    regions = list({v.get("location","") for v in vnets})
    peered = sum(1 for v in vnets if v.get("peered"))
    gw = sum(1 for v in vnets if v.get("has_gateway"))
    fw = sum(1 for v in vnets if v.get("has_firewall"))

    prompt = (
        "Write a brief cohesive overview of networking (no bullet points).\n\n"
        f"VNets: {len(vnets)} | Subnets: {subnets} | Peered: {peered} | With GW: {gw} | With Firewall: {fw}\n"
        f"Regions: {', '.join(regions[:8])}\n\n"
        "Comment on segmentation, hub/spoke vs flat, and likely next steps for hygiene."
    )
    return _call_openai(prompt)

# --- SQL estate analysis (appended by assistant) ---
def analyze_sql_section(sql_data: dict) -> str:
    """Summarise the Azure SQL estate in 1–2 concise paragraphs."""
    _ensure_client()
    if not sql_data:
        return "(No SQL data.)"

    s = sql_data.get("summary", {}) or {}
    servers = int(s.get("servers", 0))
    dbs = int(s.get("databases", 0))
    pools = int(s.get("elastic_pools", 0))
    mis = int(s.get("managed_instances", 0))
    mi_dbs = int(s.get("mi_databases", 0))
    pna_public = int(s.get("public_access_servers", 0))
    pe_ct = int(s.get("private_endpoint_servers", 0))
    aud = int(s.get("auditing_enabled_servers", 0))
    tp = int(s.get("threat_protection_enabled_servers", 0))
    vcores = int(s.get("vcores_total_approx", 0))
    dtus = int(s.get("dtu_total_approx", 0))

    prompt = f"""
You are an Azure data platform architect. Write 1–2 concise paragraphs characterising the Azure SQL footprint.

Context:
- Servers={servers}, Databases={dbs}, ElasticPools={pools}, ManagedInstances={mis}, MIDatabases={mi_dbs}
- Exposure: PublicAccessServers={pna_public}, PrivateEndpointConnections(total)={pe_ct}
- Security/Governance: AuditingEnabledServers={aud}, ThreatProtectionEnabledServers={tp}
- Capacity (approx): vCores={vcores}, DTUs={dtus}

Guidance:
- Infer whether the estate skews toward modern vCore tiers vs legacy DTU tiers.
- Note exposure posture (public vs private endpoints) and whether that aligns with enterprise best practice.
- Mention auditing/threat protection posture and any obvious gaps.
- Briefly call out if managed instances are present vs logical servers.
Keep it cohesive prose; avoid bullet points and repeating raw numbers verbatim.
"""
    return _call_openai(prompt)
