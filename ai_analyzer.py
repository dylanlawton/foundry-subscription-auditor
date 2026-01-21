# ai_analyzer.py

import os
from typing import Optional
from contextvars import ContextVar
from openai import AzureOpenAI

# Store client and deployment as globals (safe to share)
client = None
deployment = None

# Default prompt context (can be overridden by the caller)
DEFAULT_SYSTEM_PROMPT = (
    "You are an expert in Azure architecture, networking, and governance. "
    "You write concise, executive-friendly summaries with concrete, defensible inferences."
)

# Thread-safe per-run overrides via context vars
_SYSTEM_PROMPT_OVERRIDE: ContextVar[Optional[str]] = ContextVar("_SYSTEM_PROMPT_OVERRIDE", default=None)
_ANGLE_TEXT: ContextVar[Optional[str]] = ContextVar("_ANGLE_TEXT", default=None)


def set_prompt_context(system_prompt: Optional[str] = None, angle_text: Optional[str] = None) -> None:
    """Set (optional) prompt context for this run.

    - system_prompt: overrides the default system prompt when provided
    - angle_text: appended to every user prompt as extra steering context when provided

    Uses ContextVar so concurrent web runs don't leak prompt context between threads.
    """
    sp = system_prompt.strip() if system_prompt and system_prompt.strip() else None
    at = angle_text.strip() if angle_text and angle_text.strip() else None
    _SYSTEM_PROMPT_OVERRIDE.set(sp)
    _ANGLE_TEXT.set(at)


def _resolved_system_prompt() -> str:
    # explicit set_prompt_context() wins; otherwise allow env var; otherwise default.
    return _SYSTEM_PROMPT_OVERRIDE.get() or os.getenv("REPORT_SYSTEM_PROMPT") or DEFAULT_SYSTEM_PROMPT


def _resolved_angle_text() -> Optional[str]:
    # explicit set_prompt_context() wins; otherwise allow env var.
    return _ANGLE_TEXT.get() or (os.getenv("REPORT_ANGLE_TEXT") or None)


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
    """Send a single prompt to the configured Azure OpenAI chat deployment.

    Uses:
      - a default system prompt (or override via set_prompt_context / REPORT_SYSTEM_PROMPT)
      - optional angle text appended to the user prompt (set_prompt_context / REPORT_ANGLE_TEXT)
    """
    _ensure_client()

    system_prompt = _resolved_system_prompt()
    angle_text = _resolved_angle_text()

    user_content = prompt
    if angle_text:
        user_content = (
            f"{prompt}\n\n"
            f"---\n"
            f"Additional report angle / stakeholder context (apply consistently):\n"
            f"{angle_text}\n"
        )

    response = client.chat.completions.create(
        model=deployment,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content},
        ],
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
        f"Tags (at group level): {group['tags']}\n"
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


# ---------------- Estate-level overview (uses headlines) ----------------

def _index_counts(rows):
    idx = {}
    for r in rows:
        t = str(r.get("type", "")).lower()
        idx[t] = int(r.get("count", 0))
    return idx


def _derive_estate_metrics(rows):
    c = _index_counts(rows)
    get = lambda k: c.get(k, 0)
    vm = get("microsoft.compute/virtualmachines")
    disks = get("microsoft.compute/disks")
    nics  = get("microsoft.network/networkinterfaces")
    vmext = get("microsoft.compute/virtualmachines/extensions")
    avsets = get("microsoft.compute/availabilitysets")
    vm_estimate = max(vm, round(disks * 0.65), round(nics * 0.65), round(vmext * 0.6))
    network = {
        "vnets": get("microsoft.network/virtualnetworks"),
        "nsgs": get("microsoft.network/networksecuritygroups"),
        "route_tables": get("microsoft.network/routetables"),
        "private_endpoints": get("microsoft.network/privateendpoints"),
        "private_dns_zones": get("microsoft.network/privatednszones"),
        "private_dns_links": get("microsoft.network/privatednszones/virtualnetworklinks"),
        "vnet_gateways": get("microsoft.network/virtualnetworkgateways"),
        "expressroute": get("microsoft.network/expressroutecircuits"),
        "app_gateways": get("microsoft.network/applicationgateways"),
        "load_balancers": get("microsoft.network/loadbalancers"),
        "public_ips": get("microsoft.network/publicipaddresses"),
    }
    observability = {
        "log_analytics": get("microsoft.operationalinsights/workspaces"),
        "app_insights": get("microsoft.insights/components"),
        "workbooks": get("microsoft.insights/workbooks"),
        "action_groups": get("microsoft.insights/actiongroups"),
        "metric_alerts": get("microsoft.insights/metricalerts"),
        "activity_log_alerts": get("microsoft.insights/activitylogalerts"),
        "scheduled_query_rules": get("microsoft.insights/scheduledqueryrules"),
        "dcr": get("microsoft.insights/datacollectionrules"),
        "dce": get("microsoft.insights/datacollectionendpoints"),
    }
    protection = {
        "recovery_vaults": get("microsoft.recoveryservices/vaults"),
        "restore_point_collections": get("microsoft.compute/restorepointcollections"),
    }
    security = { "key_vaults": get("microsoft.keyvault/vaults") }
    return {
        "counts": c,
        "vm_actual": vm,
        "vm_estimate": vm_estimate,
        "signals": {"disks": disks, "nics": nics, "vm_extensions": vmext, "availability_sets": avsets},
        "network": network,
        "observability": observability,
        "protection": protection,
        "security": security,
    }


_HEADLINE_WEIGHTS = {
    "microsoft.network/expressroutecircuits": 10,
    "microsoft.network/virtualnetworkgateways": 9,
    "microsoft.network/privateendpoints": 8,
    "microsoft.network/privatednszones": 7,
    "microsoft.recoveryservices/vaults": 8,
    "microsoft.insights/metricalerts": 6,
    "microsoft.insights/scheduledqueryrules": 6,
    "microsoft.insights/activitylogalerts": 5,
    "microsoft.insights/workbooks": 4,
    "microsoft.operationalinsights/workspaces": 7,
    "microsoft.compute/virtualmachines": 8,
    "microsoft.compute/disks": 7,
    "microsoft.network/networksecuritygroups": 6,
    "microsoft.network/virtualnetworks": 5,
    "microsoft.apimanagement/service": 7,
    "microsoft.containerregistry/registries": 6,
    "microsoft.containerservice/managedclusters": 8,
    "microsoft.app/containerapps": 6,
    "microsoft.eventhub/namespaces": 6,
    "microsoft.servicebus/namespaces": 6,
    "microsoft.applicationinsights/components": 6,
}


def _score_headline(rtype: str, count: int) -> float:
    from math import log10
    base = _HEADLINE_WEIGHTS.get(rtype.lower(), 1)
    if count <= 0:
        return 0.0
    return base * (1 + log10(max(1, count)))


def _build_headline_snippets(rows, per_type_notes, max_items=10):
    scored = []
    for r in rows:
        rtype = str(r.get("type", "")).lower()
        count = int(r.get("count", 0))
        note = per_type_notes.get(rtype, "")
        score = _score_headline(rtype, count)
        if score > 0 and note:
            scored.append((score, rtype, count, note))
    scored.sort(reverse=True, key=lambda x: x[0])
    top = scored[:max_items]
    lines = [f"- {t} ({c}): {note}" for _, t, c, note in top]
    return "\n".join(lines)


def analyze_subscription_resources_overview(payload: dict) -> str:
    _ensure_client()
    rows = payload.get("types", []) or []
    sub_id = payload.get("subscription_id", "<unknown>")
    per_type_notes = payload.get("per_type_notes", {}) or {}
    d = _derive_estate_metrics(rows)
    vm_actual = d["vm_actual"]; vm_est = d["vm_estimate"]
    n = d["network"]; o = d["observability"]
    headlines = _build_headline_snippets(rows, per_type_notes, max_items=10)
    compact = (
        f"Subscription: {sub_id}\n"
        f"VMs(listed)={vm_actual}, VMs(estimated)≈{vm_est}; Disks={d['signals']['disks']}, NICs={d['signals']['nics']}.\n"
        f"VNets={n['vnets']}, NSGs={n['nsgs']}, PEs={n['private_endpoints']}, PrivDNS={n['private_dns_zones']}, "
        f"GW={n['vnet_gateways']}, ER={n['expressroute']}, LB={n['load_balancers']}, PIPs={n['public_ips']}.\n"
        f"LA={o['log_analytics']}, AppInsights={o['app_insights']}, Workbooks={o['workbooks']}.\n\n"
        f"Candidate headlines (rewrite into prose; do NOT bullet):\n{headlines}"
    )
    prompt = f"""
Write 2–3 concise paragraphs explaining what this Azure subscription likely hosts and how it operates.
Use the numeric context to ground statements. Weave in only meaningful headlines (ER, VPN GWs, PEs/PrivDNS,
RSVs/backup posture, large alert volumes, AKS/APIM/events, etc.). Avoid lists; cohesive prose only.

Context:
{compact}
"""
    return _call_openai(prompt)


# ---------------- Per-type narrative (for the main table) ----------------

_TYPE_HINTS = {
    "microsoft.compute/virtualmachines": "Compute workloads running on IaaS VMs (apps, infra roles, or legacy services).",
    "microsoft.compute/virtualmachines/extensions": "VM agents/extensions for management, monitoring, backup or custom scripts.",
    "microsoft.compute/disks": "Managed OS/data disks; volume roughly correlates with VM estate size.",
    "microsoft.network/networkinterfaces": "NICs for VMs and appliances; useful proxy for VM count.",
    "microsoft.compute/availabilitysets": "Fault/UD domain grouping for higher VM availability.",
    "microsoft.compute/restorepointcollections": "Restore points for backup/ASR; indicates protection posture.",
    "microsoft.network/virtualnetworks": "Foundational network segmentation for workloads.",
    "microsoft.network/networksecuritygroups": "Traffic filtering at subnet/NIC; enforce microsegmentation.",
    "microsoft.network/routetables": "Custom routing (NVA/firewall hops, hub/spoke control).",
    "microsoft.network/virtualnetworkgateways": "VPN/ER gateways for site connectivity or P2S.",
    "microsoft.network/expressroutecircuits": "Private connectivity to on-prem / partners.",
    "microsoft.network/loadbalancers": "Layer-4 load distribution across VM backends.",
    "microsoft.network/applicationgateways": "Layer-7 gateway/WAF for HTTP(S) apps.",
    "microsoft.network/publicipaddresses": "Public ingress/egress; internet exposure points.",
    "microsoft.network/privateendpoints": "Private access to PaaS via Private Link; reduces exposure.",
    "microsoft.network/privatednszones": "Name resolution for Private Link endpoints.",
    "microsoft.network/privatednszones/virtualnetworklinks": "DNS links wiring VNets to Private DNS zones.",
    "microsoft.operationalinsights/workspaces": "Log Analytics workspaces for centralised logs/metrics.",
    "microsoft.insights/components": "Application Insights for app telemetry & availability.",
    "microsoft.insights/metricalerts": "Metric-based alerts (CPU, latency, queue depth, etc.).",
    "microsoft.insights/scheduledqueryrules": "Log alert rules; higher counts can mean mature monitoring or noisy alerting.",
    "microsoft.recoveryservices/vaults": "Backup vaults for IaaS workloads; indicates protection baseline.",
    "microsoft.keyvault/vaults": "Secrets/keys/certs; should usually be private-access and RBAC controlled.",
}


def _hint_for_type(rtype: str) -> str:
    return _TYPE_HINTS.get((rtype or "").lower(), "")


def describe_resource_types(rows: list) -> dict:
    """
    Create an AI narrative per resource type row:
      { "microsoft.compute/virtualmachines": "Likely ...", ... }
    """
    _ensure_client()
    out = {}
    for r in rows or []:
        rtype = str(r.get("type", "")).lower()
        count = int(r.get("count", 0))
        samples = r.get("sampleNames", []) or []
        hint = _hint_for_type(rtype)

        sample_txt = ", ".join(samples[:5]) if samples else ""
        prompt = f"""
In 1–2 sentences, explain what the Azure resource type below likely represents in an enterprise subscription,
and what its presence/count implies. Keep it concrete and non-generic.

Resource type: {rtype}
Count: {count}
Example names: {sample_txt}
Optional hint (use if helpful, but do not repeat verbatim): {hint}
"""
        try:
            out[rtype] = _call_openai(prompt)
        except Exception as e:
            out[rtype] = f"(AI note unavailable: {e})"
    return out


# ---------------- Section summaries (VM/Storage/Network/RG) ----------------

def analyze_vm_section(vm_data: dict) -> str:
    _ensure_client()
    s = vm_data.get("summary", {}) or {}
    d = vm_data.get("disk_summary", {}) or {}
    vs = vm_data.get("vmss_summary", {}) or {}
    prompt = f"""
Summarise this Azure VM estate in 1–2 short paragraphs. Focus on governance signals and optimisation opportunities.
Be factual and grounded in the numbers; no bullet lists.

VM summary:
- Total VMs (all): {s.get('total_vms_all')}
- Sampled: {s.get('total_vms')}
- OS split (sample): {s.get('os_counts')}
- Top sizes (sample): {s.get('size_top')}
- Power states (sample): {s.get('power_counts')}
- Spot VMs (sample): {s.get('spot_vms')}
- Availability-set attached VMs (sample): {s.get('avset_attached_vms')}
- VMs with Managed Identity (sample): {s.get('identity_vms')}
- VMSS count: {vs.get('count')}
- Disks total: {d.get('total_disks')}, Unattached: {d.get('unattached_disks')}
"""
    return _call_openai(prompt)


def analyze_storage_section(storage_data: dict) -> str:
    _ensure_client()
    s = storage_data.get("summary", {}) or {}
    prompt = f"""
Summarise this Azure Storage estate in 1–2 short paragraphs. Emphasise security posture, exposure risk,
and operational hygiene. Ground statements in the metrics; no bullet lists.

Storage summary:
- Total accounts: {s.get('total_accounts')}
- Kinds: {s.get('kinds')}
- SKUs: {s.get('skus')}
- Private endpoint connections (accounts total): {s.get('private_endpoint_accounts')}
- Public-allowed accounts: {s.get('public_allowed_accounts')}
- Versioning enabled accounts: {s.get('versioning_enabled_accounts')}
- Static website accounts: {s.get('static_website_accounts')}
- Estimated total used GB: {s.get('est_total_used_gb')}
"""
    return _call_openai(prompt)


def analyze_network_section(net_data: dict) -> str:
    _ensure_client()
    counts = net_data.get("summary", {}).get("counts", {}) or {}
    prompt = f"""
Summarise this Azure networking footprint in 1–2 short paragraphs. Focus on connectivity patterns,
segmentation maturity, private access adoption, and internet exposure signals. No bullet lists.

Network counts:
{counts}
"""
    return _call_openai(prompt)


def analyze_rg_section(rg_data: dict) -> str:
    _ensure_client()
    total = (rg_data.get("summary", {}) or {}).get("total_rgs")
    groups = rg_data.get("groups", []) or []
    top_samples = []
    for g in groups[:8]:
        top_samples.append({
            "name": g.get("name"),
            "location": g.get("location"),
            "resource_count": g.get("resource_count"),
            "top_types": g.get("top_types"),
            "tags": g.get("tags"),
        })
    prompt = f"""
Summarise resource group hygiene in 1–2 short paragraphs. Comment on naming, tagging consistency,
and whether the grouping pattern suggests clear ownership or sprawl. No bullet lists.

Total RGs: {total}
Sample RGs (first {len(top_samples)}):
{top_samples}
"""
    return _call_openai(prompt)


# ---------------- Governance/Security/Cost summary ----------------

def analyze_governance_security_cost_section(gsc_data: dict) -> str:
    _ensure_client()
    prompt = f"""
Summarise the governance, security posture, and cost signals for this Azure subscription in 2–3 concise paragraphs.

Focus on:
- Governance maturity (management group alignment, policy assignment coverage and enforcement posture)
- Security posture (Defender plans, secure score if available, alerts signal/noise)
- Cost signals (last 5 months totals, trend direction, any obvious anomalies)
- Practical target-state recommendations and a short set of work packages (decision-oriented, HLD tone)

Be grounded in the provided data. If a field is missing due to permissions, explicitly state that.

Data:
{gsc_data}
"""
    return _call_openai(prompt)
