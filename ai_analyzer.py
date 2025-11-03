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
            {"role": "system", "content": "You are an expert in Azure architecture, networking, and governance. You write concise, executive-friendly summaries with concrete, defensible inferences."},
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
    "microsoft.insights/activitylogalerts": "Control-plane alerts (RBAC, policy, create/update/delete).",
    "microsoft.insights/scheduledqueryrules": "Log query–driven alerts (KQL).",
    "microsoft.insights/actiongroups": "Notification/automation targets for alerts (email, ITSM, webhook).",
    "microsoft.insights/workbooks": "Interactive operational dashboards in Azure Monitor.",
    "microsoft.insights/datacollectionrules": "DCRs for AMA-based data collection.",
    "microsoft.insights/datacollectionendpoints": "Endpoints used by DCRs/AMA to route telemetry.",
    "microsoft.recoveryservices/vaults": "Backup/ASR protection stores and policies.",
    "microsoft.keyvault/vaults": "Secrets/keys/certs for apps and infra.",
    "microsoft.resourcegraph/queries": "Saved KQL for inventory/ops insight.",
    "microsoft.automation/automationaccounts": "Runbooks/schedules for ops automation.",
    "microsoft.automation/automationaccounts/runbooks": "Automation scripts used by jobs/schedules.",
    "microsoft.logic/workflows": "Logic Apps for integration & remediation flows.",
    "microsoft.storage/storageaccounts": "General-purpose storage (VM disks, logs, app data, file shares).",
    "microsoft.network/networkwatchers": "Regional Network Watcher instances for diagnostics.",
    "microsoft.network/networkwatchers/flowlogs": "NSG flow logs for traffic analytics.",
    "microsoft.network/virtualwans": "VWAN hub for scalable branch connectivity.",
    "microsoft.network/virtualhubs": "VWAN hubs; centralised transit with routing.",
    "microsoft.network/p2svpngateways": "Point-to-Site VPN access for users.",
    "microsoft.migrate/*": "Azure Migrate artifacts for discovery/assessment/migration.",
    "microsoft.offazure/*": "Azure Migrate (server/VMware master/import) for lift-and-shift.",
    "microsoft.operationsmanagement/solutions": "Legacy OMS solutions (Update, Activity, VMInsights).",
    "microsoft.portal/dashboards": "Shared Azure Portal dashboards.",
    "microsoft.resources/templatespecs": "Reusable ARM/Bicep template specs (governance).",
    "microsoft.resources/templatespecs/versions": "Versioned template specs for repeatable deployments.",
    "microsoft.hybridcompute/machines": "Arc-enabled servers (non-Azure).",
    "microsoft.hybridcompute/machines/extensions": "Arc extensions (monitoring/management on hybrid).",
    "microsoft.sqlvirtualmachine/sqlvirtualmachines": "SQL IaaS extension–managed SQL VMs.",
    "microsoft.eventhub/namespaces": "Event ingestion at scale (telemetry/streaming).",
    "microsoft.alertsmanagement/smartdetectoralertrules": "AI smart detector alerts from App Insights.",
    "microsoft.devtestlab/schedules": "Auto-shutdown schedules (DevTest labs / VMs).",
    "microsoft.storagesync/storagesyncservices": "Azure File Sync management service.",
    "microsoft.managedidentity/userassignedidentities": "User-assigned identities for workloads.",
    "microsoft.visualstudio/account": "DevOps/VS subscriptions linkage.",
    "microsoft.maintenance/maintenanceconfigurations": "Pinned maintenance windows on resources.",
    "microsoft.compute/galleries": "Shared Image Gallery (SIG) for image distribution.",
    "microsoft.compute/galleries/images": "Images published in SIG.",
    "microsoft.compute/galleries/images/versions": "Versioned images in SIG.",
    "microsoft.compute/images": "Managed images (legacy or bespoke builds).",
    "microsoft.datareplication/replicationvaults": "Modern DR replication vaults.",
    "microsoft.operationalinsights/querypacks": "Saved KQL query packs for reuse.",
}

def _first_match_hint(rtype: str) -> str:
    rtype_l = rtype.lower()
    if rtype_l in _TYPE_HINTS:
        return _TYPE_HINTS[rtype_l]
    for k, v in _TYPE_HINTS.items():
        if k.endswith("/*"):
            prefix = k[:-2]
            if rtype_l.startswith(prefix):
                return v
    return ""

def _heuristic_tail(rtype: str, count: int, samples: list) -> str:
    name_blob = " ".join(samples).lower() if samples else ""
    extra = ""
    if "privatelink" in rtype or "privateendpoints" in rtype or "privatelink" in name_blob:
        extra = " Used to keep PaaS traffic on private IP space."
    elif "virtualnetworkgateways" in rtype or "p2svpn" in rtype or "vpn" in name_blob:
        extra = " Indicates site or user VPN connectivity."
    elif "expressroute" in rtype:
        extra = " Suggests private MPLS/ISP connectivity back to datacentres."
    elif "applicationgateways" in rtype or "waf" in name_blob:
        extra = " Implies HTTP(S) publishing with WAF options."
    elif "sql" in rtype or "mssql" in name_blob:
        extra = " Points to SQL workloads running on IaaS."
    elif "automation" in rtype or "runbooks" in rtype:
        extra = " Used for patching, start/stop, cleanup, or remediation."
    elif "workbooks" in rtype:
        extra = " Operations dashboards—consider consolidation."
    elif "actiongroups" in rtype:
        extra = " Notification endpoints for alerts; review for noise."
    elif "metricalerts" in rtype or "scheduledqueryrules" in rtype:
        extra = " Alert rules—check for duplication and threshold tuning."
    elif "recoveryservices/vaults" in rtype:
        extra = " Holds backup/ASR configs—verify coverage and retention."
    elif "keyvault" in rtype:
        extra = " Secrets/keys for apps; ensure RBAC and purge protection."
    elif "privatednszones" in rtype:
        extra = " Make sure zone-to-VNet links match Private Endpoints."
    elif "networksecuritygroups" in rtype or "nsg" in name_blob:
        extra = " Validate rules and ensure least-privilege."
    elif "routetables" in rtype:
        extra = " Custom routes should align with hub/spoke and NVAs."
    return extra

def describe_resource_types(rows: list) -> dict:
    out = {}
    for r in rows:
        rtype = str(r.get("type", ""))
        count = int(r.get("count", 0))
        samples = r.get("sampleNames", []) or []
        base = _first_match_hint(rtype)
        if not base:
            vendor = rtype.split("/")[0] if "/" in rtype else rtype
            base = f"{vendor} resource type."
        tail = _heuristic_tail(rtype, count, samples)
        out[rtype.lower()] = f"{base} Count ≈ {count}.{tail}"
    return out

# ---------------- NEW: AI narratives for detailed sections ----------------

def analyze_network_section(net_data: dict) -> str:
    """
    1–2 paragraphs: describe the network posture (hub/spoke hints, ER/VPN, PE/PrivDNS, NSG/UDR density),
    peering presence, and call out likely operational priorities.
    """
    _ensure_client()
    counts = net_data.get("summary", {}).get("counts", {}) if net_data else {}
    vnets = net_data.get("vnets", []) if net_data else []

    # Cheap signals for peering prevalence, gateways, firewalls, etc.
    peered = sum(1 for v in vnets if v.get("peered"))
    gateways = counts.get("vnet_gateways", 0)
    ers = counts.get("expressroute_circuits", 0)
    pes = counts.get("private_endpoints", 0)
    privdns = counts.get("private_dns_zones", 0)
    nsgs = counts.get("nsgs", 0)
    udrs = counts.get("route_tables", 0)
    firewalls = counts.get("azure_firewalls", 0)
    appgws = counts.get("application_gateways", 0)
    lbs = counts.get("load_balancers", 0)
    pips = counts.get("public_ips", 0)
    vnets_ct = counts.get("vnets", len(vnets))

    prompt = f"""
You are an Azure networking architect. Write 1–2 concise paragraphs that describe the networking posture.

Context (counts):
- VNets={vnets_ct}, PeeredVNets≈{peered}, VNetGateways={gateways}, ExpressRoute={ers}
- PrivateEndpoints={pes}, PrivateDNSZones={privdns}
- NSGs={nsgs}, UDRs={udrs}, AzureFirewalls={firewalls}
- AppGateways={appgws}, LoadBalancers={lbs}, PublicIPs={pips}

Hints:
- If ExpressRoute or VNet gateways exist, infer hybrid connectivity and likely hub/spoke.
- If many Private Endpoints & Private DNS zones, infer Private Link usage for PaaS isolation.
- If NSGs/UDRs are numerous, mention micro-segmentation and custom routing via NVAs/firewall.
- Comment briefly on Internet exposure if there are many Public IPs/App Gateways.
- Keep it crisp; no lists; a couple of tight paragraphs only.
"""
    return _call_openai(prompt)

def analyze_rg_section(rg_data: dict) -> str:
    """
    1–2 paragraphs: describe RG organization (count, spread, top types), tagging hygiene hints,
    and whether the grouping suggests env-based, app-based, or platform-based organization.
    """
    _ensure_client()
    total = rg_data.get("summary", {}).get("total_rgs", 0) if rg_data else 0
    groups = rg_data.get("groups", []) if rg_data else []

    # Simple tag signal and top-type signal
    with_tags = sum(1 for g in groups if g.get("tags") and g["tags"] != "None")
    top_types_examples = ", ".join(g.get("top_types","") for g in groups[:8] if g.get("top_types"))

    prompt = f"""
You are an Azure governance expert. Write 1–2 concise paragraphs that describe how resource groups are organised and what it implies.

Context:
- TotalRGs={total}, RGsWithAnyTags≈{with_tags}
- Examples of top resource types per RG (sampled): {top_types_examples}

Hints:
- If many RGs have tags, infer some level of tagging hygiene; otherwise call it out.
- Use top types examples to infer whether grouping is app-centric, env-centric (dev/test/prod), or platform-centric (networking/security/shared).
- Mention if high RG count likely reflects many projects or fragmentation; suggest consolidation if appropriate.
- Keep it crisp; no lists; a couple of tight paragraphs only.
"""
    return _call_openai(prompt)

def analyze_vm_section(vm_data: dict) -> str:
    """
    1–2 paragraphs: describe VM estate scale, OS split, power state posture (idle/deallocated),
    Spot usage, AvSet coverage, VMSS presence, and unattached disk risk. Keep crisp, no lists.
    """
    _ensure_client()
    if not vm_data:
        return "(No VM data.)"

    s = vm_data.get("summary", {}) or {}
    d = vm_data.get("disk_summary", {}) or {}
    vs = vm_data.get("vmss_summary", {}) or {}

    total_vms_all = int(s.get("total_vms_all", 0))
    total_vms_sample = int(s.get("total_vms", 0))
    os_counts = s.get("os_counts", {})
    size_top  = s.get("size_top", [])
    power     = s.get("power_counts", {})
    spot      = int(s.get("spot_vms", 0))
    avset_vm  = int(s.get("avset_attached_vms", 0))
    identity  = int(s.get("identity_vms", 0))
    total_disks = int(d.get("total_disks", 0))
    unattached  = int(d.get("unattached_disks", 0))
    vmss_count  = int(vs.get("count", 0))
    sample_note = s.get("sample_note", "")

    prompt = f"""
You are an Azure compute engineer. Write 1–2 concise paragraphs that characterise the VM estate.

Context:
- TotalVMs(all)={total_vms_all}, Sampled={total_vms_sample}, PowerStates(sample)={power}
- SpotVMs(sample)={spot}, AvSetAttachedVMs(sample)={avset_vm}, WithIdentity(sample)={identity}
- OSCounts(sample)={os_counts}, TopSizes(sample)={size_top}
- VMScaleSets={vmss_count}
- Disks: Total={total_disks}, Unattached={unattached}
- Note: {sample_note}

Guidance:
- Ground statements in the ALL count for overall scale; derive composition from the sample.
- If many deallocated/unknown states in the sample, mention potential optimisation (stop/deallocate, right-size).
- Comment on Spot usage, availability posture (AvSets/VMSS), and unattached disks (cost & security).
- Do not use bullet points; cohesive prose only.
"""
    return _call_openai(prompt)
