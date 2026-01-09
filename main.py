# main.py

from dotenv import load_dotenv
import os
import tempfile
from datetime import datetime, timezone
from azure.identity import InteractiveBrowserCredential

from rg_reader import get_rg_details
from network_reader import get_network_details
from vm_reader import get_vm_details
from storage_reader import get_storage_details
from subscription_resources import audit_subscription_resources
from governance_security_cost_reader import get_governance_security_cost_details

from ai_analyzer import (
    set_prompt_context,
    analyze_subscription_resources_overview,
    describe_resource_types,
    analyze_network_section,
    analyze_rg_section,
    analyze_vm_section,
    analyze_storage_section,
    analyze_governance_security_cost_section,
)

import sys
import warnings


# ============================
# Console output helpers
# ============================

def _line(label: str, result: str, note: str = "") -> None:
    # Example: "Inventory:   OK (ARM fallback...)"
    msg = f"{label:<12} {result}"
    if note:
        msg += f" {note}"
    print(msg)


def _is_sdk_missing(note: str) -> bool:
    n = (note or "").lower()
    return (
        "sdk not available" in n
        or "sdk not installed" in n
        or "no module named" in n
        or "module not found" in n
    )


# ============================
# Helpers
# ============================

def _now_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _file_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


def _safe_sub_id(sub_id: str) -> str:
    return sub_id.replace("/", "_")


def _ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def _html_escape(s: str) -> str:
    return (
        (s or "")
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def _write_text(path: str, text: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def _fmt_money(x) -> str:
    if x is None:
        return "None"
    try:
        return f"{float(x):.2f}"
    except Exception:
        return str(x)


# ============================
# HTML sections
# ============================

def _render_gsc_section(ai_text: str, gsc_data: dict) -> str:
    """
    Governance/Security/Cost section.

    IMPORTANT CHANGE:
    - Removed "Top cost drivers" rendering entirely.
    - Show a simple "Last 5 months" list (from cost['trend_3m']['months'] or similar).
    """
    if not gsc_data:
        return "<div class='section'><h2>Governance, Security &amp; Cost</h2><p class='small'>No data.</p></div>"

    sub = gsc_data.get("subscription", {}) or {}
    mg = gsc_data.get("management_group", {}) or {}
    pol = gsc_data.get("policy", {}) or {}
    cost = gsc_data.get("cost", {}) or {}
    dfd = gsc_data.get("defender", {}) or {}

    ai_html = f"<div class='ai'>{_html_escape(ai_text or '(No AI narrative)')}</div>"

    mg_path = " → ".join(mg.get("path", []) or []) or "Unknown / not returned"
    pol_count = int(pol.get("assignment_count", 0) or 0)

    # Cost: show last 5 months only (no top drivers)
    trend = cost.get("trend_3m", {}) or {}
    months = trend.get("months", []) or cost.get("months", []) or []
    months = months[-5:] if len(months) > 5 else months

    if months:
        li = []
        for m in months:
            li.append(
                f"<li><b>{_html_escape(str(m.get('month','')))}</b>: {_html_escape(_fmt_money(m.get('total')))}</li>"
            )
        cost_html = "<ul>" + "".join(li) + "</ul>"
    else:
        cost_html = "<p class='small'>No monthly cost data returned.</p>"

    defender_plans_ct = len(dfd.get("plans", []) or [])
    alerts = dfd.get("alerts_last_30d", None)
    secure_score = dfd.get("secure_score", None)

    return f"""
    <div class="section">
      <h2>Governance, Security &amp; Cost</h2>
      {ai_html}

      <p class="small"><b>Subscription</b>: <code>{_html_escape(sub.get('display_name',''))}</code>
      • <b>State</b>: {_html_escape(sub.get('state',''))}
      • <b>Tenant</b>: <code>{_html_escape(sub.get('tenant_id',''))}</code></p>

      <p class="small"><b>Management Group path</b>: {_html_escape(mg_path)}</p>
      <p class="small"><b>Policy assignments (subscription scope)</b>: {pol_count}</p>

      <p class="small"><b>Cost</b>: last 5 months (best-effort)</p>
      {cost_html}

      <p class="small"><b>Defender for Cloud</b> • Plans returned: {defender_plans_ct}
      • Alerts(best-effort): {_html_escape(str(alerts))}
      • Secure score: {_html_escape(str(secure_score))}</p>

      <p class="small">{_html_escape(str(mg.get('note','') or ''))}</p>
      <p class="small">{_html_escape(str(pol.get('note','') or ''))}</p>
      <p class="small">{_html_escape(str(cost.get('note','') or ''))}</p>
      <p class="small">{_html_escape(str(dfd.get('note','') or ''))}</p>
    </div>
    """


def _render_vm_section(ai_text: str, vm_data: dict, max_rows: int = 30) -> str:
    if not vm_data:
        return "<div class='section'><h2>Virtual Machines (detailed)</h2><p class='small'>No VM data.</p></div>"

    vms = vm_data.get("vms", [])[:max_rows]
    s = vm_data.get("summary", {}) or {}
    dsk = vm_data.get("disk_summary", {}) or {}
    vs = vm_data.get("vmss_summary", {}) or {}

    summary = (
        f"Total VMs (all): {int(s.get('total_vms_all',0))} • "
        f"Sampled: {int(s.get('total_vms',0))} • "
        f"Spot: {int(s.get('spot_vms',0))} • "
        f"AvSet-attached: {int(s.get('avset_attached_vms',0))} • "
        f"With Identity: {int(s.get('identity_vms',0))} • "
        f"VMSS: {int(vs.get('count',0))} • "
        f"Disks: {int(dsk.get('total_disks',0))} (unattached {int(dsk.get('unattached_disks',0))})"
    )

    rows = []
    for vm in vms:
        rows.append(
            "<tr>"
            f"<td><code>{_html_escape(vm.get('name',''))}</code></td>"
            f"<td>{_html_escape(vm.get('rg',''))}</td>"
            f"<td>{_html_escape(vm.get('location',''))}</td>"
            f"<td>{_html_escape(vm.get('size',''))}</td>"
            f"<td>{_html_escape(vm.get('os',''))}</td>"
            f"<td>{_html_escape(vm.get('power',''))}</td>"
            f"<td>{_html_escape(vm.get('priority',''))}</td>"
            f"<td>{_html_escape(vm.get('availability_set',''))}</td>"
            f"<td>{_html_escape(vm.get('identity_kind',''))}</td>"
            "</tr>"
        )

    table_html = (
        "<p class='small'>No VMs found.</p>"
        if not rows
        else f"""
        <table>
          <tr>
            <th style="width:22%;">VM</th>
            <th style="width:18%;">Resource Group</th>
            <th style="width:10%;">Location</th>
            <th style="width:12%;">Size</th>
            <th style="width:10%;">OS</th>
            <th style="width:10%;">Power</th>
            <th style="width:8%;">Priority</th>
            <th style="width:10%;">AvSet</th>
            <th style="width:12%;">Identity</th>
          </tr>
          {''.join(rows)}
        </table>
        """
    )

    ai_html = f"<div class='ai'>{_html_escape(ai_text or '(No AI narrative)')}</div>"

    return f"""
    <div class="section">
      <h2>Virtual Machines (detailed)</h2>
      {ai_html}
      <p class="small">{_html_escape(summary)}</p>
      {table_html}
    </div>
    """


def _render_storage_section(ai_text: str, storage_data: dict, max_rows: int = 40) -> str:
    if not storage_data:
        return "<div class='section'><h2>Storage (detailed)</h2><p class='small'>No storage data.</p></div>"

    s = storage_data.get("summary", {}) or {}
    accs = storage_data.get("accounts", [])[:max_rows]

    summary = (
        f"Accounts: {int(s.get('total_accounts',0))} • "
        f"Kinds: {s.get('kinds', {})} • "
        f"SKUs: {s.get('skus', {})} • "
        f"PE connections (total): {int(s.get('private_endpoint_accounts',0))} • "
        f"Public-allowed accounts: {int(s.get('public_allowed_accounts',0))} • "
        f"Versioning on: {int(s.get('versioning_enabled_accounts',0))} • "
        f"Static sites: {int(s.get('static_website_accounts',0))} • "
        f"Est. total used: {float(s.get('est_total_used_gb',0.0))} GB"
    )

    rows = []
    for a in accs:
        exposure = "PrivateOnly" if (
            str(a.get("public_network_access", "")).lower() == "disabled"
            and str(a.get("network_default_action", "")).lower() == "deny"
        ) else "PublicAllowed"

        rows.append(
            "<tr>"
            f"<td><code>{_html_escape(a.get('name',''))}</code></td>"
            f"<td>{_html_escape(a.get('rg',''))}</td>"
            f"<td>{_html_escape(a.get('location',''))}</td>"
            f"<td>{_html_escape(a.get('kind',''))}</td>"
            f"<td>{_html_escape(a.get('sku',''))}</td>"
            f"<td>{_html_escape(a.get('access_tier',''))}</td>"
            f"<td>{_html_escape(exposure)}</td>"
            f"<td>{int(a.get('private_endpoint_count',0))}</td>"
            f"<td>{_html_escape('Yes' if a.get('blob_versioning') else 'No')}</td>"
            f"<td>{_html_escape('Yes' if a.get('static_website') else 'No')}</td>"
            f"<td>{_html_escape(str(a.get('used_gb','')))} GB</td>"
            "</tr>"
        )

    table_html = (
        "<p class='small'>No storage accounts found.</p>"
        if not rows
        else f"""
        <table>
          <tr>
            <th style="width:18%;">Account</th>
            <th style="width:18%;">Resource Group</th>
            <th style="width:10%;">Location</th>
            <th style="width:10%;">Kind</th>
            <th style="width:10%;">SKU</th>
            <th style="width:8%;">Tier</th>
            <th style="width:10%;">Exposure</th>
            <th style="width:6%;">PEs</th>
            <th style="width:6%;">Versioning</th>
            <th style="width:6%;">Static</th>
            <th style="width:8%;">Used</th>
          </tr>
          {''.join(rows)}
        </table>
        """
    )

    ai_html = f"<div class='ai'>{_html_escape(ai_text or '(No AI narrative)')}</div>"

    return f"""
    <div class="section">
      <h2>Storage (detailed)</h2>
      {ai_html}
      <p class="small">{_html_escape(summary)}</p>
      {table_html}
    </div>
    """


def _render_network_section(ai_text: str, net_data: dict, max_rows: int = 25) -> str:
    if not net_data:
        return "<div class='section'><h2>Networking (detailed)</h2><p class='small'>No networking data.</p></div>"

    counts = (net_data.get("summary", {}) or {}).get("counts", {}) or {}
    vnets = net_data.get("vnets", [])[:max_rows]

    bullets = []
    for k in [
        "vnets",
        "vnet_gateways",
        "expressroute_circuits",
        "private_endpoints",
        "private_dns_zones",
        "nsgs",
        "route_tables",
        "application_gateways",
        "load_balancers",
        "public_ips",
        "azure_firewalls",
    ]:
        if k in counts:
            bullets.append(f"<li><b>{k.replace('_',' ').title()}</b>: {counts[k]}</li>")
    summary_ul = "<ul>" + "".join(bullets) + "</ul>"

    rows = []
    for v in vnets:
        sub_count = len(v.get("subnets", []) or [])
        rows.append(
            "<tr>"
            f"<td><code>{_html_escape(v.get('name',''))}</code></td>"
            f"<td>{_html_escape(v.get('rg',''))}</td>"
            f"<td>{_html_escape(v.get('location',''))}</td>"
            f"<td>{_html_escape(', '.join(v.get('address_space',[]) or []))}</td>"
            f"<td>{'Yes' if v.get('peered') else 'No'} ({int(v.get('peerings_count',0))})</td>"
            f"<td>{sub_count}</td>"
            f"<td>{'Yes' if v.get('has_gateway') else 'No'}</td>"
            f"<td>{'Yes' if v.get('has_firewall') else 'No'}</td>"
            "</tr>"
        )

    vnet_table = (
        "<p class='small'>No VNets found.</p>"
        if not rows
        else f"""
        <table>
          <tr>
            <th style="width:20%;">VNet</th>
            <th style="width:16%;">Resource Group</th>
            <th style="width:10%;">Location</th>
            <th>Address Space</th>
            <th style="width:10%;">Peered</th>
            <th style="width:8%;">Subnets</th>
            <th style="width:10%;">Gateway</th>
            <th style="width:10%;">Firewall</th>
          </tr>
          {''.join(rows)}
        </table>
        """
    )

    ai_html = f"<div class='ai'>{_html_escape(ai_text or '(No AI narrative)')}</div>"

    return f"""
    <div class="section">
      <h2>Networking (detailed)</h2>
      {ai_html}
      <p class="small"><b>Summary</b></p>
      {summary_ul}
      <p class="small"><b>Top VNets (first {len(vnets)} shown)</b></p>
      {vnet_table}
    </div>
    """


def _render_rg_section(ai_text: str, rg_data: dict, max_rows: int = 30) -> str:
    if not rg_data:
        return "<div class='section'><h2>Resource Groups (detailed)</h2><p class='small'>No resource group data.</p></div>"

    groups = rg_data.get("groups", [])[:max_rows]
    total = (rg_data.get("summary", {}) or {}).get("total_rgs", len(groups))

    rows = []
    for g in groups:
        rows.append(
            "<tr>"
            f"<td><code>{_html_escape(g.get('name',''))}</code></td>"
            f"<td>{_html_escape(g.get('location',''))}</td>"
            f"<td>{int(g.get('resource_count',0))}</td>"
            f"<td>{_html_escape(g.get('top_types',''))}</td>"
            f"<td>{_html_escape(g.get('tags',''))}</td>"
            "</tr>"
        )

    table_html = (
        "<p class='small'>No resource groups found.</p>"
        if not rows
        else f"""
        <table>
          <tr>
            <th style="width:26%;">Resource Group</th>
            <th style="width:12%;">Location</th>
            <th style="width:10%;">Resources</th>
            <th style="width:30%;">Top Types</th>
            <th>Tags</th>
          </tr>
          {''.join(rows)}
        </table>
        """
    )

    ai_html = f"<div class='ai'>{_html_escape(ai_text or '(No AI narrative)')}</div>"

    return f"""
    <div class="section">
      <h2>Resource Groups (detailed)</h2>
      {ai_html}
      <p class="small">Total resource groups: {int(total)}. Showing first {len(groups)}.</p>
      {table_html}
    </div>
    """


def _render_html_report(
    subscription_id: str,
    rows: list,
    per_type_notes: dict,
    ai_summary: str,
    gsc_ai: str,
    vm_ai: str,
    net_ai: str,
    rg_ai: str,
    storage_ai: str,
    gsc_data: dict,
    vm_data: dict,
    net_data: dict,
    rg_data: dict,
    storage_data: dict,
    generated_at: str,
) -> str:
    safe_sub = _html_escape(subscription_id)
    ai_html = _html_escape(ai_summary or "(No AI summary)")

    inv_tr = []
    for r in rows:
        rtype = str(r.get("type", ""))
        rtype_disp = _html_escape(rtype)
        count = int(r.get("count", 0))
        samples = r.get("sampleNames", []) or []
        sample_text = ", ".join(samples[:5])
        narrative = per_type_notes.get(rtype.lower(), "")

        inv_tr.append(
            "<tr>"
            f"<td><code>{rtype_disp}</code></td>"
            f"<td>{count}</td>"
            f"<td>{_html_escape(sample_text)}</td>"
            f"<td class='narr'>{_html_escape(narrative)}</td>"
            "</tr>"
        )
    inv_rows = "\n".join(inv_tr) if inv_tr else "<tr><td colspan='4'>No data</td></tr>"

    gsc_section = _render_gsc_section(gsc_ai, gsc_data)
    vm_section = _render_vm_section(vm_ai, vm_data)
    storage_section = _render_storage_section(storage_ai, storage_data)
    net_section = _render_network_section(net_ai, net_data)
    rg_section = _render_rg_section(rg_ai, rg_data)

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Azure Subscription Overview – {safe_sub}</title>
<style>
body {{ font-family: Arial, sans-serif; margin:20px; line-height:1.45; }}
table {{ width:100%; border-collapse: collapse; margin-top:12px; }}
th,td {{ padding:8px; border-bottom:1px solid #ddd; vertical-align:top; }}
th {{ background:#fafafa; }}
code {{ background:#f3f3f3; padding:2px 4px; border-radius:4px; }}
.ai {{ white-space: pre-wrap; background:#fafafa; border:1px solid #e5e7eb; padding:12px; border-radius:8px; }}
td.narr {{ color:#111; }}
.small {{ color:#666; font-size:0.9em; }}
.section {{ margin-top:28px; }}
</style>
</head>
<body>

<h1>Azure Subscription Overview</h1>
<p class="small"><b>Subscription:</b> <code>{safe_sub}</code> &nbsp; • &nbsp; <b>Generated:</b> {generated_at}</p>

<h2>AI Estate Overview</h2>
<div class="ai">{ai_html}</div>

{gsc_section}

<h2>Resource Inventory</h2>
<table>
<tr>
  <th style="width:30%;">Resource Type</th>
  <th style="width:8%;">Count</th>
  <th style="width:30%;">Sample Names</th>
  <th>AI Narrative (purpose & context)</th>
</tr>
{inv_rows}
</table>

{vm_section}
{storage_section}
{net_section}
{rg_section}

<p class="small">Generated by foundry-subscription-auditor</p>

</body>
</html>"""


# ============================
# Main
# ============================

def main() -> int:
    warnings.filterwarnings("ignore", category=DeprecationWarning)
    load_dotenv()

    subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID")
    tenant_id = os.getenv("AZURE_TENANT_ID")
    SAMPLE_SIZE = int(os.getenv("SUBSCRIPTION_OVERVIEW_SAMPLE_SIZE", "5"))

    # ✅ TEMP OUTPUT DEFAULT (still overridable by OUTPUT_DIR in .env)
    default_out = os.path.join(tempfile.gettempdir(), "foundry-subscription-auditor")
    OUTPUT_DIR = os.getenv("OUTPUT_DIR") or default_out

    MAX_VNETS = int(os.getenv("DETAIL_MAX_VNETS", "25"))
    MAX_RGS = int(os.getenv("DETAIL_MAX_RGS", "30"))
    MAX_VMS = int(os.getenv("DETAIL_MAX_VMS", "30"))
    MAX_STOR = int(os.getenv("DETAIL_MAX_STORAGE", "200"))

    REPORT_SYSTEM_PROMPT = os.getenv("REPORT_SYSTEM_PROMPT")
    REPORT_ANGLE_TEXT = os.getenv("REPORT_ANGLE_TEXT")

    if not subscription_id or not tenant_id:
        print("Foundry Subscription Auditor | missing AZURE_SUBSCRIPTION_ID / AZURE_TENANT_ID")
        return 2

    print(f"Foundry Subscription Auditor | sub={subscription_id}\n")

    credential = InteractiveBrowserCredential(tenant_id=tenant_id)
    set_prompt_context(system_prompt=REPORT_SYSTEM_PROMPT, angle_text=REPORT_ANGLE_TEXT)

    _ensure_dir(OUTPUT_DIR)
    file_stamp = _file_stamp()
    safe_sub = _safe_sub_id(subscription_id)
    html_path = os.path.join(OUTPUT_DIR, f"subscription_overview_{safe_sub}_{file_stamp}.html")

    inv_ok = False
    narr_ok = False
    gov_ok = False
    cost_ok = False
    def_ok = False
    vms_ok = False
    stor_ok = False
    net_ok = False
    rg_ok = False

    rows = []
    per_type_notes = {}
    try:
        rows = audit_subscription_resources(subscription_id, credential, sample_size=SAMPLE_SIZE)
        inv_ok = True
    except Exception:
        rows = []

    try:
        per_type_notes = describe_resource_types(rows) if rows else {}
        narr_ok = True
    except Exception:
        per_type_notes = {}
        narr_ok = False

    gsc_data = {}
    try:
        gsc_data = get_governance_security_cost_details(subscription_id, tenant_id, credential)
        gov_ok = True

        cost_note = (gsc_data.get("cost", {}) or {}).get("note", "") or ""
        def_note = (gsc_data.get("defender", {}) or {}).get("note", "") or ""

        cost_ok = (not _is_sdk_missing(cost_note)) and ("failed" not in cost_note.lower())
        def_ok = (not _is_sdk_missing(def_note)) and ("failed" not in def_note.lower())
    except Exception:
        gsc_data = {}
        gov_ok = False
        cost_ok = False
        def_ok = False

    vm_data = {}
    storage_data = {}
    net_data = {}
    rg_data = {}

    try:
        vm_data = get_vm_details(subscription_id, credential, max_vms=MAX_VMS)
        vms_ok = True
    except Exception:
        vm_data = {}
        vms_ok = False

    try:
        storage_data = get_storage_details(subscription_id, credential, max_accounts=MAX_STOR)
        stor_ok = True
    except Exception:
        storage_data = {}
        stor_ok = False

    try:
        net_data = get_network_details(subscription_id, credential, max_vnets=MAX_VNETS)
        net_ok = True
    except Exception:
        net_data = {}
        net_ok = False

    try:
        rg_data = get_rg_details(subscription_id, credential, max_groups=MAX_RGS)
        rg_ok = True
    except Exception:
        rg_data = {}
        rg_ok = False

    try:
        if rows:
            ai_summary = analyze_subscription_resources_overview({
                "subscription_id": subscription_id,
                "types": rows,
                "per_type_notes": per_type_notes,
            })
        else:
            ai_summary = "(No inventory data returned. Check ARG or RBAC permissions.)"
    except Exception as e:
        ai_summary = f"(AI summary unavailable: {e})"

    try:
        gsc_ai = analyze_governance_security_cost_section(gsc_data) if gsc_data else "(No governance/security/cost data to summarise.)"
    except Exception as e:
        gsc_ai = f"(Governance/Security/Cost AI narrative unavailable: {e})"

    try:
        vm_ai = analyze_vm_section(vm_data) if vm_data else "(No VM data to summarise.)"
    except Exception as e:
        vm_ai = f"(VM AI narrative unavailable: {e})"

    try:
        storage_ai = analyze_storage_section(storage_data) if storage_data else "(No storage data to summarise.)"
    except Exception as e:
        storage_ai = f"(Storage AI narrative unavailable: {e})"

    try:
        net_ai = analyze_network_section(net_data) if net_data else "(No networking data to summarise.)"
    except Exception as e:
        net_ai = f"(Networking AI narrative unavailable: {e})"

    try:
        rg_ai = analyze_rg_section(rg_data) if rg_data else "(No resource group data to summarise.)"
    except Exception as e:
        rg_ai = f"(RG AI narrative unavailable: {e})"

    report_html = _render_html_report(
        subscription_id, rows, per_type_notes,
        ai_summary, gsc_ai, vm_ai, net_ai, rg_ai, storage_ai,
        gsc_data, vm_data, net_data, rg_data, storage_data,
        _now_stamp()
    )
    _write_text(html_path, report_html)

    _line("Inventory:", "OK" if inv_ok else "FAIL", "(ARM fallback if ARG unavailable)" if inv_ok else "")
    _line("Narratives:", "OK" if narr_ok else "FAIL")

    cost_status = "OK" if cost_ok else "SKIP (SDK)" if _is_sdk_missing((gsc_data.get("cost", {}) or {}).get("note", "")) else "WARN"
    def_status = "OK" if def_ok else "SKIP (SDK)" if _is_sdk_missing((gsc_data.get("defender", {}) or {}).get("note", "")) else "WARN"

    _line("Governance:", "OK" if gov_ok else "FAIL", f"| Cost: {cost_status} | Defender: {def_status}")

    _line(
        "Details:",
        "OK" if (vms_ok and stor_ok and net_ok and rg_ok) else "PARTIAL",
        f"(VMs={'OK' if vms_ok else 'FAIL'}, Storage={'OK' if stor_ok else 'FAIL'}, Network={'OK' if net_ok else 'FAIL'}, RGs={'OK' if rg_ok else 'FAIL'})"
    )
    print("")
    _line("Report:", "OK", html_path)

    overall_ok = inv_ok and narr_ok and gov_ok and vms_ok and stor_ok and net_ok and rg_ok
    print(f"Result:      {'SUCCESS ✔' if overall_ok else 'DONE (check WARN/FAIL)'}")

    return 0 if overall_ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
