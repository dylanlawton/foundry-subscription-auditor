# main.py

from dotenv import load_dotenv
import os
from datetime import datetime
from azure.identity import InteractiveBrowserCredential

from rg_reader import audit_resource_groups, get_rg_details
from network_reader import audit_virtual_networks, get_network_details
from vm_reader import audit_virtual_machines, get_vm_details
from subscription_resources import audit_subscription_resources
from ai_analyzer import (
    analyze_subscription_resources_overview,
    describe_resource_types,
    analyze_network_section,
    analyze_rg_section,
    analyze_vm_section,
)

# ============================
# Helpers
# ============================

def _now_stamp() -> str:
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")

def _file_stamp() -> str:
    return datetime.utcnow().strftime("%Y%m%d-%H%M%S")

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
    with open(path, "w", encoding="utf-8") as f:
        f.write(text if text else "")

# ============================
# HTML sections
# ============================

def _render_vm_section(ai_text: str, vm_data: dict, max_rows: int = 30) -> str:
    if not vm_data:
        return "<div class='section'><h2>Virtual Machines (detailed)</h2><p class='small'>No VM data.</p></div>"

    vms = vm_data.get("vms", [])[:max_rows]
    s   = vm_data.get("summary", {}) or {}
    dsk = vm_data.get("disk_summary", {}) or {}
    vs  = vm_data.get("vmss_summary", {}) or {}

    # quick summary line
    summary = (
        f"Total VMs: {int(s.get('total_vms',0))} • "
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
            f"<td><code>{_html_escape(vm['name'])}</code></td>"
            f"<td>{_html_escape(vm['rg'])}</td>"
            f"<td>{_html_escape(vm['location'])}</td>"
            f"<td>{_html_escape(vm['size'])}</td>"
            f"<td>{_html_escape(vm['os'])}</td>"
            f"<td>{_html_escape(vm['power'])}</td>"
            f"<td>{_html_escape(vm['priority'])}</td>"
            f"<td>{_html_escape(vm['availability_set'])}</td>"
            f"<td>{_html_escape(vm['identity_kind'])}</td>"
            "</tr>"
        )
    table_html = (
        "<p class='small'>No VMs found.</p>" if not rows else
        f"""
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

def _render_network_section(ai_text: str, net_data: dict, max_rows: int = 25) -> str:
    if not net_data:
        return "<div class='section'><h2>Networking (detailed)</h2><p class='small'>No networking data.</p></div>"

    counts = net_data.get("summary", {}).get("counts", {})
    vnets = net_data.get("vnets", [])[:max_rows]

    # Summary bullets
    bullets = []
    for k in ["vnets","vnet_gateways","expressroute_circuits","private_endpoints",
              "private_dns_zones","nsgs","route_tables","application_gateways",
              "load_balancers","public_ips","azure_firewalls"]:
        if k in counts:
            bullets.append(f"<li><b>{k.replace('_',' ').title()}</b>: {counts[k]}</li>")
    summary_ul = "<ul>" + "".join(bullets) + "</ul>"

    # VNet table
    rows = []
    for v in vnets:
        sub_count = len(v.get("subnets", []) or [])
        rows.append(
            "<tr>"
            f"<td><code>{_html_escape(v['name'])}</code></td>"
            f"<td>{_html_escape(v['rg'])}</td>"
            f"<td>{_html_escape(v['location'])}</td>"
            f"<td>{_html_escape(', '.join(v.get('address_space',[]) or []))}</td>"
            f"<td>{'Yes' if v.get('peered') else 'No'} ({v.get('peerings_count',0)})</td>"
            f"<td>{sub_count}</td>"
            f"<td>{'Yes' if v.get('has_gateway') else 'No'}</td>"
            f"<td>{'Yes' if v.get('has_firewall') else 'No'}</td>"
            "</tr>"
        )
    if not rows:
        vnet_table = "<p class='small'>No VNets found.</p>"
    else:
        vnet_table = f"""
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
    total = rg_data.get("summary", {}).get("total_rgs", len(groups))

    rows = []
    for g in groups:
        rows.append(
            "<tr>"
            f"<td><code>{_html_escape(g['name'])}</code></td>"
            f"<td>{_html_escape(g['location'])}</td>"
            f"<td>{int(g.get('resource_count',0))}</td>"
            f"<td>{_html_escape(g.get('top_types',''))}</td>"
            f"<td>{_html_escape(g.get('tags',''))}</td>"
            "</tr>"
        )
    if not rows:
        table_html = "<p class='small'>No resource groups found.</p>"
    else:
        table_html = f"""
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

    ai_html = f"<div class='ai'>{_html_escape(ai_text or '(No AI narrative)')}</div>"

    return f"""
    <div class="section">
      <h2>Resource Groups (detailed)</h2>
      {ai_html}
      <p class="small">Total resource groups: {int(total)}. Showing first {len(groups)}.</p>
      {table_html}
    </div>
    """

def _render_html_report(subscription_id: str, rows: list, per_type_notes: dict,
                        ai_summary: str, vm_ai: str, net_ai: str, rg_ai: str,
                        vm_data: dict, net_data: dict, rg_data: dict,
                        generated_at: str) -> str:
    safe_sub = _html_escape(subscription_id)
    ai_html = _html_escape(ai_summary or "(No AI summary)")

    # Inventory rows
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

    vm_section  = _render_vm_section(vm_ai, vm_data)
    net_section = _render_network_section(net_ai, net_data)
    rg_section  = _render_rg_section(rg_ai, rg_data)

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
{net_section}
{rg_section}

<p class="small">Generated by foundry-subscription-auditor</p>

</body>
</html>"""

# ============================
# Main
# ============================

load_dotenv()

subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID")
tenant_id = os.getenv("AZURE_TENANT_ID")
SAMPLE_SIZE = int(os.getenv("SUBSCRIPTION_OVERVIEW_SAMPLE_SIZE", "5"))
OUTPUT_DIR = os.getenv("OUTPUT_DIR", "outputs")
MAX_VNETS = int(os.getenv("DETAIL_MAX_VNETS", "25"))
MAX_RGS   = int(os.getenv("DETAIL_MAX_RGS", "30"))
MAX_VMS   = int(os.getenv("DETAIL_MAX_VMS", "30"))

if not subscription_id or not tenant_id:
    raise ValueError("Missing AZURE_SUBSCRIPTION_ID or AZURE_TENANT_ID")

credential = InteractiveBrowserCredential(tenant_id=tenant_id)
print(f"\nAuditing Azure Subscription: {subscription_id}\n")

_ensure_dir(OUTPUT_DIR)
file_stamp = _file_stamp()
safe_sub = _safe_sub_id(subscription_id)
html_path = os.path.join(OUTPUT_DIR, f"subscription_overview_{safe_sub}_{file_stamp}.html")

# ---- Inventory ----
try:
    rows = audit_subscription_resources(subscription_id, credential, sample_size=SAMPLE_SIZE)
except Exception as e:
    print(f"[WARN] Subscription overview failed: {e}")
    rows = []

# ---- Per-type narratives ----
try:
    per_type_notes = describe_resource_types(rows)
except Exception as e:
    print(f"[WARN] Per-type narrative generation failed: {e}")
    per_type_notes = {}

# ---- Detailed data ----
try:
    vm_data = get_vm_details(subscription_id, credential, max_vms=MAX_VMS)
except Exception as e:
    print(f"[WARN] VM detail failed: {e}")
    vm_data = {}

try:
    net_data = get_network_details(subscription_id, credential, max_vnets=MAX_VNETS)
except Exception as e:
    print(f"[WARN] Networking detail failed: {e}")
    net_data = {}

try:
    rg_data = get_rg_details(subscription_id, credential, max_groups=MAX_RGS)
except Exception as e:
    print(f"[WARN] RG detail failed: {e}")
    rg_data = {}

# ---- AI summaries ----
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
    vm_ai = analyze_vm_section(vm_data) if vm_data else "(No VM data to summarise.)"
except Exception as e:
    vm_ai = f"(VM AI narrative unavailable: {e})"

try:
    net_ai = analyze_network_section(net_data) if net_data else "(No networking data to summarise.)"
except Exception as e:
    net_ai = f"(Networking AI narrative unavailable: {e})"

try:
    rg_ai = analyze_rg_section(rg_data) if rg_data else "(No resource group data to summarise.)"
except Exception as e:
    rg_ai = f"(RG AI narrative unavailable: {e})"

# ---- Render ----
report_html = _render_html_report(
    subscription_id, rows, per_type_notes,
    ai_summary, vm_ai, net_ai, rg_ai,
    vm_data, net_data, rg_data,
    _now_stamp()
)
_write_text(html_path, report_html)
print(f"[INFO] HTML report generated: {html_path}")

# ---- Console detailed audits (still available) ----
try:
    audit_virtual_machines(subscription_id, credential)
except Exception as e:
    print(f"[WARN] VM audit failed: {e}")

try:
    audit_resource_groups(subscription_id, credential)
except Exception as e:
    print(f"[WARN] RG audit failed: {e}")

try:
    audit_virtual_networks(subscription_id, credential)
except Exception as e:
    print(f"[WARN] Network audit failed: {e}")
