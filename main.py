# main.py

from dotenv import load_dotenv
import os
from datetime import datetime
from azure.identity import InteractiveBrowserCredential

from rg_reader import audit_resource_groups, get_rg_details
from network_reader import audit_virtual_networks, get_network_details
from vm_reader import audit_virtual_machines, get_vm_details
from storage_reader import audit_storage, get_storage_details
from subscription_resources import audit_subscription_resources
from sql_reader import get_sql_details, audit_sql
from ai_analyzer import (
    analyze_subscription_resources_overview,
    describe_resource_types,
    analyze_network_section,
    analyze_virtual_networks_overview,
    analyze_virtual_network_detailed,
    analyze_resource_group,
    analyze_vm_section,
    analyze_storage_section,
    analyze_rg_section,
    analyze_sql_section,
)

# ============================
# Env / Globals
# ============================

load_dotenv()

# Controls for detail volume (keep in sync with reader modules)
MAX_VNETS = int(os.getenv("DETAIL_MAX_VNETS", "200"))
MAX_VMS   = int(os.getenv("DETAIL_MAX_VMS", "300"))
MAX_RGS   = int(os.getenv("DETAIL_MAX_RGS", "250"))
MAX_STOR  = int(os.getenv("DETAIL_MAX_STORAGE", "250"))

# Auth scope
TENANT_ID = os.getenv("AZURE_TENANT_ID")
SUBSCRIPTION_ID = os.getenv("AZURE_SUBSCRIPTION_ID")

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

def _fmt_bool(b) -> str:
    return "Yes" if bool(b) else "No"

# ============================
# HTML sections
# ============================

def _render_vm_section(ai_text: str, vm_data: dict, max_rows: int = 80) -> str:
    if not vm_data:
        return "<div class='section'><h2>Virtual Machines (detailed)</h2><p class='small'>No VM data.</p></div>"

    vms = vm_data.get("vms", [])[:max_rows]
    s = vm_data.get("summary", {}) or {}

    summary = (
        f"VMs: {int(s.get('total_vms',0))} • "
        f"Regions: {', '.join(s.get('regions',[])[:8])} • "
        f"Common Sizes: {', '.join(s.get('top_sizes',[])[:8])} • "
        f"Gen2: {int(s.get('gen2',0))} • "
        f"Spot: {int(s.get('spot',0))} • "
        f"Zonal: {int(s.get('zonal',0))}"
    )

    rows = []
    for vm in vms:
        rows.append(
            "<tr>"
            f"<td><code>{_html_escape(vm['name'])}</code></td>"
            f"<td>{_html_escape(vm['resource_group'])}</td>"
            f"<td>{_html_escape(vm['location'])}</td>"
            f"<td>{_html_escape(vm['size'])}</td>"
            f"<td>{_html_escape(vm.get('os_type',''))}</td>"
            f"<td>{_html_escape(vm.get('zone',''))}</td>"
            f"<td>{_fmt_bool(vm.get('ultra_ssd'))}</td>"
            f"<td>{_fmt_bool(vm.get('boot_diagnostics'))}</td>"
            f"<td>{_html_escape(vm.get('priority',''))}</td>"
            "</tr>"
        )

    if not rows:
        table_html = "<p class='small'>No VMs found.</p>"
    else:
        table_html = f"""
        <table>
          <tr>
            <th style="width:20%;">VM</th>
            <th style="width:18%;">Resource Group</th>
            <th style="width:10%;">Location</th>
            <th style="width:12%;">Size</th>
            <th style="width:10%;">OS</th>
            <th style="width:6%;">Zone</th>
            <th style="width:8%;">UltraSSD</th>
            <th style="width:10%;">BootDiag</th>
            <th style="width:6%;">Priority</th>
          </tr>
          {''.join(rows)}
        </table>
        """

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
        rows.append(
            "<tr>"
            f"<td><code>{_html_escape(a['name'])}</code></td>"
            f"<td>{_html_escape(a['rg'])}</td>"
            f"<td>{_html_escape(a['location'])}</td>"
            f"<td>{_html_escape(a.get('kind',''))}</td>"
            f"<td>{_html_escape(a.get('sku',''))}</td>"
            f"<td>{_fmt_bool(a.get('allow_blob_public_access'))}</td>"
            f"<td>{int(a.get('private_endpoints',0))}</td>"
            f"<td>{_fmt_bool(a.get('blob_versioning'))}</td>"
            f"<td>{_fmt_bool(a.get('static_website'))}</td>"
            f"<td>{float(a.get('est_used_gb',0.0))}</td>"
            "</tr>"
        )

    if not rows:
        table_html = "<p class='small'>No storage accounts found.</p>"
    else:
        table_html = f"""
        <table>
          <tr>
            <th style="width:18%;">Storage</th>
            <th style="width:16%;">Resource Group</th>
            <th style="width:10%;">Location</th>
            <th style="width:10%;">Kind</th>
            <th style="width:8%;">SKU</th>
            <th style="width:8%;">BlobPublic</th>
            <th style="width:8%;">PEs</th>
            <th style="width:8%;">Versioning</th>
            <th style="width:8%;">Static Web</th>
            <th style="width:8%;">Est Used (GB)</th>
          </tr>
          {''.join(rows)}
        </table>
        """

    ai_html = f"<div class='ai'>{_html_escape(ai_text or '(No AI narrative)')}</div>"

    return f"""
    <div class="section">
      <h2>Storage (detailed)</h2>
      {ai_html}
      <p class="small">{_html_escape(summary)}</p>
      {table_html}
    </div>
    """

def _render_sql_section(ai_text: str, sql_data: dict, max_rows: int = 40) -> str:
    if not sql_data:
        return "<div class='section'><h2>SQL (detailed)</h2><p class='small'>No SQL data.</p></div>"
    s = sql_data.get("summary", {}) or {}
    servers = sql_data.get("servers", [])[:max_rows]
    dbs = sql_data.get("databases", [])[:max_rows]
    summary = (
        f"Servers: {int(s.get('servers',0))} • Databases: {int(s.get('databases',0))} • "
        f"Pools: {int(s.get('elastic_pools',0))} • Managed Instances: {int(s.get('managed_instances',0))} • "
        f"MI DBs: {int(s.get('mi_databases',0))} • Public-access servers: {int(s.get('public_access_servers',0))} • "
        f"PE connections (server total): {int(s.get('private_endpoint_servers',0))} • "
        f"Auditing on (servers): {int(s.get('auditing_enabled_servers',0))} • "
        f"Threat protection on (servers): {int(s.get('threat_protection_enabled_servers',0))} • "
        f"vCores≈{int(s.get('vcores_total_approx',0))} • DTUs≈{int(s.get('dtu_total_approx',0))}"
    )
    svr_rows = []
    for sv in servers:
        svr_rows.append(
            "<tr>"
            f"<td><code>{_html_escape(sv['name'])}</code></td>"
            f"<td>{_html_escape(sv['rg'])}</td>"
            f"<td>{_html_escape(sv['location'])}</td>"
            f"<td>{_html_escape(sv['public_network_access'])}</td>"
            f"<td>{'Yes' if sv.get('auditing') else 'No'}</td>"
            f"<td>{'Yes' if sv.get('threat_protection') else 'No'}</td>"
            f"<td>{int(sv.get('db_count',0))}</td>"
            f"<td>{int(sv.get('pool_count',0))}</td>"
            "</tr>"
        )
    if not svr_rows:
        svr_table = "<p class='small'>No SQL servers found.</p>"
    else:
        svr_table = f"""
        <table>
          <tr>
            <th style="width:22%;">Server</th>
            <th style="width:18%;">Resource Group</th>
            <th style="width:10%;">Location</th>
            <th style="width:12%;">Public Access</th>
            <th style="width:10%;">Auditing</th>
            <th style="width:10%;">Defender</th>
            <th style="width:8%;">DBs</th>
            <th style="width:8%;">Pools</th>
          </tr>
          {''.join(svr_rows)}
        </table>
        """
    db_rows = []
    for d in dbs:
        db_rows.append(
            "<tr>"
            f"<td><code>{_html_escape(d['name'])}</code></td>"
            f"<td>{_html_escape(d['server'])}</td>"
            f"<td>{_html_escape(d['sku'])}</td>"
            f"<td>{_html_escape(d['compute_model'])}</td>"
            f"<td>{int(d.get('capacity',0))}</td>"
            f"<td>{d.get('max_size_gb',0.0)} GB</td>"
            f"<td>{'Yes' if d.get('zone_redundant') else 'No'}</td>"
            f"<td>{_html_escape(str(d.get('backup_storage_redundancy','')))}</td>"
            "</tr>"
        )
    if not db_rows:
        db_table = "<p class='small'>No user databases found.</p>"
    else:
        db_table = f"""
        <table>
          <tr>
            <th style="width:22%;">Database</th>
            <th style="width:18%;">Server</th>
            <th style="width:12%;">SKU</th>
            <th style="width:10%;">Model</th>
            <th style="width:8%;">Cap</th>
            <th style="width:10%;">Max Size</th>
            <th style="width:10%;">Zone Red.</th>
            <th style="width:10%;">Backup Red.</th>
          </tr>
          {''.join(db_rows)}
        </table>
        """
    ai_html = f"<div class='ai'>{_html_escape(ai_text or '(No AI narrative)')}</div>"
    return f"""
    <div class="section">
      <h2>SQL (detailed)</h2>
      {ai_html}
      <p class="small">{_html_escape(summary)}</p>
      <p class="small"><b>Servers</b></p>
      {svr_table}
      <p class="small"><b>Databases (sample)</b></p>
      {db_table}
    </div>
    """

def _render_network_section(ai_text: str, net_data: dict, max_rows: int = 80) -> str:
    if not net_data:
        return "<div class='section'><h2>Networking (detailed)</h2><p class='small'>No VNet data.</p></div>"

    vnets = net_data.get("vnets", [])[:max_rows]
    s = net_data.get("summary", {}) or {}

    bullets = []
    counts = {
        "total_vnets": int(s.get("total_vnets", 0)),
        "total_subnets": int(s.get("total_subnets", 0)),
        "peered_vnets": int(s.get("peered_vnets", 0)),
        "vnets_with_gateway": int(s.get("vnets_with_gateway", 0)),
        "vnets_with_firewall": int(s.get("vnets_with_firewall", 0)),
    }
    for k in ["total_vnets","total_subnets","peered_vnets","vnets_with_gateway","vnets_with_firewall"]:
        if counts[k]:
            bullets.append(f"<li><b>{k.replace('_',' ').title()}</b>: {counts[k]}</li>")
    summary_ul = "<ul>" + "".join(bullets) + "</ul>"

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
            <th style="width:8%;">Gateway</th>
            <th style="width:8%;">Firewall</th>
          </tr>
          {''.join(rows)}
        </table>
        """

    ai_html = f"<div class='ai'>{_html_escape(ai_text or '(No AI narrative)')}</div>"

    return f"""
    <div class="section">
      <h2>Networking (detailed)</h2>
      {ai_html}
      <p class="small"><b>Overview</b></p>
      {summary_ul}
      <p class="small"><b>VNets</b></p>
      {vnet_table}
    </div>
    """

def _render_rg_section(ai_text: str, rg_data: dict, max_rows: int = 150) -> str:
    if not rg_data:
        return "<div class='section'><h2>Resource Groups (detailed)</h2><p class='small'>No RG data.</p></div>"

    rgs = rg_data.get("rgs", [])[:max_rows]
    rows = []
    for r in rgs:
        rows.append(
            "<tr>"
            f"<td><code>{_html_escape(r['name'])}</code></td>"
            f"<td>{_html_escape(r['location'])}</td>"
            f"<td>{int(r.get('count',0))}</td>"
            f"<td>{_html_escape(', '.join(r.get('top_types',[])[:3]))}</td>"
            f"<td>{_fmt_bool(r.get('has_tags'))}</td>"
            "</tr>"
        )
    if not rows:
        table_html = "<p class='small'>No Resource Groups found.</p>"
    else:
        table_html = f"""
        <table>
          <tr>
            <th style="width:30%;">Resource Group</th>
            <th style="width:14%;">Location</th>
            <th style="width:10%;">Resource Count</th>
            <th style="width:28%;">Top Types</th>
            <th style="width:8%;">Has Tags</th>
          </tr>
          {''.join(rows)}
        </table>
        """

    ai_html = f"<div class='ai'>{_html_escape(ai_text or '(No AI narrative)')}</div>"
    return f"""
    <div class="section">
      <h2>Resource Groups (detailed)</h2>
      {ai_html}
      {table_html}
    </div>
    """

# ============================
# HTML wrapper
# ============================

def _render_html_report(subscription_id: str, rows: list, per_type_notes: dict,
                        ai_summary: str, vm_ai: str, net_ai: str, rg_ai: str, storage_ai: str, sql_ai: str,
                        vm_data: dict, net_data: dict, rg_data: dict, storage_data: dict, sql_data: dict,
                        generated_at: str) -> str:

    safe_sub = _safe_sub_id(subscription_id)

    # Resource type inventory table (ARG summary)
    inv_tr = []
    for r in rows:
        rtype = r.get("type","")
        cnt = r.get("count",0)
        narrative = per_type_notes.get(rtype,"")
        inv_tr.append(
            "<tr>"
            f"<td><code>{_html_escape(rtype)}</code></td>"
            f"<td>{int(cnt)}</td>"
            f"<td class='narr'>{_html_escape(narrative)}</td>"
            "</tr>"
        )
    inv_rows = "\n".join(inv_tr) if inv_tr else "<tr><td colspan='4'>No data</td></tr>"

    vm_section  = _render_vm_section(vm_ai, vm_data)
    storage_section = _render_storage_section(storage_ai, storage_data)
    sql_section = _render_sql_section(sql_ai, sql_data)
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
<p><b>Subscription:</b> <code>{_html_escape(subscription_id)}</code> &nbsp;&nbsp; <b>Generated:</b> {generated_at}</p>

<div class="section">
  <h2>Inventory (ARG)</h2>
  <div class="ai">{_html_escape(ai_summary or '(No AI summary)')}</div>
  <table>
    <tr><th style="width:38%;">Resource Type</th><th style="width:10%;">Count</th><th>Narrative</th></tr>
    {inv_rows}
  </table>
</div>

{vm_section}
{storage_section}
{sql_section}
{net_section}
{rg_section}

</body>
</html>
"""

# ============================
# Main
# ============================

def main():
    # Auth (browser pop-up if needed)
    credential = InteractiveBrowserCredential(tenant_id=TENANT_ID)
    subscription_id = SUBSCRIPTION_ID or ""

    print(f"\n=== Subscription: {subscription_id} ===\n")

    # ---- Inventory (ARG) ----
    try:
        rows, stats = audit_subscription_resources(subscription_id, credential)
    except Exception as e:
        print(f"[WARN] Inventory failed: {e}")
        rows, stats = [], {}

    # Build per-type notes using AI (short descriptors)
    per_type_notes = {}
    try:
        preview_rows = rows[:12]
        note_text = describe_resource_types(preview_rows)
        # quick associative notes (simple mapping for table)
        for r in preview_rows:
            per_type_notes[r["type"]] = f"Part of the broader mix. See overview."
    except Exception as e:
        print(f"[WARN] Type description failed: {e}")

    # ---- Detailed data ----
    try:
        vm_data = get_vm_details(subscription_id, credential, max_vms=MAX_VMS)
    except Exception as e:
        print(f"[WARN] VM detail failed: {e}")
        vm_data = {}

    try:
        storage_data = get_storage_details(subscription_id, credential, max_accounts=MAX_STOR)
    except Exception as e:
        print(f"[WARN] Storage detail failed: {e}")
        storage_data = {}

    try:
        sql_data = get_sql_details(subscription_id, credential)
    except Exception as e:
        print(f"[WARN] SQL detail failed: {e}")
        sql_data = {}

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

    # ---- AI overview of inventory ----
    try:
        if stats:
            ai_summary = analyze_subscription_resources_overview({
                "total": stats.get("total_resources",0),
                "regions": stats.get("regions",[]),
                "top_types": stats.get("top_types",[]),
                "tag_coverage": stats.get("tag_coverage",{}),
            })
        else:
            ai_summary = "(No inventory data returned. Check ARG or RBAC permissions.)"
    except Exception as e:
        ai_summary = f"(AI summary unavailable: {e})"

    # ---- AI summaries (sections) ----
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

    try:
        sql_ai = analyze_sql_section(sql_data) if sql_data else "(No SQL data to summarise.)"
    except Exception as e:
        sql_ai = f"(SQL AI narrative unavailable: {e})"

    # ---- Render ----
    report_html = _render_html_report(
        subscription_id, rows, per_type_notes,
        ai_summary, vm_ai, net_ai, rg_ai, storage_ai, sql_ai,
        vm_data, net_data, rg_data, storage_data, sql_data,
        datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    )

    out_dir = os.getenv("OUTPUT_DIR", "out")
    _ensure_dir(out_dir)
    out_path = os.path.join(out_dir, f"audit_{_safe_sub_id(subscription_id)}_{_file_stamp()}.html")
    _write_text(out_path, report_html)
    print(f"Report written: {out_path}")

    # ---- Console audits (optional) ----
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

    try:
        audit_storage(subscription_id, credential)
    except Exception as e:
        print(f"[WARN] Storage audit failed: {e}")

    try:
        audit_sql(subscription_id, credential)
    except Exception as e:
        print(f"[WARN] SQL audit failed: {e}")

if __name__ == "__main__":
    main()
