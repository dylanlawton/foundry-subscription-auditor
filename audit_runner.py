# audit_runner.py
from __future__ import annotations

import os
from datetime import datetime
from typing import Any, Dict, Optional

from subscription_resources import audit_subscription_resources
from rg_reader import get_rg_details
from vm_reader import get_vm_details
from storage_reader import get_storage_details
from network_reader import get_network_details

from governance_security_cost_reader import get_governance_security_cost_details

from ai_analyzer import (
    set_prompt_context,
    describe_resource_types,
    analyze_subscription_resources_overview,
    analyze_vm_section,
    analyze_storage_section,
    analyze_network_section,
    analyze_rg_section,
    analyze_governance_security_cost_section,
)

# ----------------------------
# HTML helpers (lifted in spirit from main.py)
# ----------------------------
def _html_escape(s: Any) -> str:
    t = "" if s is None else str(s)
    return (
        t.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def _write_text(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        f.write(text if text else "")


def _fmt_bool(b: Any) -> str:
    return "Yes" if bool(b) else "No"


def _page_shell(title: str, subtitle: str, body_html: str) -> str:
    css = """
    body { font-family: Arial, sans-serif; margin: 24px; color: #111; }
    h1 { margin: 0 0 6px 0; }
    .sub { color: #444; margin-bottom: 18px; }
    .section { margin: 18px 0 26px 0; padding-top: 4px; }
    .ai { background: #f6f6f6; border-left: 4px solid #999; padding: 10px 12px; margin: 10px 0; white-space: pre-wrap; }
    .small { color: #444; font-size: 13px; }
    table { border-collapse: collapse; width: 100%; }
    th, td { border: 1px solid #ccc; padding: 6px 8px; font-size: 13px; vertical-align: top; }
    th { background: #f0f0f0; text-align: left; }
    code { background: #eee; padding: 1px 4px; border-radius: 4px; }
    details { background:#fafafa; border:1px solid #ddd; padding:10px 12px; border-radius:8px; }
    summary { cursor:pointer; }
    pre { background:#f3f3f3; padding:10px 12px; border-radius:8px; overflow:auto; }
    """
    return f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>{_html_escape(title)}</title>
  <style>{css}</style>
</head>
<body>
  <h1>{_html_escape(title)}</h1>
  <div class="sub">{_html_escape(subtitle)}</div>
  {body_html}
</body>
</html>"""


def _render_prompt_section(system_prompt: Optional[str], angle_text: Optional[str]) -> str:
    sp = (system_prompt or "").strip()
    at = (angle_text or "").strip()

    if not sp and not at:
        return """
        <div class="section">
          <h2>AI prompt context</h2>
          <p class="small">No per-run prompt overrides were provided. Defaults (App Settings) may still apply.</p>
        </div>
        """

    return f"""
    <div class="section">
      <h2>AI prompt context (used for this run)</h2>
      <details open>
        <summary>Show prompt inputs</summary>
        <p class="small">These values steer the AI narrative sections of this report.</p>
        <h3 class="small">System prompt</h3>
        <pre>{_html_escape(sp) if sp else "(not provided - defaults used)"}</pre>
        <h3 class="small">Report angle</h3>
        <pre>{_html_escape(at) if at else "(not provided - defaults used)"}</pre>
      </details>
    </div>
    """


def _render_inventory_section(ai_text: str, inv: dict, max_rows: int = 50) -> str:
    rows = inv.get("types", []) or []
    per_type_notes = inv.get("per_type_notes", {}) or {}

    top = rows[:max_rows]
    trs = []
    for r in top:
        rtype = str(r.get("type", ""))
        cnt = int(r.get("count", 0))
        samples = r.get("sampleNames", []) or []
        note = per_type_notes.get(rtype.lower(), "")
        trs.append(
            "<tr>"
            f"<td><code>{_html_escape(rtype)}</code></td>"
            f"<td>{cnt}</td>"
            f"<td class='small'>{_html_escape(', '.join(samples[:5]))}</td>"
            f"<td class='small'>{_html_escape(note)}</td>"
            "</tr>"
        )

    table = (
        "<p class='small'>No inventory rows returned.</p>"
        if not trs
        else f"""
        <table>
          <tr><th style="width:34%;">Resource type</th><th style="width:8%;">Count</th><th style="width:28%;">Sample names</th><th>AI note</th></tr>
          {''.join(trs)}
        </table>
        """
    )

    ai_html = f"<div class='ai'>{_html_escape(ai_text or '(No AI narrative)')}</div>"
    return f"""
    <div class="section">
      <h2>Subscription resource inventory</h2>
      {ai_html}
      {table}
    </div>
    """


def _render_vm_section(ai_text: str, vm_data: dict, max_rows: int = 30) -> str:
    if not vm_data:
        return "<div class='section'><h2>Virtual Machines</h2><p class='small'>No VM data.</p></div>"

    vms = (vm_data.get("vms") or [])[:max_rows]
    s = vm_data.get("summary", {}) or {}
    d = vm_data.get("disk_summary", {}) or {}
    vs = vm_data.get("vmss_summary", {}) or {}

    summary = (
        f"Total VMs (all): {int(s.get('total_vms_all',0))} • "
        f"Sampled: {int(s.get('total_vms',0))} • "
        f"Spot: {int(s.get('spot_vms',0))} • "
        f"AvSet-attached: {int(s.get('avset_attached_vms',0))} • "
        f"With Identity: {int(s.get('identity_vms',0))} • "
        f"VMSS: {int(vs.get('count',0))} • "
        f"Disks: {int(d.get('total_disks',0))} (unattached {int(d.get('unattached_disks',0))})"
    )

    trs = []
    for vm in vms:
        trs.append(
            "<tr>"
            f"<td><code>{_html_escape(vm.get('name'))}</code></td>"
            f"<td>{_html_escape(vm.get('rg'))}</td>"
            f"<td>{_html_escape(vm.get('location'))}</td>"
            f"<td>{_html_escape(vm.get('size'))}</td>"
            f"<td>{_html_escape(vm.get('os'))}</td>"
            f"<td>{_html_escape(vm.get('power'))}</td>"
            f"<td>{_html_escape(vm.get('priority'))}</td>"
            f"<td>{_html_escape(vm.get('availability_set'))}</td>"
            f"<td>{_html_escape(vm.get('identity_kind'))}</td>"
            "</tr>"
        )

    table = (
        "<p class='small'>No VMs returned.</p>"
        if not trs
        else f"""
        <table>
          <tr>
            <th style="width:22%;">VM</th><th style="width:18%;">RG</th><th style="width:10%;">Loc</th>
            <th style="width:12%;">Size</th><th style="width:10%;">OS</th><th style="width:10%;">Power</th>
            <th style="width:8%;">Priority</th><th style="width:10%;">AvSet</th><th style="width:12%;">Identity</th>
          </tr>
          {''.join(trs)}
        </table>
        """
    )

    ai_html = f"<div class='ai'>{_html_escape(ai_text or '(No AI narrative)')}</div>"
    return f"""
    <div class="section">
      <h2>Virtual Machines</h2>
      {ai_html}
      <p class="small">{_html_escape(summary)}</p>
      {table}
    </div>
    """


def _render_storage_section(ai_text: str, storage_data: dict, max_rows: int = 40) -> str:
    if not storage_data:
        return "<div class='section'><h2>Storage</h2><p class='small'>No storage data.</p></div>"

    s = storage_data.get("summary", {}) or {}
    accs = (storage_data.get("accounts") or [])[:max_rows]
    summary = (
        f"Accounts: {int(s.get('total_accounts',0))} • "
        f"PE connections(total): {int(s.get('private_endpoint_accounts',0))} • "
        f"Public-allowed accounts: {int(s.get('public_allowed_accounts',0))} • "
        f"Versioning on: {int(s.get('versioning_enabled_accounts',0))} • "
        f"Static sites: {int(s.get('static_website_accounts',0))} • "
        f"Est. total used: {float(s.get('est_total_used_gb',0.0))} GB"
    )

    trs = []
    for a in accs:
        exposure = "PrivateOnly" if (str(a.get("public_network_access","")).lower()=="disabled" and str(a.get("network_default_action","")).lower()=="deny") else "PublicAllowed"
        trs.append(
            "<tr>"
            f"<td><code>{_html_escape(a.get('name'))}</code></td>"
            f"<td>{_html_escape(a.get('rg'))}</td>"
            f"<td>{_html_escape(a.get('location'))}</td>"
            f"<td>{_html_escape(a.get('kind'))}</td>"
            f"<td>{_html_escape(a.get('sku'))}</td>"
            f"<td>{_html_escape(a.get('access_tier',''))}</td>"
            f"<td>{_html_escape(exposure)}</td>"
            f"<td>{int(a.get('private_endpoint_count',0))}</td>"
            f"<td>{_fmt_bool(a.get('blob_versioning'))}</td>"
            f"<td>{_fmt_bool(a.get('static_website'))}</td>"
            f"<td>{_html_escape(a.get('used_gb',''))} GB</td>"
            "</tr>"
        )

    table = (
        "<p class='small'>No storage accounts returned.</p>"
        if not trs
        else f"""
        <table>
          <tr>
            <th style="width:18%;">Account</th><th style="width:14%;">RG</th><th style="width:10%;">Loc</th>
            <th style="width:10%;">Kind</th><th style="width:10%;">SKU</th><th style="width:10%;">Tier</th>
            <th style="width:10%;">Exposure</th><th style="width:6%;">PE</th>
            <th style="width:6%;">Ver</th><th style="width:6%;">Static</th><th style="width:10%;">Used</th>
          </tr>
          {''.join(trs)}
        </table>
        """
    )

    ai_html = f"<div class='ai'>{_html_escape(ai_text or '(No AI narrative)')}</div>"
    return f"""
    <div class="section">
      <h2>Storage</h2>
      {ai_html}
      <p class="small">{_html_escape(summary)}</p>
      {table}
    </div>
    """


def _render_network_section(ai_text: str, net_data: dict, max_rows: int = 30) -> str:
    if not net_data:
        return "<div class='section'><h2>Network</h2><p class='small'>No network data.</p></div>"

    s = net_data.get("summary", {}) or {}
    vnets = (net_data.get("vnets") or [])[:max_rows]
    summary = (
        f"VNets(sampled): {int(s.get('vnets',0))} • "
        f"NSGs: {int(s.get('nsgs',0))} • "
        f"Private Endpoints: {int(s.get('private_endpoints',0))} • "
        f"Private DNS zones: {int(s.get('private_dns_zones',0))} • "
        f"VNet Gateways: {int(s.get('vnet_gateways',0))} • "
        f"ExpressRoute: {int(s.get('expressroute',0))} • "
        f"Public IPs: {int(s.get('public_ips',0))}"
    )

    trs = []
    for v in vnets:
        trs.append(
            "<tr>"
            f"<td><code>{_html_escape(v.get('name'))}</code></td>"
            f"<td>{_html_escape(v.get('rg'))}</td>"
            f"<td>{_html_escape(v.get('location'))}</td>"
            f"<td class='small'>{_html_escape(','.join(v.get('address_space') or []))}</td>"
            f"<td>{_fmt_bool(v.get('peered'))} ({int(v.get('peerings_count',0))})</td>"
            f"<td>{_fmt_bool(v.get('has_gateway'))}</td>"
            f"<td>{_fmt_bool(v.get('has_firewall'))}</td>"
            "</tr>"
        )

    table = (
        "<p class='small'>No VNets returned.</p>"
        if not trs
        else f"""
        <table>
          <tr>
            <th style="width:22%;">VNet</th><th style="width:16%;">RG</th><th style="width:10%;">Loc</th>
            <th style="width:22%;">Address space</th><th style="width:12%;">Peering</th>
            <th style="width:9%;">Gateway</th><th style="width:9%;">Firewall</th>
          </tr>
          {''.join(trs)}
        </table>
        """
    )

    ai_html = f"<div class='ai'>{_html_escape(ai_text or '(No AI narrative)')}</div>"
    return f"""
    <div class="section">
      <h2>Network</h2>
      {ai_html}
      <p class="small">{_html_escape(summary)}</p>
      {table}
    </div>
    """


def _render_gsc_section(ai_text: str, gsc_data: dict) -> str:
    if not gsc_data:
        return "<div class='section'><h2>Governance, Security &amp; Cost</h2><p class='small'>No data.</p></div>"

    # Pull a few headline stats (best-effort)
    sub = gsc_data.get("subscription", {}) or {}
    mg = gsc_data.get("management_group", {}) or {}
    pol = gsc_data.get("policy", {}) or {}
    cost = gsc_data.get("cost", {}) or {}
    defn = gsc_data.get("defender", {}) or {}

    mg_path = " > ".join(mg.get("path") or []) if isinstance(mg.get("path"), list) else ""
    pol_count = pol.get("assignment_count")
    secure_score = defn.get("secure_score")
    alerts = defn.get("alerts_last_30d")
    months = cost.get("months") or []

    cost_line = ""
    if isinstance(months, list) and months:
        try:
            last = months[-1]
            cost_line = f"Latest month: {last.get('month')} total {last.get('total')}"
        except Exception:
            cost_line = ""

    headline = (
        f"Subscription: {sub.get('display_name') or ''} ({sub.get('state') or ''}) • "
        f"MG: {mg_path or '(unknown)'} • "
        f"Policy assignments: {pol_count if pol_count is not None else '(unknown)'} • "
        f"Secure score: {secure_score if secure_score is not None else '(n/a)'} • "
        f"Alerts: {alerts if alerts is not None else '(n/a)'}"
    )
    if cost_line:
        headline += f" • Cost: {cost_line}"

    ai_html = f"<div class='ai'>{_html_escape(ai_text or '(No AI narrative)')}</div>"

    raw = _html_escape(str(gsc_data))
    return f"""
    <div class="section">
      <h2>Governance, Security &amp; Cost</h2>
      {ai_html}
      <p class="small">{_html_escape(headline)}</p>
      <details>
        <summary>Raw signals</summary>
        <pre>{raw}</pre>
      </details>
    </div>
    """


def _render_rg_section(ai_text: str, rg_data: dict, max_rows: int = 60) -> str:
    if not rg_data:
        return "<div class='section'><h2>Resource Groups</h2><p class='small'>No RG data.</p></div>"

    rgs = (rg_data.get("groups") or rg_data.get("resource_groups") or [])[:max_rows]
    s = rg_data.get("summary", {}) or {}
    summary = f"Resource Groups: {int(s.get('count', len(rgs)))}"

    trs = []
    for g in rgs:
        trs.append(
            "<tr>"
            f"<td><code>{_html_escape(g.get('name'))}</code></td>"
            f"<td>{_html_escape(g.get('location'))}</td>"
            f"<td>{int(g.get('resource_count', 0))}</td>"
            f"<td class='small'>{_html_escape(str(g.get('tags', {})))}</td>"
            "</tr>"
        )

    table = (
        "<p class='small'>No RGs returned.</p>"
        if not trs
        else f"""
        <table>
          <tr><th style="width:24%;">RG</th><th style="width:12%;">Location</th><th style="width:10%;">Resources</th><th>Tags</th></tr>
          {''.join(trs)}
        </table>
        """
    )

    ai_html = f"<div class='ai'>{_html_escape(ai_text or '(No AI narrative)')}</div>"
    return f"""
    <div class="section">
      <h2>Resource Groups</h2>
      {ai_html}
      <p class="small">{_html_escape(summary)}</p>
      {table}
    </div>
    """


# ----------------------------
# Main entrypoint called by app.py
# ----------------------------
def run_audit(
    *,
    subscription_id: str,
    credential,
    output_dir: str = "/tmp/outputs",
    report_system_prompt: Optional[str] = None,
    report_angle_text: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Shared audit engine entrypoint.
    - Called by app.py (web)
    - credential is StaticTokenCredential wrapping an ARM user token (delegated).
    - prompt overrides are per-run, thread-safe via ai_analyzer contextvars.
    """
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    # Keep run_id stable: use folder name if output_dir ends in it
    run_id = os.path.basename(os.path.normpath(output_dir)) or f"{subscription_id}_{timestamp}"

    # Set per-run AI context (thread-safe)
    set_prompt_context(system_prompt=report_system_prompt, angle_text=report_angle_text)

    # 1) Subscription-wide inventory
    types_rows = audit_subscription_resources(subscription_id, credential, sample_size=5)
    per_type_notes = describe_resource_types(types_rows)

    inventory_payload = {
        "subscription_id": subscription_id,
        "types": types_rows,
        "per_type_notes": per_type_notes,
    }

    # 2) Detailed sections
    vm_data = get_vm_details(subscription_id=subscription_id, credential=credential)
    storage_data = get_storage_details(subscription_id=subscription_id, credential=credential)
    network_data = get_network_details(subscription_id=subscription_id, credential=credential)
    rg_data = get_rg_details(subscription_id=subscription_id, credential=credential)

    # 2b) Governance/Security/Cost (best-effort)
    tenant_id = os.getenv("AZURE_TENANT_ID", "") or ""
    gsc_data = get_governance_security_cost_details(
        subscription_id=subscription_id,
        tenant_id=tenant_id,
        credential=credential,
    )

    # 3) AI narratives (best-effort; never fail the run if OpenAI isn't configured)
    def _safe_ai(fn, arg) -> str:
        try:
            return fn(arg)
        except Exception as e:
            return f"(AI narrative unavailable: {e})"

    ai_overview = _safe_ai(analyze_subscription_resources_overview, inventory_payload)
    ai_vm = _safe_ai(analyze_vm_section, vm_data)
    ai_storage = _safe_ai(analyze_storage_section, storage_data)
    ai_network = _safe_ai(analyze_network_section, network_data)
    ai_gsc = _safe_ai(analyze_governance_security_cost_section, gsc_data)
    ai_rg = _safe_ai(analyze_rg_section, rg_data)

    # 4) Render HTML report (stable name for UI link)
    title = "Azure Subscription Audit"
    subtitle = f"Subscription: {subscription_id} • Run: {run_id} • Generated (UTC): {datetime.utcnow().isoformat()}Z"

    body = (
        _render_prompt_section(report_system_prompt, report_angle_text)
        + _render_inventory_section(ai_overview, inventory_payload)
        + _render_vm_section(ai_vm, vm_data)
        + _render_storage_section(ai_storage, storage_data)
        + _render_network_section(ai_network, network_data)
        + _render_gsc_section(ai_gsc, gsc_data)
        + _render_rg_section(ai_rg, rg_data)
    )

    html = _page_shell(title, subtitle, body)

    # Write stable + archival filename
    report_file_ui = "report.html"
    report_file = f"subscription_overview_{subscription_id}_{timestamp}.html"

    report_path_ui = os.path.join(output_dir, report_file_ui)
    report_path = os.path.join(output_dir, report_file)

    _write_text(report_path_ui, html)
    _write_text(report_path, html)

    # 5) Return results to app.py for result.json
    # (Keep this small-ish; raw payloads are still returned for debugging/future use.)
    summary = {
        "subscription_id": subscription_id,
        "run_id": run_id,
        "generated_utc": datetime.utcnow().isoformat() + "Z",
        "inventory_types": len(types_rows or []),
        "vm_total_all": (vm_data.get("summary", {}) or {}).get("total_vms_all"),
        "storage_accounts": (storage_data.get("summary", {}) or {}).get("total_accounts"),
        "vnets": (network_data.get("summary", {}) or {}).get("vnets"),
        "resource_groups": (rg_data.get("summary", {}) or {}).get("count") if isinstance(rg_data, dict) else None,
        "policy_assignments": (gsc_data.get("policy", {}) or {}).get("assignment_count"),
        "secure_score": (gsc_data.get("defender", {}) or {}).get("secure_score"),
    }

    return {
        "summary": summary,
        "report_file": report_file,
        "report_file_ui": report_file_ui,
        "prompt_context": {
            "report_system_prompt": report_system_prompt,
            "report_angle_text": report_angle_text,
        },
        "inventory": inventory_payload,
        "vm": vm_data,
        "storage": storage_data,
        "network": network_data,
        "governance_security_cost": gsc_data,
        "resource_groups": rg_data,
    }
