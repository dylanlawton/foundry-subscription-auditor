# storage_reader.py

from typing import Dict, Any, List
from collections import Counter
from datetime import datetime, timedelta

from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.monitor import MonitorManagementClient

def _id_to_rg(resource_id: str) -> str:
    try:
        parts = resource_id.split("/")
        return parts[parts.index("resourceGroups")+1]
    except Exception:
        return ""

def _safe(val, default=None):
    return val if val is not None else default

def _bytes_fmt(n: float) -> float:
    try:
        return round(n / (1024**3), 2)  # GB
    except Exception:
        return 0.0

def _latest_metric_value(series) -> float:
    """
    Given a MetricValue/timeSeries list, return the last non-null Total or Average.
    """
    latest = None
    if not series:
        return 0.0
    for ts in series:
        data = getattr(ts, "data", None) or []
        for mv in data:
            # Walk forward and keep last non-null
            v = getattr(mv, "total", None)
            if v is None:
                v = getattr(mv, "average", None)
            if v is not None:
                latest = v
    return float(latest or 0.0)

def _get_capacity_metrics(mon: MonitorManagementClient, resource_id: str) -> Dict[str, float]:
    # Try a short recent window to get a value
    end = datetime.utcnow()
    start = end - timedelta(days=2)
    timespan = f"{start.isoformat()}Z/{end.isoformat()}Z"
    metricnames = "UsedCapacity,BlobCapacity,FileCapacity,TableCapacity,QueueCapacity"

    try:
        metrics = mon.metrics.list(
            resource_id,
            timespan=timespan,
            metricnames=metricnames,
            aggregation="Total,Average",
        )
    except Exception:
        # If metrics API not authorized/available, return zeros
        return {
            "UsedCapacity": 0.0,
            "BlobCapacity": 0.0,
            "FileCapacity": 0.0,
            "TableCapacity": 0.0,
            "QueueCapacity": 0.0,
        }

    out = {
        "UsedCapacity": 0.0,
        "BlobCapacity": 0.0,
        "FileCapacity": 0.0,
        "TableCapacity": 0.0,
        "QueueCapacity": 0.0,
    }
    for m in getattr(metrics, "value", []) or []:
        name = getattr(getattr(m, "name", None), "value", "")
        val = _latest_metric_value(getattr(m, "timeseries", None) or [])
        if name in out:
            out[name] = val
    return out

def get_storage_details(subscription_id: str, credential, max_accounts: int = 200) -> Dict[str, Any]:
    """
    Collects storage accounts with:
      - Kind & SKU (performance tier), min TLS, HTTPS only
      - Network exposure (publicNetworkAccess, defaultAction, vnet/ip rules)
      - Private Endpoints
      - Blob features (versioning, change feed, delete retention, static website)
      - Estimated capacity via Azure Monitor metrics
    Returns:
      {
        "summary": {...},
        "accounts": [
           { name, rg, location, kind, sku, min_tls, https_only,
             public_network_access, network_default_action,
             vnet_rules, ip_rules, private_endpoint_count, private_endpoints,
             blob_versioning, blob_change_feed, blob_delete_retention,
             static_website, access_tier, endpoints, used_gb, used_breakdown_gb {Blob, File, Table, Queue} }
        ]
      }
    """
    sclient = StorageManagementClient(credential, subscription_id)
    mclient = MonitorManagementClient(credential, subscription_id)

    accounts: List[Dict[str, Any]] = []
    kind_counter = Counter()
    sku_counter = Counter()
    pe_total = 0
    public_allowed = 0
    versioning_on = 0
    static_web_on = 0
    est_total_used_bytes = 0.0

    # Enumerate accounts
    for i, sa in enumerate(sclient.storage_accounts.list()):
        if i >= max_accounts:
            break

        rg = _id_to_rg(sa.id)
        name = sa.name
        location = sa.location
        kind = _safe(getattr(sa, "kind", ""), "")
        sku_name = _safe(getattr(getattr(sa, "sku", None), "name", ""), "")
        min_tls = _safe(getattr(sa, "minimum_tls_version", ""), "")
        https_only = bool(getattr(sa, "enable_https_traffic_only", False))
        public_network_access = _safe(getattr(sa, "public_network_access", ""), "")
        endpoints = {}
        try:
            eps = getattr(sa, "primary_endpoints", None)
            if eps:
                endpoints = {k: v for k, v in eps.__dict__.items() if isinstance(v, str)}
        except Exception:
            pass

        # Properties (network rules, PEs)
        try:
            props = sclient.storage_accounts.get_properties(rg, name)
        except Exception:
            props = None

        network_default_action = ""
        vnet_rules = 0
        ip_rules = 0
        private_endpoints = []
        if props:
            try:
                nrs = getattr(props, "network_rule_set", None)
                if nrs:
                    network_default_action = _safe(getattr(nrs, "default_action", ""), "")
                    vnet_rules = len(_safe(getattr(nrs, "virtual_network_rules", []), []))
                    ip_rules = len(_safe(getattr(nrs, "ip_rules", []), []))
            except Exception:
                pass
            try:
                pecs = getattr(props, "private_endpoint_connections", []) or []
                for pec in pecs:
                    # Subresource (blob,file,queue,table)
                    subr = _safe(getattr(pec, "private_link_service_connection_state", None), None)
                    # Sometimes subresource is not exposed here; we can at least capture name
                    private_endpoints.append(_safe(getattr(pec, "name", ""), ""))
            except Exception:
                pass

        private_endpoint_count = len(private_endpoints)
        pe_total += private_endpoint_count

        # Blob service level props
        blob_versioning = False
        blob_change_feed = False
        blob_delete_retention = False
        static_website = False
        access_tier = ""

        try:
            bprops = sclient.blob_services.get_service_properties(rg, name, "default")
            # Versioning + change feed
            try:
                blob_versioning = bool(getattr(bprops, "is_versioning_enabled", False))
            except Exception:
                blob_versioning = False
            try:
                cf = getattr(bprops, "change_feed", None)
                blob_change_feed = bool(getattr(cf, "enabled", False)) if cf else False
            except Exception:
                blob_change_feed = False
            try:
                drp = getattr(bprops, "delete_retention_policy", None)
                blob_delete_retention = bool(getattr(drp, "enabled", False)) if drp else False
            except Exception:
                blob_delete_retention = False
            try:
                sw = getattr(bprops, "static_website", None)
                static_website = bool(getattr(sw, "enabled", False)) if sw else False
            except Exception:
                static_website = False
            try:
                # Default access tier (Hot/Cool) where applicable
                at = getattr(bprops, "default_service_version", None)  # not actually tier; best-effort
            except Exception:
                at = None
        except Exception:
            bprops = None

        # Try to read the account-level access tier (BlobStorage/FileStorage/GPv2 may expose different fields)
        try:
            # Some kinds expose the "access_tier" on the account (e.g., BlobStorage; GPv2 default is often 'Hot')
            at_acct = getattr(props, "access_tier", None) if props else None
            if at_acct:
                access_tier = str(at_acct)
        except Exception:
            pass

        # Metrics (bytes)
        used = _get_capacity_metrics(mclient, sa.id)
        used_breakdown_gb = {
            "Blob": _bytes_fmt(used.get("BlobCapacity", 0.0)),
            "File": _bytes_fmt(used.get("FileCapacity", 0.0)),
            "Table": _bytes_fmt(used.get("TableCapacity", 0.0)),
            "Queue": _bytes_fmt(used.get("QueueCapacity", 0.0)),
        }
        used_gb = _bytes_fmt(
            used.get("UsedCapacity", 0.0) or
            max(used.get("BlobCapacity", 0.0), 0.0) + max(used.get("FileCapacity", 0.0), 0.0) +
            max(used.get("TableCapacity", 0.0), 0.0) + max(used.get("QueueCapacity", 0.0), 0.0)
        )
        est_total_used_bytes += (used.get("UsedCapacity", 0.0) or 0.0)

        # Public exposure quick signal
        if str(public_network_access).lower() != "disabled" or str(network_default_action).lower() == "allow":
            public_allowed += 1

        if blob_versioning:
            versioning_on += 1
        if static_website:
            static_web_on += 1

        kind_counter[kind] += 1
        sku_counter[sku_name] += 1

        accounts.append({
            "name": name,
            "rg": rg,
            "location": location,
            "kind": kind,
            "sku": sku_name,
            "min_tls": min_tls,
            "https_only": https_only,
            "public_network_access": public_network_access,
            "network_default_action": network_default_action,
            "vnet_rules": vnet_rules,
            "ip_rules": ip_rules,
            "private_endpoint_count": private_endpoint_count,
            "private_endpoints": private_endpoints,
            "blob_versioning": blob_versioning,
            "blob_change_feed": blob_change_feed,
            "blob_delete_retention": blob_delete_retention,
            "static_website": static_website,
            "access_tier": access_tier,
            "endpoints": endpoints,
            "used_gb": used_gb,
            "used_breakdown_gb": used_breakdown_gb,
        })

    summary = {
        "total_accounts": len(accounts),
        "kinds": dict(kind_counter),
        "skus": dict(sku_counter),
        "private_endpoint_accounts": pe_total,
        "public_allowed_accounts": public_allowed,
        "versioning_enabled_accounts": versioning_on,
        "static_website_accounts": static_web_on,
        "est_total_used_gb": round(est_total_used_bytes / (1024**3), 2) if est_total_used_bytes else 0.0,
    }

    return {
        "summary": summary,
        "accounts": accounts
    }

def audit_storage(subscription_id: str, credential) -> Dict[str, Any]:
    data = get_storage_details(subscription_id, credential, max_accounts=9999)
    s = data["summary"]
    print("\nAuditing Storage Accounts:\n")
    print(f"Total accounts: {s['total_accounts']}, kinds={s['kinds']}, skus={s['skus']}")
    print(f"With PEs (connections total): {s['private_endpoint_accounts']}, public-allowed: {s['public_allowed_accounts']}")
    print(f"Blob versioning enabled: {s['versioning_enabled_accounts']}, static websites: {s['static_website_accounts']}")
    print(f"Estimated total used (GB): {s['est_total_used_gb']}")
    for a in data["accounts"][:15]:
        print(f"- {a['name']} ({a['rg']}) kind={a['kind']} sku={a['sku']} used≈{a['used_gb']}GB PEs={a['private_endpoint_count']} versioning={a['blob_versioning']} public={a['public_network_access']}")
    print("")
    return data
