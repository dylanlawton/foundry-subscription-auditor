# sql_reader.py
"""
Collects Azure SQL resource details (logical servers, databases, elastic pools, and managed instances)
and produces both summary statistics and detailed lists.

Follows same design pattern as storage_reader.py and vm_reader.py.
"""

from azure.mgmt.sql import SqlManagementClient


def _safe(x, default=None):
    return x if x is not None else default


def _id_to_rg(resource_id: str) -> str:
    try:
        parts = resource_id.split("/")
        return parts[parts.index("resourceGroups") + 1]
    except Exception:
        return ""


def _db_sku_info(db):
    sku = getattr(db, "sku", None)
    if not sku:
        return ("", "Unknown", 0)
    name = _safe(getattr(sku, "name", ""), "")
    tier = _safe(getattr(sku, "tier", ""), "")
    cap = int(_safe(getattr(sku, "capacity", 0), 0))
    model = "vCore" if any(x in (tier or "").lower() for x in ["gp", "bc", "hs", "serverless"]) else "DTU"
    return (name or tier, model, cap)


def _gb_from_bytes(n) -> float:
    try:
        return round((float(n or 0) / (1024 ** 3)), 2)
    except Exception:
        return 0.0


def get_sql_details(subscription_id: str, credential, max_servers: int = 100, max_databases: int = 500):
    """
    Enumerate Azure SQL servers and databases.
    Returns a dict structure compatible with the reporting engine.
    """

    client = SqlManagementClient(credential, subscription_id)
    servers, databases, pools, mis, mi_dbs = [], [], [], [], []

    auditing_yes = threat_yes = pna_public = pe_server_total = 0
    vcore_total = dtu_total = 0

    # --- Logical Servers ---
    try:
        all_servers = list(client.servers.list())[:max_servers]
    except Exception:
        all_servers = []

    for s in all_servers:
        rg = _id_to_rg(s.id)
        name = s.name
        loc = s.location
        pna = str(_safe(getattr(s, "public_network_access", ""), ""))
        if pna.lower() != "disabled":
            pna_public += 1

        # auditing
        auditing = False
        try:
            pol = client.server_blob_auditing_policies.get(rg, name)
            auditing = getattr(pol, "state", "").lower() == "enabled"
        except Exception:
            pass
        if auditing:
            auditing_yes += 1

        # threat protection
        threat = False
        try:
            sap = client.server_security_alert_policies.get(rg, name)
            threat = getattr(sap, "state", "").lower() == "enabled"
        except Exception:
            pass
        if threat:
            threat_yes += 1

        # private endpoints
        pe_count = 0
        try:
            pe_count = len(list(client.private_endpoint_connections.list_by_server(rg, name)))
        except Exception:
            pass
        pe_server_total += pe_count

        # Databases
        db_count = 0
        try:
            for db in client.databases.list_by_server(rg, name):
                if db.name.lower() == "master":
                    continue
                db_count += 1
                sku_name, model, cap = _db_sku_info(db)
                if model == "vCore":
                    vcore_total += cap
                elif model == "DTU":
                    dtu_total += cap

                databases.append({
                    "name": db.name,
                    "server": name,
                    "rg": rg,
                    "location": loc,
                    "sku": sku_name,
                    "compute_model": model,
                    "capacity": cap,
                    "max_size_gb": _gb_from_bytes(getattr(db, "max_size_bytes", None)),
                    "zone_redundant": getattr(db, "zone_redundant", False),
                    "backup_storage_redundancy": getattr(db, "backup_storage_redundancy", "")
                })
        except Exception:
            pass

        servers.append({
            "name": name,
            "rg": rg,
            "location": loc,
            "public_network_access": pna,
            "private_endpoints": pe_count,
            "auditing": auditing,
            "threat_protection": threat,
            "db_count": db_count,
        })

    # --- Managed Instances ---
    try:
        for mi in client.managed_instances.list_by_subscription():
            rg = _id_to_rg(mi.id)
            mis.append({
                "name": mi.name,
                "rg": rg,
                "location": mi.location,
                "vcores": getattr(mi, "v_cores", 0),
                "storage_gb": getattr(mi, "storage_size_in_gb", 0),
                "license_type": getattr(mi, "license_type", ""),
                "public_data_endpoint_enabled": getattr(mi, "public_data_endpoint_enabled", False),
            })
    except Exception:
        pass

    summary = {
        "servers": len(servers),
        "databases": len(databases),
        "elastic_pools": len(pools),
        "managed_instances": len(mis),
        "mi_databases": len(mi_dbs),
        "public_access_servers": pna_public,
        "private_endpoint_servers": pe_server_total,
        "auditing_enabled_servers": auditing_yes,
        "threat_protection_enabled_servers": threat_yes,
        "vcores_total_approx": vcore_total,
        "dtu_total_approx": dtu_total,
    }

    return {
        "summary": summary,
        "servers": servers,
        "databases": databases[:max_databases],
        "elastic_pools": pools,
        "managed_instances": mis,
        "mi_databases": mi_dbs,
    }


def audit_sql(subscription_id: str, credential):
    """
    Console summary for quick checks.
    """
    try:
        data = get_sql_details(subscription_id, credential)
        s = data["summary"]
        print("\n=== Azure SQL Estate Summary ===")
        print(
            f"Servers={s['servers']}  DBs={s['databases']}  Pools={s['elastic_pools']}  "
            f"ManagedInstances={s['managed_instances']}"
        )
        print(
            f"Public-access servers={s['public_access_servers']}  "
            f"PrivateEndpointConnections={s['private_endpoint_servers']}"
        )
        print(
            f"AuditingEnabled={s['auditing_enabled_servers']}  "
            f"DefenderEnabled={s['threat_protection_enabled_servers']}"
        )
        print(f"Approx vCores={s['vcores_total_approx']}  DTUs={s['dtu_total_approx']}")
        for sv in data["servers"][:10]:
            print(f"- {sv['name']} ({sv['location']}) | PNA={sv['public_network_access']} | DBs={sv['db_count']}")
        print("")
        return data
    except Exception as e:
        print(f"[ERROR] SQL audit failed: {e}")
        return {}
