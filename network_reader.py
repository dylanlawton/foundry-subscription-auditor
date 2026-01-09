# network_reader.py

from typing import Dict, List, Any
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource import ResourceManagementClient


def _safe(x):
    return x or ""


def _id_to_rg(resource_id: str) -> str:
    # /subscriptions/.../resourceGroups/<rg-name>/...
    try:
        parts = resource_id.split("/")
        return parts[parts.index("resourceGroups") + 1]
    except Exception:
        return ""


def _list_by_type(subscription_id: str, credential, type_name: str) -> List[Any]:
    """
    Use ResourceManagementClient to list all resources of a given type across the subscription.
    """
    rm = ResourceManagementClient(credential, subscription_id)
    # Filter syntax: resourceType eq 'Microsoft.Network/virtualNetworkGateways'
    filt = f"resourceType eq '{type_name}'"
    return list(rm.resources.list(filter=filt))


def get_network_details(subscription_id: str, credential, max_vnets: int = 50) -> Dict[str, Any]:
    """
    Returns a dict with detailed networking info:
      {
        "summary": { ... high-level counts ... },
        "vnets": [ { name, rg, location, address_space, peered, peerings_count, subnets: [{name,nsg,udr}] , has_gateway, has_firewall } ... ],
      }
    """
    nclient = NetworkManagementClient(credential, subscription_id)

    # Subscription-wide counts via Network client where list_all exists
    try:
        nsgs = list(nclient.network_security_groups.list_all())
    except Exception:
        nsgs = []
    try:
        route_tables = list(nclient.route_tables.list_all())
    except Exception:
        route_tables = []
    try:
        app_gateways = list(nclient.application_gateways.list_all())
    except Exception:
        app_gateways = []
    try:
        load_balancers = list(nclient.load_balancers.list_all())
    except Exception:
        load_balancers = []
    try:
        public_ips = list(nclient.public_ip_addresses.list_all())
    except Exception:
        public_ips = []

    # Azure Firewall (may not be registered in all subs)
    try:
        firewalls = list(nclient.azure_firewalls.list_all())
    except Exception:
        firewalls = []

    # Items that DO NOT have list_all() in the Network client (or live under a different RP):
    gateways_res = _list_by_type(subscription_id, credential, "Microsoft.Network/virtualNetworkGateways")
    er_circuits_res = _list_by_type(subscription_id, credential, "Microsoft.Network/expressRouteCircuits")

    # Private DNS lives under Microsoft.Network but in a separate client; use RM for reliability
    priv_dns_res = _list_by_type(subscription_id, credential, "Microsoft.Network/privateDnsZones")
    priv_dns_links = _list_by_type(subscription_id, credential, "Microsoft.Network/privateDnsZones/virtualNetworkLinks")

    # Private Endpoints DO have list_all on Network client:
    try:
        private_eps = list(nclient.private_endpoints.list_all())
    except Exception:
        private_eps = []

    # Build quick lookup sets for has_* heuristics
    gateway_rg_loc = set((_id_to_rg(g.id), getattr(g, "location", None)) for g in gateways_res)
    firewall_locs = set(getattr(fw, "location", None) for fw in firewalls if getattr(fw, "location", None))

    # VNets (list_all is available)
    vnets_iter = nclient.virtual_networks.list_all()
    vnets: List[Dict[str, Any]] = []

    for v in vnets_iter:
        name = v.name
        rg = _id_to_rg(v.id)
        addr = (v.address_space.address_prefixes or []) if getattr(v, "address_space", None) else []
        location = v.location

        # Peerings
        try:
            peerings = list(nclient.virtual_network_peerings.list(rg, name))
            peered = len(peerings) > 0
            peer_ct = len(peerings)
        except Exception:
            peered = False
            peer_ct = 0

        # Subnets + NSG/UDR
        subnets_out = []
        try:
            for sn in nclient.subnets.list(rg, name):
                subnets_out.append(
                    {
                        "name": sn.name,
                        "nsg": (
                            sn.network_security_group.id.split("/")[-1]
                            if (getattr(sn, "network_security_group", None) and sn.network_security_group.id)
                            else "None"
                        ),
                        "udr": (
                            sn.route_table.id.split("/")[-1]
                            if (getattr(sn, "route_table", None) and sn.route_table.id)
                            else "None"
                        ),
                    }
                )
        except Exception:
            pass

        # Heuristic presence flags
        has_gateway = (rg, location) in gateway_rg_loc
        has_firewall = location in firewall_locs

        vnets.append(
            {
                "name": name,
                "rg": rg,
                "location": location,
                "address_space": addr,
                "peered": peered,
                "peerings_count": peer_ct,
                "subnets": subnets_out,
                "has_gateway": has_gateway,
                "has_firewall": has_firewall,
            }
        )

        if len(vnets) >= max_vnets:
            break

    summary = {
        "counts": {
            "vnets": len(vnets),
            "nsgs": len(nsgs),
            "route_tables": len(route_tables),
            "application_gateways": len(app_gateways),
            "load_balancers": len(load_balancers),
            "public_ips": len(public_ips),
            "vnet_gateways": len(gateways_res),
            "expressroute_circuits": len(er_circuits_res),
            "private_endpoints": len(private_eps),
            "private_dns_zones": len(priv_dns_res),
            "private_dns_links": len(priv_dns_links),
            "azure_firewalls": len(firewalls),
        }
    }

    return {"summary": summary, "vnets": vnets}


def audit_virtual_networks(subscription_id: str, credential) -> Dict[str, Any]:
    """
    Backwards-compatible: returns structured data.

    NOTE: Console printing removed to keep main.py output clean.
    """
    return get_network_details(subscription_id, credential, max_vnets=99999)
