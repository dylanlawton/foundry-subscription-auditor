from azure.mgmt.network import NetworkManagementClient
from ai_analyzer import analyze_virtual_network_detailed

def audit_virtual_networks(subscription_id, credential):
    client = NetworkManagementClient(credential, subscription_id)
    vnets = client.virtual_networks.list_all()

    print("\nAuditing Virtual Networks:\n")

    for vnet in vnets:
        vnet_name = vnet.name
        rg_name = vnet.id.split("/")[4]
        address_space = vnet.address_space.address_prefixes

        # Peering
        peerings = list(client.virtual_network_peerings.list(rg_name, vnet_name))
        is_peered = len(peerings) > 0

        # Subnet NSG and UDR
        subnet_info = []
        for subnet in client.subnets.list(rg_name, vnet_name):
            subnet_data = {
                "name": subnet.name,
                "nsg": subnet.network_security_group.id.split("/")[-1] if subnet.network_security_group else "None",
                "udr": subnet.route_table.id.split("/")[-1] if subnet.route_table else "None"
            }
            subnet_info.append(subnet_data)

        # Azure Firewall detection
        firewalls = list(client.azure_firewalls.list_all())
        has_firewall = any(fw.location == vnet.location for fw in firewalls)

        # ExpressRoute circuits
        circuits = list(client.express_route_circuits.list_all())
        has_expressroute = any(circuit.location == vnet.location for circuit in circuits)

        # Virtual Network Gateway (VPN / ExpressRoute Gateway)
        gateways = list(client.virtual_network_gateways.list(rg_name))
        has_vnet_gateway = any(gw.location == vnet.location for gw in gateways)
        has_site_to_site_vpn = any(gw.gateway_type == "Vpn" and "VpnClientConfiguration" in str(gw) for gw in gateways)

        # Print core info
        print(f"VNet: {vnet_name}")
        print(f"  Location: {vnet.location}")
        print(f"  Address Space: {address_space}")
        print(f"  Peered: {'Yes' if is_peered else 'No'}")
        print(f"  Has Azure Firewall: {'Yes' if has_firewall else 'No'}")
        print(f"  Has ExpressRoute: {'Yes' if has_expressroute else 'No'}")
        print(f"  Has VNet Gateway: {'Yes' if has_vnet_gateway else 'No'}")
        print(f"  Site-to-Site VPN Configured: {'Yes' if has_site_to_site_vpn else 'No'}")
        print("  Subnets:")
        for sn in subnet_info:
            print(f"    - {sn['name']}: NSG = {sn['nsg']}, UDR = {sn['udr']}")

        # Call AI analysis
        ai_summary = analyze_virtual_network_detailed({
            "name": vnet_name,
            "location": vnet.location,
            "address_space": address_space,
            "peered": is_peered,
            "subnets": subnet_info,
            "has_firewall": has_firewall,
            "expressroute": has_expressroute,
            "has_gateway": has_vnet_gateway,
            "site_to_site_vpn": has_site_to_site_vpn
        })

        print(f"  AI Analysis: {ai_summary}\n")
