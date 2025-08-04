from azure.mgmt.network import NetworkManagementClient
from ai_analyzer import analyze_virtual_network

def audit_virtual_networks(subscription_id, credential):
    client = NetworkManagementClient(credential, subscription_id)
    vnets = client.virtual_networks.list_all()

    print("\nAuditing Virtual Networks:\n")

    for vnet in vnets:
        vnet_name = vnet.name
        rg_name = vnet.id.split("/")[4]
        address_space = vnet.address_space.address_prefixes
        peerings = list(client.virtual_network_peerings.list(rg_name, vnet_name))

        subnet_info = []
        for subnet in client.subnets.list(rg_name, vnet_name):
            subnet_data = {
                "name": subnet.name,
                "nsg": subnet.network_security_group.id.split("/")[-1] if subnet.network_security_group else "None",
                "udr": subnet.route_table.id.split("/")[-1] if subnet.route_table else "None"
            }
            subnet_info.append(subnet_data)

        # Print basic details
        print(f"VNet: {vnet_name}")
        print(f"  Location: {vnet.location}")
        print(f"  Address Space: {address_space}")
        print(f"  Peered: {'Yes' if peerings else 'No'}")
        print(f"  Subnets:")
        for sn in subnet_info:
            print(f"    - {sn['name']}: NSG = {sn['nsg']}, UDR = {sn['udr']}")

        # AI Analysis
        ai_summary = analyze_virtual_network({
            "name": vnet_name,
            "location": vnet.location,
            "address_space": address_space,
            "peered": bool(peerings),
            "subnets": subnet_info
        })
        print(f"  AI Analysis: {ai_summary}\n")
