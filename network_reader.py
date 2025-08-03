from azure.identity import InteractiveBrowserCredential
from azure.mgmt.network import NetworkManagementClient

def list_virtual_networks(subscription_id):
    credential = InteractiveBrowserCredential()
    network_client = NetworkManagementClient(credential, subscription_id)

    vnets = network_client.virtual_networks.list_all()
    vnet_list = []

    for vnet in vnets:
        vnet_list.append({
            "name": vnet.name,
            "location": vnet.location,
            "address_space": vnet.address_space.address_prefixes
        })

    return vnet_list
