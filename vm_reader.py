# vm_reader.py

from typing import Dict, List, Any
from collections import Counter
from azure.mgmt.compute import ComputeManagementClient

def _id_to_rg(resource_id: str) -> str:
    try:
        parts = resource_id.split("/")
        return parts[parts.index("resourceGroups")+1]
    except Exception:
        return ""

def _get_power_state(instance_view) -> str:
    """
    Extracts PowerState from instance view statuses, e.g. 'PowerState/running'.
    """
    try:
        for st in instance_view.statuses or []:
            if st.code and st.code.lower().startswith("powerstate/"):
                return st.code.split("/", 1)[1].capitalize()
    except Exception:
        pass
    return "Unknown"

def get_vm_details(subscription_id: str, credential, max_vms: int = 100) -> Dict[str, Any]:
    """
    Returns:
      {
        "summary": {
            "total_vms_all": <true total>,
            "total_vms": <sampled>,
            "os_counts": {...}, "size_top": [...], "power_counts": {...},
            "spot_vms": <int>, "avset_attached_vms": <int>, "identity_vms": <int>,
            "sample_note": "Detailed rows and instance views limited to first X of Y VMs."
        },
        "vms": [
          { name, rg, location, size, os, power, availability_set, priority, has_identity, identity_kind }
        ],
        "disk_summary": { total_disks, unattached_disks },
        "vmss_summary": { count }
      }
    """
    cclient = ComputeManagementClient(credential, subscription_id)

    # List ALL VMs once (cheap list operation)
    all_vms_list = list(cclient.virtual_machines.list_all())
    total_vms_all = len(all_vms_list)

    # Build detailed rows only up to max_vms
    vms: List[Dict[str, Any]] = []

    os_counts = Counter()
    size_counts = Counter()
    power_counts = Counter()
    spot_count = 0
    avset_count = 0
    identity_count = 0

    for i, vm in enumerate(all_vms_list):
        if i >= max_vms:
            break

        rg = _id_to_rg(vm.id)
        name = vm.name
        location = vm.location
        size = getattr(vm.hardware_profile, "vm_size", None) if getattr(vm, "hardware_profile", None) else None

        # OS
        os_type = None
        try:
            os_type = str(vm.storage_profile.os_disk.os_type) if vm.storage_profile and vm.storage_profile.os_disk else None
        except Exception:
            os_type = None
        if os_type:
            os_counts[os_type] += 1

        if size:
            size_counts[size] += 1

        # Power state (instance view)
        try:
            iv = cclient.virtual_machines.instance_view(rg, name)
            power = _get_power_state(iv)
        except Exception:
            power = "Unknown"
        power_counts[power] += 1

        # Availability Set
        avset = None
        try:
            avset = vm.availability_set.id.split("/")[-1] if getattr(vm, "availability_set", None) and vm.availability_set.id else None
        except Exception:
            avset = None
        if avset:
            avset_count += 1

        # Spot / priority
        priority = None
        try:
            priority = getattr(vm, "priority", None)  # "Spot" or None
        except Exception:
            priority = None
        if priority and str(priority).lower() == "spot":
            spot_count += 1

        # Managed Identity
        has_identity = False
        identity_kind = None
        try:
            if vm.identity and vm.identity.type:
                has_identity = True
                identity_kind = str(vm.identity.type)  # 'SystemAssigned', 'UserAssigned', etc.
        except Exception:
            pass
        if has_identity:
            identity_count += 1

        vms.append({
            "name": name,
            "rg": rg,
            "location": location,
            "size": size or "Unknown",
            "os": os_type or "Unknown",
            "power": power,
            "availability_set": avset or "—",
            "priority": str(priority) if priority else "Regular",
            "has_identity": has_identity,
            "identity_kind": identity_kind or "—",
        })

    # Disks (full)
    disks = list(cclient.disks.list())
    unattached = sum(1 for d in disks if not getattr(d, "managed_by", None))

    # VMSS (count, full)
    try:
        vmss_list = list(cclient.virtual_machine_scale_sets.list_all())
        vmss_count = len(vmss_list)
    except Exception:
        vmss_count = 0

    summary = {
        "total_vms_all": total_vms_all,        # TRUE total across the subscription
        "total_vms": len(vms),                 # sample size processed
        "os_counts": dict(os_counts),
        "size_top": [f"{s} ({n})" for s, n in size_counts.most_common(5)],
        "power_counts": dict(power_counts),
        "spot_vms": spot_count,
        "avset_attached_vms": avset_count,
        "identity_vms": identity_count,
        "sample_note": f"Detailed rows and instance views limited to first {len(vms)} of {total_vms_all} VMs."
    }

    return {
        "summary": summary,
        "vms": vms,
        "disk_summary": {
            "total_disks": len(disks),
            "unattached_disks": unattached
        },
        "vmss_summary": {
            "count": vmss_count
        }
    }

def audit_virtual_machines(subscription_id: str, credential) -> Dict[str, Any]:
    """
    Backwards-compatible console output + return structured data.
    """
    data = get_vm_details(subscription_id, credential, max_vms=99999)

    s = data["summary"]
    d = data["disk_summary"]
    vs = data["vmss_summary"]
    print("\nAuditing Virtual Machines:\n")
    print(f"Total VMs (all): {s.get('total_vms_all', 0)} | Sampled: {s.get('total_vms', 0)}")
    print(f"OS split (sample): {s['os_counts']}")
    print(f"Top sizes (sample): {s['size_top']}")
    print(f"Power states (sample): {s['power_counts']}")
    print(f"Spot VMs (sample): {s['spot_vms']}, AvSet-attached (sample): {s['avset_attached_vms']}, With Identity (sample): {s['identity_vms']}")
    print(f"Disks: total={d['total_disks']}, unattached={d['unattached_disks']}")
    print(f"VM Scale Sets: {vs['count']}")
    print(s.get("sample_note", ""))
    print("")
    for vm in data["vms"][:20]:
        print(f"VM: {vm['name']} ({vm['rg']}) [{vm['location']}] size={vm['size']} OS={vm['os']} power={vm['power']} "
              f"priority={vm['priority']} avset={vm['availability_set']} identity={vm['identity_kind']}")
    print("")
    return data
