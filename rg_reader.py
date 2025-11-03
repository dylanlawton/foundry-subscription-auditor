# rg_reader.py

from typing import Dict, List, Any
from collections import Counter
from azure.mgmt.resource import ResourceManagementClient

def _top_types(items: List[str], k=3) -> List[str]:
    c = Counter(items)
    return [f"{t} ({n})" for t, n in c.most_common(k)]

def _fmt_tags(tags: dict, limit=5) -> str:
    if not tags:
        return "None"
    items = [f"{k}={v}" for k, v in list(tags.items())[:limit]]
    more = len(tags) - len(items)
    return ", ".join(items) + (f" (+{more} more)" if more > 0 else "")

def get_rg_details(subscription_id: str, credential, max_groups: int = 100) -> Dict[str, Any]:
    """
    Returns a dict:
      {
        "summary": { "total_rgs": N },
        "groups": [
           { name, location, tags_text, resource_count, top_types_text }
        ]
      }
    """
    client = ResourceManagementClient(credential, subscription_id)

    out_groups: List[Dict[str, Any]] = []
    rgs = list(client.resource_groups.list())

    for rg in rgs[:max_groups]:
        name = rg.name
        location = rg.location
        tags_text = _fmt_tags(rg.tags or {})

        # list resources in RG
        res_types = []
        res_count = 0
        try:
            for r in client.resources.list_by_resource_group(name):
                res_count += 1
                if getattr(r, "type", None):
                    res_types.append(r.type.lower())
        except Exception:
            pass

        top_types = _top_types(res_types, k=4)
        top_types_text = ", ".join(top_types) if top_types else "—"

        out_groups.append({
            "name": name,
            "location": location,
            "tags": tags_text,
            "resource_count": res_count,
            "top_types": top_types_text,
        })

    return {
        "summary": { "total_rgs": len(rgs) },
        "groups": out_groups
    }

def audit_resource_groups(subscription_id: str, credential) -> Dict[str, Any]:
    """
    Backwards-compatible: prints summary to console AND returns structured data.
    """
    data = get_rg_details(subscription_id, credential, max_groups=99999)

    print("\nAuditing Resource Groups:\n")
    print(f"Total RGs: {data['summary']['total_rgs']}")
    for g in data["groups"]:
        print(f"RG: {g['name']} ({g['location']})")
        print(f"  Tags: {g['tags']}")
        print(f"  Resources: {g['resource_count']}")
        print(f"  Top Types: {g['top_types']}")
        print("")

    return data
