# subscription_resources.py
"""
Full inventory of ALL Azure resources in a subscription.

Strategy:
1) Try Azure Resource Graph (fast, scalable)
2) If zero rows or ARG unavailable, fallback to ARM resources.list() (slower but guaranteed)
3) Always return a list:
   [
     {"type": "microsoft.compute/virtualmachines", "count": 5, "sampleNames": ["vm1","vm2"]}
   ]
"""

from typing import List, Dict, Any
from collections import defaultdict
import traceback

# --- Try ARG imports ---
try:
    from azure.mgmt.resourcegraph import ResourceGraphClient
    from azure.mgmt.resourcegraph.models import QueryRequest, QueryRequestOptions, ResultFormat
    HAS_ARG = True
except Exception:
    HAS_ARG = False

# ARM fallback
from azure.mgmt.resource import ResourceManagementClient

def _preview(rows: List[Dict[str, Any]], limit=20):
    print(f"[INFO] Resource type categories discovered: {len(rows)}")
    for r in rows[:limit]:
        samples = r.get("sampleNames", []) or []
        print(f"  - {r['type']} : {r['count']} (examples: {', '.join(samples[:3])})")
    if len(rows) > limit:
        print(f"  ... +{len(rows) - limit} more")

def _query_arg(subscription_id: str, credential, sample_size: int) -> List[Dict[str, Any]]:
    if not HAS_ARG:
        print("[WARN] Resource Graph SDK not present.")
        return []

    print("[INFO] Trying Azure Resource Graph inventory...")
    client = ResourceGraphClient(credential=credential)

    query = f"""
Resources
| summarize count = count(), sampleNames = make_set(name, {sample_size}) by type
| order by count desc
"""

    req = QueryRequest(
        subscriptions=[subscription_id],
        query=query,
        options=QueryRequestOptions(result_format=ResultFormat.OBJECT_ARRAY)
    )

    resp = client.resources(req)
    rows = resp.data or []
    print(f"[DEBUG] ARG returned rows: {len(rows)}")
    return rows

def _query_arm(subscription_id: str, credential, sample_size: int) -> List[Dict[str, Any]]:
    print("[INFO] ARG returned zero. Falling back to ARM resources.list() ...")

    rm = ResourceManagementClient(credential, subscription_id)
    type_counts = defaultdict(int)
    type_samples = defaultdict(list)

    count_total = 0
    for res in rm.resources.list():
        rtype = (res.type or "").lower()
        rname = res.name or ""

        type_counts[rtype] += 1
        if len(type_samples[rtype]) < sample_size:
            type_samples[rtype].append(rname)
        count_total += 1

    print(f"[DEBUG] ARM total resources discovered: {count_total}")

    rows = [
        {"type": t, "count": type_counts[t], "sampleNames": type_samples[t]}
        for t in type_counts
    ]
    rows.sort(key=lambda x: x["count"], reverse=True)
    return rows

def audit_subscription_resources(subscription_id: str, credential, sample_size=5) -> List[Dict[str, Any]]:
    print("\n=== Subscription Resource Inventory (ALL resources) ===\n")

    try:
        rows = _query_arg(subscription_id, credential, sample_size)
    except Exception as e:
        print(f"[WARN] ARG query failed: {e}")
        traceback.print_exc()
        rows = []

    if not rows:
        try:
            rows = _query_arm(subscription_id, credential, sample_size)
        except Exception as e:
            print(f"[ERROR] ARM fallback also failed: {e}")
            traceback.print_exc()
            rows = []

    _preview(rows)
    return rows
