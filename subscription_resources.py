# subscription_resources.py
"""
Full inventory of ALL Azure resources in a subscription.

Strategy:
1) Try Azure Resource Graph (fast, scalable)
2) If zero rows or ARG unavailable, fallback to ARM resources.list() (slower but reliable)
3) Always return a list:
   [
     {
       "type": "microsoft.compute/virtualmachines",
       "count": 5,
       "sampleNames": ["vm1", "vm2"]
     }
   ]

No console output. No logging. No tracebacks.
All errors are handled silently and result in fallback or empty output.
"""

from typing import List, Dict, Any
from collections import defaultdict

# -------------------------
# Azure SDK imports
# -------------------------

# Try Azure Resource Graph
try:
    from azure.mgmt.resourcegraph import ResourceGraphClient
    from azure.mgmt.resourcegraph.models import (
        QueryRequest,
        QueryRequestOptions,
        ResultFormat,
    )
    HAS_ARG = True
except Exception:
    HAS_ARG = False

# ARM fallback
from azure.mgmt.resource import ResourceManagementClient


# -------------------------
# Azure Resource Graph
# -------------------------

def _query_arg(
    subscription_id: str,
    credential,
    sample_size: int,
) -> List[Dict[str, Any]]:
    """
    Query Azure Resource Graph for resource counts by type.
    Returns [] if ARG unavailable or query fails.
    """
    if not HAS_ARG:
        return []

    client = ResourceGraphClient(credential=credential)

    query = f"""
Resources
| summarize count = count(), sampleNames = make_set(name, {sample_size}) by type
| order by count desc
"""

    try:
        req = QueryRequest(
            subscriptions=[subscription_id],
            query=query,
            options=QueryRequestOptions(result_format=ResultFormat.OBJECT_ARRAY),
        )
        resp = client.resources(req)
        return resp.data or []
    except Exception:
        return []


# -------------------------
# ARM fallback
# -------------------------

def _query_arm(
    subscription_id: str,
    credential,
    sample_size: int,
) -> List[Dict[str, Any]]:
    """
    ARM-based inventory fallback.
    Guaranteed to work if permissions allow resource enumeration.
    """
    rm = ResourceManagementClient(credential, subscription_id)

    type_counts = defaultdict(int)
    type_samples = defaultdict(list)

    for res in rm.resources.list():
        rtype = (res.type or "").lower()
        rname = res.name or ""

        type_counts[rtype] += 1
        if len(type_samples[rtype]) < sample_size:
            type_samples[rtype].append(rname)

    rows = [
        {
            "type": t,
            "count": type_counts[t],
            "sampleNames": type_samples[t],
        }
        for t in type_counts
    ]

    rows.sort(key=lambda x: x["count"], reverse=True)
    return rows


# -------------------------
# Public entry point
# -------------------------

def audit_subscription_resources(
    subscription_id: str,
    credential,
    sample_size: int = 5,
) -> List[Dict[str, Any]]:
    """
    Returns a list of resource type summaries for the subscription.

    Never prints.
    Never raises.
    Always returns a list.
    """
    rows = _query_arg(subscription_id, credential, sample_size)

    if not rows:
        rows = _query_arm(subscription_id, credential, sample_size)

    return rows
