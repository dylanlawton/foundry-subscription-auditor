# governance_security_cost_reader.py
"""
Governance, Security & Cost signals for an Azure subscription.

Collects (best-effort):
- Subscription metadata (display name/state) + tenant ID
- Management Group path via Azure Resource Graph
- Policy assignments (subscription scope)
- Cost: last 5 months totals (single monthly-granularity query, retry/backoff on 429)
- Defender for Cloud: pricing/plans, secure score, alerts count

Design:
- No console output by default.
- Optional debug logging via env var: FSA_DEBUG=1
- Never raises from collector functions; returns notes instead.
"""

from __future__ import annotations

import os
import time
import random
from datetime import datetime, timezone
from typing import Any, Dict, List, Tuple, Optional

from azure.mgmt.resource import SubscriptionClient

# -------------------------
# Optional debug
# -------------------------

_DEBUG = os.getenv("FSA_DEBUG", "").strip() in ("1", "true", "True", "yes", "YES")


def _debug(msg: str) -> None:
    if _DEBUG:
        print(msg)


# -------------------------
# Optional SDK imports
# -------------------------

# Policy (comes from azure-mgmt-resource)
try:
    from azure.mgmt.resource.policy import PolicyClient
    HAS_POLICY = True
except Exception as e:
    _debug(f"[GSC][DEBUG] PolicyClient import failed: {e!r}")
    HAS_POLICY = False

# Cost Management
try:
    from azure.mgmt.costmanagement import CostManagementClient
    from azure.mgmt.costmanagement.models import (
        QueryDefinition,
        QueryDataset,
        QueryAggregation,
        QueryTimePeriod,
    )
    HAS_COST = True
except Exception as e:
    _debug(f"[GSC][DEBUG] CostManagementClient import failed: {e!r}")
    HAS_COST = False

# Defender / Security Center
try:
    from azure.mgmt.security import SecurityCenter
    HAS_SECURITY = True
except Exception as e:
    _debug(f"[GSC][DEBUG] SecurityCenter import failed: {e!r}")
    HAS_SECURITY = False

# Resource Graph (for Management Group path)
try:
    from azure.mgmt.resourcegraph import ResourceGraphClient
    from azure.mgmt.resourcegraph.models import QueryRequest, QueryRequestOptions, ResultFormat
    HAS_ARG = True
except Exception as e:
    _debug(f"[GSC][DEBUG] ResourceGraphClient import failed: {e!r}")
    HAS_ARG = False


# -------------------------
# Helpers
# -------------------------

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _safe_str(x: Any) -> str:
    return "" if x is None else str(x)


def _month_start(dt: datetime) -> datetime:
    return datetime(dt.year, dt.month, 1, tzinfo=timezone.utc)


def _add_months(dt: datetime, months: int) -> datetime:
    """
    Safe month arithmetic without extra deps.
    Returns first day of the computed month at UTC midnight.
    """
    y = dt.year
    m = dt.month + months
    while m > 12:
        y += 1
        m -= 12
    while m < 1:
        y -= 1
        m += 12
    return datetime(y, m, 1, tzinfo=timezone.utc)


# -------------------------
# Throttling / retry
# -------------------------

def _is_throttle_exc(e: Exception) -> bool:
    s = str(e).lower()
    return ("429" in s) or ("too many requests" in s) or ("thrott" in s)


def _retry(fn, *, attempts: int = 7, base_delay: float = 1.0):
    """
    Retry wrapper (primarily for Cost API throttling).
    Exponential backoff + jitter.
    """
    last: Optional[Exception] = None
    for i in range(attempts):
        try:
            return fn()
        except Exception as e:
            last = e
            if not _is_throttle_exc(e):
                raise
            delay = base_delay * (2 ** i) + random.uniform(0.0, 0.35)
            _debug(f"[GSC][DEBUG] Throttled; retrying in {delay:.2f}s (attempt {i+1}/{attempts})")
            time.sleep(delay)
    raise last  # type: ignore[misc]


def _extract_cost_rows(res: Any) -> List[list]:
    """
    CostManagement query responses differ across SDK versions.
    Handle common shapes:
      - res.rows
      - res.properties.rows
      - dict-like {"rows": ...} or {"properties":{"rows":...}}
    """
    if res is None:
        return []

    # res.rows
    try:
        rows = getattr(res, "rows", None)
        if rows is not None:
            return rows or []
    except Exception:
        pass

    # res.properties.rows
    try:
        props = getattr(res, "properties", None)
        if props is not None:
            rows = getattr(props, "rows", None)
            if rows is not None:
                return rows or []
    except Exception:
        pass

    # dict-like
    if isinstance(res, dict):
        rows = res.get("rows")
        if rows is not None:
            return rows or []
        props = res.get("properties") or {}
        rows = (props or {}).get("rows")
        if rows is not None:
            return rows or []

    return []


# -------------------------
# Management Group
# -------------------------

def _try_resource_graph_mg_path(subscription_id: str, credential) -> Dict[str, Any]:
    out = {"path": [], "leaf_mg": "", "note": ""}

    if not HAS_ARG:
        out["note"] = "Resource Graph SDK not available."
        return out

    try:
        rg = ResourceGraphClient(credential=credential)
        query = f"""
ResourceContainers
| where type == 'microsoft.resources/subscriptions'
| where subscriptionId == '{subscription_id}'
| project mgChain = properties.managementGroupAncestorsChain
"""
        req = QueryRequest(
            subscriptions=[subscription_id],
            query=query,
            options=QueryRequestOptions(result_format=ResultFormat.OBJECT_ARRAY),
        )
        resp = rg.resources(req)
        rows = resp.data or []

        if not rows:
            out["note"] = "No management group chain returned."
            return out

        chain = rows[0].get("mgChain") or []
        path: List[str] = []
        for item in chain:
            disp = item.get("displayName") or item.get("name")
            if disp:
                path.append(str(disp))

        out["path"] = path
        out["leaf_mg"] = path[-1] if path else ""
        out["note"] = "Derived from Resource Graph."
        return out

    except Exception as e:
        out["note"] = f"Failed to resolve management group path: {e}"
        return out


# -------------------------
# Policy
# -------------------------

def _try_list_policy_assignments(subscription_id: str, credential) -> Dict[str, Any]:
    out = {"assignment_count": 0, "assignments": [], "top_initiatives": [], "note": ""}

    if not HAS_POLICY:
        out["note"] = "Policy SDK not available."
        return out

    try:
        pc = PolicyClient(credential, subscription_id)
        initiatives: Dict[str, int] = {}
        assignments: List[Dict[str, Any]] = []

        for a in pc.policy_assignments.list():
            pdid = _safe_str(getattr(a, "policy_definition_id", "")).lower()
            is_init = "policysetdefinitions" in pdid

            assignments.append({
                "name": _safe_str(getattr(a, "name", None)),
                "scope": _safe_str(getattr(a, "scope", None)),
                "definition_type": "initiative" if is_init else "policy",
                "enforcement": _safe_str(getattr(a, "enforcement_mode", None)) or "Default",
            })

            if is_init:
                initiatives[pdid] = initiatives.get(pdid, 0) + 1

        out["assignment_count"] = len(assignments)
        out["assignments"] = assignments
        out["top_initiatives"] = [k for k, _ in sorted(initiatives.items(), key=lambda x: x[1], reverse=True)]
        out["note"] = "Policy assignments enumerated at subscription scope."
        return out

    except Exception as e:
        out["note"] = f"Failed to list policy assignments: {e}"
        return out


# -------------------------
# Cost (simple + robust)
# -------------------------

def _parse_monthly_rows(rows: List[list]) -> Dict[str, float]:
    """
    Attempt to map month -> cost from a monthly-granularity Cost query.

    Depending on schema, rows may look like:
      [ [<cost>, <monthKey?>, ...], ... ]
      [ [<monthKey?>, <cost>, ...], ... ]
      [ [<date>, <cost>], ... ]
      [ [<cost>], ... ]  (unlikely with Monthly, but handle defensCT

    We'll scan each row for:
      - a numeric 'cost' candidate
      - a month-like string candidate:
          '2026-01', '202601', '2026-01-01', etc.
    """
    out: Dict[str, float] = {}

    def to_float(v: Any) -> Optional[float]:
        try:
            # bool is int subclass; exclude
            if isinstance(v, bool):
                return None
            return float(v)
        except Exception:
            return None

    def to_month(v: Any) -> Optional[str]:
        if v is None:
            return None
        s = str(v).strip()
        if not s:
            return None
        # Common forms:
        #  - 2026-01-01T00:00:00Z
        #  - 2026-01-01
        #  - 2026-01
        #  - 202601
        #  - 2026/01/01
        s2 = s.replace("/", "-")
        if len(s2) >= 7 and s2[4] == "-" and s2[7:8] in ("", "-"):
            # take YYYY-MM
            return s2[:7]
        if len(s2) == 6 and s2.isdigit():
            return f"{s2[:4]}-{s2[4:]}"
        return None

    for r in rows or []:
        if not isinstance(r, (list, tuple)) or not r:
            continue

        month: Optional[str] = None
        cost: Optional[float] = None

        # Pass 1: find a month-like value
        for v in r:
            m = to_month(v)
            if m:
                month = m
                break

        # Pass 2: find a numeric cost (prefer larger magnitude if multiple numbers)
        nums: List[float] = []
        for v in r:
            f = to_float(v)
            if f is not None:
                nums.append(f)
        if nums:
            # Heuristic: cost is typically the largest absolute numeric in the row
            nums_sorted = sorted(nums, key=lambda x: abs(x), reverse=True)
            cost = nums_sorted[0]

        if month and (cost is not None):
            out[month] = float(cost)

    return out


def _try_cost_last_5_months(subscription_id: str, credential) -> Dict[str, Any]:
    """
    Returns last 5 months totals using ONE monthly-granularity Cost query (best-effort).
    Avoids top/grouping and avoids per-month loops.

    Output shape (what main.py should render):
      {
        "months": [{"month":"YYYY-MM","total":12.34}, ...],
        "note": "..."
      }
    """
    out: Dict[str, Any] = {"months": [], "note": ""}

    if not HAS_COST:
        out["note"] = "Cost Management SDK not available."
        return out

    try:
        cm = CostManagementClient(credential)
        scope = f"/subscriptions/{subscription_id}"

        now = _utcnow()
        this_month = _month_start(now)
        start = _add_months(this_month, -4)        # start of month 4 months ago
        end = _add_months(this_month, 1)           # start of next month (exclusive-ish)

        # One query: Monthly granularity, total cost aggregation.
        dataset = QueryDataset(
            granularity="Monthly",
            aggregation={"totalCost": QueryAggregation(name="Cost", function="Sum")},
        )
        q = QueryDefinition(
            type="Usage",
            timeframe="Custom",
            time_period=QueryTimePeriod(from_property=start, to=end),
            dataset=dataset,
        )

        res = _retry(lambda: cm.query.usage(scope=scope, parameters=q))
        rows = _extract_cost_rows(res)

        if not rows:
            out["note"] = "Cost query returned no rows (possible no spend, permissions, or API limits)."
            return out

        by_month = _parse_monthly_rows(rows)

        # Ensure we return exactly the last 5 months in order (even if missing -> 0.0)
        months_out: List[Dict[str, Any]] = []
        for i in range(4, -1, -1):
            m_start = _add_months(this_month, -i)
            key = f"{m_start.year}-{m_start.month:02d}"
            months_out.append({"month": key, "total": round(float(by_month.get(key, 0.0)), 2)})

        out["months"] = months_out
        out["note"] = "Cost totals retrieved (last 5 months) via Cost Management API (monthly granularity)."
        return out

    except Exception as e:
        out["note"] = f"Failed to query monthly cost totals: {e}"
        return out


# -------------------------
# Defender for Cloud
# -------------------------

def _try_defender_posture(subscription_id: str, credential) -> Dict[str, Any]:
    """
    Best-effort:
    - Plans/pricing tiers (SDK signature varies across versions)
    - Secure score (if available)
    - Alerts count (if available)
    """
    out = {"plans": [], "secure_score": None, "alerts_last_30d": None, "note": ""}

    if not HAS_SECURITY:
        out["note"] = "Security (Defender) SDK not available."
        return out

    try:
        sc = SecurityCenter(credential, subscription_id)
        scope_id = f"/subscriptions/{subscription_id}"

        # ---- Pricing/plans (signature varies) ----
        pricings = []
        pricing_err: Optional[Exception] = None

        # Try keyword form first
        try:
            pricings = list(sc.pricings.list(scope_id=scope_id))  # type: ignore[call-arg]
        except Exception as e_kw:
            pricing_err = e_kw
            # Try positional form
            try:
                pricings = list(sc.pricings.list(scope_id))  # type: ignore[misc]
                pricing_err = None
            except Exception as e_pos:
                pricing_err = e_pos
                # Try no-arg (older versions)
                try:
                    pricings = list(sc.pricings.list())
                    pricing_err = None
                except Exception as e_old:
                    pricing_err = e_old
                    pricings = []

        plans = []
        for p in pricings or []:
            try:
                plans.append({
                    "name": getattr(p, "name", "") or "",
                    "tier": getattr(p, "pricing_tier", "") or "",
                })
            except Exception:
                continue
        out["plans"] = plans

        # ---- Secure score (shape varies across versions) ----
        try:
            scores = list(sc.secure_scores.list())
            if scores:
                s = scores[0]
                out["secure_score"] = {
                    "current": float(getattr(s, "current", 0.0)),
                    "max": float(getattr(s, "max", 0.0)),
                }
        except Exception:
            out["secure_score"] = None

        # ---- Alerts (best-effort; permissions vary) ----
        try:
            out["alerts_last_30d"] = len(list(sc.alerts.list()))
        except Exception:
            out["alerts_last_30d"] = None

        # If we got secure score or alerts, treat this as success and keep the note clean.
        if out.get("secure_score") is not None or out.get("alerts_last_30d") is not None:
            out["note"] = "Defender posture retrieved from Security Center."
        elif plans:
            out["note"] = "Defender pricing/plans retrieved from Security Center."
        else:
            out["note"] = "Failed to retrieve Defender posture (insufficient permissions or API limits)."
        return out

    except Exception as e:
        out["note"] = f"Failed to query Defender posture: {e}"
        return out


# -------------------------
# Public entry point
# -------------------------

def get_governance_security_cost_details(
    subscription_id: str,
    tenant_id: str,
    credential,
) -> Dict[str, Any]:
    sub = {
        "subscription_id": subscription_id,
        "display_name": "",
        "state": "",
        "tenant_id": tenant_id,
        "note": "",
    }

    try:
        s = SubscriptionClient(credential).subscriptions.get(subscription_id)
        sub["display_name"] = getattr(s, "display_name", "") or ""
        sub["state"] = getattr(s, "state", "") or ""
        sub["note"] = "Subscription metadata retrieved."
    except Exception as e:
        sub["note"] = f"Failed to retrieve subscription metadata: {e}"

    return {
        "subscription": sub,
        "management_group": _try_resource_graph_mg_path(subscription_id, credential),
        "policy": _try_list_policy_assignments(subscription_id, credential),
        "cost": _try_cost_last_5_months(subscription_id, credential),
        "defender": _try_defender_posture(subscription_id, credential),
    }
