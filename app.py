"""
app.py — Foundry Subscription Auditor (Flask on Azure App Service Linux)

Auth model:
- App Service "Easy Auth" handles sign-in.
- Easy Auth injects headers:
  - X-MS-CLIENT-PRINCIPAL (base64 JSON claims)
  - X-MS-TOKEN-AAD-ID-TOKEN
  - X-MS-TOKEN-AAD-ACCESS-TOKEN

Goal:
- Use signed-in user identity to call ARM and list subscriptions.
- Provide /subscriptions/simple for UI list.
- Provide /run (Option B): async audit run returning run_id + poll endpoint.
"""

from __future__ import annotations

import base64
import json
import os
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import msal
import requests
from flask import Flask, jsonify, request

from token_credential import StaticTokenCredential
from audit_runner import run_audit

app = Flask(__name__)

ARM_SUBS_URL = "https://management.azure.com/subscriptions?api-version=2020-01-01"

# NEW: simple version stamp (set APP_VERSION in App Settings if you want)
APP_VERSION = os.getenv("APP_VERSION", "2.1-option-b")


# ----------------------------
# Helpers
# ----------------------------
def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _env(name: str, default: Optional[str] = None) -> Optional[str]:
    v = os.getenv(name)
    return v if v not in ("", None) else default


def decode_easy_auth_principal() -> Optional[Dict[str, Any]]:
    b64 = request.headers.get("X-MS-CLIENT-PRINCIPAL")
    if not b64:
        return None
    try:
        decoded = base64.b64decode(b64).decode("utf-8")
        return json.loads(decoded)
    except Exception as e:
        return {"error": f"Failed to decode principal: {e}"}


def bearer(token: str) -> Dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def get_easy_auth_access_token() -> Optional[str]:
    return request.headers.get("X-MS-TOKEN-AAD-ACCESS-TOKEN")


def get_easy_auth_id_token() -> Optional[str]:
    return request.headers.get("X-MS-TOKEN-AAD-ID-TOKEN")


def body_snippet(text: str, limit: int = 600) -> str:
    return (text or "")[:limit]


def try_list_subscriptions_with_token(access_token: str) -> requests.Response:
    return requests.get(ARM_SUBS_URL, headers=bearer(access_token), timeout=30)


def obo_arm_token(user_assertion_jwt: str) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    tenant_id = _env("AZURE_TENANT_ID")
    client_id = _env("AZURE_CLIENT_ID")
    client_secret = _env("AZURE_CLIENT_SECRET")

    if not (tenant_id and client_id and client_secret):
        return None, {
            "error": "Missing required App Settings for OBO.",
            "required": ["AZURE_TENANT_ID", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET"],
            "present": {
                "AZURE_TENANT_ID": bool(tenant_id),
                "AZURE_CLIENT_ID": bool(client_id),
                "AZURE_CLIENT_SECRET": bool(client_secret),
            },
        }

    authority = f"https://login.microsoftonline.com/{tenant_id}"
    cca = msal.ConfidentialClientApplication(
        client_id=client_id,
        authority=authority,
        client_credential=client_secret,
    )

    result = cca.acquire_token_on_behalf_of(
        user_assertion=user_assertion_jwt,
        scopes=["https://management.azure.com/.default"],
    )

    if "access_token" in result:
        return result["access_token"], None

    return None, result


def get_arm_token_for_request() -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    user_assertion = get_easy_auth_id_token() or get_easy_auth_access_token()
    if not user_assertion:
        return None, {"error": "No Easy Auth token headers present for OBO."}
    return obo_arm_token(user_assertion)


def normalize_subscriptions(payload: Dict[str, Any]) -> Dict[str, Any]:
    items = payload.get("value", []) or []
    simple = [
        {
            "subscriptionId": s.get("subscriptionId"),
            "displayName": s.get("displayName"),
            "state": s.get("state"),
            "tenantId": s.get("tenantId"),
        }
        for s in items
    ]
    enabled = [x for x in simple if (x.get("state") or "").lower() == "enabled"]
    return {
        "count": len(simple),
        "enabled_count": len(enabled),
        "subscriptions": simple,
        "enabled_subscriptions": enabled,
    }


def _outputs_root() -> Path:
    return Path(_env("OUTPUTS_ROOT", "/tmp/outputs"))


def _run_dir(run_id: str) -> Path:
    return _outputs_root() / run_id


def _write_json(p: Path, obj: Any) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, indent=2), encoding="utf-8")


def _read_json(p: Path) -> Optional[Dict[str, Any]]:
    if not p.exists():
        return None
    return json.loads(p.read_text(encoding="utf-8"))


# ----------------------------
# Routes
# ----------------------------
@app.get("/")
def health():
    return jsonify({"status": "ok", "version": APP_VERSION})


@app.get("/whoami")
def whoami():
    principal = decode_easy_auth_principal()
    return jsonify(
        {
            "version": APP_VERSION,
            "is_azure": bool(_env("WEBSITE_INSTANCE_ID")),
            "headers_present": {
                "X-MS-CLIENT-PRINCIPAL": bool(request.headers.get("X-MS-CLIENT-PRINCIPAL")),
                "X-MS-TOKEN-AAD-ACCESS-TOKEN": bool(get_easy_auth_access_token()),
                "X-MS-TOKEN-AAD-ID-TOKEN": bool(get_easy_auth_id_token()),
            },
            "principal": principal,
            "tips": {"logout_url": "/.auth/logout"},
        }
    )


@app.get("/subscriptions/simple")
def subscriptions_simple():
    arm_token, obo_error = get_arm_token_for_request()
    if not arm_token:
        return jsonify({"error": "Could not obtain ARM token", "details": obo_error}), 401

    r = try_list_subscriptions_with_token(arm_token)
    if r.status_code != 200:
        return (
            jsonify(
                {
                    "error": "ARM subscriptions call failed",
                    "status_code": r.status_code,
                    "body_snippet": body_snippet(r.text),
                }
            ),
            r.status_code,
        )

    return jsonify(normalize_subscriptions(r.json()))


@app.post("/run")
def run_async():
    """
    OPTION B (async):
    - POST /run starts a run and immediately returns run_id (202 Accepted)
    - GET /run/<run_id> returns status/results

    Body:
      {
        "subscriptionId": "<guid>",
        "outputDir": "/tmp/outputs"  # optional override
      }
    """
    body = request.get_json(silent=True) or {}
    subscription_id = body.get("subscriptionId") or body.get("subscription_id")
    if not subscription_id:
        return jsonify({"error": "Missing subscriptionId"}), 400

    arm_token, obo_error = get_arm_token_for_request()
    if not arm_token:
        return jsonify({"error": "Could not obtain ARM token via OBO", "details": obo_error}), 401

    # Create run
    run_id = f"{subscription_id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
    out_root = Path(body.get("outputDir") or body.get("output_dir") or str(_outputs_root()))
    run_path = out_root / run_id

    status_path = run_path / "status.json"
    result_path = run_path / "result.json"

    _write_json(
        status_path,
        {
            "run_id": run_id,
            "subscription_id": subscription_id,
            "status": "running",
            "started_utc": _utc_now(),
        },
    )

    def _worker():
        try:
            credential = StaticTokenCredential(arm_token)
            results = run_audit(
                subscription_id=subscription_id,
                credential=credential,
                output_dir=str(run_path),
            )
            _write_json(result_path, results)
            _write_json(
                status_path,
                {
                    "run_id": run_id,
                    "subscription_id": subscription_id,
                    "status": "succeeded",
                    "started_utc": _read_json(status_path).get("started_utc") if _read_json(status_path) else None,
                    "finished_utc": _utc_now(),
                },
            )
        except Exception as e:
            _write_json(
                status_path,
                {
                    "run_id": run_id,
                    "subscription_id": subscription_id,
                    "status": "failed",
                    "finished_utc": _utc_now(),
                    "error": str(e),
                },
            )

    t = threading.Thread(target=_worker, daemon=True)
    t.start()

    return (
        jsonify(
            {
                "run_id": run_id,
                "subscription_id": subscription_id,
                "status": "running",
                "poll": f"/run/{run_id}",
                "output_dir": str(run_path),
                "version": APP_VERSION,
            }
        ),
        202,
    )


@app.get("/run/<run_id>")
def run_status(run_id: str):
    """
    Poll endpoint for Option B.
    Returns status.json always; includes result.json when present.
    """
    base = _outputs_root()
    status_path = base / run_id / "status.json"
    result_path = base / run_id / "result.json"

    status = _read_json(status_path)
    if not status:
        return jsonify({"error": "run_id not found", "run_id": run_id, "version": APP_VERSION}), 404

    result = _read_json(result_path)
    payload = {"status": status, "result": result, "version": APP_VERSION}
    return jsonify(payload)
