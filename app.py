"""
app.py — Foundry Subscription Auditor (Flask on Azure App Service Linux)

Auth model:
- App Service "Easy Auth" handles sign-in.
- Easy Auth injects headers:
  - X-MS-CLIENT-PRINCIPAL (base64 JSON claims)
  - X-MS-TOKEN-AAD-ID-TOKEN
  - X-MS-TOKEN-AAD-ACCESS-TOKEN

Goal:
- Use the signed-in user's identity to call Azure Resource Manager (ARM)
  and list subscriptions the user can see.

Implementation:
- Try ARM call with Easy Auth access token (may fail if token audience is Graph)
- If it fails, do OBO (On-Behalf-Of) using MSAL confidential client:
  exchange the user's token for an ARM-scoped token.

Required App Settings (for OBO fallback):
- AZURE_TENANT_ID
- AZURE_CLIENT_ID
- AZURE_CLIENT_SECRET

Startup command (App Service → Stack settings):
- gunicorn --bind=0.0.0.0:8000 app:app
"""

from __future__ import annotations

import base64
import json
import os
from typing import Any, Dict, Optional, Tuple

import msal
import requests
from flask import Flask, jsonify, request

app = Flask(__name__)

ARM_SUBS_URL = "https://management.azure.com/subscriptions?api-version=2020-01-01"


# ----------------------------
# Helpers
# ----------------------------
def _env(name: str, default: Optional[str] = None) -> Optional[str]:
    v = os.getenv(name)
    return v if v not in ("", None) else default


def decode_easy_auth_principal() -> Optional[Dict[str, Any]]:
    """
    Decode X-MS-CLIENT-PRINCIPAL which is base64 JSON.
    """
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


def try_list_subscriptions_with_token(access_token: str) -> requests.Response:
    """
    Call ARM list subscriptions with a given bearer token.
    """
    return requests.get(ARM_SUBS_URL, headers=bearer(access_token), timeout=30)


def obo_arm_token(user_assertion_jwt: str) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    """
    On-Behalf-Of flow: exchange the user's token for an ARM token.
    Returns (access_token, error_dict).
    """
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

    # Request ARM scope
    result = cca.acquire_token_on_behalf_of(
        user_assertion=user_assertion_jwt,
        scopes=["https://management.azure.com/.default"],
    )

    if "access_token" in result:
        return result["access_token"], None

    # Return the full MSAL error payload for troubleshooting
    return None, result


def body_snippet(text: str, limit: int = 600) -> str:
    if not text:
        return ""
    return text[:limit]


# ----------------------------
# Routes
# ----------------------------
@app.get("/")
def health():
    """
    Simple health endpoint.
    """
    return jsonify({"status": "ok"})


@app.get("/whoami")
def whoami():
    """
    Shows Easy Auth principal + whether relevant headers exist.
    """
    principal = decode_easy_auth_principal()
    return jsonify(
        {
            "is_azure": bool(_env("WEBSITE_INSTANCE_ID")),
            "headers_present": {
                "X-MS-CLIENT-PRINCIPAL": bool(request.headers.get("X-MS-CLIENT-PRINCIPAL")),
                "X-MS-TOKEN-AAD-ACCESS-TOKEN": bool(get_easy_auth_access_token()),
                "X-MS-TOKEN-AAD-ID-TOKEN": bool(get_easy_auth_id_token()),
            },
            "principal": principal,
            "tips": {
                "logout_url": "/.auth/logout",
                "login_hint": "If tokens look stale, open /.auth/logout then refresh /whoami.",
            },
        }
    )


@app.get("/subscriptions")
def subscriptions():
    """
    List subscriptions visible to the signed-in user.

    Step 1: try Easy Auth access token directly (often Graph audience -> fails)
    Step 2: do OBO to ARM and retry
    """
    first_attempt: Dict[str, Any] = {}

    # 1) Try Easy Auth access token directly
    easy_access = get_easy_auth_access_token()
    if easy_access:
        r = try_list_subscriptions_with_token(easy_access)
        if r.status_code == 200:
            return jsonify({"source": "easy_auth_access_token", **r.json()})

        first_attempt = {
            "status_code": r.status_code,
            "body_snippet": body_snippet(r.text),
            "note": "Easy Auth access token failed for ARM (often wrong audience or expired).",
        }
    else:
        first_attempt = {"error": "No X-MS-TOKEN-AAD-ACCESS-TOKEN header present."}

    # 2) OBO fallback
    # Prefer ID token as assertion; if not present, fall back to access token.
    user_assertion = get_easy_auth_id_token() or get_easy_auth_access_token()
    if not user_assertion:
        return (
            jsonify(
                {
                    "error": "No user token available from Easy Auth headers for OBO.",
                    "first_attempt": first_attempt,
                }
            ),
            401,
        )

    arm_token, obo_error = obo_arm_token(user_assertion)
    if not arm_token:
        return (
            jsonify(
                {
                    "error": "ARM token not available (OBO failed).",
                    "first_attempt": first_attempt,
                    "obo_error": obo_error,
                    "next_steps": [
                        "Confirm AZURE_TENANT_ID/AZURE_CLIENT_ID/AZURE_CLIENT_SECRET are set in App Settings.",
                        "Confirm API permissions include 'Azure Service Management' delegated 'user_impersonation' and consent is granted.",
                        "Try /.auth/logout then re-login to refresh user tokens.",
                    ],
                }
            ),
            500,
        )

    r2 = try_list_subscriptions_with_token(arm_token)
    if r2.status_code == 200:
        return jsonify({"source": "obo_arm_token", **r2.json()})

    return (
        jsonify(
            {
                "error": "ARM call failed even after OBO.",
                "first_attempt": first_attempt,
                "obo_attempt": {"status_code": r2.status_code, "body_snippet": body_snippet(r2.text)},
                "next_steps": [
                    "Check user RBAC to subscriptions (Reader or above).",
                    "If 401, verify scope/audience and that Entra app is configured correctly.",
                ],
            }
        ),
        r2.status_code,
    )
