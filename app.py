"""
app.py — Foundry Subscription Auditor (Flask on Azure App Service Linux)

Auth model:
- App Service "Easy Auth" handles sign-in.
- Easy Auth injects headers:
  - X-MS-CLIENT-PRINCIPAL (base64 JSON claims)
  - X-MS-TOKEN-AAD-ID-TOKEN
  - X-MS-TOKEN-AAD-ACCESS-TOKEN

Goal:
- Use signed-in user identity to call ARM (delegated) via OBO.
- Provide /subscriptions/simple for UI dropdown list.
- Provide /run (async audit run) and /run/<id> polling.
- Serve /outputs/<run_id>/report.html as a clickable report link.
- Provide /ui minimal UX that ALSO allows custom AI prompts per run.

Multi-tenant note:
- Default OBO authority uses tid from the signed-in user principal ('tid' claim) when available.
- Fallback to AZURE_TENANT_ID if tid is unavailable (keeps single-tenant behaviour working).

Tenant forcing note (v2.7-multitenant + GUID):
- /auth/tenant?tid=<tenant-guid> redirects browser to Entra authorize endpoint for that tenant
  using Easy Auth callback as redirect_uri. Helpful when you want the browser session tid to change.

Option 1 note (v2.8-option1-tenant-test):
- Adds /subscriptions/tenant?tid=<tenant-guid> which *keeps Easy Auth unchanged*
  and instead requests an ARM token via OBO against the specified tenant authority.
  This is the clean "guest tenant test" endpoint.

Health / startup stability note:
- When Easy Auth is set to "Require authentication" globally, platform health probes can receive 302/401 and
  mistakenly treat the container as unhealthy, causing restart loops / SiteStartupCancelled.
- Fix: expose an unauthenticated /healthz endpoint, exclude it from Easy Auth protection, and point App Service
  Health Check at /healthz.
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
from urllib.parse import urlencode

import msal
import requests
from flask import Flask, jsonify, request, send_from_directory

from token_credential import StaticTokenCredential
from audit_runner import run_audit

app = Flask(__name__)

ARM_SUBS_URL = "https://management.azure.com/subscriptions?api-version=2020-01-01"
APP_VERSION = os.getenv("APP_VERSION", "2.8-option1-tenant-test")


# ----------------------------
# Helpers
# ----------------------------
def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _env(name: str, default: Optional[str] = None) -> Optional[str]:
    v = os.getenv(name)
    return v if v not in ("", None) else default


def _https_host_url() -> str:
    """
    App Service often forwards requests internally over http, so request.host_url may be http://...
    For redirect URIs registered in Entra, we want https://... to avoid AADSTS50011.
    """
    return request.host_url.replace("http://", "https://").rstrip("/")


def decode_easy_auth_principal() -> Optional[Dict[str, Any]]:
    b64 = request.headers.get("X-MS-CLIENT-PRINCIPAL")
    if not b64:
        return None
    try:
        decoded = base64.b64decode(b64).decode("utf-8")
        return json.loads(decoded)
    except Exception as e:
        return {"error": f"Failed to decode principal: {e}"}


def _principal_claim(principal: Optional[Dict[str, Any]], claim_types: Tuple[str, ...]) -> Optional[str]:
    if not principal:
        return None
    claims = principal.get("claims") or []
    for c in claims:
        typ = (c.get("typ") or "").strip()
        if typ in claim_types:
            val = (c.get("val") or "").strip()
            return val or None
    return None


def get_tid_from_principal() -> Optional[str]:
    """
    Best-effort tenant id from Easy Auth principal.
    Common claim types seen:
      - 'tid'
      - 'http://schemas.microsoft.com/identity/claims/tenantid'
    """
    p = decode_easy_auth_principal()
    return _principal_claim(p, ("tid", "http://schemas.microsoft.com/identity/claims/tenantid"))


def get_upn_from_principal() -> Optional[str]:
    p = decode_easy_auth_principal()
    return _principal_claim(
        p,
        (
            "preferred_username",
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn",
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
        ),
    )


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


def _looks_like_guid(s: str) -> bool:
    # loose check: 36 chars including hyphens; good enough for UI guardrails
    s = (s or "").strip()
    return len(s) == 36 and s.count("-") == 4


def obo_arm_token(
    user_assertion_jwt: str, tenant_id_override: Optional[str] = None
) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    """
    OBO flow:
    - user_assertion_jwt comes from Easy Auth (ID token or access token)
    - exchange for ARM token: https://management.azure.com/.default

    Multi-tenant:
    - prefer tenant_id_override (tid, or explicit test tenant id)
    - fallback to AZURE_TENANT_ID (keeps existing behaviour working)
    """
    tenant_id = (tenant_id_override or "").strip() or _env("AZURE_TENANT_ID")
    client_id = _env("AZURE_CLIENT_ID")
    client_secret = _env("AZURE_CLIENT_SECRET")

    if not (tenant_id and client_id and client_secret):
        return None, {
            "error": "Missing required App Settings for OBO.",
            "required": ["AZURE_TENANT_ID (or tid override)", "AZURE_CLIENT_ID", "AZURE_CLIENT_SECRET"],
            "present": {
                "AZURE_TENANT_ID": bool(_env("AZURE_TENANT_ID")),
                "tenant_id_override": bool(tenant_id_override),
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


def _get_user_assertion() -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    """
    Prefer ID token as user assertion, fallback to access token.
    """
    user_assertion = get_easy_auth_id_token() or get_easy_auth_access_token()
    if not user_assertion:
        return None, {"error": "No Easy Auth token headers present for OBO."}
    return user_assertion, None


def get_arm_token_for_request() -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    """
    Default behaviour:
    - OBO authority uses tid from current signed-in principal, else env AZURE_TENANT_ID.
    """
    user_assertion, err = _get_user_assertion()
    if not user_assertion:
        return None, err
    tid = get_tid_from_principal()
    return obo_arm_token(user_assertion, tenant_id_override=tid)


def get_arm_token_for_tenant(tenant_id: str) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    """
    Option 1 behaviour:
    - Keep Easy Auth unchanged.
    - Explicitly request ARM token via OBO against a specified tenant authority.
    """
    user_assertion, err = _get_user_assertion()
    if not user_assertion:
        return None, err
    return obo_arm_token(user_assertion, tenant_id_override=tenant_id)


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


def _trim_prompt(s: Any, max_len: int = 12000) -> Optional[str]:
    if s is None:
        return None
    t = str(s).strip()
    if not t:
        return None
    return t[:max_len]


# ----------------------------
# Routes
# ----------------------------
@app.get("/")
def health():
    return jsonify({"status": "ok", "version": APP_VERSION})


@app.get("/healthz")
def healthz():
    """
    Unauthenticated health endpoint for Azure App Service Health Check / container probes.

    IMPORTANT:
    - Add /healthz to Easy Auth "Excluded paths" (or allow anonymous access to selected paths).
    - Configure App Service Health Check to use /healthz.

    This prevents restart loops when authentication is required for other routes.
    """
    return "ok", 200


@app.get("/prompts/defaults")
def prompt_defaults():
    """
    Returns server-side defaults. These are NOT secrets.
    (Do not return OpenAI keys etc.)
    """
    return jsonify(
        {
            "report_system_prompt": os.getenv("REPORT_SYSTEM_PROMPT", ""),
            "report_angle_text": os.getenv("REPORT_ANGLE_TEXT", ""),
        }
    )


@app.get("/auth/tenant")
def auth_tenant():
    """
    Force sign-in against a specific tenant GUID by sending the browser to:
      https://login.microsoftonline.com/<tenant>/oauth2/v2.0/authorize

    redirect_uri points at Easy Auth callback:
      https://<host>/.auth/login/aad/callback

    Notes:
    - This relies on the Easy Auth callback being configured as a redirect URI in the App Registration.
    - This does not change your OBO design; it only helps establish a session with tid=<tenant>.
    - We force https to avoid AADSTS50011 due to proxy/http host_url.
    """
    tenant = (request.args.get("tid") or "").strip()
    if not tenant:
        return jsonify({"error": "Missing tid query parameter"}), 400
    if not _looks_like_guid(tenant):
        return jsonify({"error": "tid does not look like a tenant GUID", "tid": tenant}), 400

    client_id = os.getenv("AZURE_CLIENT_ID")
    if not client_id:
        return jsonify({"error": "Missing AZURE_CLIENT_ID app setting"}), 500

    callback = _https_host_url() + "/.auth/login/aad/callback"

    params = {
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": callback,
        "response_mode": "query",
        "scope": "openid profile email",
        "prompt": "select_account",
    }

    url = f"https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize?{urlencode(params)}"
    return ("", 302, {"Location": url})


@app.get("/ui")
def ui():
    return """<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <title>Foundry Subscription Auditor</title>
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <style>
    body { font-family: Arial, sans-serif; margin: 24px; max-width: 1050px; }
    h1 { margin: 0 0 6px 0; }
    .muted { color: #555; font-size: 13px; margin-bottom: 16px; }
    .row { margin: 12px 0; display: flex; gap: 10px; align-items: center; flex-wrap: wrap; }
    select, button, textarea, input { font-size: 14px; padding: 8px 10px; }
    textarea { width: 100%; min-height: 92px; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; }
    button { cursor: pointer; }
    .box { background: #f6f6f6; padding: 12px; border-radius: 8px; }
    .status { font-weight: bold; }
    a { word-break: break-all; }
    code { background: #eee; padding: 2px 4px; border-radius: 4px; }
    details { margin-top: 10px; }
    summary { cursor: pointer; }
    .label { font-weight: bold; display:block; margin: 8px 0 6px; }
    .twoCol { display:grid; grid-template-columns: 1fr; gap: 12px; }
    @media (min-width: 900px) { .twoCol { grid-template-columns: 1fr 1fr; } }
    .pill { display:inline-block; padding: 2px 6px; border-radius: 10px; background:#eee; font-size: 12px; }
    .warn { background:#fff3cd; border:1px solid #ffe69c; padding:10px 12px; border-radius:8px; }
    pre { background:#111; color:#eee; padding:10px; border-radius:8px; overflow:auto; }
  </style>
</head>
<body>
  <h1>Foundry Subscription Auditor</h1>
  <div class="muted">
    Run-as-user audit (delegated). Pick a subscription, tune the AI prompts, run audit, then open the HTML report.
    <span style="margin-left:12px;"><a href="/.auth/logout">Sign out</a></span>
  </div>

  <div class="box" style="margin-bottom: 14px;">
    <div class="row" style="justify-content: space-between;">
      <b>Tenant context</b>
      <span class="pill" id="tenantPill">Loading…</span>
    </div>

    <div class="muted">
      <b>Important:</b> <code>/subscriptions/simple</code> uses your current sign-in <code>tid</code>.
      If you're a guest in another tenant, your current <code>tid</code> may still be your home tenant.
    </div>

    <div class="warn">
      <div style="font-weight:bold; margin-bottom:6px;">Tenant tools</div>

      <div class="row" style="gap:8px;">
        <input id="tenantGuid" placeholder="Tenant GUID (e.g. 11111111-2222-3333-4444-555555555555)" style="min-width:520px;" />
        <button id="tenantLoginBtn" title="Redirects through Entra for this tenant (Easy Auth callback)">Sign in to this tenant</button>
        <button id="tenantTestBtn" title="Option 1: calls /subscriptions/tenant?tid=... using OBO against that tenant">Test subscriptions in this tenant</button>
      </div>

      <div class="muted" style="margin:0;">
        <b>Option 1 test</b> does not change Easy Auth. It requests an ARM token via OBO against the tenant you provide,
        then lists subscriptions visible in that tenant. Perfect for validating guest access.
      </div>

      <div id="tenantTestOut" style="margin-top:10px; display:none;">
        <div class="muted" style="margin-bottom:6px;"><b>Tenant test output</b></div>
        <pre id="tenantTestPre"></pre>
      </div>
    </div>

    <div class="row">
      <a id="reauthLink" href="/.auth/login/aad?post_login_redirect_uri=/ui">Re-auth (default)</a>
      <span class="muted">Tip: In some cases, using an InPrivate window helps force the account/tenant picker.</span>
    </div>

    <details>
      <summary>Show identity details</summary>
      <pre id="whoamiBox" style="white-space:pre-wrap;"></pre>
    </details>
  </div>

  <div class="row">
    <label for="subSelect"><b>Subscription</b></label>
    <select id="subSelect" style="min-width:520px;"></select>
    <button id="refreshBtn">Refresh</button>
  </div>

  <div class="box">
    <div class="row" style="justify-content: space-between;">
      <b>AI Prompt Controls (per run)</b>
      <button id="loadDefaultsBtn" title="Load server defaults from App Settings">Load defaults</button>
    </div>

    <div class="twoCol">
      <div>
        <span class="label">System prompt (who the AI is)</span>
        <textarea id="systemPrompt" placeholder="e.g. You are a senior Solution Architect producing an HLD-grade assessment..."></textarea>
      </div>
      <div>
        <span class="label">Report angle (stakeholder steering)</span>
        <textarea id="angleText" placeholder="e.g. Write for solution/technical stakeholders, decision-oriented, call out key gaps/risks..."></textarea>
      </div>
    </div>

    <details>
      <summary>Tips (how this is applied)</summary>
      <div class="muted" style="margin-top:8px;">
        The <code>system prompt</code> is used as the chat system message.
        The <code>report angle</code> is appended to each analysis prompt as consistent steering.
        These values are stored with the run output so the report is reproducible.
      </div>
    </details>
  </div>

  <div class="row">
    <button id="runBtn">Run audit</button>
    <span class="status" id="status"></span>
  </div>

  <div class="box" id="resultBox" style="display:none;">
    <div id="resultText"></div>
    <div id="reportLink" style="margin-top:8px;"></div>
  </div>

<script>
const subSelect = document.getElementById("subSelect");
const statusEl = document.getElementById("status");
const resultBox = document.getElementById("resultBox");
const resultText = document.getElementById("resultText");
const reportLink = document.getElementById("reportLink");
const systemPromptEl = document.getElementById("systemPrompt");
const angleTextEl = document.getElementById("angleText");
const tenantPill = document.getElementById("tenantPill");
const whoamiBox = document.getElementById("whoamiBox");

const tenantTestOut = document.getElementById("tenantTestOut");
const tenantTestPre = document.getElementById("tenantTestPre");

function setStatus(msg) { statusEl.textContent = msg; }
function showResult(html) {
  resultBox.style.display = "block";
  resultText.innerHTML = html;
}
function setReportLink(url) {
  reportLink.innerHTML = url ? ('<a href="' + url + '" target="_blank">Open HTML report</a>') : '';
}

async function loadDefaults() {
  const r = await fetch("/prompts/defaults");
  if (!r.ok) return;
  const data = await r.json();
  if (!systemPromptEl.value.trim()) systemPromptEl.value = data.report_system_prompt || "";
  if (!angleTextEl.value.trim()) angleTextEl.value = data.report_angle_text || "";
}

async function loadWhoami() {
  const r = await fetch("/whoami");
  if (!r.ok) { tenantPill.textContent = "whoami failed"; return; }
  const data = await r.json();
  const principal = data.principal || {};
  const claims = principal.claims || [];
  const tid = (claims.find(c => c.typ === "tid") || claims.find(c => c.typ === "http://schemas.microsoft.com/identity/claims/tenantid") || {}).val;
  const upn = (claims.find(c => c.typ === "preferred_username") || claims.find(c => c.typ === "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn") || {}).val;

  tenantPill.textContent = tid ? ("tid: " + tid) : "tid: (unknown)";
  if (upn) tenantPill.textContent += " • " + upn;

  whoamiBox.textContent = JSON.stringify(data, null, 2);
}

async function loadSubs() {
  setStatus("Loading subscriptions...");
  resultBox.style.display = "none";
  setReportLink("");
  subSelect.innerHTML = "";

  const r = await fetch("/subscriptions/simple");
  if (!r.ok) {
    setStatus("Failed: /subscriptions/simple (" + r.status + ")");
    return;
  }
  const data = await r.json();
  const list = data.enabled_subscriptions || data.subscriptions || [];
  if (!list.length) {
    setStatus("No subscriptions visible for your identity (in this tenant context).");
    return;
  }
  for (const s of list) {
    const opt = document.createElement("option");
    opt.value = s.subscriptionId;
    opt.textContent = s.displayName + " (" + s.subscriptionId + ")";
    subSelect.appendChild(opt);
  }
  setStatus("Ready.");
}

async function startRun() {
  const subscriptionId = subSelect.value;
  if (!subscriptionId) { setStatus("Pick a subscription."); return; }

  setStatus("Starting run...");
  resultBox.style.display = "none";
  setReportLink("");

  const payload = {
    subscriptionId,
    reportSystemPrompt: systemPromptEl.value,
    reportAngleText: angleTextEl.value
  };

  const r = await fetch("/run", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });

  const data = await r.json();
  if (!r.ok) {
    setStatus("Failed to start (" + r.status + ")");
    showResult("<pre>" + JSON.stringify(data, null, 2) + "</pre>");
    return;
  }

  const runId = data.run_id;
  setStatus("Running… " + runId);
  await poll(runId);
}

async function poll(runId) {
  const pollUrl = "/run/" + runId;
  while (true) {
    const r = await fetch(pollUrl);
    if (!r.ok) {
      setStatus("Poll failed (" + r.status + ")");
      return;
    }
    const payload = await r.json();
    const st = (payload.status && payload.status.status) || "unknown";

    if (st === "running") {
      setStatus("Running…");
      await new Promise(res => setTimeout(res, 2500));
      continue;
    }

    if (st === "failed") {
      setStatus("Failed.");
      const err = (payload.status && payload.status.error) || "(unknown)";
      showResult("Audit failed: <code>" + err + "</code>");
      return;
    }

    if (st === "succeeded") {
      setStatus("Succeeded.");
      const reportUrl = payload.result && payload.result.report_url;
      const stats = payload.result && payload.result.summary;
      showResult("Audit complete." + (stats ? ("<pre>" + JSON.stringify(stats, null, 2) + "</pre>") : ""));
      setReportLink(reportUrl);
      return;
    }

    setStatus("Status: " + st);
    await new Promise(res => setTimeout(res, 2500));
  }
}

async function tenantTest() {
  const tid = (document.getElementById("tenantGuid").value || "").trim();
  if (!tid) { alert("Enter a tenant GUID"); return; }

  tenantTestOut.style.display = "block";
  tenantTestPre.textContent = "Calling /subscriptions/tenant?tid=" + tid + " ...";

  const r = await fetch("/subscriptions/tenant?tid=" + encodeURIComponent(tid));
  let data = null;
  try { data = await r.json(); } catch(e) { data = { error: "Non-JSON response", status: r.status }; }

  tenantTestPre.textContent = JSON.stringify(data, null, 2);

  if (r.ok) {
    // If this returns subs, you've proven guest tenant visibility works from code.
    setStatus("Tenant test OK. (See output)");
  } else {
    setStatus("Tenant test failed (" + r.status + "). (See output)");
  }
}

document.getElementById("refreshBtn").addEventListener("click", loadSubs);
document.getElementById("runBtn").addEventListener("click", startRun);
document.getElementById("loadDefaultsBtn").addEventListener("click", loadDefaults);

document.getElementById("tenantLoginBtn").addEventListener("click", () => {
  const tid = (document.getElementById("tenantGuid").value || "").trim();
  if (!tid) { alert("Enter a tenant GUID"); return; }
  window.location.href = "/auth/tenant?tid=" + encodeURIComponent(tid);
});

document.getElementById("tenantTestBtn").addEventListener("click", tenantTest);

// initial
loadWhoami();
loadSubs();
loadDefaults();
</script>
</body>
</html>"""


@app.get("/whoami")
def whoami():
    principal = decode_easy_auth_principal()
    tid = get_tid_from_principal()
    upn = get_upn_from_principal()
    return jsonify(
        {
            "version": APP_VERSION,
            "is_azure": bool(_env("WEBSITE_INSTANCE_ID")),
            "headers_present": {
                "X-MS-CLIENT-PRINCIPAL": bool(request.headers.get("X-MS-CLIENT-PRINCIPAL")),
                "X-MS-TOKEN-AAD-ACCESS-TOKEN": bool(get_easy_auth_access_token()),
                "X-MS-TOKEN-AAD-ID-TOKEN": bool(get_easy_auth_id_token()),
            },
            "tenant_context": {
                "tid": tid,
                "user": upn,
                "obo_authority": f"https://login.microsoftonline.com/{tid}" if tid else None,
                "fallback_env_tenant": _env("AZURE_TENANT_ID"),
            },
            "principal": principal,
            "tips": {
                "logout_url": "/.auth/logout",
                "reauth_url": "/.auth/login/aad?post_login_redirect_uri=/ui",
                "force_tenant_url_example": "/auth/tenant?tid=<tenant-guid>",
                "option1_test_url_example": "/subscriptions/tenant?tid=<tenant-guid>",
            },
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


@app.get("/subscriptions/tenant")
def subscriptions_for_tenant():
    """
    Option 1 test endpoint:
      GET /subscriptions/tenant?tid=<tenant-guid>

    This does NOT attempt to change Easy Auth configuration.
    It simply requests an ARM token via OBO against the specified tenant authority
    and lists subscriptions visible in that tenant for the current user.
    """
    tid = (request.args.get("tid") or "").strip()
    if not tid:
        return jsonify({"error": "Missing tid query parameter"}), 400
    if not _looks_like_guid(tid):
        return jsonify({"error": "tid does not look like a tenant GUID", "tid": tid}), 400

    arm_token, obo_error = get_arm_token_for_tenant(tid)
    if not arm_token:
        return (
            jsonify(
                {
                    "error": "Could not obtain ARM token for specified tenant (OBO)",
                    "requested_tid": tid,
                    "principal_tid": get_tid_from_principal(),
                    "details": obo_error,
                }
            ),
            401,
        )

    r = try_list_subscriptions_with_token(arm_token)
    if r.status_code != 200:
        return (
            jsonify(
                {
                    "error": "ARM subscriptions call failed (tenant test)",
                    "requested_tid": tid,
                    "principal_tid": get_tid_from_principal(),
                    "status_code": r.status_code,
                    "body_snippet": body_snippet(r.text),
                }
            ),
            r.status_code,
        )

    out = normalize_subscriptions(r.json())
    out["_debug"] = {
        "requested_tid": tid,
        "principal_tid": get_tid_from_principal(),
        "obo_authority": f"https://login.microsoftonline.com/{tid}",
    }
    return jsonify(out)


@app.post("/run")
def run_async():
    """
    Async run:
    - POST /run starts a run and immediately returns run_id (202 Accepted)
    - GET /run/<run_id> returns status/results
    """
    body = request.get_json(silent=True) or {}
    subscription_id = body.get("subscriptionId") or body.get("subscription_id")
    if not subscription_id:
        return jsonify({"error": "Missing subscriptionId"}), 400

    report_system_prompt = _trim_prompt(body.get("reportSystemPrompt") or body.get("report_system_prompt"))
    report_angle_text = _trim_prompt(body.get("reportAngleText") or body.get("report_angle_text"))

    arm_token, obo_error = get_arm_token_for_request()
    if not arm_token:
        return jsonify({"error": "Could not obtain ARM token via OBO", "details": obo_error}), 401

    run_id = f"{subscription_id}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"
    run_path = _run_dir(run_id)

    status_path = run_path / "status.json"
    result_path = run_path / "result.json"
    inputs_path = run_path / "inputs.json"

    _write_json(
        status_path,
        {
            "run_id": run_id,
            "subscription_id": subscription_id,
            "status": "running",
            "started_utc": _utc_now(),
        },
    )

    _write_json(
        inputs_path,
        {
            "subscription_id": subscription_id,
            "report_system_prompt": report_system_prompt,
            "report_angle_text": report_angle_text,
            "started_utc": _utc_now(),
            "version": APP_VERSION,
            "principal_tid": get_tid_from_principal(),
            "principal_user": get_upn_from_principal(),
        },
    )

    def _worker():
        try:
            credential = StaticTokenCredential(arm_token)
            results = run_audit(
                subscription_id=subscription_id,
                credential=credential,
                output_dir=str(run_path),
                report_system_prompt=report_system_prompt,
                report_angle_text=report_angle_text,
            )

            report_file_ui = results.get("report_file_ui") or "report.html"
            results["report_url"] = f"/outputs/{run_id}/{report_file_ui}"

            _write_json(result_path, results)

            started = (_read_json(status_path) or {}).get("started_utc")
            _write_json(
                status_path,
                {
                    "run_id": run_id,
                    "subscription_id": subscription_id,
                    "status": "succeeded",
                    "started_utc": started,
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

    threading.Thread(target=_worker, daemon=True).start()

    return (
        jsonify(
            {
                "run_id": run_id,
                "subscription_id": subscription_id,
                "status": "running",
                "poll": f"/run/{run_id}",
                "report_hint": f"/outputs/{run_id}/report.html",
                "version": APP_VERSION,
            }
        ),
        202,
    )


@app.get("/run/<run_id>")
def run_status(run_id: str):
    status_path = _run_dir(run_id) / "status.json"
    result_path = _run_dir(run_id) / "result.json"

    status = _read_json(status_path)
    if not status:
        return jsonify({"error": "run_id not found", "run_id": run_id, "version": APP_VERSION}), 404

    result = _read_json(result_path)
    return jsonify({"status": status, "result": result, "version": APP_VERSION})


@app.get("/outputs/<run_id>/<path:filename>")
def outputs_file(run_id: str, filename: str):
    folder = _run_dir(run_id)
    return send_from_directory(folder, filename)
