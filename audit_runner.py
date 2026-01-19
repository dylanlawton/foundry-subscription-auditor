# audit_runner.py
from __future__ import annotations

import os
from datetime import datetime
from typing import Any, Dict, Optional

from rg_reader import get_rg_details  # your existing module

def run_audit(
    *,
    subscription_id: str,
    credential,
    output_dir: str = "/tmp/outputs",
) -> Dict[str, Any]:
    """
    Shared audit engine entrypoint.
    - Called by main.py (local) and app.py (web)
    - credential is either InteractiveBrowserCredential (local) or StaticTokenCredential (web)
    """
    os.makedirs(output_dir, exist_ok=True)

    timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    run_id = f"{subscription_id}_{timestamp}"

    # 1) Collect data (start small: RGs)
    rg_data = get_rg_details(subscription_id=subscription_id, credential=credential)

    # 2) Assemble results model (expand later with VMs, network, storage, etc.)
    results = {
        "run_id": run_id,
        "subscription_id": subscription_id,
        "resource_groups": rg_data,
    }

    # 3) (Later) Render HTML report here and write to output_dir
    # For now we just return JSON to prove end-to-end.

    return results
