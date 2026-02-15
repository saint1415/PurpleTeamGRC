#!/usr/bin/env python3
"""
Purple Team GRC - License & Tier Management

Manages feature tiers (community / pro / enterprise) and enforces
usage limits.  Community tier is the default -- no license key needed.
Pro and Enterprise tiers require a signed license file stored at
``data/license.json``.
"""

import hashlib
import hmac
import json
import logging
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional

try:
    from .paths import paths
except ImportError:
    from paths import paths

logger = logging.getLogger("purpleteam.licensing")

# ---------------------------------------------------------------------------
# Tier definitions
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Tier philosophy  (modelled after Burp Suite Community vs Pro)
#
# Community is genuinely useful for hands-on manual work:
#   - Run any scanner, see findings, remediate -- no paywall on core workflow
#   - But: depth limited to quick/standard, deep scans are Pro only
#   - But: scans are throttled (artificial delay between checks)
#   - But: no automation (schedules, alert routing, API bulk ops)
#   - But: export limited to CSV/JSON (no HTML reports, PDF, SARIF, etc.)
#   - But: AI limited to 10 queries/day (enough to try it, not enough to rely on)
#   - But: scan history retained 30 days only (Pro: unlimited)
#   - But: no advanced scanners (credential, asm, sbom, container, openvas)
#
# The natural upgrade trigger: "I ran a scan, found issues, now I need to
# produce a client report / schedule recurring scans / go deeper."
# ---------------------------------------------------------------------------

TIERS = {
    "community": {
        "label": "Community",
        # ---- Scanning ----
        "scanners": [                           # core manual scanners only
            "network", "vulnerability", "web", "ssl",
            "windows", "linux", "compliance",
        ],
        "scan_depths": ["quick", "standard"],   # no "deep" scans
        "scan_throttle_ms": 500,                # 500ms delay between checks
        "max_targets_per_scan": 16,             # /24 is fine, /16 needs Pro
        "scan_history_days": 30,                # findings older than 30d purged
        # ---- Automation ----
        "scheduled_scans": False,               # like Burp: no automation
        "alert_routing": False,                 # no digest / severity routing
        # ---- Reporting ----
        "export_formats": ["csv", "json"],      # no HTML, PDF, SARIF, XML, etc.
        "compliance_frameworks": 3,             # pick any 3
        # ---- Notifications ----
        "notifications": ["email", "webhook"],  # no SMS, no Slack/Teams
        "sms_notifications": False,
        # ---- AI ----
        "ai_queries_per_day": 10,               # enough to try, not rely
        "ai_scan_summary": False,               # can't auto-summarise scans
        # ---- Platform ----
        "max_users": 1,
        "api_rate_limit": 100,                  # requests per hour
        "save_projects": False,                 # temporary sessions only
    },
    "pro": {
        "label": "Pro",
        # ---- Scanning ----
        "scanners": "all",                      # all 15 scanners
        "scan_depths": "all",                   # quick / standard / deep
        "scan_throttle_ms": 0,                  # full speed
        "max_targets_per_scan": None,           # unlimited
        "scan_history_days": None,              # unlimited retention
        # ---- Automation ----
        "scheduled_scans": True,
        "alert_routing": True,                  # severity routing + digests
        # ---- Reporting ----
        "export_formats": "all",                # CSV, JSON, HTML, PDF, SARIF, XML, NIST, ...
        "compliance_frameworks": None,          # unlimited
        # ---- Notifications ----
        "notifications": "all",                 # email, Slack, Teams, webhook, syslog, SMS
        "sms_notifications": True,
        # ---- AI ----
        "ai_queries_per_day": None,             # unlimited
        "ai_scan_summary": True,
        # ---- Platform ----
        "max_users": 25,
        "api_rate_limit": 10000,
        "save_projects": True,
    },
    "enterprise": {
        "label": "Enterprise",
        # Everything in Pro, plus:
        "scanners": "all",
        "scan_depths": "all",
        "scan_throttle_ms": 0,
        "max_targets_per_scan": None,
        "scan_history_days": None,
        "scheduled_scans": True,
        "alert_routing": True,
        "export_formats": "all",
        "compliance_frameworks": None,
        "notifications": "all",
        "sms_notifications": True,
        "ai_queries_per_day": None,
        "ai_scan_summary": True,
        "max_users": None,                      # unlimited
        "api_rate_limit": None,                 # unlimited
        "save_projects": True,
        # ---- Enterprise-only ----
        "sso": True,                            # SAML / OIDC
        "rbac": True,                           # role-based access control
        "custom_branding": True,                # white-label dashboard
        "multi_tenant": True,                   # tenant isolation
        "audit_log_export": True,               # SIEM integration
        "priority_support": True,
    },
}

# Public key for license validation (placeholder -- replace with real key)
_LICENSE_SIGN_KEY = b"purpleteam-grc-license-signing-key-v1"


# ---------------------------------------------------------------------------
# License Manager
# ---------------------------------------------------------------------------

class LicenseManager:
    """Reads the license file and enforces tier limits."""

    _instance: Optional["LicenseManager"] = None

    def __init__(self):
        self.license_path = paths.data / "license.json"
        self._license: Optional[Dict] = None
        self._tier: str = "community"
        self._ai_query_counts: Dict[str, int] = {}  # date_str -> count
        self._load_license()

    # ---- license file I/O ------------------------------------------------

    def _load_license(self):
        """Load and validate the license file if it exists."""
        if not self.license_path.exists():
            self._tier = "community"
            return

        try:
            data = json.loads(self.license_path.read_text("utf-8"))
            if self._validate_license(data):
                self._license = data
                self._tier = data.get("tier", "community")
                logger.info("License loaded: tier=%s", self._tier)
            else:
                logger.warning("Invalid license file -- falling back to community")
                self._tier = "community"
        except (json.JSONDecodeError, OSError) as exc:
            logger.warning("Failed to read license: %s", exc)
            self._tier = "community"

    def _validate_license(self, data: Dict) -> bool:
        """Validate a license payload against its signature."""
        signature = data.get("signature", "")
        tier = data.get("tier", "")
        expires = data.get("expires", "")
        org = data.get("organization", "")

        if tier not in ("pro", "enterprise"):
            return False

        # Check expiry
        if expires:
            try:
                exp_dt = datetime.fromisoformat(expires)
                if exp_dt < datetime.utcnow():
                    logger.warning("License expired: %s", expires)
                    return False
            except ValueError:
                return False

        # Verify HMAC signature
        payload = f"{tier}:{org}:{expires}".encode("utf-8")
        expected = hmac.new(_LICENSE_SIGN_KEY, payload, hashlib.sha256).hexdigest()
        return hmac.compare_digest(signature, expected)

    # ---- tier queries ----------------------------------------------------

    def get_tier(self) -> str:
        """Return the current tier name."""
        return self._tier

    def get_tier_label(self) -> str:
        """Return the display name of the current tier."""
        return TIERS.get(self._tier, TIERS["community"]).get("label", "Community")

    def get_limits(self) -> Dict:
        """Return the full limits dict for the current tier."""
        return dict(TIERS.get(self._tier, TIERS["community"]))

    def get_license_info(self) -> Dict:
        """Return non-secret license metadata."""
        if self._license:
            return {
                "tier": self._tier,
                "organization": self._license.get("organization", ""),
                "expires": self._license.get("expires", ""),
                "valid": True,
            }
        return {
            "tier": "community",
            "organization": "",
            "expires": "",
            "valid": True,
        }

    # ---- limit checking --------------------------------------------------

    def check_limit(self, feature: str, current_count: int = 0) -> bool:
        """Check whether the current tier allows *feature*.

        For boolean features (scheduled_scans, sso, etc.) returns True/False.
        For numeric limits (max_targets, compliance_frameworks) checks
        *current_count* against the cap (None = unlimited).
        """
        limits = self.get_limits()
        value = limits.get(feature)

        if value is None:
            return True          # unlimited
        if isinstance(value, bool):
            return value
        if isinstance(value, int):
            return current_count < value
        if isinstance(value, list):
            # list-type limits (scanners, notifications, export_formats)
            # The caller should pass the requested item as current_count
            # But for list features, use check_feature_item() instead
            return True
        if value == "all":
            return True
        return True

    def check_feature_item(self, feature: str, item: str) -> bool:
        """Check if a specific item (scanner id, format name, etc.) is allowed."""
        limits = self.get_limits()
        value = limits.get(feature)
        if value is None or value == "all":
            return True
        if isinstance(value, list):
            return item in value
        return True

    def check_ai_quota(self) -> bool:
        """Check if the daily AI query quota has been reached."""
        limits = self.get_limits()
        cap = limits.get("ai_queries_per_day")
        if cap is None:
            return True  # unlimited

        today = datetime.utcnow().strftime("%Y-%m-%d")
        used = self._ai_query_counts.get(today, 0)
        return used < cap

    def increment_ai_usage(self):
        """Record one AI query for today."""
        today = datetime.utcnow().strftime("%Y-%m-%d")
        self._ai_query_counts[today] = self._ai_query_counts.get(today, 0) + 1
        # Clean old dates
        for k in list(self._ai_query_counts):
            if k != today:
                del self._ai_query_counts[k]

    def check_scan_depth(self, depth: str) -> bool:
        """Check if a scan depth (quick/standard/deep) is allowed."""
        limits = self.get_limits()
        allowed = limits.get("scan_depths", ["quick", "standard"])
        if allowed == "all":
            return True
        return depth in allowed

    def get_scan_throttle_ms(self) -> int:
        """Return the inter-check delay in ms (0 = full speed)."""
        return self.get_limits().get("scan_throttle_ms", 500)

    def check_targets_count(self, count: int) -> bool:
        """Check if the number of targets per scan is within limits."""
        cap = self.get_limits().get("max_targets_per_scan")
        if cap is None:
            return True
        return count <= cap

    def get_upgrade_message(self, feature: str) -> str:
        """Return a user-friendly upgrade prompt for a blocked feature."""
        messages = {
            "scan_depths": (
                "Deep scans are a Pro feature. Community includes quick "
                "and standard depth. Upgrade to unlock deep scanning."
            ),
            "scan_throttle_ms": (
                "Community scans run at reduced speed. "
                "Upgrade to Pro for full-speed scanning."
            ),
            "max_targets_per_scan": (
                "Community is limited to 16 targets per scan. "
                "Upgrade to Pro for unlimited targets."
            ),
            "scan_history_days": (
                "Community retains scan history for 30 days. "
                "Upgrade to Pro for unlimited retention."
            ),
            "scheduled_scans": (
                "Scheduled scans are a Pro feature. "
                "Upgrade to automate recurring security assessments."
            ),
            "alert_routing": (
                "Alert routing and digest rules require Pro. "
                "Community sends all alerts to all channels."
            ),
            "export_formats": (
                "This export format requires Pro. Community "
                "includes CSV and JSON. Upgrade for HTML, PDF, "
                "SARIF, XML, and compliance-specific formats."
            ),
            "notifications": (
                "Slack, Teams, and SMS notifications require Pro. "
                "Community includes email and webhook."
            ),
            "sms_notifications": (
                "SMS/text notifications require a Pro license."
            ),
            "ai_queries_per_day": (
                "You've reached the daily AI limit (10 queries). "
                "Upgrade to Pro for unlimited AI analysis."
            ),
            "ai_scan_summary": (
                "AI scan summaries are a Pro feature. "
                "Upgrade to auto-generate executive reports."
            ),
            "scanners": (
                "This scanner requires Pro. Community includes: "
                "network, vulnerability, web, SSL, Windows, Linux, "
                "and compliance. Upgrade for credential, ASM, SBOM, "
                "container, AD, cloud, and OpenVAS scanners."
            ),
            "save_projects": (
                "Saving and resuming projects requires Pro. "
                "Community sessions are temporary."
            ),
            "compliance_frameworks": (
                "Community supports 3 compliance frameworks. "
                "Upgrade to Pro for unlimited frameworks."
            ),
        }
        return messages.get(feature,
                            f"This feature requires an upgrade. Current tier: {self.get_tier_label()}")


# ---------------------------------------------------------------------------
# License generation helper (for admin / testing)
# ---------------------------------------------------------------------------

def generate_license(tier: str, organization: str,
                     expires: str = "") -> Dict:
    """Generate a signed license payload.  *expires* in ISO format or empty."""
    if tier not in ("pro", "enterprise"):
        raise ValueError("tier must be 'pro' or 'enterprise'")
    payload = f"{tier}:{organization}:{expires}".encode("utf-8")
    signature = hmac.new(_LICENSE_SIGN_KEY, payload, hashlib.sha256).hexdigest()
    return {
        "tier": tier,
        "organization": organization,
        "expires": expires,
        "signature": signature,
        "generated_at": datetime.utcnow().isoformat(),
    }


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_license_manager: Optional[LicenseManager] = None


def get_license_manager() -> LicenseManager:
    """Get the license manager singleton."""
    global _license_manager
    if _license_manager is None:
        _license_manager = LicenseManager()
    return _license_manager


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    lm = get_license_manager()
    print(f"Current tier: {lm.get_tier()} ({lm.get_tier_label()})")
    print(f"Limits: {json.dumps(lm.get_limits(), indent=2)}")
    print(f"License info: {json.dumps(lm.get_license_info(), indent=2)}")

    # Check some limits
    print(f"\nmax_targets (count=3): {lm.check_limit('max_targets', 3)}")
    print(f"max_targets (count=6): {lm.check_limit('max_targets', 6)}")
    print(f"scheduled_scans: {lm.check_limit('scheduled_scans')}")
    print(f"scanner 'network': {lm.check_feature_item('scanners', 'network')}")
    print(f"scanner 'cloud': {lm.check_feature_item('scanners', 'cloud')}")
    print(f"AI quota: {lm.check_ai_quota()}")

    # Generate a test pro license
    print("\n--- Generating test Pro license ---")
    lic = generate_license("pro", "Test Corp", "2030-12-31")
    print(json.dumps(lic, indent=2))
    print("Valid:", lm._validate_license(lic))
