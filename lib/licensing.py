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

TIERS = {
    "community": {
        "label": "Community",
        "max_targets": 5,
        "max_users": 1,
        "scanners": ["network", "vulnerability", "web", "ssl"],
        "notifications": ["email", "webhook"],
        "compliance_frameworks": 3,
        "export_formats": ["csv", "json"],
        "ai_queries_per_day": 10,
        "scheduled_scans": False,
        "api_rate_limit": 100,         # requests per hour
        "alert_routing": False,
        "sms_notifications": False,
    },
    "pro": {
        "label": "Pro",
        "max_targets": None,           # unlimited
        "max_users": 10,
        "scanners": "all",
        "notifications": "all",
        "compliance_frameworks": None,  # unlimited
        "export_formats": "all",
        "ai_queries_per_day": None,    # unlimited
        "scheduled_scans": True,
        "api_rate_limit": 10000,
        "alert_routing": True,
        "sms_notifications": True,
    },
    "enterprise": {
        "label": "Enterprise",
        "max_targets": None,
        "max_users": None,
        "scanners": "all",
        "notifications": "all",
        "compliance_frameworks": None,
        "export_formats": "all",
        "ai_queries_per_day": None,
        "scheduled_scans": True,
        "api_rate_limit": None,        # unlimited
        "alert_routing": True,
        "sms_notifications": True,
        "sso": True,
        "rbac": True,
        "custom_branding": True,
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

    def get_upgrade_message(self, feature: str) -> str:
        """Return a user-friendly upgrade prompt for a blocked feature."""
        messages = {
            "max_targets": "You've reached the 5-target limit. Upgrade to Pro for unlimited targets.",
            "scheduled_scans": "Scheduled scans are a Pro feature. Upgrade to unlock automated scanning.",
            "sms_notifications": "SMS notifications require a Pro license.",
            "alert_routing": "Alert routing rules are available in Pro and Enterprise tiers.",
            "ai_queries_per_day": "You've reached the daily AI query limit (10). Upgrade to Pro for unlimited queries.",
            "scanners": "This scanner requires a Pro license. Community includes: network, vulnerability, web, ssl.",
            "export_formats": "This export format requires a Pro license. Community includes: CSV, JSON.",
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
