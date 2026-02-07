#!/usr/bin/env python3
"""
Purple Team Platform v6.0 - Credential Manager
Manages credentials for authenticated scanning.
Supports SSH (key/password), WinRM, SNMP, and HTTP basic auth.
Encrypted storage with Fernet if cryptography package available.
"""

import json
import os
import base64
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Dict, List, Optional

try:
    from .paths import paths
    from .logger import get_logger
except ImportError:
    from paths import paths
    from logger import get_logger

logger = get_logger('credential_manager')

# Try to import cryptography for encrypted storage
try:
    from cryptography.fernet import Fernet
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False
    logger.warning("cryptography package not available - credentials stored in plaintext")

# Try YAML
try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


class CredentialManager:
    """Manages credentials for authenticated scanning."""

    _instance: Optional['CredentialManager'] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True

        self.config_dir = paths.config / 'active'
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.cred_file = self.config_dir / 'credentials.yaml'
        self.key_file = self.config_dir / '.cred_key'

        self._fernet = None
        self._credentials: List[Dict] = []

        self._init_encryption()
        self._load_credentials()

    def _init_encryption(self):
        """Initialize Fernet encryption if available."""
        if not HAS_CRYPTO:
            return

        if self.key_file.exists():
            try:
                key = self.key_file.read_bytes()
                self._fernet = Fernet(key)
            except Exception as e:
                logger.warning(f"Error loading encryption key: {e}")
        else:
            try:
                key = Fernet.generate_key()
                self.key_file.write_bytes(key)
                os.chmod(str(self.key_file), 0o600)
                self._fernet = Fernet(key)
                logger.info("Generated new encryption key")
            except Exception as e:
                logger.warning(f"Error creating encryption key: {e}")

    def _encrypt(self, data: str) -> str:
        """Encrypt a string value."""
        if self._fernet:
            return self._fernet.encrypt(data.encode()).decode()
        return data

    def _decrypt(self, data: str) -> str:
        """Decrypt a string value."""
        if self._fernet and data:
            try:
                return self._fernet.decrypt(data.encode()).decode()
            except Exception:
                return data
        return data

    def _load_credentials(self):
        """Load credentials from config file."""
        if not self.cred_file.exists():
            self._credentials = []
            return

        try:
            content = self.cred_file.read_text()
            if HAS_YAML:
                data = yaml.safe_load(content) or {}
            else:
                data = json.loads(content) if content.strip() else {}

            self._credentials = data.get('credentials', [])
            logger.debug(f"Loaded {len(self._credentials)} credentials")
        except Exception as e:
            logger.warning(f"Error loading credentials: {e}")
            self._credentials = []

    def _save_credentials(self):
        """Save credentials to config file."""
        data = {'credentials': self._credentials}

        try:
            if HAS_YAML:
                content = yaml.dump(data, default_flow_style=False)
            else:
                content = json.dumps(data, indent=2)

            self.cred_file.write_text(content)
            os.chmod(str(self.cred_file), 0o600)
        except Exception as e:
            logger.error(f"Error saving credentials: {e}")

    def add_credential(self, name: str, cred_type: str, target_pattern: str,
                       **params) -> Dict:
        """
        Add a credential entry.

        Args:
            name: Friendly name for the credential
            cred_type: 'ssh_password', 'ssh_key', 'winrm', 'snmp', 'http_basic'
            target_pattern: IP, hostname, or CIDR pattern to match
            **params: Type-specific parameters (username, password, key_path, etc.)
        """
        # Encrypt sensitive fields
        sensitive_fields = ['password', 'key_passphrase', 'community_string', 'secret']
        encrypted_params = {}
        for k, v in params.items():
            if k in sensitive_fields and v:
                encrypted_params[k] = self._encrypt(str(v))
            else:
                encrypted_params[k] = v

        credential = {
            'name': name,
            'type': cred_type,
            'target_pattern': target_pattern,
            'params': encrypted_params,
            'enabled': True,
        }

        # Remove existing with same name
        self._credentials = [c for c in self._credentials if c.get('name') != name]
        self._credentials.append(credential)
        self._save_credentials()

        logger.info(f"Added credential: {name} ({cred_type}) for {target_pattern}")
        return credential

    def get_credential_for_target(self, target_ip: str, cred_type: str = None) -> Optional[Dict]:
        """Get matching credential for a target IP."""
        for cred in self._credentials:
            if not cred.get('enabled', True):
                continue

            if cred_type and cred.get('type') != cred_type:
                continue

            pattern = cred.get('target_pattern', '')

            # Match by exact IP
            if pattern == target_ip:
                return self._decrypt_credential(cred)

            # Match by CIDR
            try:
                if '/' in pattern:
                    network = ip_network(pattern, strict=False)
                    if ip_address(target_ip) in network:
                        return self._decrypt_credential(cred)
            except (ValueError, TypeError):
                pass

            # Match by wildcard
            if '*' in pattern:
                import fnmatch
                if fnmatch.fnmatch(target_ip, pattern):
                    return self._decrypt_credential(cred)

        return None

    def _decrypt_credential(self, cred: Dict) -> Dict:
        """Return credential with decrypted sensitive fields."""
        result = cred.copy()
        params = cred.get('params', {}).copy()

        sensitive_fields = ['password', 'key_passphrase', 'community_string', 'secret']
        for field in sensitive_fields:
            if field in params:
                params[field] = self._decrypt(params[field])

        result['params'] = params
        return result

    def get_all_credentials(self, decrypt: bool = False) -> List[Dict]:
        """Get all credentials (optionally decrypted)."""
        if decrypt:
            return [self._decrypt_credential(c) for c in self._credentials]
        return self._credentials.copy()

    def remove_credential(self, name: str) -> bool:
        """Remove a credential by name."""
        before = len(self._credentials)
        self._credentials = [c for c in self._credentials if c.get('name') != name]
        if len(self._credentials) < before:
            self._save_credentials()
            logger.info(f"Removed credential: {name}")
            return True
        return False

    def has_credentials_for(self, target_ip: str) -> bool:
        """Check if any credentials are configured for a target."""
        return self.get_credential_for_target(target_ip) is not None

    def test_credential(self, target: str, credential: Dict) -> Dict:
        """Test if a credential works against a target."""
        import subprocess

        cred_type = credential.get('type', '')
        params = credential.get('params', {})
        result = {'success': False, 'message': ''}

        if cred_type in ('ssh_password', 'ssh_key'):
            username = params.get('username', 'root')

            try:
                # Try paramiko first
                import paramiko
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

                if cred_type == 'ssh_key':
                    key_path = params.get('key_path', '')
                    if key_path and Path(key_path).exists():
                        client.connect(
                            target, username=username,
                            key_filename=key_path,
                            timeout=10
                        )
                    else:
                        result['message'] = f"Key file not found: {key_path}"
                        return result
                else:
                    client.connect(
                        target, username=username,
                        password=params.get('password', ''),
                        timeout=10
                    )

                client.close()
                result['success'] = True
                result['message'] = f"SSH connection successful as {username}"

            except ImportError:
                # Fallback to ssh subprocess
                cmd = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=5',
                       f'{username}@{target}', 'echo ok']
                try:
                    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                    result['success'] = proc.returncode == 0
                    result['message'] = proc.stdout.strip() or proc.stderr.strip()
                except Exception as e:
                    result['message'] = str(e)

            except Exception as e:
                result['message'] = str(e)

        else:
            result['message'] = f"Testing not implemented for {cred_type}"

        return result

    @property
    def is_encrypted(self) -> bool:
        """Check if credential storage is encrypted."""
        return self._fernet is not None


# Singleton accessor
_credential_manager: Optional[CredentialManager] = None


def get_credential_manager() -> CredentialManager:
    """Get the credential manager singleton."""
    global _credential_manager
    if _credential_manager is None:
        _credential_manager = CredentialManager()
    return _credential_manager


if __name__ == '__main__':
    cm = get_credential_manager()
    print("Credential Manager initialized")
    print(f"Config: {cm.cred_file}")
    print(f"Encrypted: {cm.is_encrypted}")
    print(f"Credentials loaded: {len(cm.get_all_credentials())}")

    # Example credential
    print("\nExample: Adding test SSH credential...")
    cm.add_credential(
        name='test-ssh',
        cred_type='ssh_password',
        target_pattern='192.168.1.0/24',
        username='admin',
        password='test_password_123'
    )
    print(f"Credentials count: {len(cm.get_all_credentials())}")

    # Test retrieval
    cred = cm.get_credential_for_target('192.168.1.100')
    if cred:
        print(f"Found credential for 192.168.1.100: {cred['name']}")

    # Cleanup test
    cm.remove_credential('test-ssh')
    print("Removed test credential")
