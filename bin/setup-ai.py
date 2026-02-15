#!/usr/bin/env python3
"""
Purple Team GRC Platform - AI Model Setup

Downloads and configures AI models for local (air-gapped) operation via
Ollama.  Run this script on a connected machine to pull the required models,
then copy the Ollama model storage to the target system.

Usage:
    python bin/setup-ai.py                        # Pull default models
    python bin/setup-ai.py --models mistral:7b    # Pull specific model(s)
    python bin/setup-ai.py --skip-pull             # Skip downloads, configure only
    python bin/setup-ai.py --test-only             # Just test model availability
"""

import sys
import os
import json
import argparse
import urllib.request
import urllib.error
from pathlib import Path

# ---------------------------------------------------------------------------
# Resolve project paths
# ---------------------------------------------------------------------------
SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parent
DATA_DIR = PROJECT_ROOT / 'data'
AI_CONFIG_PATH = DATA_DIR / 'ai_config.json'

sys.path.insert(0, str(PROJECT_ROOT / 'lib'))

OLLAMA_BASE_URL = "http://localhost:11434"

# Default models to pull
DEFAULT_MODELS = [
    'mistral:7b',
    'codellama:7b',
    'llama3.2:3b',
]

# Custom Modelfile name for the security-tuned model
CUSTOM_MODEL_NAME = 'purpleteam-security'


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def banner():
    print()
    print("  ============================================================")
    print("   Purple Team GRC Platform - AI Model Setup")
    print("  ============================================================")
    print()


def ollama_is_running() -> bool:
    """Check if Ollama is reachable at the default endpoint."""
    try:
        req = urllib.request.Request(
            f"{OLLAMA_BASE_URL}/api/tags",
            headers={'User-Agent': 'PurpleTeamGRC/1.0'},
            method='GET',
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            return 'models' in data
    except Exception:
        return False


def get_installed_models() -> list:
    """Return a list of model names currently available in Ollama."""
    try:
        req = urllib.request.Request(
            f"{OLLAMA_BASE_URL}/api/tags",
            headers={'User-Agent': 'PurpleTeamGRC/1.0'},
            method='GET',
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode('utf-8'))
            return [m.get('name', '') for m in data.get('models', [])]
    except Exception:
        return []


def pull_model(model_name: str) -> bool:
    """
    Pull a model via Ollama's /api/pull endpoint.

    Streams the response and prints progress.
    """
    print(f"\n  Pulling model: {model_name}")
    print(f"  This may take several minutes depending on model size and connection speed...")

    url = f"{OLLAMA_BASE_URL}/api/pull"
    payload = json.dumps({'name': model_name, 'stream': True}).encode('utf-8')

    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            'Content-Type': 'application/json',
            'User-Agent': 'PurpleTeamGRC/1.0',
        },
        method='POST',
    )

    try:
        with urllib.request.urlopen(req, timeout=1800) as resp:
            last_status = ''
            for line in resp:
                if not line.strip():
                    continue
                try:
                    obj = json.loads(line.decode('utf-8'))
                    status = obj.get('status', '')

                    # Progress display
                    if 'total' in obj and 'completed' in obj:
                        total = obj['total']
                        completed = obj['completed']
                        if total > 0:
                            pct = completed * 100 // total
                            mb_done = completed / (1024 * 1024)
                            mb_total = total / (1024 * 1024)
                            print(
                                f"\r  {status}: {pct}% "
                                f"({mb_done:.0f}/{mb_total:.0f} MB)",
                                end='', flush=True,
                            )
                    elif status and status != last_status:
                        print(f"\n  {status}", end='', flush=True)
                        last_status = status

                    if obj.get('error'):
                        print(f"\n  ERROR: {obj['error']}")
                        return False

                except json.JSONDecodeError:
                    continue

        print(f"\n  Model {model_name} pulled successfully.")
        return True

    except urllib.error.URLError as exc:
        print(f"\n  FAILED to pull {model_name}: {exc}")
        return False
    except Exception as exc:
        print(f"\n  FAILED to pull {model_name}: {exc}")
        return False


def create_custom_modelfile(base_model: str) -> bool:
    """
    Create a custom Ollama model with a security-focused system prompt
    using the Modelfile template from ai_prompts.
    """
    print(f"\n  Creating custom model '{CUSTOM_MODEL_NAME}' from {base_model}...")

    # Import the template
    try:
        from ai_prompts import MODELFILE_TEMPLATE
    except ImportError:
        print("  WARNING: Could not import ai_prompts.MODELFILE_TEMPLATE")
        print("  Using inline fallback Modelfile.")
        MODELFILE_TEMPLATE = (
            "FROM {base_model}\n"
            "SYSTEM \"You are a senior cybersecurity analyst for the Purple Team "
            "GRC Platform. Analyze vulnerabilities, prioritize findings, and "
            "provide actionable remediation guidance. Respond in structured JSON "
            "when requested.\"\n"
            "PARAMETER temperature 0.3\n"
            "PARAMETER num_predict 2048\n"
        )

    modelfile_content = MODELFILE_TEMPLATE.format(base_model=base_model)

    # POST to /api/create
    url = f"{OLLAMA_BASE_URL}/api/create"
    payload = json.dumps({
        'name': CUSTOM_MODEL_NAME,
        'modelfile': modelfile_content,
        'stream': True,
    }).encode('utf-8')

    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            'Content-Type': 'application/json',
            'User-Agent': 'PurpleTeamGRC/1.0',
        },
        method='POST',
    )

    try:
        with urllib.request.urlopen(req, timeout=300) as resp:
            for line in resp:
                if not line.strip():
                    continue
                try:
                    obj = json.loads(line.decode('utf-8'))
                    status = obj.get('status', '')
                    if status:
                        print(f"  {status}")
                    if obj.get('error'):
                        print(f"  ERROR: {obj['error']}")
                        return False
                except json.JSONDecodeError:
                    continue

        print(f"  Custom model '{CUSTOM_MODEL_NAME}' created successfully.")
        return True

    except Exception as exc:
        print(f"  FAILED to create custom model: {exc}")
        return False


def test_model(model_name: str) -> bool:
    """Send a quick test prompt to verify the model works."""
    print(f"  Testing model: {model_name} ...", end=' ', flush=True)

    url = f"{OLLAMA_BASE_URL}/api/generate"
    payload = json.dumps({
        'model': model_name,
        'prompt': 'Respond with exactly: MODEL_OK',
        'stream': False,
        'options': {
            'temperature': 0.0,
            'num_predict': 20,
        },
    }).encode('utf-8')

    req = urllib.request.Request(
        url,
        data=payload,
        headers={
            'Content-Type': 'application/json',
            'User-Agent': 'PurpleTeamGRC/1.0',
        },
        method='POST',
    )

    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            result = json.loads(resp.read().decode('utf-8'))
            response_text = result.get('response', '').strip()
            if response_text:
                print(f"OK (response: {response_text[:60]})")
                return True
            else:
                print("EMPTY RESPONSE")
                return False
    except Exception as exc:
        print(f"FAILED ({exc})")
        return False


def save_config(models_available: list, custom_model: str, test_results: dict):
    """Write AI configuration to data/ai_config.json."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    config = {
        'version': '1.0',
        'ollama_url': OLLAMA_BASE_URL,
        'models_available': models_available,
        'custom_model': custom_model,
        'preferred_model': custom_model if custom_model in models_available else (
            models_available[0] if models_available else None
        ),
        'test_results': test_results,
        'setup_timestamp': __import__('datetime').datetime.utcnow().isoformat(),
        'setup_host': os.environ.get('COMPUTERNAME', os.environ.get('HOSTNAME', 'unknown')),
    }

    with open(AI_CONFIG_PATH, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=2)

    print(f"\n  Configuration saved: {AI_CONFIG_PATH}")
    return config


def print_install_instructions():
    """Print Ollama installation instructions for the user."""
    print("  Ollama is NOT running at http://localhost:11434")
    print()
    print("  To install Ollama:")
    print()
    print("    Windows:")
    print("      1. Download from https://ollama.com/download/windows")
    print("      2. Run the installer")
    print("      3. Ollama will start automatically as a background service")
    print()
    print("    Linux:")
    print("      curl -fsSL https://ollama.com/install.sh | sh")
    print()
    print("    macOS:")
    print("      1. Download from https://ollama.com/download/mac")
    print("      2. Move Ollama.app to Applications and launch it")
    print()
    print("  After installation, run this script again:")
    print("      python bin/setup-ai.py")
    print()
    print("  For air-gapped deployment:")
    print("      1. Run this script on a connected machine to download models")
    print("      2. Copy the Ollama model storage directory to the target:")
    print("         - Windows: %USERPROFILE%\\.ollama\\models")
    print("         - Linux/macOS: ~/.ollama/models")
    print("      3. Install Ollama on the target (installer does not need internet)")
    print()


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description='Download and configure AI models for Purple Team GRC Platform')

    parser.add_argument(
        '--models', nargs='+', metavar='MODEL',
        default=None,
        help='Specific model(s) to pull (e.g. mistral:7b codellama:7b). '
             'Defaults to: ' + ', '.join(DEFAULT_MODELS),
    )
    parser.add_argument(
        '--skip-pull', action='store_true',
        help='Skip model downloads, only configure and test existing models',
    )
    parser.add_argument(
        '--test-only', action='store_true',
        help='Only test model availability, do not download or configure',
    )

    args = parser.parse_args()
    models_to_pull = args.models or DEFAULT_MODELS

    banner()

    # -------------------------------------------------------------------
    # Step 1: Check Ollama availability
    # -------------------------------------------------------------------
    print("[1/5] Checking Ollama availability...")
    if not ollama_is_running():
        print_install_instructions()
        sys.exit(1)

    installed = get_installed_models()
    print(f"  Ollama is running. {len(installed)} model(s) installed:")
    for m in installed:
        print(f"    - {m}")

    # -------------------------------------------------------------------
    # Test-only mode
    # -------------------------------------------------------------------
    if args.test_only:
        print()
        print("[TEST] Testing all installed models...")
        test_results = {}
        for m in installed:
            ok = test_model(m)
            test_results[m] = 'pass' if ok else 'fail'
        passed = sum(1 for v in test_results.values() if v == 'pass')
        print(f"\n  Results: {passed}/{len(test_results)} models responding")
        save_config(installed, CUSTOM_MODEL_NAME, test_results)
        sys.exit(0 if passed > 0 else 1)

    # -------------------------------------------------------------------
    # Step 2: Pull models
    # -------------------------------------------------------------------
    if not args.skip_pull:
        print(f"\n[2/5] Pulling {len(models_to_pull)} model(s)...")
        pull_results = {}
        for model in models_to_pull:
            # Check if already installed
            if model in installed:
                print(f"\n  Model {model} is already installed, skipping pull.")
                pull_results[model] = 'already_installed'
                continue
            ok = pull_model(model)
            pull_results[model] = 'success' if ok else 'failed'

        # Refresh installed list
        installed = get_installed_models()
        success_count = sum(1 for v in pull_results.values() if v != 'failed')
        print(f"\n  Pull results: {success_count}/{len(models_to_pull)} successful")
    else:
        print("\n[2/5] Skipping model downloads (--skip-pull)")

    # -------------------------------------------------------------------
    # Step 3: Create custom Modelfile
    # -------------------------------------------------------------------
    print(f"\n[3/5] Creating custom security-tuned model...")

    # Pick the best base model for the custom Modelfile
    base_model = None
    preferred_bases = ['mistral:7b', 'llama3.2:3b', 'llama3:latest']
    for pb in preferred_bases:
        if pb in installed:
            base_model = pb
            break
    # Fall back to any model tagged '7b' or the first available
    if not base_model:
        for m in installed:
            if '7b' in m:
                base_model = m
                break
    if not base_model and installed:
        base_model = installed[0]

    if base_model:
        custom_ok = create_custom_modelfile(base_model)
        if custom_ok:
            installed = get_installed_models()
    else:
        print("  No base model available for custom Modelfile creation.")
        custom_ok = False

    # -------------------------------------------------------------------
    # Step 4: Test models
    # -------------------------------------------------------------------
    print(f"\n[4/5] Testing model availability...")
    test_results = {}
    for m in installed:
        ok = test_model(m)
        test_results[m] = 'pass' if ok else 'fail'

    passed = sum(1 for v in test_results.values() if v == 'pass')
    print(f"\n  Test results: {passed}/{len(test_results)} models responding")

    # -------------------------------------------------------------------
    # Step 5: Save configuration
    # -------------------------------------------------------------------
    print(f"\n[5/5] Saving configuration...")
    config = save_config(installed, CUSTOM_MODEL_NAME, test_results)

    # -------------------------------------------------------------------
    # Summary
    # -------------------------------------------------------------------
    print()
    print("  " + "=" * 58)
    print("  Setup Complete")
    print("  " + "=" * 58)
    print()
    print(f"  Backend:          Ollama ({OLLAMA_BASE_URL})")
    print(f"  Models installed: {len(installed)}")
    print(f"  Models passing:   {passed}")
    print(f"  Preferred model:  {config.get('preferred_model', 'none')}")
    print(f"  Config file:      {AI_CONFIG_PATH}")
    print()

    if passed == 0:
        print("  WARNING: No models passed testing. AI features will use template fallback.")
        print()
        sys.exit(1)

    print("  The AI engine will auto-detect these models at runtime.")
    print("  For air-gapped transfer, copy the Ollama models directory to the target.")
    print()


if __name__ == '__main__':
    main()
