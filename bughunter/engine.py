#!/usr/bin/env python3
"""
engine.py — Standalone BugHunter CLI
Works WITHOUT Claude Code or any AI subscription.

Providers (auto-detected, first available wins):
  FREE:  ollama   — local model, zero cost
                    install: curl -fsSL https://ollama.ai/install.sh | sh
                    then:    ollama pull qwen2.5:14b
         groq     — cloud free tier (fast), set GROQ_API_KEY
                    get key: https://console.groq.com
         deepseek — very cheap cloud,       set DEEPSEEK_API_KEY
                    get key: https://platform.deepseek.com
  PAID:  claude   — set ANTHROPIC_API_KEY
         openai   — set OPENAI_API_KEY
         grok     — set XAI_API_KEY
         openrouter — multi-model gateway, set OPENROUTER_API_KEY
                    get key: https://openrouter.ai/keys
         orcarouter — multi-model gateway, set ORCAROUTER_API_KEY
                    get key: https://www.orcarouter.ai
         fluxion    — multi-model gateway, set FLUXION_API_KEY
                    get key: https://fluxionai.world
                    docs: https://docs.fluxionai.world/user-guide/help-center
         litellm    — 100+ provider gateway (SDK), routes by "provider/model"
                    prefix using each provider's own key; or set
                    LITELLM_API_KEY/LITELLM_API_BASE for a LiteLLM proxy
                    docs: https://docs.litellm.ai
         requesty   - multi-model gateway, set REQUESTY_API_KEY
                    get key: https://app.requesty.ai/api-keys
                    docs: https://docs.requesty.ai
         9router    — local AI gateway / router, set NINEROUTER_API_KEY / NINEROUTER_BASE_URL
                    default: http://localhost:20128/v1
                    repo: https://github.com/decolua/9router

Usage:
  ./engine.py setup                        one-time config wizard
  ./engine.py recon  <target>              recon + AI surface analysis
  ./engine.py hunt   <target>              full hunt pipeline
  ./engine.py validate "<finding>"         7-Question Gate on a finding
  ./engine.py report [--findings-dir DIR]  write submission-ready report
  ./engine.py chain  [--findings-dir DIR]  build A->B->C exploit chain
  ./engine.py triage "<finding>"           fast triage (pass/kill/downgrade)
  ./engine.py chat                         interactive Q&A shell
  ./engine.py models                       list available models
  ./engine.py status                       show hunt status
  ./engine.py providers                    show all providers + API key status
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import textwrap
from pathlib import Path

# ── Paths ──────────────────────────────────────────────────────────────────────
HERE     = Path(__file__).resolve().parent  # resolve symlink first so /usr/local/bin/bughunter -> repo dir
AGENTS   = HERE / "agents"
TOOLS    = HERE / "tools"
# Writable output goes under a user data home, not the install dir, so the tool
# works whether it runs from a git clone or a read-only pip install.
# Override with BUGHUNTER_HOME; defaults to the clone dir if it is writable
# (preserves legacy layout), else ~/.bughunter.
def _data_home():
    import os
    env = os.environ.get("BUGHUNTER_HOME")
    if env:
        return Path(env).expanduser()
    if os.access(HERE, os.W_OK):
        return HERE
    return Path.home() / ".bughunter"

DATA_HOME = _data_home()
RECON    = DATA_HOME / "recon"
FINDINGS = DATA_HOME / "findings"
REPORTS  = DATA_HOME / "reports"
CONFIG   = Path.home() / ".bughunter" / "config.json"

# ── Colors ─────────────────────────────────────────────────────────────────────
GREEN  = "\033[0;32m"
CYAN   = "\033[0;36m"
YELLOW = "\033[1;33m"
RED    = "\033[0;31m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
NC     = "\033[0m"


def ok(msg):   print(f"{GREEN}{BOLD}[+]{NC} {msg}")
def info(msg): print(f"{CYAN}{BOLD}[*]{NC} {msg}")
def warn(msg): print(f"{YELLOW}{BOLD}[!]{NC} {msg}")
def err(msg):  print(f"{RED}{BOLD}[-]{NC} {msg}")


def header(title: str):
    width = max(len(title) + 4, 60)
    print(f"\n{BOLD}{'═' * width}{NC}")
    print(f"{BOLD}  {title}{NC}")
    print(f"{BOLD}{'═' * width}{NC}\n")


def load_config() -> dict:
    if CONFIG.exists():
        try:
            return json.loads(CONFIG.read_text())
        except json.JSONDecodeError as e:
            warn(f"Corrupted config file {CONFIG}, using defaults: {e}")
        except OSError as e:
            warn(f"Could not read config file {CONFIG}: {e}")
    return {}


def save_config(cfg: dict):
    # The config can hold API keys. write_text() would create the file under
    # the process umask (often 0o644) and only chmod afterward, leaving a brief
    # world-readable window on a multi-user host. Create it 0o600 from the
    # start (and tighten the dir), then chmod in case it pre-existed.
    CONFIG.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(CONFIG.parent, 0o700)
    except OSError:
        pass
    fd = os.open(str(CONFIG), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(json.dumps(cfg, indent=2))
    os.chmod(CONFIG, 0o600)


COMMAND_ALIASES = {
    "setup": {"setup", "init"},
    "login": {"login", "auth"},
    "providers": {"providers", "p"},
    "models": {"models", "m"},
    "status": {"status", "s"},
    "chat": {"chat", "ask"},
    "recon": {"recon", "r"},
    "hunt": {"hunt", "h"},
    "validate": {"validate", "v"},
    "triage": {"triage", "t"},
    "report": {"report", "rep"},
    "chain": {"chain", "c"},
}


def _print_quick_help():
    print(textwrap.dedent("""
    BugHunter — fast commands

    bughunter help                 Show full help
    bughunter setup                Configure your AI provider
    bughunter recon target.com     Map the attack surface
    bughunter hunt target.com      Run the full hunt pipeline
    bughunter validate "finding"   Run the 7-Question Gate
    bughunter report               Write a submission-ready report
    bughunter status               Show pipeline status

    Short aliases:
      init=setup   p=providers   m=models   s=status   r=recon
      h=hunt       v=validate    t=triage   rep=report   c=chain
    """).strip())


def _normalize_cli_argv(argv: list[str]) -> list[str]:
    if not argv:
        return argv
    if argv[0] in {"help", "-help"}:
        return ["--help", *argv[1:]]
    return ["--help" if item == "-help" else item for item in argv]


def load_agent_prompt(agent_name: str) -> str:
    """Read agents/<name>.md, strip YAML frontmatter, return body as system prompt."""
    md = AGENTS / f"{agent_name}.md"
    if not md.exists():
        return ""
    text = md.read_text()
    if text.startswith("---"):
        end = text.find("---", 3)
        if end != -1:
            text = text[end + 3:].lstrip()
    return text.strip()


def _import_brain():
    """Import Brain and LLMClient from brain.py."""
    sys.path.insert(0, str(HERE))
    try:
        from brain import Brain, LLMClient  # noqa: PLC0415
        return Brain, LLMClient
    except ImportError as e:
        err(f"Could not import brain.py: {e}")
        sys.exit(1)


def _configured_model(cfg: dict, provider: str | None) -> str | None:
    """Resolve a model override from env or the per-provider saved config."""
    if os.environ.get("BRAIN_MODEL"):
        return os.environ["BRAIN_MODEL"]
    models = cfg.get("models", {})
    if isinstance(models, dict) and provider:
        return models.get(provider) or None
    return None


def _get_client(provider: str | None = None):
    """Return an LLMClient, applying saved config if no env override."""
    _, LLMClient = _import_brain()
    cfg = load_config()
    provider = provider or os.environ.get("BRAIN_PROVIDER") or cfg.get("provider")
    if provider:
        os.environ["BRAIN_PROVIDER"] = provider
    model = _configured_model(cfg, provider)
    if model:
        os.environ["BRAIN_MODEL"] = model
    if cfg.get("NINEROUTER_BASE_URL") and "NINEROUTER_BASE_URL" not in os.environ:
        os.environ["NINEROUTER_BASE_URL"] = cfg["NINEROUTER_BASE_URL"]
    if cfg.get("NINEROUTER_API_KEY") and "NINEROUTER_API_KEY" not in os.environ:
        os.environ["NINEROUTER_API_KEY"] = cfg["NINEROUTER_API_KEY"]
    return LLMClient(provider, model=model)


def _get_brain(provider: str | None = None):
    """Return a Brain instance."""
    Brain, _ = _import_brain()
    cfg = load_config()
    provider = provider or os.environ.get("BRAIN_PROVIDER") or cfg.get("provider")
    if provider:
        os.environ["BRAIN_PROVIDER"] = provider
    model = _configured_model(cfg, provider)
    if model:
        os.environ["BRAIN_MODEL"] = model
    if cfg.get("NINEROUTER_BASE_URL") and "NINEROUTER_BASE_URL" not in os.environ:
        os.environ["NINEROUTER_BASE_URL"] = cfg["NINEROUTER_BASE_URL"]
    if cfg.get("NINEROUTER_API_KEY") and "NINEROUTER_API_KEY" not in os.environ:
        os.environ["NINEROUTER_API_KEY"] = cfg["NINEROUTER_API_KEY"]
    return Brain(model=model, provider=provider)


def _run_shell(cmd: list[str], cwd: str | None = None, timeout: int = 3600,
               env: dict | None = None) -> tuple[bool, str]:
    """Run a command with live output, return (success, combined_output).
    Takes an argv list, not a shell string — see
    SECURITY-REVIEW-2026-08-22.md finding #5 for why shell=True with
    f-string-interpolated targets was a command injection bug.
    `env`, when given, is merged over the current environment."""
    proc_env = {**os.environ, **env} if env else None
    try:
        proc = subprocess.Popen(
            cmd, shell=False, cwd=cwd or str(HERE), env=proc_env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        lines = []
        for line in proc.stdout:
            print(line, end="", flush=True)
            lines.append(line)
        proc.wait(timeout=timeout)
        return proc.returncode == 0, "".join(lines)
    except subprocess.TimeoutExpired:
        proc.kill()
        return False, "timed out"
    except Exception as e:
        return False, str(e)


# ── Commands ───────────────────────────────────────────────────────────────────

def cmd_setup(args):
    """Interactive setup wizard."""
    header("BugHunter Setup")

    providers = {
        "1":  ("ollama",     "Ollama     (local, FREE)       — needs ollama running locally"),
        "2":  ("9router",    "9Router    (local gateway)     — needs 9router running locally"),
        "3":  ("groq",       "Groq       (cloud, FREE tier)  — needs GROQ_API_KEY"),
        "4":  ("deepseek",   "DeepSeek   (cloud, very cheap)— needs DEEPSEEK_API_KEY"),
        "5":  ("claude",     "Claude     (paid)              — needs ANTHROPIC_API_KEY"),
        "6":  ("openai",     "OpenAI     (paid)              — needs OPENAI_API_KEY"),
        "7":  ("grok",       "Grok/xAI   (paid)              — needs XAI_API_KEY"),
        "8":  ("openrouter", "OpenRouter (multi-model)       — needs OPENROUTER_API_KEY"),
        "9":  ("orcarouter", "OrcaRouter (multi-model)       — needs ORCAROUTER_API_KEY"),
        "10": ("fluxion",    "Fluxion    (multi-model)       — needs FLUXION_API_KEY"),
        "11": ("litellm",     "LiteLLM     (100+ providers)    — uses per-provider keys or LITELLM_API_KEY"),
        "12": ("requesty",    "Requesty    (multi-model)       — needs REQUESTY_API_KEY"),
        "13": ("antigravity", "Antigravity / Gemini (Google OAuth — Gemini AI)"),
    }

    requested_provider = (
        getattr(args, "setup_provider", None)
        or getattr(args, "provider", None)
    )
    if requested_provider:
        provider = requested_provider.lower()
        info(f"Selected provider: {provider}")
    else:
        print("Choose your AI backend:\n")
        for k, (_, desc) in providers.items():
            print(f"  {k:>2}) {desc}")
        print()

        choice = input("Enter number [1]: ").strip() or "1"
        provider = providers.get(choice, ("ollama", ""))[0]

    if provider in ("gemini", "gemini-oauth", "google-oauth", "agy") and not os.environ.get("GEMINI_API_KEY"):
        provider = "antigravity"

    requested_model = (
        getattr(args, "setup_model", None)
        or getattr(args, "model", None)
    )

    cfg = load_config()
    cfg["provider"] = provider

    env_map = {
        "groq":       "GROQ_API_KEY",
        "deepseek":   "DEEPSEEK_API_KEY",
        "claude":     "ANTHROPIC_API_KEY",
        "openai":     "OPENAI_API_KEY",
        "grok":       "XAI_API_KEY",
        "openrouter": "OPENROUTER_API_KEY",
        "orcarouter": "ORCAROUTER_API_KEY",
        "fluxion":    "FLUXION_API_KEY",
        "requesty":   "REQUESTY_API_KEY",
        "9router":    "NINEROUTER_API_KEY",
        "gemini":     "GEMINI_API_KEY",
    }

    if provider == "antigravity":
        sys.path.insert(0, str(HERE))
        from tools.google_oauth import (
            ANTIGRAVITY_MODEL_LABELS,
            get_valid_credentials,
            interactive_google_oauth_login,
            resolve_antigravity_model,
        )
        creds = get_valid_credentials()
        if creds and creds.get("access_token"):
            email = creds.get("email") or "Google Account"
            ok(f"Google OAuth session active: {email}")
            if not requested_provider and sys.stdin.isatty():
                relogin = input("Login with another Google account? (y/N): ").strip().lower()
                if relogin.startswith("y"):
                    no_browser = input("Use manual authorization code instead of browser? (y/N): ").strip().lower().startswith("y")
                    creds = interactive_google_oauth_login(no_browser=no_browser)
                    ok(f"Google OAuth login successful: {creds.get('email', 'authenticated')}")
        elif not requested_provider and sys.stdin.isatty():
            do_oauth = input("Sign in with Google OAuth in browser now? (Y/n): ").strip().lower()
            if not do_oauth.startswith("n"):
                no_browser = input("Use manual copy-paste code instead of opening browser? (y/N): ").strip().lower().startswith("y")
                try:
                    creds = interactive_google_oauth_login(no_browser=no_browser)
                    ok(f"Google OAuth login successful: {creds.get('email', 'authenticated')}")
                except Exception as exc:
                    warn(f"Browser OAuth skipped ({exc}) — using active Antigravity CLI session")

    elif provider in ("9router", "ninerouter"):
        existing_base = os.environ.get("NINEROUTER_BASE_URL", "") or cfg.get("NINEROUTER_BASE_URL", "") or "http://localhost:20128/v1"
        try:
            print(f"\nEnter 9Router Base URL [{existing_base}]: ", end="", flush=True)
            base_in = input().strip()
            chosen_base = base_in or existing_base
        except (EOFError, KeyboardInterrupt):
            chosen_base = existing_base
        cfg["NINEROUTER_BASE_URL"] = chosen_base
        os.environ["NINEROUTER_BASE_URL"] = chosen_base

        existing_key = os.environ.get("NINEROUTER_API_KEY", "") or cfg.get("NINEROUTER_API_KEY", "")
        prompt_key = " (blank to keep existing)" if existing_key else " (blank if no auth)"
        try:
            print(f"Enter NINEROUTER_API_KEY{prompt_key}: ", end="", flush=True)
            api_key = input().strip()
            if api_key:
                cfg["NINEROUTER_API_KEY"] = api_key
                os.environ["NINEROUTER_API_KEY"] = api_key
            elif existing_key:
                cfg["NINEROUTER_API_KEY"] = existing_key
                os.environ["NINEROUTER_API_KEY"] = existing_key
        except (EOFError, KeyboardInterrupt):
            if existing_key:
                cfg["NINEROUTER_API_KEY"] = existing_key
                os.environ["NINEROUTER_API_KEY"] = existing_key

    elif provider in env_map:
        env_var = env_map[provider]
        existing = os.environ.get(env_var, "") or cfg.get(env_var, "")
        print(f"\nEnter {env_var} (blank = keep existing): ", end="")
        api_key = input().strip()
        if api_key:
            cfg[env_var] = api_key
            os.environ[env_var] = api_key
        elif existing:
            cfg[env_var] = existing
            os.environ[env_var] = existing
            info(f"Using existing {env_var} from environment")
        else:
            warn(f"No {env_var} set — provider may not work")

    # Test connection
    info("Testing connection...")
    _, LLMClient = _import_brain()
    if provider in env_map and cfg.get(env_map[provider]):
        os.environ[env_map[provider]] = cfg[env_map[provider]]
    if cfg.get("NINEROUTER_BASE_URL"):
        os.environ["NINEROUTER_BASE_URL"] = cfg["NINEROUTER_BASE_URL"]
    if cfg.get("NINEROUTER_API_KEY"):
        os.environ["NINEROUTER_API_KEY"] = cfg["NINEROUTER_API_KEY"]

    client = LLMClient(provider)
    if client.available:
        ok(f"Connected: {client.description}")
        selected_model = None
        if provider == "ollama":
            models = client.list_models()
            if models:
                if requested_model:
                    if requested_model not in models:
                        err(f"Ollama model '{requested_model}' is not installed")
                        print("  Available models:")
                        for model_name in models:
                            print(f"    {model_name}")
                        print(f"  Install it with: ollama pull {requested_model}")
                        return
                    selected_model = requested_model
                else:
                    saved_models = cfg.get("models", {})
                    current = saved_models.get("ollama") if isinstance(saved_models, dict) else None
                    default_index = models.index(current) + 1 if current in models else 1
                    print("\nChoose the Ollama model BugHunter should use:\n")
                    for index, model_name in enumerate(models, start=1):
                        marker = " (current)" if model_name == current else ""
                        print(f"  {index}) {model_name}{marker}")
                    choice = input(f"\nEnter number [{default_index}]: ").strip()
                    try:
                        selected_model = models[int(choice or default_index) - 1]
                    except (ValueError, IndexError):
                        warn("Invalid model choice — using the default selection")
                        selected_model = models[default_index - 1]
                if not isinstance(cfg.get("models"), dict):
                    cfg["models"] = {}
                cfg.setdefault("models", {})["ollama"] = selected_model
                os.environ["BRAIN_MODEL"] = selected_model
                ok(f"Selected model: {selected_model}")
            else:
                warn("No local Ollama models found — pull one, then run setup again")
        elif provider == "antigravity" and not requested_model and sys.stdin.isatty():
            sys.path.insert(0, str(HERE))
            from tools.google_oauth import ANTIGRAVITY_MODEL_LABELS, resolve_antigravity_model
            models = client.list_models()
            if models:
                saved_models = cfg.get("models", {})
                current = saved_models.get(provider) if isinstance(saved_models, dict) else None
                if current:
                    current = resolve_antigravity_model(current)
                default_index = models.index(current) + 1 if current in models else 1
                print("\nChoose the Antigravity / Gemini model BugHunter should use:\n")
                for index, model_name in enumerate(models, start=1):
                    label = ANTIGRAVITY_MODEL_LABELS.get(model_name, "")
                    label_str = f" — {label}" if label else ""
                    marker = " (current)" if model_name == current else ""
                    print(f"  {index:>2}) {model_name:<25}{label_str}{marker}")
                choice = input(f"\nEnter number [{default_index}]: ").strip()
                try:
                    selected_model = models[int(choice or default_index) - 1]
                except (ValueError, IndexError):
                    selected_model = models[default_index - 1]
                if not isinstance(cfg.get("models"), dict):
                    cfg["models"] = {}
                cfg.setdefault("models", {})[provider] = selected_model
                os.environ["BRAIN_MODEL"] = selected_model
                ok(f"Selected model: {selected_model}")
        elif provider in ("9router", "ninerouter"):
            if requested_model:
                selected_model = requested_model
            else:
                models = client.list_models()
                saved_models = cfg.get("models", {})
                current = saved_models.get(provider) if isinstance(saved_models, dict) else None
                if models:
                    default_index = models.index(current) + 1 if current in models else 1
                    print(f"\nChoose the 9Router model BugHunter should use ({len(models)} available):\n")
                    for index, model_name in enumerate(models, start=1):
                        marker = " (current)" if model_name == current else ""
                        print(f"  {index:>2}) {model_name}{marker}")
                    try:
                        print(f"\nEnter number or model name [{default_index}]: ", end="", flush=True)
                        choice = input().strip()
                        if not choice:
                            selected_model = models[default_index - 1]
                        elif choice.isdigit() and 1 <= int(choice) <= len(models):
                            selected_model = models[int(choice) - 1]
                        else:
                            selected_model = choice
                    except (EOFError, KeyboardInterrupt):
                        selected_model = models[default_index - 1]
                else:
                    default_m = current or "openai/gpt-4o"
                    try:
                        print(f"\nEnter 9Router model name to use [{default_m}]: ", end="", flush=True)
                        selected_model = input().strip() or default_m
                    except (EOFError, KeyboardInterrupt):
                        selected_model = default_m

            if not isinstance(cfg.get("models"), dict):
                cfg["models"] = {}
            cfg.setdefault("models", {})[provider] = selected_model
            os.environ["BRAIN_MODEL"] = selected_model
            ok(f"Selected model: {selected_model}")
        elif requested_model:
            if provider == "antigravity":
                sys.path.insert(0, str(HERE))
                from tools.google_oauth import resolve_antigravity_model
                requested_model = resolve_antigravity_model(requested_model)
            if not isinstance(cfg.get("models"), dict):
                cfg["models"] = {}
            cfg.setdefault("models", {})[provider] = requested_model
            os.environ["BRAIN_MODEL"] = requested_model
            selected_model = requested_model
            ok(f"Selected model: {selected_model}")

        save_config(cfg)
        ok(f"Config saved to {CONFIG}")
        reply = client.chat(selected_model, "You are a helpful assistant.",
                            "Reply with exactly: READY", max_tokens=10)
        ok(f"Model responded: {reply.strip()}" if reply else "Connected (no reply — pull a model if using Ollama)")
    else:
        if not requested_model:
            save_config(cfg)
            ok(f"Config saved to {CONFIG}")
        else:
            warn("Configuration was not changed because the requested model could not be verified")
        err(f"Provider '{provider}' not available")
        if provider == "ollama":
            print(f"\n  {YELLOW}Install Ollama:{NC}")
            print("    curl -fsSL https://ollama.ai/install.sh | sh")
            print("    ollama pull qwen2.5:14b")
        elif provider in env_map:
            print(f"\n  {YELLOW}Set API key:{NC}  export {env_map[provider]}=your_key_here")


def cmd_login(args):
    """Google OAuth 2.0 login / status / logout for Gemini AI Pro."""
    header("Google OAuth — Gemini AI Pro")
    sys.path.insert(0, str(HERE))
    from tools.google_oauth import (
        BUGHUNTER_OAUTH_FILE,
        clear_oauth_credentials,
        get_valid_credentials,
        interactive_google_oauth_login,
    )

    if getattr(args, "logout", False):
        if clear_oauth_credentials():
            ok(f"Removed saved Google OAuth credentials ({BUGHUNTER_OAUTH_FILE})")
        else:
            info("No saved Google OAuth credentials to remove.")
        return

    if getattr(args, "status", False):
        creds = get_valid_credentials()
        if creds and creds.get("access_token"):
            email = creds.get("email") or "authenticated"
            tier = creds.get("user_tier_name") or creds.get("user_tier") or "Gemini AI Pro"
            proj = creds.get("project_id") or "auto"
            ok(f"Google OAuth active: {email}")
            info(f"Tier: {tier} | Project: {proj}")
            info(f"Credentials file: {creds.get('_source_path', BUGHUNTER_OAUTH_FILE)}")
        else:
            warn("Not logged in with Google OAuth. Run: bughunter login")
        return

    no_browser = bool(getattr(args, "no_browser", False))
    try:
        creds = interactive_google_oauth_login(no_browser=no_browser)
    except Exception as exc:
        err(f"Google OAuth login failed: {exc}")
        sys.exit(1)

    email = creds.get("email") or "Google Account"
    tier = creds.get("user_tier_name") or creds.get("user_tier") or "Gemini AI Pro (Antigravity)"
    ok(f"Logged in as: {email} ({tier})")
    ok(f"Credentials saved to: {BUGHUNTER_OAUTH_FILE}")

    cfg = load_config()
    cfg["provider"] = "antigravity"
    cfg.setdefault("models", {})["antigravity"] = (
        getattr(args, "model", None) or cfg.get("models", {}).get("antigravity") or "gemini-4-argon-high"
    )
    save_config(cfg)
    ok(f"Active provider set to 'antigravity' (model: {cfg['models']['antigravity']})")


def cmd_providers(args):
    """Show all providers and API key status."""
    import shutil
    _, LLMClient = _import_brain()
    cfg = load_config()
    saved = cfg.get("provider", "")
    if saved in ("gemini", "gemini-oauth", "google-oauth", "agy") and not os.environ.get("GEMINI_API_KEY"):
        saved = "antigravity"

    sys.path.insert(0, str(HERE))
    try:
        from tools.google_oauth import load_oauth_credentials
        oauth_creds = load_oauth_credentials()
    except Exception:
        oauth_creds = None

    env_map = {
        "ollama":       None,
        "antigravity":  None,
        "groq":         "GROQ_API_KEY",
        "deepseek":     "DEEPSEEK_API_KEY",
        "claude":       "ANTHROPIC_API_KEY",
        "openai":       "OPENAI_API_KEY",
        "grok":         "XAI_API_KEY",
        "openrouter":   "OPENROUTER_API_KEY",
        "orcarouter":   "ORCAROUTER_API_KEY",
        "fluxion":      "FLUXION_API_KEY",
        "requesty":     "REQUESTY_API_KEY",
        "9router":      "NINEROUTER_API_KEY",
    }
    tier = {
        "ollama":       "FREE (local)",
        "9router":      "FREE (gateway)",
        "antigravity":  "Gemini AI Pro",
        "groq":         "FREE tier",
        "deepseek":     "cheap",
        "claude":       "paid",
        "openai":       "paid",
        "grok":         "paid",
        "openrouter":   "subscription",
        "orcarouter":   "subscription",
        "fluxion":      "subscription",
        "requesty":     "pay-as-you-go",
    }

    print(f"\n  {'PROVIDER':<14} {'TIER':<16} {'STATUS':<22} {'NOTE'}")
    print(f"  {'─'*14} {'─'*16} {'─'*22} {'─'*30}")

    for prov, env_var in env_map.items():
        if prov == "antigravity":
            agy_bin = os.environ.get("AGY_BIN") or shutil.which("agy") or str(Path.home() / ".local" / "bin" / "agy")
            email = (oauth_creds or {}).get("email")
            if agy_bin and os.path.isfile(agy_bin) and os.access(agy_bin, os.X_OK):
                status = f"{GREEN}OAuth ready{NC}"
                note = f"{email} (Google OAuth)" if email else "Google OAuth / agy"
            else:
                status = f"{RED}not installed{NC}"
                note = "install Antigravity CLI"
        elif prov in ("9router", "ninerouter"):
            base_url = (os.environ.get("NINEROUTER_BASE_URL", "")
                        or "http://localhost:20128/v1").rstrip("/")
            try:
                import urllib.request
                urllib.request.urlopen(f"{base_url}/models", timeout=1)
                status = f"{GREEN}running{NC}"
                note   = f"{base_url}"
            except Exception:
                key_set = bool(os.environ.get("NINEROUTER_API_KEY") or cfg.get("NINEROUTER_API_KEY"))
                if key_set:
                    status = f"{YELLOW}key set (offline){NC}"
                    note   = "NINEROUTER_API_KEY set"
                else:
                    status = f"{YELLOW}not running{NC}"
                    note   = "start: 9router (port 20128)"
        elif env_var:
            key_set = bool(os.environ.get(env_var) or cfg.get(env_var))
            status  = f"{GREEN}key set{NC}" if key_set else f"{RED}no key{NC}"
            note    = env_var if not key_set else ""
        else:
            try:
                import urllib.request
                urllib.request.urlopen("http://localhost:11434", timeout=1)
                status = f"{GREEN}running{NC}"
                note   = ""
            except Exception:
                status = f"{YELLOW}not running{NC}"
                note   = "ollama serve"

        marker = f" {BOLD}<- active{NC}" if prov == saved else ""
        print(f"  {BOLD}{prov:<14}{NC} {tier[prov]:<16} {status:<32} {DIM}{note}{NC}{marker}")

    print(f"\n  Config: {CONFIG}")
    print(f"  Change: ./engine.py setup\n")


def cmd_models(args):
    """List available models for the active provider."""
    cfg = load_config()
    provider = getattr(args, "provider", None) or cfg.get("provider")
    client = _get_client(provider)
    if not client.available:
        err(f"Provider '{client.provider}' not available. Run: ./engine.py setup")
        return
    models = client.list_models()
    info(f"Provider: {client.description}")
    selected = _configured_model(cfg, client.provider)
    if models:
        sys.path.insert(0, str(HERE))
        try:
            from tools.google_oauth import ANTIGRAVITY_MODEL_LABELS
        except Exception:
            ANTIGRAVITY_MODEL_LABELS = {}
        for m in models:
            label = ANTIGRAVITY_MODEL_LABELS.get(m, "")
            label_str = f" — {DIM}{label}{NC}" if label else ""
            marker = f" {BOLD}<- selected{NC}" if m == selected else ""
            print(f"  {GREEN}•{NC} {m:<25}{label_str}{marker}")
    else:
        warn("No models found")
        if client.provider == "ollama":
            print("  Pull a model: ollama pull qwen2.5:14b")


def cmd_recon(args):
    """Run recon pipeline then AI surface analysis."""
    from tools.target_normalize import safe_target_dirname

    target = args.target
    # The scanners need a bare host; the output dir must match what
    # recon_engine.sh writes. Both derive it the same way (host, no scheme/port),
    # and we pin RECON_OUT_DIR so the two never disagree across install layouts.
    # Reject anything that isn't a safe single path component — never fall back
    # to the raw target, or `recon ../../etc/x` / `recon /etc/x` would write
    # outside the recon sandbox.
    host = safe_target_dirname(target)
    if not host:
        err(f"Refusing unsafe target {target!r} — expected a hostname, IP or CIDR")
        return
    recon_dir = RECON / host
    header(f"Recon: {host}")

    script = TOOLS / "recon_engine.sh"
    if script.exists():
        info("Running recon pipeline...")
        success, _ = _run_shell(["bash", str(script), target],
                                env={"RECON_OUT_DIR": str(recon_dir)})
        if not success:
            warn("Recon had issues — continuing with AI analysis")
    else:
        warn("recon_engine.sh not found — skipping to AI analysis")

    info("Running AI surface analysis...")
    brain = _get_brain()
    result = brain.analyze_recon(str(recon_dir) if recon_dir.exists() else target)
    if result:
        print(f"\n{result}")
    else:
        warn("AI analysis returned no output — check provider with: ./engine.py providers")


def cmd_hunt(args):
    """Full hunt pipeline: recon + vuln scan + AI analysis."""
    from tools.target_normalize import safe_target_dirname

    target = args.target
    host = safe_target_dirname(target)
    if not host:
        err(f"Refusing unsafe target {target!r} — expected a hostname, IP or CIDR")
        return
    header(f"Hunt: {host}")

    recon_dir = RECON / host

    # Run recon
    script = TOOLS / "recon_engine.sh"
    if script.exists():
        info("Phase 1: Recon...")
        _run_shell(["bash", str(script), target],
                   env={"RECON_OUT_DIR": str(recon_dir)})

    # Run vuln scan
    vuln_script = TOOLS / "vuln_scanner.sh"
    if vuln_script.exists() and recon_dir.exists():
        info("Phase 2: Vuln scan...")
        _run_shell(["bash", str(vuln_script), str(recon_dir)])

    # AI analysis
    info("Phase 3: AI analysis...")
    brain = _get_brain()
    findings_dir = FINDINGS / host
    if findings_dir.exists():
        brain.interpret_scan(str(findings_dir))
    elif recon_dir.exists():
        brain.analyze_recon(str(recon_dir))
    else:
        warn(f"No data for {host} — run recon first")


def cmd_validate(args):
    """Run 7-Question Gate on a finding description."""
    finding = getattr(args, "finding", "") or ""
    if not finding:
        finding = _read_stdin_or_prompt("Paste your finding description (Ctrl+D when done):\n")

    header("7-Question Gate")
    info(f"Finding: {finding[:120]}{'...' if len(finding) > 120 else ''}")

    brain = _get_brain()
    decision, explanation = brain.triage_finding(finding)

    print(f"\n{BOLD}{'─'*60}{NC}")
    if decision.startswith("PASS"):
        color = GREEN
    elif "DOWNGRADE" in decision or "CHAIN" in decision:
        color = YELLOW
    else:
        color = RED
    print(f"{color}{BOLD}DECISION: {decision}{NC}")
    if explanation:
        print(f"\n{explanation}")
    print(f"{BOLD}{'─'*60}{NC}\n")


def cmd_triage(args):
    """Alias for validate."""
    cmd_validate(args)


def cmd_report(args):
    """Generate a submission-ready bug report."""
    findings_dir = getattr(args, "findings_dir", "") or ""
    session_id = getattr(args, "session_id", None)
    output_format = getattr(args, "format", None)
    if session_id:
        from bughunter.memory.evidence import EvidenceError
        from bughunter.phases.p09_reporting import write_session_report

        if findings_dir:
            raise SystemExit("report: choose a session ID or --findings-dir")
        try:
            path = write_session_report(session_id, output_format or "markdown")
        except (EvidenceError, OSError, ValueError) as error:
            raise SystemExit(f"report: {error}") from None
        print(path)
        return
    if output_format:
        raise SystemExit("report: --format requires a session ID")
    if not findings_dir:
        targets = sorted(FINDINGS.glob("*/")) if FINDINGS.exists() else []
        if targets:
            findings_dir = str(targets[-1])
            info(f"Using findings dir: {findings_dir}")
        else:
            err("No findings dir found. Use: ./engine.py report --findings-dir findings/<target>")
            sys.exit(1)

    header("Report Writer")
    brain = _get_brain()

    recon_dir = ""
    target_name = Path(findings_dir).name
    candidate = RECON / target_name
    if candidate.exists():
        recon_dir = str(candidate)

    result = brain.write_report(findings_dir, recon_dir)
    if result:
        print(f"\n{result}")
        ok("Report written.")
    else:
        warn("No report output — ensure findings directory has data")


def cmd_retest(args):
    """Differential retesting on a previous assessment session."""
    session_id = getattr(args, "session_id", None)
    if not session_id:
        raise SystemExit("retest: session_id is required")
    from bughunter.core.session import SessionManager
    from bughunter.harness.orchestrator import HarnessOrchestrator
    try:
        manager = SessionManager()
        state = manager.load(session_id)
        orch = HarnessOrchestrator(
            session_id=session_id,
            target=state["target"],
            session_manager=manager,
            dry_run=getattr(args, "dry_run", False),
        )
        res = orch.retest()
        print(json.dumps(res, indent=2))
    except Exception as e:
        raise SystemExit(f"retest error: {e}")


def cmd_chain(args):
    """Build A->B->C exploit chain."""
    findings_dir = getattr(args, "findings_dir", "") or ""
    finding = getattr(args, "finding", "") or ""

    if not findings_dir:
        targets = sorted(FINDINGS.glob("*/")) if FINDINGS.exists() else []
        if targets:
            findings_dir = str(targets[-1])

    header("Chain Builder")

    if findings_dir and Path(findings_dir).exists():
        brain = _get_brain()
        result = brain.build_chains(findings_dir)
        if result:
            print(f"\n{result}")
            return

    # Fallback: agent-prompt mode with finding description
    if not finding:
        finding = _read_stdin_or_prompt("Describe the bug to chain from:\n")

    system = load_agent_prompt("chain-builder")
    client = _get_client()
    if not client.available:
        err("No AI provider available. Run: ./engine.py setup")
        sys.exit(1)
    sys.path.insert(0, str(HERE))
    from brain import BRAIN_SYSTEM  # noqa: PLC0415
    result = client.chat(None, system or BRAIN_SYSTEM,
                         f"Build an exploit chain starting from this bug:\n\n{finding}")
    if result:
        print(f"\n{result}")


def cmd_chat(args):
    """Interactive Q&A shell."""
    header("BugHunter Chat")
    client = _get_client()
    if not client.available:
        err("No AI provider available. Run: ./engine.py setup")
        sys.exit(1)

    sys.path.insert(0, str(HERE))
    from brain import BRAIN_SYSTEM  # noqa: PLC0415

    ok(f"Connected: {client.description}")
    print(f"{DIM}Type 'exit' or Ctrl+C to quit{NC}\n")

    history: list[dict] = []
    while True:
        try:
            user_input = input(f"{CYAN}{BOLD}you>{NC} ").strip()
        except (KeyboardInterrupt, EOFError):
            print()
            break

        if user_input.lower() in ("exit", "quit", "q"):
            break
        if not user_input:
            continue

        ctx_parts = []
        for turn in history[-4:]:
            ctx_parts.append(f"[you] {turn['user']}")
            ctx_parts.append(f"[assistant] {turn['assistant']}")
        prompt = ("\n".join(ctx_parts) + "\n\n" if ctx_parts else "") + f"[you] {user_input}"

        reply = client.chat(None, BRAIN_SYSTEM, prompt, max_tokens=2000)
        if reply:
            print(f"\n{reply}\n")
            history.append({"user": user_input, "assistant": reply})
        else:
            warn("No response — check provider with: ./engine.py providers")


def cmd_status(args):
    """Show pipeline status."""
    header("Hunt Status")

    recon_targets = sorted(RECON.glob("*/")) if RECON.exists() else []
    print(f"  {BOLD}Recon completed:{NC} {len(recon_targets)} target(s)")
    for t in recon_targets[:5]:
        subs = t / "subdomains" / "all.txt"
        live = t / "live" / "urls.txt"
        n_subs = sum(1 for _ in subs.open()) if subs.exists() else 0
        n_live = sum(1 for _ in live.open()) if live.exists() else 0
        print(f"    {GREEN}•{NC} {t.name}: {n_subs} subdomains, {n_live} live hosts")

    finding_targets = sorted(FINDINGS.glob("*/")) if FINDINGS.exists() else []
    print(f"\n  {BOLD}Findings:{NC} {len(finding_targets)} target(s)")
    for t in finding_targets[:5]:
        summary = t / "summary.txt"
        if summary.exists():
            m = re.search(r"TOTAL FINDINGS:\s*(\d+)", summary.read_text())
            count = m.group(1) if m else "?"
            print(f"    {GREEN}•{NC} {t.name}: {count} findings")

    report_targets = sorted(REPORTS.glob("*/")) if REPORTS.exists() else []
    print(f"\n  {BOLD}Reports:{NC} {len(report_targets)} target(s)")
    for t in report_targets[:5]:
        print(f"    {GREEN}•{NC} {t.name}: {len(list(t.glob('*.md')))} report(s)")

    print(f"\n  {BOLD}Provider:{NC} ", end="")
    client = _get_client()
    if client.available:
        model = _configured_model(load_config(), client.provider)
        model_note = f" | model: {model}" if model else " | model: automatic"
        print(f"{GREEN}{client.description}{model_note}{NC}")
    else:
        print(f"{RED}not configured{NC} — run: ./engine.py setup")
    print()


def cmd_mcp(args):
    """MCP serve / doctor / tools — delegates to mcp/bughunter-mcp/cli.py."""
    mcp_dir = Path(__file__).resolve().parent / "mcp" / "bughunter-mcp"
    if str(mcp_dir) not in sys.path:
        sys.path.insert(0, str(mcp_dir))
    from cli import main as mcp_main  # type: ignore
    sub = getattr(args, "mcp_command", "serve") or "serve"
    raise SystemExit(mcp_main([sub]))


# ── Utility ────────────────────────────────────────────────────────────────────

def _read_stdin_or_prompt(prompt_text: str) -> str:
    if not sys.stdin.isatty():
        return sys.stdin.read().strip()
    print(prompt_text, end="", flush=True)
    lines = []
    try:
        while True:
            lines.append(input())
    except EOFError:
        pass
    return "\n".join(lines).strip()


def _print_banner():
    G1  = "\033[1;32m"   # bright green
    G2  = "\033[0;32m"   # normal green
    G3  = "\033[2;32m"   # dim green
    LINES = [
        ("   █████╗  ██████╗ ███████╗███╗   ██╗████████╗██╗ ██████╗ ", G1),
        ("  ██╔══██╗██╔════╝ ██╔════╝████╗  ██║╚══██╔══╝██║██╔════╝ ", G2),
        ("  ███████║██║  ███╗█████╗  ██╔██╗ ██║   ██║   ██║██║      ", G1),
        ("  ██╔══██║██║   ██║██╔══╝  ██║╚██╗██║   ██║   ██║██║      ", G2),
        ("  ██║  ██║╚██████╔╝███████╗██║ ╚████║   ██║   ██║╚██████╗ ", G1),
        ("  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝ ╚═════╝ ", G3),
        ("  ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ ",    G1),
        ("  ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗",    G2),
        ("  ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝",    G1),
        ("  ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗",    G2),
        ("  ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║",     G1),
        ("  ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝",    G3),
    ]
    print()
    for line, color in LINES:
        print(f"{color}{line}{NC}")
    print()


# ── CLI entry point ────────────────────────────────────────────────────────────

def main():
    argv = _normalize_cli_argv(sys.argv[1:])
    parser = argparse.ArgumentParser(
        prog="engine.py",
        description="Standalone BugHunter Engine — works without Claude Code",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
        Free setup (zero subscription):
          curl -fsSL https://ollama.ai/install.sh | sh
          ollama pull qwen2.5:14b
          ./engine.py setup
          ./engine.py recon target.com

        Free cloud (Groq — very fast):
          export GROQ_API_KEY=gsk_...
          ./engine.py recon target.com

        Switch providers anytime:
          ./engine.py setup
        """),
    )
    parser.add_argument("--provider", "-p",
                        help="Force provider: ollama / 9router / gemini-oauth / antigravity / gemini / groq / deepseek / claude / openai / grok / openrouter / orcarouter / fluxion / litellm / requesty")
    parser.add_argument("--model", "-m", help="Force model for this invocation (for example qwen3:14b)")
    parser.add_argument("--no-banner", action="store_true", help="Suppress banner")

    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    from bughunter.cli.attack_command import register as register_attack, run as run_attack
    register_attack(sub)

    p_setup = sub.add_parser("setup", aliases=["init"], help="Configure and persist provider/model")
    p_setup.add_argument(
        "--provider", dest="setup_provider",
        choices=["ollama", "9router", "ninerouter", "groq", "deepseek", "claude", "openai", "grok",
                 "openrouter", "orcarouter", "fluxion", "litellm", "requesty",
                 "gemini", "gemini-oauth", "google-oauth", "antigravity", "agy"],
        help="Provider to persist (skips the provider prompt)",
    )
    p_setup.add_argument(
        "--model", dest="setup_model",
        help="Model to persist; an Ollama model must already be installed",
    )

    p_login = sub.add_parser("login", aliases=["auth"], help="Login with Google OAuth (Gemini AI Pro)")
    p_login.add_argument("--no-browser", action="store_true", help="Use manual copy-paste authorization code instead of opening browser")
    p_login.add_argument("--status", action="store_true", help="Check current Google OAuth login status")
    p_login.add_argument("--logout", action="store_true", help="Remove saved Google OAuth credentials")
    sub.add_parser("providers", aliases=["p"], help="Show all providers + API key status")
    sub.add_parser("models",    aliases=["m"], help="List available models for active provider")
    sub.add_parser("status",    aliases=["s"], help="Show hunt pipeline status")
    sub.add_parser("chat",      aliases=["ask"], help="Interactive AI shell")

    p_recon = sub.add_parser("recon", aliases=["r"], help="Recon + AI surface analysis")
    p_recon.add_argument("target", help="Target domain or IP")

    p_hunt = sub.add_parser("hunt", aliases=["h"], help="Full hunt pipeline")
    p_hunt.add_argument("target", help="Target domain or IP")
    p_hunt.add_argument("--quick", action="store_true", help="Quick mode (fewer checks)")

    p_val = sub.add_parser("validate", aliases=["v"], help="7-Question Gate on a finding")
    p_val.add_argument("finding", nargs="?", default="", help="Finding description (or pipe via stdin)")

    p_triage = sub.add_parser("triage", aliases=["t"], help="Fast triage (alias for validate)")
    p_triage.add_argument("finding", nargs="?", default="", help="Finding description")

    p_rep = sub.add_parser("report", aliases=["rep"], help="Write a bug report or export an assessment session")
    p_rep.add_argument("session_id", nargs="?", help="Assessment session ID for offline export")
    p_rep.add_argument("--format", choices=["markdown", "json"], help="Assessment session export format")
    p_rep.add_argument("--findings-dir", default="", help="Path to findings/<target> directory")

    p_chain = sub.add_parser("chain", aliases=["c"], help="Build A->B->C exploit chain")
    p_chain.add_argument("--findings-dir", default="", help="Path to findings/<target> directory")
    p_chain.add_argument("finding", nargs="?", default="", help="Bug A description (or pipe via stdin)")

    p_mcp = sub.add_parser("mcp", help="MCP server / doctor / tool catalog")
    p_mcp.add_argument(
        "mcp_command",
        nargs="?",
        default="serve",
        choices=["serve", "doctor", "tools"],
        help="serve (stdio MCP), doctor, or tools",
    )

    p_retest = sub.add_parser("retest", help="Differential retesting on a previous assessment session")
    p_retest.add_argument("session_id", help="Session ID to retest")
    p_retest.add_argument("--dry-run", action="store_true", help="Retest in dry-run mode")

    args = parser.parse_args(argv)

    # Apply provider override
    if getattr(args, "provider", None):
        os.environ["BRAIN_PROVIDER"] = args.provider
    if getattr(args, "model", None):
        os.environ["BRAIN_MODEL"] = args.model

    # Load saved API keys into environment before any LLM call
    cfg = load_config()
    for env_var in ("GROQ_API_KEY", "DEEPSEEK_API_KEY", "ANTHROPIC_API_KEY",
                    "OPENAI_API_KEY", "XAI_API_KEY", "OPENROUTER_API_KEY",
                    "ORCAROUTER_API_KEY", "FLUXION_API_KEY", "REQUESTY_API_KEY",
                    "GEMINI_API_KEY"):
        if not os.environ.get(env_var) and cfg.get(env_var):
            os.environ[env_var] = cfg[env_var]

    quiet_cmds = {"status", "providers", "models", "mcp", "login", "auth", "attack", "retest", None}
    if not getattr(args, "no_banner", False) and args.command not in quiet_cmds:
        _print_banner()

    dispatch = {
        "attack":    run_attack,
        "retest":    cmd_retest,
        "setup":     cmd_setup,
        "login":     cmd_login,
        "auth":      cmd_login,
        "providers": cmd_providers,
        "models":    cmd_models,
        "recon":     cmd_recon,
        "hunt":      cmd_hunt,
        "validate":  cmd_validate,
        "triage":    cmd_triage,
        "report":    cmd_report,
        "chain":     cmd_chain,
        "chat":      cmd_chat,
        "status":    cmd_status,
        "mcp":       cmd_mcp,
    }

    if not args.command:
        parser.print_help()
        print()
        _print_quick_help()
        return

    fn = dispatch.get(args.command)
    if fn:
        fn(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
