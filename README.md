<p align="center">
  <img src="https://raw.githubusercontent.com/ArrafiNurHafiz/Agentic-Hunter/main/assets/banner.png" alt="Agentic Hunter" width="100%"/>
</p>

<p align="center">
  <b>AI-Powered Bug Bounty Reconnaissance, Vulnerability Discovery & Differential Retesting.</b>
  <br/>
  <i>Engineered for professional bug bounty hunters, ethical hackers, and defensive security teams.</i>
</p>

<p align="center">
  <a href="#overview">Overview</a>
  ·
  <a href="#key-capabilities">Key Capabilities</a>
  ·
  <a href="#quickstart">Quickstart</a>
  ·
  <a href="#supported-ai-providers">AI Providers</a>
  ·
  <a href="#cli-commands-reference">CLI Reference</a>
  ·
  <a href="#security--evidence-integrity">Integrity Architecture</a>
  ·
  <a href="#specialized-skills">Skills</a>
  ·
  <a href="#verification--testing">Testing</a>
  ·
  <a href="#disclaimer">Disclaimer</a>
</p>

<p align="center">
  <a href="https://github.com/ArrafiNurHafiz/Agentic-Hunter/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg?style=flat-square" alt="MIT License"></a>
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB.svg?style=flat-square&logo=python&logoColor=white" alt="Python 3.10+">
  <img src="https://img.shields.io/badge/Test%20Suite-1%2C227%20Passed%20(100%25)-brightgreen.svg?style=flat-square" alt="Tests">
  <img src="https://img.shields.io/badge/Status-Production--Ready-success.svg?style=flat-square" alt="Status">
  <a href="https://github.com/ArrafiNurHafiz/Agentic-Hunter/stargazers"><img src="https://img.shields.io/github/stars/ArrafiNurHafiz/Agentic-Hunter?style=flat-square&color=yellow" alt="GitHub Stars"></a>
</p>

<p align="center">
  Maintained by <b><a href="https://github.com/ArrafiNurHafiz">Arrafi Nur Hafiz</a></b>
</p>

---

## Overview

**Agentic Hunter** is an advanced AI-augmented security testing toolkit and autonomous command-line engine built to streamline the entire ethical bug bounty lifecycle. From initial scope verification and asset discovery to attack surface ranking, cryptographic evidence validation, differential fix verification, and audit-ready report generation, Agentic Hunter works directly inside your terminal or as an intelligent agent plugin.

Unlike generic LLM wrappers, Agentic Hunter pairs large language models with **rigorous deterministic guardrails**:
- **Zero Hallucination Proofs**: Findings require verifiable evidence provenance before they can be marked `CONFIRMED`.
- **Offline Differential Retesting**: Automatically compares target snapshots between historical assessments to verify actual fixes without assuming remediation based on absent findings.
- **Provider-Agnostic Engine**: Run 100% locally with free offline models via **Ollama**, route through local **9Router** gateways, connect with **Google OAuth (Gemini 2.0 / 1.5 Pro)**, or leverage ultra-fast inference via **Groq**, **DeepSeek**, **Claude**, or **OpenAI**.
- **Universal Multi-Harness Integration**: Run as a standalone terminal CLI (`bughunter`), or seamlessly plug into **Google Antigravity**, **Claude Code**, **OpenCode**, **Codex**, or **Pi Agent**.

---

## Key Capabilities

| Capability | Technical Realization | Hunter Benefit |
|---|---|---|
| **Intelligent Recon & Surface Ranking** | Aggregates subdomains, DNS records, JS bundles, parameters, and HTTP endpoints; ranks attack surface using heuristics & LLM reasoning. | Focuses attention on high-yield, complex logic and API surfaces first. |
| **Lead Board Ledger** | Persistent ledger (`lead_board.py`) tracking uncovered assets, parameters, and attack vectors across sessions. | Never lose or forget a promising vulnerability lead during complex recon. |
| **7-Question Validation Gate** | Automated pre-submission triage validating reachability, authorization, impact, and repeatability. | Eliminates low-impact noise and false positives before writing reports. |
| **Exploit Chain Synthesis** | Analyzes findings to compose multi-step impact escalations (e.g., CORS Misconfig + CSRF &rarr; Account Takeover). | Maximizes finding severity and bounty payout potential responsibly. |
| **Differential Retesting** | Compares snapshot states between assessment runs (`p10_retesting.py`) against verified baseline evidence. | Validates true vendor fixes without false positives; flags regressions. |
| **Defensive Remediation Advisory** | Sanitized metadata advisory generation (`remediation.py`) with CWE mappings and fix snippets. | Delivers actionable, professional remediation advice to development teams. |

---

## Security & Evidence Integrity

Agentic Hunter implements an enterprise-grade evidence and session integrity model to protect assessment integrity and comply with strict testing standards:

```mermaid
flowchart TD
    A["Target Assessment Scope"] --> B["Active / Passive Reconnaissance"]
    B --> C["Finding Discovery & Lead Ledger"]
    C --> D{"Evidence Provenance Gate"}
    D -- "Verified Anchor Digest" --> E["CONFIRMED Finding"]
    D -- "Missing / Unverified Proof" --> F["INCONCLUSIVE (Rejected)"]
    E --> G["Differential Retesting Engine"]
    G --> H{"Snapshot Comparison"}
    H -- "Verified Counter-Evidence" --> I["Status: FIXED"]
    H -- "Vulnerability Persists" --> J["Status: STILL PRESENT"]
    H -- "Target Service Errors (500+)" --> K["Status: REGRESSION"]
    H -- "Observation Missing Without Proof" --> L["Status: INCONCLUSIVE"]
```

### Core Integrity Guarantees
1. **Cryptographic Artifact Digesting**:
   - Every session artifact (raw responses, logs, extracted endpoints) is hashed with **SHA-256**.
   - Atomic rollback prevents corrupted or half-written session states in the event of I/O failure.
2. **Strict Verification Hierarchy**:
   - Findings without verified cryptographic evidence chains cannot achieve `CONFIRMED` status; they are marked `INCONCLUSIVE` to prevent false claims.
3. **Automated Sensitive Data Redaction**:
   - Authorization headers, bearer tokens, API keys, and sensitive target credentials are automatically sanitized (`redact_obj`) prior to reporting or exporting.
4. **Deterministic Retesting Matrix**:
   - Retesting strictly refuses to mark a finding as *Fixed* solely due to an absent observation. Fixed status requires verified counter-evidence (e.g. valid input rejection with HTTP 400/422).

---

## Quickstart

Get up and running in under a minute with Python 3.10+ and [`uv`](https://github.com/astral-sh/uv):

```bash
# Clone the repository
git clone https://github.com/ArrafiNurHafiz/Agentic-Hunter.git
cd Agentic-Hunter

# Install dependencies and sync virtual environment
uv sync

# Configure your preferred AI model (Ollama, 9Router, Google, Groq, etc.)
uv run bughunter setup

# Run your first reconnaissance or surface analysis
uv run bughunter recon example.com
```

---

## Supported AI Providers

Agentic Hunter natively supports diverse model runtimes with zero lock-in. Switch providers at any time using `bughunter setup` or `--provider <name>`.

### 1. Free & 100% Offline (Ollama)
No API keys or cloud subscriptions required:
```bash
# 1. Install Ollama and pull your preferred model
curl -fsSL https://ollama.ai/install.sh | sh
ollama pull qwen2.5:14b

# 2. Select Ollama in BugHunter
bughunter setup   # Select 'ollama' -> qwen2.5:14b
bughunter recon target.com
```

### 2. Local 9Router Gateway
Connect through local OpenAI-compatible routing gateways with full tool calling:
```bash
# Connect to 9Router on default port 20128
bughunter setup   # Select '9router' -> http://127.0.0.1:20128/v1
bughunter attack target.com --dry-run
```

### 3. Google Gemini / Antigravity OAuth (Zero-Key Cloud)
Authenticate directly through your browser using Google OAuth loopback:
```bash
bughunter login   # Opens browser for OAuth consent
bughunter hunt target.com
```

### 4. Cloud API Providers
Export your API key for lightning-fast inference:
```bash
# Groq (Ultra-fast free tier)
export GROQ_API_KEY="gsk_..."

# DeepSeek (Cost-effective reasoning)
export DEEPSEEK_API_KEY="sk-..."

# Anthropic Claude
export ANTHROPIC_API_KEY="sk-ant-..."

# OpenAI
export OPENAI_API_KEY="sk-..."
```

---

## CLI Commands Reference

The `bughunter` CLI provides a unified, scriptable command-line interface:

### Configuration & Authentication
| Command | Arguments | Description |
|---|---|---|
| `bughunter setup` | `[init]` | Interactively configure and persist provider, endpoint, and model preferences. |
| `bughunter login` | `[auth]` | Authenticate using Google OAuth loopback for Gemini Pro models. |
| `bughunter providers` | `[p]` | Display all supported providers and their current API key / connectivity status. |
| `bughunter models` | `[m]` | List available models for the currently active provider. |
| `bughunter status` | `[s]` | Show active assessment status, memory state, and session metrics. |

### Assessment & Execution Pipeline
| Command | Arguments | Description |
|---|---|---|
| `bughunter attack` | `<target> [--dry-run] [--scope <file>] [--profile passive\|active] [--phase 1-3]` | Run modular assessment pipeline with strict scope validation and dry-run safety gates. |
| `bughunter retest` | `<session_id> [--dry-run]` | Perform differential snapshot retesting against baseline session evidence. |
| `bughunter recon` | `<target> [r]` | Execute subdomain enumeration, DNS resolution, and AI surface ranking. |
| `bughunter hunt` | `<target> [h]` | Launch guided multi-phase bug bounty hunting pipeline. |
| `bughunter validate`| `<finding> [v]` | Run the 7-Question Gate to verify vulnerability reproducibility and impact. |
| `bughunter triage`  | `<finding> [t]` | Fast-path triage validation for incoming findings. |
| `bughunter report`  | `<session_id> [rep]` | Generate sanitized Markdown / JSON reports with verified evidence provenance. |
| `bughunter chain`   | `[c]` | Synthesize multi-vulnerability exploit chains for escalated impact. |
| `bughunter chat`    | `[ask]` | Launch an interactive security assistant terminal shell. |
| `bughunter mcp`     | `[doctor\|catalog]` | Inspect and run native Model Context Protocol (MCP) server endpoints. |
