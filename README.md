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
