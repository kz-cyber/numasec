# Changelog

All notable changes to NumaSec will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] - 2026-02-02 🚀

### Initial Public Release

**NumaSec** - The AI that hacks for you.

#### 🧠 Core Features

- **MCP-Native Architecture** - First security tool built on Model Context Protocol
- **28 Integrated Security Tools** - nmap, sqlmap, nuclei, ffuf, hydra, and more
- **Adaptive Reasoning** - SINGLE → LIGHT → DEEP mode escalation based on task complexity
- **UCB1 Exploration** - Mathematical loop-breaking prevents getting stuck
- **Reflexion Memory** - Learns from past actions via LanceDB vector storage

#### 🎯 Cognitive Architecture

- **Unified Adaptive Strategy** - Goal-oriented planning with meta-learning
- **Epistemic State (FactStore)** - Persistent storage of confirmed vulnerabilities and credentials
- **Commitment Mode** - Auto-focus on exploiting confirmed vulnerabilities
- **Reflexive RAG** - Self-healing knowledge retrieval when agent gets stuck

#### 🔧 Technical Stack

- Python 3.11+
- Async/await throughout
- Pydantic v2 validation
- LanceDB for vector storage
- Rich TUI (cyberpunk interface)

#### 📊 Performance

- **-80% iterations** vs naive ReAct loop (validated on OWASP Juice Shop)
- **<$0.05/scan** with DeepSeek provider
- **<100ms** RAG retrieval latency

#### 🔐 Supported Providers

- DeepSeek (recommended - cheapest)
- Anthropic Claude
- OpenAI GPT-4

---

[1.0.0]: https://github.com/numasec/numasec/releases/tag/v1.0.0
