# 🎮 Cyberpunk CLI Guide

**NumaSec.1.0** - God Mode Terminal

---

## ⚡ Quick Start

```bash
# Launch the CLI
numasec

# Or with Python module
python -m numasec
```

---

## 🎨 Interface Features

### Real-Time Streaming
Watch the agent think and work in real-time, just like Claude Code:
- **Reasoning phase**: See the agent's thought process
- **Action phase**: Watch tools execute
- **Result phase**: View outputs as they stream

### Interruptible Execution
Press **ESC** or **Ctrl+C** to pause the agent mid-execution:
- Agent gracefully stops current action
- You regain control immediately
- Resume or redirect with new instructions

### Cyberpunk Aesthetic
- **Neon Green**: Success states
- **Cyber Purple**: Agent thinking
- **Warning Red**: Errors and alerts
- **Electric Blue**: Information

---

## 💬 Commands

### Basic Chat Mode
```
❯ scan localhost:3000 for vulnerabilities
```

### Structured Assessment
```
❯ /assess https://target.com -o "find SQL injection"
```

### Tool Listing
```
❯ /tools
```

### Help
```
❯ /help
```

---

## ⌨️ Key Bindings

| Key | Action |
|-----|--------|
| **ESC** | Interrupt agent |
| **Ctrl+C** | Interrupt or exit |
| **Ctrl+D** | Exit CLI |
| **↑/↓** | Command history |
| **Tab** | Autocomplete |

---

## 🔧 Configuration

### Environment Variables
```bash
# Required: At least one LLM provider
export DEEPSEEK_API_KEY="your-key"

# Optional: Fallback providers
export ANTHROPIC_API_KEY="your-key"
export OPENAI_API_KEY="your-key"

# Optional: Debug mode
export NUMASEC_DEBUG=1
```

### Approval Modes
- **SUPERVISED**: Confirm each tool execution (default)
- **SEMI_AUTO**: Confirm only risky actions
- **AUTONOMOUS**: Full auto (for training environments)

---

## 🎯 Example Session

```
❯ test sql injection on localhost:3000

🧠 Analyzing target...
   Target: localhost:3000
   Type: Web Application
   
⚡ Executing: web_request
   URL: http://localhost:3000/
   Status: 200 OK
   
🧠 Found login form at /login...
   Testing SQL injection payloads...
   
⚡ Executing: web_request
   URL: http://localhost:3000/login
   Data: username=admin'--&password=test
   Status: 302 Redirect → /dashboard
   
🚨 VULNERABILITY FOUND!
   Type: SQL Injection - Authentication Bypass
   Severity: CRITICAL (CVSS 9.8)
   Evidence: Login bypassed with admin'--
```

---

## 📖 More Information

- [ARCHITECTURE.md](../ARCHITECTURE.md) - Technical deep dive
- [README.md](../README.md) - Project overview
- [CHANGELOG.md](../CHANGELOG.md) - Version history
