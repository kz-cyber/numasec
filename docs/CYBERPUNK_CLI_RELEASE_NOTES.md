# 🚀 Cyberpunk CLI Release Notes

## v2.1.0 - January 2026

### 🎮 God Mode Terminal

Revolutionary CLI interface that transforms how you interact with AI pentesting.

### ✨ What's New

#### Interruptible Execution
- **ESC to pause**: Stop the agent mid-execution without losing context
- **Graceful interruption**: Agent completes current action, then stops
- **Resume capability**: Continue where you left off or redirect

#### Real-Time Streaming  
- **Watch the agent think**: See reasoning as it happens
- **Live tool execution**: Output streams in real-time
- **Progress indicators**: Know exactly what's happening

#### Cyberpunk Aesthetic
- **Matrix-inspired theme**: Neon green, cyber purple, electric blue
- **Mr. Robot vibes**: Terminal interface that looks the part
- **Rich formatting**: Tables, panels, and styled output

#### Agent Conversations
- **Natural language**: Chat like you're talking to a security expert
- **Context awareness**: Agent remembers your session
- **Smart suggestions**: Relevant follow-up actions

### 🔧 Technical Details

- Built with `prompt_toolkit` for async input handling
- `rich` library for beautiful terminal output  
- State machine architecture: IDLE ↔ BUSY ↔ INTERRUPTED
- Full MCP protocol integration

### 📊 Performance

- Startup time: <2 seconds
- Memory footprint: ~100MB
- Response latency: <500ms (after LLM call)

### 🎯 Usage

```bash
# Launch
numasec

# Start testing
❯ scan localhost:3000 for OWASP Top 10
```

### 🐛 Known Issues

- Async tests require `pytest-asyncio` (optional dependency)
- Some terminals may not render all Unicode correctly

### 📖 Documentation

See [CYBERPUNK_CLI.md](CYBERPUNK_CLI.md) for full guide.
