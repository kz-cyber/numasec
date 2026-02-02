# 📚 NumaSec - Documentation

**Quick reference for project documentation.**

---

## 📖 Core Documentation

### Essential (Start Here)

1. **[../README.md](../README.md)** - Project overview, quick start, features
2. **[../ARCHITECTURE.md](../ARCHITECTURE.md)** - Complete technical architecture + v2.2.0 status
3. **[../CHANGELOG.md](../CHANGELOG.md)** - Version history and release notes
4. **[../MISSION.md](../MISSION.md)** - Project vision and goals
5. **[../.cursorrules](../.cursorrules)** - Development guidelines (879 lines)

---

## 🔬 Technical Docs

### MCP Protocol
- **[MCP_CLIENT_ARCHITECTURE.md](MCP_CLIENT_ARCHITECTURE.md)** - Model Context Protocol details

---

## 🎯 Quick Reading Paths

### Path 1: Quick Overview (10 min)
1. `../README.md` - What is NumaSec
2. `../ARCHITECTURE.md` - v2.2.0 Status section
3. `../CHANGELOG.md` - Latest changes

**Purpose:** Understand current state and performance

---

### Path 2: Technical Deep Dive (1 hour)
1. `../ARCHITECTURE.md` - Full architecture (6-stage cognitive loop)
2. `../.cursorrules` - Development standards and patterns
3. `MCP_CLIENT_ARCHITECTURE.md` - Tool protocol

**Purpose:** Understand implementation details

---

### Path 3: Contributor Guide (30 min)
1. `../README.md` - Features and structure
2. `../.cursorrules` - Coding standards
3. `../ARCHITECTURE.md` - Scientific foundations

**Purpose:** Start contributing code

---

## 📊 Documentation Structure

```
numasec/
├── README.md                    # Project overview
├── ARCHITECTURE.md              # Technical architecture + v2.2.0 status
├── CHANGELOG.md                 # Version history
├── MISSION.md                   # Project vision
├── .cursorrules                 # Development guide (879 lines)
│
├── docs/
│   ├── README.md                # This file
│   └── MCP_CLIENT_ARCHITECTURE.md
│
├── benchmarks/
│   ├── README.md
│   └── ctf_suite.py
│
└── tests/
    └── unit/
        ├── test_fact_store.py
        └── test_tool_grounding.py
```

---

## ✅ Key Information Locations

### Performance Metrics
- **Location:** `ARCHITECTURE.md` → "v2.2.0 Consolidation Status"
- **What:** 7 iterations on Medium CTF, 5x faster than industry

### Implementation Details
- **Location:** `ARCHITECTURE.md` → "Cognitive Architecture" section
- **What:** 6-stage loop (PERCEIVE → REFLECT → THINK → UCB1 → ACT → LEARN)

### Recent Changes
- **Location:** `CHANGELOG.md` → v2.2.0 section
- **What:** P0/P1/P2 fixes, performance impact

### Development Guidelines
- **Location:** `.cursorrules`
- **What:** Coding standards, patterns, checklist

### Scientific Papers
- **Location:** `ARCHITECTURE.md` → "Scientific Foundations"
- **What:** 6 peer-reviewed papers implemented

---

## 🆕 What's New (v2.2.0)

**Jan 26, 2026 - Production Consolidation**

✅ **Performance:** 60 → 7 iterations (-88%)  
✅ **Cost:** $0.50 → $0.15 (-70%)  
✅ **Rank:** Top 3 globally (#1 in speed)  

**Key fixes:**
- P0: Silent exceptions eliminated
- P1: Commitment Mode expanded (SESSION/CREDENTIAL triggers)
- P1: Token optimization (80% SINGLE mode)
- P1: Aggressive UCB1 (blocks after 2-3 failures)

**See:** `ARCHITECTURE.md` → "v2.2.0 Consolidation Status" for complete details

---

## 🎓 For New Contributors

**Start here:**
1. Read `../README.md` (10 min)
2. Read `../ARCHITECTURE.md` → "System Overview" (20 min)
3. Read `../.cursorrules` → "Python Coding Standards" (15 min)
4. Run tests: `pytest tests/unit/` (5 min)

**Total:** 50 minutes to productive contribution

---

## 📞 Support

**Questions?**
- Architecture: Check `ARCHITECTURE.md`
- Development: Check `.cursorrules`
- Changes: Check `CHANGELOG.md`
- Issues: GitHub Issues

---

_Documentation Hub - Updated 2026-01-26_  
_Version: 2.2.0_  
_Status: Consolidated_
