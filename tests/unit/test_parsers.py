"""
Unit tests for knowledge base parsers.

Tests the parsing of markdown files into structured knowledge entries.
"""

import pytest
from pathlib import Path
from numasec.knowledge.seeds.parsers import PayloadParser, TechniqueParser


def test_payload_parser_extracts_basic_fields():
    """Verify parser extracts payload, use case, and tags."""
    
    # Create mock markdown content
    mock_content = """# SQL Injection Payloads

## Basic UNION

**Payload:** `' UNION SELECT NULL--`
**Use case:** Detect number of columns
**Context:** URL parameter
**Tags:** sqli, union, detection

## Boolean Blind

**Payload:** `' AND 1=1--`
**Use case:** Boolean-based blind injection
**Tags:** sqli, blind
"""
    
    # Create temporary file
    import tempfile
    with tempfile.NamedTemporaryFile(
        mode='w',
        suffix='.md',
        delete=False,
        prefix='payloads_sqli_'
    ) as f:
        f.write(mock_content)
        temp_path = Path(f.name)
    
    try:
        # Parse
        payloads = PayloadParser.parse_file(temp_path)
        
        # Verify
        assert len(payloads) == 2
        
        # Check first payload
        first = payloads[0]
        assert first.name == "Basic UNION"
        assert "UNION SELECT NULL" in first.payload
        assert first.use_case == "Detect number of columns"
        assert "sqli" in first.tags
        assert "union" in first.tags
        
        # Check second payload
        second = payloads[1]
        assert second.name == "Boolean Blind"
        assert "AND 1=1" in second.payload
        assert "blind" in second.tags
        
    finally:
        # Cleanup
        temp_path.unlink()


def test_payload_parser_handles_missing_fields():
    """Verify parser handles payloads with missing optional fields."""
    
    mock_content = """# XSS Payloads

## Simple Alert

**Payload:** `<script>alert(1)</script>`
"""
    
    import tempfile
    with tempfile.NamedTemporaryFile(
        mode='w',
        suffix='.md',
        delete=False,
        prefix='payloads_xss_'
    ) as f:
        f.write(mock_content)
        temp_path = Path(f.name)
    
    try:
        payloads = PayloadParser.parse_file(temp_path)
        
        assert len(payloads) == 1
        first = payloads[0]
        assert first.name == "Simple Alert"
        assert "alert(1)" in first.payload
        # Optional fields - parser may auto-generate use_case or leave empty
        # bypass_technique should be None if not specified
        assert first.bypass_technique is None or first.bypass_technique == ""
        
    finally:
        temp_path.unlink()


def test_technique_parser_extracts_steps():
    """Verify parser extracts technique steps."""
    
    mock_content = """# Linux Cheatsheet

## SUID Binary Exploitation

**Steps:**
1. Find SUID binaries: `find / -perm -4000 2>/dev/null`
2. Check for GTFOBins: search binary name
3. Exploit with: `./binary -exec /bin/sh`

**Tools:** find, gtfobins
**MITRE:** T1548.001
"""
    
    import tempfile
    with tempfile.NamedTemporaryFile(
        mode='w',
        suffix='_cheatsheet.md',
        delete=False,
        prefix='linux'
    ) as f:
        f.write(mock_content)
        temp_path = Path(f.name)
    
    try:
        techniques = TechniqueParser.parse_file(temp_path)
        
        assert len(techniques) == 1
        tech = techniques[0]
        
        assert tech.name == "SUID Binary Exploitation"
        assert len(tech.steps) == 3
        assert "find" in tech.steps[0].lower()
        assert "gtfobins" in tech.steps[1].lower()
        assert "find" in tech.tools
        assert "gtfobins" in tech.tools
        assert tech.mitre_id == "T1548.001"
        
    finally:
        temp_path.unlink()


def test_payload_parser_handles_empty_file():
    """Verify parser returns empty list for empty/invalid file."""
    
    import tempfile
    with tempfile.NamedTemporaryFile(
        mode='w',
        suffix='.md',
        delete=False
    ) as f:
        f.write("# Empty\n\nNo content")
        temp_path = Path(f.name)
    
    try:
        payloads = PayloadParser.parse_file(temp_path)
        assert payloads == []
    finally:
        temp_path.unlink()
