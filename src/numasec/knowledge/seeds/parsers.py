"""
Markdown parsers for knowledge base population.

Supports:
- Payload files (knowledge/payloads/*.md)
- Technique files (knowledge/*.md cheatsheets)
- Attack chain files (knowledge/attack_chains/*.md)

Scientific basis:
- Structured knowledge extraction (Meta AI, 2024)
- Domain-specific parsing for security content
"""

import re
from pathlib import Path
from typing import List
import logging

from numasec.knowledge.store import (
    PayloadEntry,
    TechniqueEntry,
    generate_payload_id,
    generate_technique_id,
)

logger = logging.getLogger(__name__)


class PayloadParser:
    """
    Parse payload markdown files into structured PayloadEntry objects.
    
    Supports multiple formats:
    - Structured format with **Payload:** markers
    - Code block format with ``` markers
    - Mixed formats
    """
    
    @staticmethod
    def parse_file(filepath: Path) -> List[PayloadEntry]:
        """
        Parse a payload markdown file.
        
        Expected format:
        ```markdown
        # SQL Injection Payloads
        
        ## Basic UNION
        
        **Payload:** `' UNION SELECT NULL--`
        **Use case:** Detect number of columns
        **Context:** URL parameter, POST data
        **Tags:** sqli, union, detection
        
        ## Boolean-based blind
        ...
        ```
        
        Args:
            filepath: Path to markdown file
            
        Returns:
            List of PayloadEntry objects
        """
        try:
            content = filepath.read_text(encoding='utf-8')
        except Exception as e:
            logger.error(f"Failed to read {filepath}: {e}")
            return []
        
        payloads = []
        
        # Extract category from filename
        # e.g., "payloads_deserialization.md" -> "deserialization"
        # e.g., "command_injection.md" -> "command injection"
        category = filepath.stem.replace("payloads_", "").replace("_", " ")
        
        # Split by ## headers (each section)
        sections = re.split(r'\n## ', content)
        
        for section_idx, section in enumerate(sections[1:], 1):  # Skip first (title)
            try:
                # Extract section name (first line)
                lines = section.split('\n')
                name = lines[0].strip()
                
                # Skip meta sections (Table of Contents, Summary, Tools, References)
                if any(skip in name.lower() for skip in ['summary', 'tools', 'references', 'labs', 'table of contents']):
                    continue
                
                section_content = '\n'.join(lines[1:])
                
                # STRATEGY 1: Extract from **Payload:** markers
                payload_markers = re.findall(
                    r'\*\*Payload:\*\*\s*`?([^`\n]+)`?',
                    section_content
                )
                
                # STRATEGY 2: Extract from code blocks (```bash, ```python, etc.)
                code_blocks = re.findall(
                    r'```(?:bash|sh|python|js|php)?\n(.*?)\n```',
                    section_content,
                    re.DOTALL
                )
                
                # STRATEGY 3: Extract from inline code (single backticks on their own lines)
                inline_codes = re.findall(
                    r'^`([^`]+)`\s*$',
                    section_content,
                    re.MULTILINE
                )
                
                # Combine all extracted payloads
                all_payloads = payload_markers + code_blocks + inline_codes
                
                # Extract metadata
                use_case = ""
                context = ""
                bypass_technique = ""
                tags = []
                
                for line in lines[1:]:
                    if line.startswith('**Use case:**'):
                        use_case = line.replace('**Use case:**', '').strip()
                    elif line.startswith('**Context:**'):
                        context = line.replace('**Context:**', '').strip()
                    elif line.startswith('**Bypass:**'):
                        bypass_technique = line.replace('**Bypass:**', '').strip()
                    elif line.startswith('**Tags:**'):
                        tags_str = line.replace('**Tags:**', '').strip()
                        tags = [t.strip() for t in tags_str.split(',') if t.strip()]
                
                # Create entries for each payload found
                for payload_idx, payload_text in enumerate(all_payloads, 1):
                    payload_text = payload_text.strip()
                    
                    # Skip empty or very short payloads
                    if len(payload_text) < 2:
                        continue
                    
                    # Skip comment lines
                    if payload_text.startswith('#'):
                        continue
                    
                    # Generate unique name
                    if len(all_payloads) == 1:
                        payload_name = name
                    else:
                        payload_name = f"{name} #{payload_idx}"
                    
                    # Use first line as description if multi-line payload
                    if '\n' in payload_text:
                        first_line = payload_text.split('\n')[0]
                        description = f"{name} - {first_line[:50]}"
                    else:
                        description = f"{name} - {use_case}" if use_case else name
                    
                    entry = PayloadEntry(
                        id=generate_payload_id(category, payload_name),
                        name=payload_name,
                        category=category,
                        payload=payload_text,
                        description=description,
                        use_case=use_case or f"Execute OS commands via {category}",
                        bypass_technique=bypass_technique,  # field_validator handles None
                        context=context,  # field_validator handles None
                        tags=tags + [category.replace(" ", "_")],
                        success_rate=0.5,
                    )
                    payloads.append(entry)
            except Exception as e:
                logger.warning(f"Failed to parse section in {filepath}: {e}")
                continue
        
        return payloads
    
    @staticmethod
    def parse_simple_list(filepath: Path, category: str) -> List[PayloadEntry]:
        """
        Parse simple newline-separated payload lists.
        
        For files that are just lists of payloads without structure.
        
        Args:
            filepath: Path to file
            category: Category for all payloads
            
        Returns:
            List of PayloadEntry objects
        """
        try:
            content = filepath.read_text(encoding='utf-8')
        except Exception as e:
            logger.error(f"Failed to read {filepath}: {e}")
            return []
        
        payloads = []
        
        for i, line in enumerate(content.split('\n'), 1):
            line = line.strip()
            if line and not line.startswith('#'):  # Skip empty and comments
                entry = PayloadEntry(
                    id=generate_payload_id(category, f"payload_{i}"),
                    name=f"{category.title()} Payload {i}",
                    category=category,
                    payload=line,
                    description=f"Auto-imported {category} payload",
                    use_case=f"Generic {category} exploitation",
                    tags=[category],
                    success_rate=0.5,
                )
                payloads.append(entry)
        
        return payloads


class TechniqueParser:
    """Parse technique markdown files (cheatsheets) into TechniqueEntry objects."""
    
    @staticmethod
    def parse_file(filepath: Path) -> List[TechniqueEntry]:
        """
        Parse technique cheatsheet.
        
        Expected format:
        ```markdown
        # Linux Privilege Escalation
        
        ## SUID Binary Exploitation
        
        **Prerequisites:**
        - SUID binary with known vulnerability
        - Write access to /tmp
        
        **Steps:**
        1. Find SUID binaries: `find / -perm -4000 2>/dev/null`
        2. Check for GTFOBins: search binary name
        3. Exploit with: `./binary -exec /bin/sh`
        
        **Tools:** find, gtfobins
        **MITRE:** T1548.001
        ```
        
        Args:
            filepath: Path to markdown file
            
        Returns:
            List of TechniqueEntry objects
        """
        try:
            content = filepath.read_text(encoding='utf-8')
        except Exception as e:
            logger.error(f"Failed to read {filepath}: {e}")
            return []
        
        techniques = []
        
        # Extract category from filename
        # e.g., "linux_cheatsheet.md" -> "linux"
        category = filepath.stem.replace("_cheatsheet", "").replace("_", " ")
        
        # Split by ## headers
        sections = re.split(r'\n## ', content)
        
        for section in sections[1:]:  # Skip first (title)
            try:
                lines = section.split('\n')
                name = lines[0].strip()
                
                description = ""
                prerequisites = []
                steps = []
                tools = []
                mitre_id = None
                
                current_section = None
                
                for line in lines[1:]:
                    if line.startswith('**Prerequisites:**'):
                        current_section = 'prerequisites'
                    elif line.startswith('**Steps:**'):
                        current_section = 'steps'
                    elif line.startswith('**Tools:**'):
                        tools_str = line.replace('**Tools:**', '').strip()
                        tools = [t.strip() for t in tools_str.split(',') if t.strip()]
                        current_section = None
                    elif line.startswith('**MITRE:**'):
                        mitre_id = line.replace('**MITRE:**', '').strip()
                        current_section = None
                    elif line.strip() and not line.startswith('**'):
                        if current_section == 'prerequisites':
                            if line.startswith('- '):
                                prerequisites.append(line[2:].strip())
                        elif current_section == 'steps':
                            # Extract step (numbered list or code block)
                            step_match = re.match(r'\d+\.\s*(.+)', line)
                            if step_match:
                                steps.append(step_match.group(1))
                            elif line.startswith('`') and line.endswith('`'):
                                steps.append(line.strip('`'))
                        elif not current_section and not description:
                            description = line.strip()
                
                if steps:  # Only add if we have actionable steps
                    entry = TechniqueEntry(
                        id=generate_technique_id(name),
                        name=name,
                        category=category,
                        description=description or name,
                        prerequisites=prerequisites,
                        steps=steps,
                        tools=tools,
                        indicators=[],
                        mitre_id=mitre_id,  # field_validator handles None
                        difficulty="medium",
                        tags=[category.replace(" ", "_"), "cheatsheet"],
                    )
                    techniques.append(entry)
            except Exception as e:
                logger.warning(f"Failed to parse section in {filepath}: {e}")
                continue
        
        return techniques
