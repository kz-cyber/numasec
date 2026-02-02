"""
Knowledge base seed data and population utilities.

Two systems:
1. Legacy: Hardcoded payloads in payloads.py (for backwards compatibility)
2. New: Dynamic parsing from markdown files (parsers.py + populate.py)
"""

# Legacy hardcoded payloads (backwards compatibility)
from numasec.knowledge.seeds.payloads import (
    ALL_PAYLOADS,
    get_payloads_by_category,
    get_all_categories,
    get_payload_count,
    get_payload_stats,
    seed_payloads,
)

# Advanced exploitation payloads
from numasec.knowledge.seeds.advanced_payloads import (
    ALL_ADVANCED_PAYLOADS,
    ADVANCED_CRYPTO_PAYLOADS,
    ADVANCED_FORENSICS_PAYLOADS,
    ADVANCED_REVERSE_PAYLOADS,
    ADVANCED_PWN_PAYLOADS,
    ADVANCED_MISC_PAYLOADS,
    get_advanced_payloads_by_category,
    get_advanced_payload_categories,
    get_advanced_payload_count,
)

# Real-world payload harvesting
from numasec.knowledge.seeds.real_world_payloads import (
    harvest_real_world_sources,
    harvest_hackerone_payloads,
    harvest_cve_exploits,
    harvest_portswigger_labs,
    harvest_owasp_payloads,
    harvest_payloadsallthethings,
)

# New dynamic parsers
from numasec.knowledge.seeds.parsers import (
    PayloadParser,
    TechniqueParser,
)

__all__ = [
    # Legacy
    "ALL_PAYLOADS",
    "get_payloads_by_category",
    "get_all_categories", 
    "get_payload_count",
    "get_payload_stats",
    "seed_payloads",
    # Advanced Payloads
    "ALL_ADVANCED_PAYLOADS",
    "ADVANCED_CRYPTO_PAYLOADS",
    "ADVANCED_FORENSICS_PAYLOADS",
    "ADVANCED_REVERSE_PAYLOADS", 
    "ADVANCED_PWN_PAYLOADS",
    "ADVANCED_MISC_PAYLOADS",
    "get_advanced_payloads_by_category",
    "get_advanced_payload_categories",
    "get_advanced_payload_count",
    # Real-World Payloads
    "harvest_real_world_sources",
    "harvest_hackerone_payloads", 
    "harvest_cve_exploits",
    "harvest_portswigger_labs",
    "harvest_owasp_payloads",
    "harvest_payloadsallthethings",
    # Parsers
    "PayloadParser",
    "TechniqueParser",
]
