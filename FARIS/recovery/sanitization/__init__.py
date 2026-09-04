"""
FARIS Specialized Sanitization Recovery Package
================================================
Forensic recovery and analysis stages specifically designed for sanitized,
wiped, overwritten, or cryptographically erased storage media.

Includes Stages A through J:
  - Stage A: Overwrite Pattern Analysis
  - Stage B: Residual Data / Remnant Analysis
  - Stage C: Sector / Block-Level Recovery
  - Stage D: Multi-Pass Pattern Analysis
  - Stage E: File-System Journal / Log Analysis
  - Stage F: SSD / NAND Remnant Analysis
  - Stage G: Wear-Leveling Analysis
  - Stage H: Hidden / Unallocated Area Analysis
  - Stage I: Previous-State Reconstruction
  - Stage J: Cryptographic-Erasure Analysis

Orchestrated via SanitizationManager.
"""

from .overwrite_analysis import OverwritePatternAnalyzer, overwrite_analyzer
from .residual_analysis import ResidualDataAnalyzer, residual_analyzer
from .sector_block_recovery import SectorBlockRecoveryEngine, sector_block_engine
from .multipass_analysis import MultiPassAnalyzer, multipass_analyzer
from .journal_log_analysis import JournalLogAnalyzer, journal_log_analyzer
from .ssd_nand_ftl_analysis import SSDNANDFTLAnalyzer, ssd_nand_ftl_analyzer
from .wear_leveling_analysis import WearLevelingAnalyzer, wear_leveling_analyzer
from .hidden_unallocated_analysis import HiddenUnallocatedAnalyzer, hidden_unallocated_analyzer
from .previous_state_reconstruction import PreviousStateReconstructor, previous_state_reconstructor
from .crypto_erase_analysis import CryptoEraseAnalyzer, crypto_erase_analyzer
from .sanitization_manager import SanitizationManager, sanitization_manager

__all__ = [
    "OverwritePatternAnalyzer",
    "overwrite_analyzer",
    "ResidualDataAnalyzer",
    "residual_analyzer",
    "SectorBlockRecoveryEngine",
    "sector_block_engine",
    "MultiPassAnalyzer",
    "multipass_analyzer",
    "JournalLogAnalyzer",
    "journal_log_analyzer",
    "SSDNANDFTLAnalyzer",
    "ssd_nand_ftl_analyzer",
    "WearLevelingAnalyzer",
    "wear_leveling_analyzer",
    "HiddenUnallocatedAnalyzer",
    "hidden_unallocated_analyzer",
    "PreviousStateReconstructor",
    "previous_state_reconstructor",
    "CryptoEraseAnalyzer",
    "crypto_erase_analyzer",
    "SanitizationManager",
    "sanitization_manager",
]
