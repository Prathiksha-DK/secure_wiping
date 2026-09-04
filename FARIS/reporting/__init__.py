"""
FARIS Reporting Module
Multi-format forensic report generator (JSON, CSV, HTML, PDF/Printable).
"""

from .report_generator import ReportGenerator, report_generator

__all__ = [
    "ReportGenerator",
    "report_generator",
]
