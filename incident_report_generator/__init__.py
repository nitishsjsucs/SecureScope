"""
Incident Report Generator Module

Auto-generates professional PDF incident reports from security data.
Integrates with Reducto for PDF extraction and CVE intelligence for enrichment.
"""

from .form_generator import IncidentReportGenerator, IncidentData
from .auto_filler import AutoReportFiller

__all__ = ['IncidentReportGenerator', 'IncidentData', 'AutoReportFiller']
__version__ = '1.0.0'
