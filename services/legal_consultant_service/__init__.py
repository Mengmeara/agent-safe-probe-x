"""
Standalone LegalConsultantAgent service package.

Everything inside this directory is intentionally isolated from the rest of the
codebase so that spinning up or tearing down the service has zero impact on the
main ASP-X workflow.
"""

from .config import ServiceConfig  # noqa: F401
from .runner import LegalConsultantService, LegalConsultantServiceError  # noqa: F401

