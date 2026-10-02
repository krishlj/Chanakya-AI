class RegistryAdmissionError(ValueError):
    """Raised by SecurityToolRegistry for a duplicate/invalid registration or
    an illegal lifecycle status transition (docs/TOOL-REGISTRY.md §6)."""
