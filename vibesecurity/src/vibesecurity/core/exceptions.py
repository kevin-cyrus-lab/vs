class VibeSecurityError(Exception):
    """Base exception for all VibeSecurity errors."""
    pass

class ProjectNotFoundError(VibeSecurityError):
    pass

class PolicyViolationError(VibeSecurityError):
    pass

class PatchApplicationError(VibeSecurityError):
    pass

class VerificationFailureError(VibeSecurityError):
    pass

class ScannerExecutionError(VibeSecurityError):
    pass

