class AuditSystemError(Exception):
    """Base exception for project-specific failures."""


class AuthenticationError(AuditSystemError):
    """Raised when credentials are invalid."""


class AuthorizationError(AuditSystemError):
    """Raised when a user attempts an unauthorized action."""


class IntegrityError(AuditSystemError):
    """Raised when ledger integrity or node consistency fails."""


class ValidationError(AuditSystemError):
    """Raised when input data is malformed or incomplete."""

