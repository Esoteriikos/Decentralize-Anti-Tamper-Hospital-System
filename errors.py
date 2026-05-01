class AuditSystemError(Exception):
    """Base exception for project-specific failures."""


class AuthenticationError(AuditSystemError):
    """Raised when credentials or tokens are invalid."""


class AuthorizationError(AuditSystemError):
    """Raised when a user attempts an unauthorized action."""


class IntegrityError(AuditSystemError):
    """Raised when ledger integrity or node consistency fails."""


class ValidationError(AuditSystemError):
    """Raised when input data is malformed or incomplete."""


class NotFoundError(AuditSystemError):
    """Raised when a requested entity does not exist."""


class ConsensusError(AuditSystemError):
    """Raised when a quorum of nodes cannot be reached."""
