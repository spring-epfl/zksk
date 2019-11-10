"""
Common exception classes.
"""


class IncompleteValuesError(Exception):
    """Cannot evaluate a proof as not all secret values are set."""


class InvalidExpression(Exception):
    pass


class InconsistentChallengeError(Exception):
    """Recomputed and global challenge values do not match."""


class StatementMismatch(Exception):
    """Proof statements mismatch, impossible to verify."""


class StatementSpecError(Exception):
    """Statement not fully specified."""


class InvalidSecretsError(Exception):
    """Secrets re-occur in an unsupported manner."""


class GroupMismatchError(Exception):
    """Generator groups mismatch."""


class VerificationError(Exception):
    """Error during verification."""


class ValidationError(Exception):
    """Error during validation."""
