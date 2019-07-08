
class IncompleteValuesError(Exception):
    """Cannot evaluate a proof as not all secret values are set."""

class InvalidExpression(Exception):
    pass

class StatementMismatch(Exception):
    """Proof statements mismatch, impossible to verify."""

class StatementSpecError(Exception):
    """Statement not fully specified."""
