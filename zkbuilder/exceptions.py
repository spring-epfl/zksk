
class IncompleteValuesError(Exception):
    """Cannot evaluate a proof as not all secret values are set."""

class StatementMismatch(Exception):
    """Proof statements mismatch, impossible to verify."""

class StatementSpecError(Exception):
    pass
