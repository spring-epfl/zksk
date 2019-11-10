def get_default_attr(obj, attr, default_value=None):
    """
    Get attribute by name. If does not exist, set it.

    >>> class Klass: pass
    >>> a = Klass()
    >>> hasattr(a, "answer")
    False
    >>> get_default_attr(a, "answer", 42)
    42
    >>> a.answer
    42

    """
    if not hasattr(obj, attr):
        setattr(obj, attr, default_value)
    return getattr(obj, attr)
