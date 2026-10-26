"""Endpoint scanner package."""

__all__ = ["scan_endpoint", "scan_file", "scan_parsed_api"]


def __getattr__(name):
    """Load the public scanner functions lazily."""
    if name in __all__:
        from . import scanner

        return getattr(scanner, name)
    raise AttributeError(name)
