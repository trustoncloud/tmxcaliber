class FrameworkNotFoundError(Exception):
    def __init__(self, framework: str) -> None:
        self.framework = framework
        self.message = (
            f"[Error] The framework '{self.framework}' was not found in the SCF "
            "worksheet of the provided Excel file. Please ensure that the framework "
            "name is spelled correctly, use quotes if there are spaces, and replace "
            "carriage returns by spaces if there are carriage returns "
            '(e.g., "ISO 27002 v2013" or "IEC 62443-4-2").'
        )
        super().__init__(self.message)


class FeatureClassCycleError(Exception):
    """Raised when feature class relationships form a cycle."""

    def __init__(self, cycle: object) -> None:
        self.cycle = cycle
        message = f"Invalid Feature Class relationships. Cycle detected: {cycle}"
        super().__init__(message)


class BinaryNotFound(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)
