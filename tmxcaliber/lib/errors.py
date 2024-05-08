class FrameworkNotFoundError(Exception):
    def __init__(self, framework):
        self.framework = framework
        self.message = f"[Error] The framework '{self.framework}' was not found in the SCF worksheet of the provided Excel file. Please ensure that the framework name is spelled correctly, use quotes if there are spaces, and use \\n if there are carriage return (e.g., ISO\\n27002\\nv2013 or \"IEC 62443-4-2\")."
        self.print_error()

    def print_error(self):
        print(self.message)
        exit(0)


class FeatureClassCycleError(Exception):
    """Exception raised for errors in the input due to cyclic dependencies in feature classes."""

    def __init__(self, cycle):
        self.cycle = cycle
        message = f"Invalid Feature Class relationships. Cycle detected: {cycle}"
        super().__init__(message)


class BinaryNotFound(Exception):

    def __init__(self, message):
        super().__init__(message)
