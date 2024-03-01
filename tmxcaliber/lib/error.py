class FrameworkNotFoundError(Exception):
    def __init__(self, framework):
        self.framework = framework
        self.message = f"Error: The framework '{self.framework}' was not found in the 'SCF 2023.4' worksheet of the provided Excel file. Please ensure that the framework name is spelled correctly and that it exists in the 'SCF 2023.4' worksheet."
        super().__init__(self.message)
