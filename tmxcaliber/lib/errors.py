class FrameworkNotFoundError(Exception):
    def __init__(self, framework):
        self.framework = framework
        self.message = f"[Error] The framework '{self.framework}' was not found in the SCF worksheet of the provided Excel file. Please ensure that the framework name is spelled correctly, use quotes if there are spaces, and use \\n if there are carriage return (e.g., ISO\\n27002\\nv2013 or \"IEC 62443-4-2\")."
        self.print_error()
    
    def print_error(self):
        print(self.message)
        exit(0)
