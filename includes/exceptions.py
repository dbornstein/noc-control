
class UnknownFailureException(Exception):
    """Exception raised when invalid data is encountered."""
    def __init__(self, message="UnknownFailure"):
        self._include_trace = True
        super().__init__(message)

class InvalidArgumentsError(Exception):
    """Exception raised when invalid data is encountered."""
    def __init__(self, message="Invalid arguments provided"):
        self._include_trace = False
        super().__init__(message)

class InvalidDataError(Exception):
    """Exception raised when invalid data is encountered."""
    def __init__(self, message="Invalid data provided"):
        self._include_trace = False
        super().__init__(message)

class IgnoreMessageException(Exception):
    """Exception raised when the incoming message should be ignored."""
    def __init__(self, message="no error"):
        self._include_trace = False
        super().__init__(message)
