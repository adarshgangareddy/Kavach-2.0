"""L1 Ingestion: get code into a scan workspace."""


class IngestError(Exception):
    """Input rejected. The message is safe to show to the user."""

    def __init__(self, message: str, status_code: int = 400):
        super().__init__(message)
        self.status_code = status_code
