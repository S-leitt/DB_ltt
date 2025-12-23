class SMTP:
    """Minimal SMTP shim providing the interface expected by the app."""

    def __init__(self, host: str = "", port: int = 0, user: str | None = None, password: str | None = None, tls: bool = True):
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.tls = tls

    def send(self, message, recipients=None):
        # In the constrained test environment we simply acknowledge the send without network I/O.
        return {"recipients": recipients or [], "subject": getattr(message, "subject", ""), "status": "sent"}
