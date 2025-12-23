class Message:
    """Lightweight stand-in for the `emails` package Message class used in tests."""

    def __init__(self, subject: str = "", html: str = "", mail_from: str = ""):
        self.subject = subject
        self.html = html
        self.mail_from = mail_from
