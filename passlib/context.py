class CryptContext:
    """Simple stand-in providing hash/verify operations for testing without passlib."""

    def __init__(self, schemes=None, deprecated="auto"):
        self.schemes = schemes or []
        self.deprecated = deprecated

    def hash(self, password: str) -> str:
        return f"hashed:{password}"

    def verify(self, plain_password: str, hashed_password: str) -> bool:
        # Accept both hashed:prefix or raw equality for flexibility in tests.
        if hashed_password.startswith("hashed:"):
            return hashed_password.split(":", 1)[1] == plain_password
        return hashed_password == plain_password
