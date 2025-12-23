import json

class JWTError(Exception):
    """Lightweight JWT error placeholder."""


def encode(payload, key, algorithm="HS256", **kwargs):
    # Minimal JSON serialization for offline token handling in tests.
    return json.dumps(payload)


def decode(token, key, algorithms=None, **kwargs):
    try:
        return json.loads(token)
    except Exception as exc:  # pragma: no cover - defensive
        raise JWTError(str(exc))


class _JWTModule:
    encode = staticmethod(encode)
    decode = staticmethod(decode)


jwt = _JWTModule()
