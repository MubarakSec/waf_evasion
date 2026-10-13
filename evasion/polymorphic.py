import json
import random
from typing import Any


class PolymorphicTransformer:
    """Transforms API requests into semantically identical but structurally different variants."""

    def mutate_json(self, body: dict[str, Any]) -> str:
        """Structural JSON mutation (whitespace, reordering, escaping)."""
        # 1. Randomize key order
        keys = list(body.keys())
        random.shuffle(keys)
        ordered_body = {k: body[k] for k in keys}

        # 2. Stringify with random whitespace/padding
        # We alternate to ensure structural difference
        if random.random() > 0.5:
            # Padded variant
            raw_json = json.dumps(ordered_body, separators=(', ', ' : '))
        else:
            # Compact variant with random spaces
            raw_json = json.dumps(ordered_body, separators=(',', ':'))
            raw_json = raw_json.replace(':', '  :').replace(',', ',  ')

        # 3. Randomly unicode-escape sensitive words
        # This bypasses simple string-matching WAFs
        sensitive_words = ["admin", "root", "debug", "superuser", "id", "true", "false"]
        for word in sensitive_words:
            # Match word as a string value or key
            if f'"{word}"' in raw_json:
                # Force escape half the time to ensure polymorphism
                if random.random() > 0.5:
                    escaped = "".join(f"\\u{ord(c):04x}" for c in word)
                    raw_json = raw_json.replace(f'"{word}"', f'"{escaped}"')

        return raw_json

    def apply_method_override(self, method: str, headers: dict) -> tuple[str, dict]:
        """Converts PUT/DELETE/PATCH to POST with override headers/params."""
        if method in ("PUT", "DELETE", "PATCH") and random.random() > 0.5:
            new_headers = headers.copy()
            new_headers["X-HTTP-Method-Override"] = method
            return "POST", new_headers
        return method, headers
