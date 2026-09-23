"""Role-aware recursive search for values in JSON-like Python objects."""

from policy import POLICY


def json_search(key, input_object, role=None):
    """Return every value stored under *key* that *role* may access.

    Dictionaries and lists are traversed recursively. Keys absent from
    ``POLICY`` are unrestricted; policy-controlled keys fail closed when
    the role is missing or not explicitly allowed.
    """
    allowed_roles = POLICY.get(key)
    if allowed_roles is not None and role not in allowed_roles:
        return []

    matches = []

    def visit(value):
        if isinstance(value, dict):
            for child_key, child_value in value.items():
                if child_key == key:
                    matches.append(child_value)
                visit(child_value)
        elif isinstance(value, list):
            for item in value:
                visit(item)

    visit(input_object)
    return matches
