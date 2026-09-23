# Fill the Python code in this file
from policy import POLICY

def json_search(key, input_object, role=None, ret_val=None):
    if ret_val is None:
        ret_val = []
    if isinstance(input_object, dict):
        for k, v in input_object.items():
            if k == key:
                allowed_roles = POLICY.get(k, [])
                if role in allowed_roles:
                    ret_val.append({k: v})
            if isinstance(v, dict):
                json_search(key, v, role, ret_val)
            elif isinstance(v, list):
                for item in v:
                    if not isinstance(item, (str, int)):
                        json_search(key, item, role, ret_val)
    elif isinstance(input_object, list):
        for val in input_object:
            if not isinstance(val, (str, int)):
                json_search(key, val, role, ret_val)
    return ret_val
