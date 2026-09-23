from test_data import *
from policy import * # Import cấu hình phân quyền từ policy.py

def json_search(key, input_object, role=None):
    ret_val = []
    
    # KIỂM SOÁT TRUY CẬP (RBAC): 
    # Nếu key có yêu cầu quyền truy cập mà role không hợp lệ -> chặn và trả về rỗng
    if key in policy and role not in policy[key]:
        return []

    if isinstance(input_object, dict): # Iterate dictionary
        for k, v in input_object.items(): # searching key in the dict
            if k == key:
                temp = {k: v}
                ret_val.append(temp)
            if isinstance(v, dict): # the value is another dict so repeat
                # Nhớ truyền thêm biến role vào các lệnh gọi đệ quy
                ret_val.extend(json_search(key, v, role))
            elif isinstance(v, list): # it's a list
                for item in v:
                    if not isinstance(item, (str, int)): # if dict or list repeat
                        ret_val.extend(json_search(key, item, role))
    else: # Iterate a list because some APIs return JSON object in a list
        for val in input_object:
            if not isinstance(val, (str, int)):
                ret_val.extend(json_search(key, val, role))
    return ret_val
