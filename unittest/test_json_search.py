# Fill the Python code in this file
import unittest
from recursive_json_search import *
from test_data import *

class json_search_test(unittest.TestCase):

    # --- 3 test case chức năng gốc (Bước 4) ---
    def test_search_found(self):
        '''key hợp lệ với role đủ quyền phải trả về list khác rỗng'''
        self.assertTrue([] != json_search(key1, data, role="admin"))

    def test_search_not_found(self):
        '''key không tồn tại trong data phải trả về list rỗng'''
        self.assertTrue([] == json_search(key2, data, role="admin"))

    def test_is_a_list(self):
        '''kết quả trả về luôn phải là kiểu list'''
        self.assertIsInstance(json_search(key1, data, role="admin"), list)

    # --- 3+ security test case (Yêu cầu 5) ---
    def test_viewer_cannot_read_apiKey(self):
        '''viewer không nằm trong POLICY["apiKey"] -> phải bị chặn, trả về rỗng
        (kiểm tra Information Disclosure với secret SNMP community string)'''
        result = json_search("apiKey", data, role="viewer")
        self.assertEqual([], result)

    def test_operator_cannot_read_apiKey(self):
        '''operator cũng không có quyền đọc apiKey theo policy -> phải trả về rỗng'''
        result = json_search("apiKey", data, role="operator")
        self.assertEqual([], result)

    def test_admin_can_read_apiKey(self):
        '''admin nằm trong danh sách được phép -> phải đọc được apiKey
        (đảm bảo không chặn nhầm role hợp lệ)'''
        result = json_search("apiKey", data, role="admin")
        self.assertNotEqual([], result)

    def test_viewer_cannot_read_managementIpAddress(self):
        '''viewer không có quyền đọc managementIpAddress -> Elevation of Privilege
        nếu bị lộ, nên kết quả phải rỗng'''
        result = json_search("managementIpAddress", data, role="viewer")
        self.assertEqual([], result)

    def test_no_role_defaults_to_deny(self):
        '''không truyền role (role=None) -> mặc định phải KHÔNG lộ dữ liệu nhạy cảm
        (deny-by-default, tránh bypass trust boundary)'''
        result = json_search("apiKey", data)
        self.assertEqual([], result)
    def test_operator_can_read_managementIpAddress(self):
        '''operator nằm trong POLICY["managementIpAddress"] -> phải đọc được
        (positive case, đảm bảo không chặn nhầm role hợp lệ)'''
        result = json_search("managementIpAddress", data, role="operator")
        self.assertNotEqual([], result)


if __name__ == '__main__':
    unittest.main()
