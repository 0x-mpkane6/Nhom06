import unittest
from recursive_json_search import *
from test_data import *

class json_search_test(unittest.TestCase):
    '''test module to test search function in `recursive_json_search.py`'''
    

    def test_search_found(self):
        '''key should be found, return list should not be empty'''

        self.assertTrue([] != json_search(key1, data, role="admin"))
        
    def test_search_not_found(self):
        '''key should not be found, should return an empty list'''
        self.assertTrue([] == json_search(key2, data, role="admin"))
        
    def test_is_a_list(self):
        '''Should return a list'''
        self.assertIsInstance(json_search(key1, data, role="admin"), list)

    # --- 3 SECURITY TEST MỚI CHO BƯỚC 7 ---
    def test_wrong_role_cannot_read_secret(self):
        '''role không có quyền (viewer) không được phép đọc apiKey'''
        result = json_search("apiKey", data, role="viewer")
        self.assertEqual([], result)

    def test_admin_can_read_secret(self):
        '''admin có quyền hợp lệ sẽ đọc được apiKey'''
        result = json_search("apiKey", data, role="admin")
        self.assertTrue([] != result)

    def test_operator_can_read_management_ip(self):
        '''operator có quyền truy cập managementIpAddress'''
        result = json_search("managementIpAddress", data, role="operator")
        self.assertTrue([] != result)

if __name__ == '__main__':
    unittest.main()
