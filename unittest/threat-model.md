# Threat Model — `json_search()`

Tệp dữ liệu mẫu (`test_data.py`) mô phỏng phản hồi của một API giám sát
hạ tầng mạng kiểu Cisco DNA Center — cụ thể là một bản tin sự cố báo
thiết bị mạng bất khả dụng.

## (a) Actor/role được phép gọi hàm và mục đích

| Role | Mục đích sử dụng hợp lệ |
| --- | --- |
| `admin` | Toàn quyền chẩn đoán sự cố, bao gồm truy cập thông tin xác thực thiết bị (SNMP community string, quản lý IP). |
| `operator` | Vận hành/khắc phục sự cố hằng ngày — cần IP quản lý thiết bị nhưng không cần secret xác thực. |
| `viewer` | Chỉ xem tóm tắt sự cố (dashboard, báo cáo) — không cần thông tin định danh/xác thực thiết bị. |

**Actor không hợp lệ**: bất kỳ giá trị `role` nào ngoài 3 role trên,
bao gồm cả `role=None` (không truyền role) — coi như không có quyền
với mọi trường nằm trong `POLICY`.

## (b) Asset nhạy cảm trong dữ liệu trả về

Dựa trên `test_data.py`, theo thứ tự độ nhạy cảm giảm dần:

| Asset | Vị trí trong data | Vì sao nhạy cảm |
| --- | --- | --- |
| `apiKey` (`SNMP-COMMUNITY-STRING-7f3a9c`) | `enrichmentInfo.connectedDevice[0].deviceDetails.apiKey` | Chuỗi xác thực SNMP — lộ ra cho phép đọc/ghi cấu hình thiết bị mạng thật. |
| `managementIpAddress` (`10.10.20.21`) | `enrichmentInfo.connectedDevice[0].deviceDetails.managementIpAddress` | Thông tin định danh mạng quản trị — hỗ trợ trinh sát và tấn công có chủ đích. |
| `issueSummary` | `enrichmentInfo.issueDetails.issue[0].issueSummary` | Độ nhạy cảm thấp — phù hợp chia sẻ rộng, kể cả `viewer`. |

`apiKey` và `managementIpAddress` nằm **sâu trong cấu trúc JSON lồng
nhau**, không phải top-level — cơ chế kiểm soát phải áp dụng nhất quán
ở mọi độ sâu đệ quy.

## (c) Trust boundary bị bỏ qua nếu không kiểm tra role

- **Boundary 1 (giữa hạ tầng & ứng dụng):** DNAC trả về dữ liệu đầy đủ
  (kèm credential) với giả định rằng tầng ứng dụng phía trên sẽ lọc lại
  trước khi hiển thị cho người dùng cuối. `json_search()` là cửa ngõ
  duy nhất giữa dữ liệu thô này và người gọi — nếu không lọc theo role,
  boundary 1 bị xoá bỏ hoàn toàn.
- **Boundary 2 (giữa các role trong ứng dụng):** Ranh giới quyền
  Admin/Operator/Viewer chỉ tồn tại nếu hàm kiểm tra `role` trước khi
  trả kết quả. Bỏ qua kiểm tra này, `viewer` "leo thang" thành `admin`
  về mặt dữ liệu, dù không hề thay đổi tài khoản hay quyền hệ thống.

## (d) Ánh xạ STRIDE

| # | Threat | Nhóm STRIDE | Mô tả khai thác | Hậu quả |
| --- | --- | --- | --- | --- |
| T1 | `viewer`/`operator` gọi `json_search("apiKey", data, role=...)` và nhận được community string SNMP thật vì hàm không lọc theo role trước khi trả kết quả | **Information Disclosure** | Hàm duyệt toàn bộ JSON và trả về mọi giá trị khớp `key`, không đối chiếu `POLICY` | Kẻ tấn công chiếm được credential SNMP → đọc/ghi cấu hình switch thật |
| T2 | `role` là tham số do **chính caller tự truyền** (`json_search(key, data, role="admin")`), không qua bất kỳ bước xác thực phiên nào — bất kỳ ai gọi được hàm đều có thể tự khai `role="admin"` | **Elevation of Privilege** (gốc rễ là **Spoofing** danh tính role) | Không có cơ chế nào xác minh caller *thực sự* là admin — role chỉ là một chuỗi tự khai | Actor quyền thấp (hoặc code gọi bị lỗi/bị chiếm quyền) tự cấp cho mình quyền admin mà không qua phê duyệt nào |
| T3 | Caller quên/không truyền `role` (`role=None`) khi gọi hàm cho trường nhạy cảm, và implementation coi đây là "không giới hạn" thay vì "không có quyền" | **Information Disclosure** (biến thể fail-open) | Lỗi thiếu tham số ở tầng gọi vô tình trở thành lỗ hổng lộ dữ liệu toàn hệ thống | Dữ liệu nhạy cảm bị lộ ra ngoài mà không cần kẻ tấn công chủ động khai thác gì thêm |

T1 và T2 là 2 threat bắt buộc theo Yêu cầu 3(d) (Information Disclosure
và Elevation of Privilege); T3 là threat bổ sung được rút ra trực tiếp
khi thiết kế tham số `role` cho hàm.

### Threat được cân nhắc nhưng nằm ngoài phạm vi bài Lab

Các threat sau có thật về mặt lý thuyết nhưng **không có security
requirement/test tương ứng trong bài nộp này**, vì nằm ngoài phạm vi
chức năng `json_search(key, input_object, role=None)` được giao ở Yêu
cầu 4-5 (ghi nhận để không bỏ sót, không claim đã khắc phục):

- **Denial of Service**: truy vấn trên JSON rất lớn/lồng rất sâu không
  bị giới hạn độ phức tạp — có thể làm chậm hệ thống nếu bị lạm dụng.
- **Repudiation**: hàm không ghi log ai đã tra cứu trường nhạy cảm —
  không có audit trail để truy vết khi credential bị lộ.
- **Tampering (gián tiếp)**: bug gộp kết quả đệ quy (`ret_val`) đã
  được sửa ở Yêu cầu 4 — nếu còn tồn tại, `admin` có thể nhận kết quả
  sai/thiếu, ảnh hưởng quyết định vận hành, dù không phải lỗi cấp quyền.

## Kết luận

Threat model này là căn cứ trực tiếp cho `security-requirements.md`
và cho bộ security test trong `test_json_search.py`
(`test_wrong_role_cannot_read_secret`,
`test_no_role_provided_is_denied_for_restricted_field`, v.v.).
