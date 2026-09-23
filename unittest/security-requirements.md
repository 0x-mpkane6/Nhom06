# Security Requirements — `json_search()`

Các security requirement dưới đây được phát biểu trực tiếp từ
`threat-model.md`, dùng làm căn cứ cho bộ security test trong
`test_json_search.py`.

## SR-1 — Field-level authorization (chống Information Disclosure — T1)

> Hệ thống chỉ trả về giá trị của trường `X` cho các role nằm trong
> `POLICY[X]`. Nếu `role` gọi hàm không nằm trong danh sách cho phép
> của `X`, kết quả trả về đối với trường đó phải rỗng — bất kể trường
> đó nằm ở vị trí nào trong cấu trúc JSON lồng nhau.

Cụ thể theo `policy.py`:

| Trường | Role được phép |
| --- | --- |
| `apiKey` | `admin` |
| `managementIpAddress` | `admin`, `operator` |
| `issueSummary` | `admin`, `operator`, `viewer` |

Test tương ứng: `test_wrong_role_cannot_read_secret`,
`test_operator_cannot_read_apiKey`, `test_admin_can_read_apiKey`,
`test_viewer_cannot_read_managementIpAddress`,
`test_operator_can_read_managementIpAddress`.

## SR-2 — Nhất quán trên toàn bộ cấu trúc lồng nhau (chống Information Disclosure — T1)

> Việc kiểm tra role phải áp dụng cho **mọi vị trí xuất hiện** của
> `key` trong cấu trúc JSON lồng nhau (ví dụ `apiKey` nằm sâu trong
> `enrichmentInfo.connectedDevice[].deviceDetails.apiKey`), không chỉ
> ở top-level.

Yêu cầu này trực tiếp dẫn tới việc phải sửa bug gộp kết quả đệ quy
(`ret_val += json_search(...)`) — nếu không sửa, một số nhánh con sẽ
"biến mất" khỏi kết quả một cách không nhất quán, khiến việc kiểm tra
quyền trở nên không đáng tin cậy dù logic phân quyền đúng.

## SR-3 — Fail-closed khi không xác định được role (chống Information Disclosure — T3)

> Nếu `role` không được cung cấp (`role=None`) hoặc không hợp lệ, đối
> với mọi trường có mặt trong `POLICY`, hệ thống phải coi đó là
> **không có quyền truy cập**, KHÔNG được mặc định "không giới hạn".
> Hàm không được raise exception vì lý do này — chỉ đơn giản trả về
> kết quả rỗng cho trường bị giới hạn.

Đây là requirement bổ sung được rút ra khi thiết kế lại hàm với tham
số `role`: một implementation ngây thơ coi `role=None` là "bỏ qua kiểm
tra" sẽ biến lỗi thiếu tham số ở tầng gọi thành lỗ hổng lộ dữ liệu toàn
hệ thống (T3).

Test tương ứng: `test_no_role_provided_is_denied_for_restricted_field`.

## SR-4 — Không hạn chế quá mức với trường không nhạy cảm

> Các trường không nằm trong `POLICY` (không được định nghĩa danh sách
> role) không bị giới hạn quyền truy cập, và các trường thuộc
> `POLICY["issueSummary"]` được mở cho mọi role hợp lệ.

Requirement này đảm bảo nguyên tắc "chỉ giới hạn khi cần thiết" —
tránh over-restriction gây cản trở vận hành bình thường của `operator`
và `viewer` với dữ liệu không nhạy cảm.

## SR-5 — Toàn vẹn kết quả trả về (hỗ trợ SR-1/SR-2, gián tiếp)

> Kết quả trả về của `json_search()` phải phản ánh **đầy đủ** mọi lần
> xuất hiện hợp lệ của `key` trong `input_object` mà `role` được phép
> đọc — không được thiếu sót do lỗi cài đặt đệ quy.

---

## Known Limitation — T2 (Elevation of Privilege / Spoofing) chưa được khắc phục

`json_search(key, input_object, role=None)` nhận `role` như một tham số
thường do caller tự truyền, **không** xác thực rằng caller thực sự giữ
role đó. Đây là threat T2 trong `threat-model.md` — vẫn còn tồn tại
trong bài nộp này.

Lý do không khắc phục trong phạm vi Lab 1: chữ ký hàm
`json_search(key, input_object, role=None)` được quy định cố định ở
Yêu cầu 4-5 của đề bài. Khắc phục triệt để đòi hỏi thay `role` bằng
một token/phiên đã xác thực ở tầng gọi (ví dụ session token, JWT) và
suy ra role phía server — nằm ngoài phạm vi hàm `json_search()` được
giao trong bài. Ghi nhận đây là hạn chế đã biết (known limitation) cần
bổ sung nếu triển khai thực tế ngoài phạm vi bài tập.

---

**Ánh xạ ngược lại STRIDE / Yêu cầu 3(d):**
- SR-1, SR-2 → chống **Information Disclosure** (T1).
- SR-3 → chống **Information Disclosure** biến thể fail-open (T3).
- T2 (**Elevation of Privilege**/Spoofing) → ghi nhận là known
  limitation, không có SR khắc phục trong phạm vi bài Lab (xem mục
  trên).
