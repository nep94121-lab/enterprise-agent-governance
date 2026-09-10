# 💻 TIÊU CHUẨN LẬP TRÌNH BACKEND DOANH NGHIỆP

> Các điều khoản tiêu chuẩn chất lượng cấp doanh nghiệp bắt buộc cho lập trình viên Backend / Database / API trong các dự án phát triển phần mềm doanh nghiệp.

---

<data_privacy_pii>
## PHẦN I: BẢO VỆ QUYỀN RIÊNG TƯ DỮ LIỆU & QUẢN TRỊ BÍ MẬT

### 1. 🔏 Bảo Mật Tuyệt Đối Thông Tin Cá Nhân (PII Security — Pre-Flight Tầng 6)
*   **QUY TẮC:** Tất cả các thông tin cá nhân của người dùng (Họ tên, Số điện thoại, Email, Căn cước công dân/Hộ chiếu, Địa chỉ, hình ảnh Chữ ký, ảnh tài liệu đính kèm) phải được coi là dữ liệu nhạy cảm mức độ cao nhất.
*   **Không log dữ liệu thô:** Nghiêm cấm in ra console (phía client) hoặc ghi vào file log (phía server) nội dung thô (plaintext) của các chuỗi base64 chứa chữ ký, ảnh chụp, hoặc dữ liệu sinh trắc học của người dùng. Chỉ log độ dài ký tự hoặc trạng thái xử lý để tránh rò rỉ dữ liệu và phòng chống phình dung lượng lưu trữ log (storage bloat).
*   **Phân lập dữ liệu người dùng (Authorization):** Việc truy cập và thao tác dữ liệu phải được xác thực và kiểm tra phân quyền chặt chẽ thông qua ngữ cảnh thực thi ở phía máy chủ (server-side execution context). Tuyệt đối không cho phép client tự truyền ID tài khoản hoặc ID tài nguyên để truy vấn thông tin của thực thể khác mà không qua kiểm tra quyền sở hữu, ngăn chặn triệt để lỗ hổng phân quyền ngang (Bypass RLS / IDOR).

### 2. 🔑 Quản Lý Thông Tin Nhạy Cảm Hệ Thống (Secrets Management — Pre-Flight Tầng 6)
*   **QUY TẮC:** Tuyệt đối không hardcode API Key, Token, Mật khẩu, Database URL hoặc các chuỗi nhạy cảm khác trong mã nguồn dưới bất kỳ hình thức nào.
*   **Giải pháp:** Đọc từ biến môi trường thông qua cấu hình môi trường bảo mật (như `.env` được nạp qua `pydantic-settings` với Backend, hoặc các biến build-time env với Frontend). File cấu hình `.env` chứa thông tin thực tế phải luôn được khai báo trong `.gitignore` để tránh đẩy lên Git.
</data_privacy_pii>

---

<cybersecurity_defense>
## PHẦN II: AN NINH MẠNG & CHỐNG INJECTION

### 3. 🛡️ Phòng Chống Tấn Công Injection (SQL, OS Command & Prompt Injection)
*   **QUY TẮC SQLi:** Tuyệt đối không sử dụng nối chuỗi (string concatenation) hoặc f-string để dựng câu truy vấn SQL trực tiếp từ đầu vào của người dùng. Luôn sử dụng Parameterized Queries hoặc các bộ thư viện ORM tiêu chuẩn để bảo vệ database khỏi các cuộc tấn công SQL Injection.
*   **QUY TẮC Command Injection:** Cấm gọi các lệnh hệ thống bằng cách truyền trực tiếp input người dùng vào `os.system` hoặc `subprocess.Popen(..., shell=True)`.
*   **QUY TẮC Prompt Injection:** Phân tách chi tiết chỉ thị hệ thống (System Prompt) và nội dung do người dùng cung cấp (User Prompt) bằng các tag XML/Markdown rõ ràng để ngăn chặn việc LLM bị đánh lừa hoặc ghi đè chỉ thị ban đầu (Prompt Injection).
</cybersecurity_defense>

---

<code_quality_and_performance>
## PHẦN III: CHẤT LƯỢNG MÃ NGUỒN & QUẢN LÝ TÀI NGUYÊN

### 6. 🔀 Quản Lý Luồng Bất Đồng Bộ & Phòng Chống Deadlock (Asyncio — Pre-Flight Tầng 7)
*   **QUY TẮC:** Tránh gọi `asyncio.run()` hoặc lồng `ThreadPoolExecutor` trực tiếp bên trong một Event Loop đang hoạt động để ngăn chặn lỗi `RuntimeError: This event loop is already running` và nguy cơ nghẽn toàn bộ hệ thống (Deadlock).
*   **Giải pháp:** Luôn sử dụng từ khóa `await` cho các tác vụ async. Đối với các tác vụ đồng bộ (blocking) như đọc ghi file lớn hoặc gọi API đồng bộ trong ngữ cảnh async, sử dụng `loop.run_in_executor()` hoặc các hàm chạy luồng an toàn.

### 7. 📂 Xử Lý Đường Dẫn Động & Ngăn Ngừa Path Traversal
*   **QUY TẮC:** Tuyệt đối không hardcode đường dẫn tuyệt đối dạng `C:\Users\...` hoặc `/var/www/data`. Khi đọc/ghi file từ đầu vào người dùng, luôn kiểm tra để ngăn chặn tấn công duyệt thư mục ngược (Path Traversal, ví dụ: `../../etc/passwd`).
*   **Giải pháp:** Sử dụng thư viện chuẩn xử lý đường dẫn (như `pathlib.Path` trong Python) để định nghĩa đường dẫn động tương đối dựa trên vị trí file hiện tại. Luôn kiểm tra `.resolve()` để đảm bảo file đích nằm trong thư mục gốc được phép.

### 8. 🧹 Quản Lý Tài Nguyên & Tránh Rò Rỉ (Resource Leakage — Pre-Flight Tầng 7)
*   **QUY TẮC:** Luôn đảm bảo mọi tài nguyên hệ thống (kết nối cơ sở dữ liệu, file stream, HTTP client sessions, socket) được đóng và giải phóng ngay sau khi sử dụng để tránh lỗi tràn tài nguyên hệ thống (file descriptor exhaustion) và rò rỉ bộ nhớ (Resource Leakage).
*   **Giải pháp:** Sử dụng context manager `with` hoặc `async with` để tự động thu hồi tài nguyên.

### 10. 🔐 Tạo Định Danh Cực Kỳ An Toàn (Secure UUID Generation)
*   **QUY TẮC:** Tuyệt đối không tự viết thuật toán sinh ID ngẫu nhiên thủ công (manual polyfills) bằng cách sử dụng các hàm regex thay thế ký tự. Các thuật toán tự chế không đảm bảo phân phối ngẫu nhiên an toàn (cryptographic randomness) và dễ gây lỗi trùng lặp ID (collision).
*   **Giải pháp:** Sử dụng thư viện chuẩn `uuid` trong Python (`uuid.uuid4()`) hoặc API tiêu chuẩn của trình duyệt `crypto.randomUUID()`.
</code_quality_and_performance>

---

<cicd_and_development_standards>
## PHẦN IV: QUY TRÌNH PHÁT TRIỂN & QUẢN TRỊ DỮ LIỆU

### 14. 🔑 Không Tùy Tiện Thay Đổi Cấu Hình Bảo Mật Mặc Định (Weak Key Guard)
*   Khi rà soát quy tắc "Cấm hardcode", tuyệt đối không được sửa các giá trị hằng số (fallback values) trong file cấu hình (VD: `JWT_SECRET`) thành các chuỗi rác/mock một cách máy móc nếu chưa hiểu rõ ngữ cảnh. Việc này có thể vô tình vô hiệu hóa hệ thống cảnh báo khóa yếu (Weak Key Guard) ở môi trường Production.

### 17. 🚀 Tối Ưu Kết Nối & Vòng Lặp (Connection Pooling — Pre-Flight Tầng 7)
*   Tuyệt đối không khởi tạo các đối tượng Client tạo kết nối mạng (như HTTP Client, Database Client) ở bên trong một vòng lặp. Luôn luôn khởi tạo các đối tượng Client một lần duy nhất bên ngoài vòng lặp và tái sử dụng nó để tận dụng Connection Pooling, giảm thiểu độ trễ do bắt tay TCP/TLS nhiều lần.

### 18. 🛡️ An Toàn Dữ Liệu Trong Khối Lệnh (Context Manager Lifecycle — Pre-Flight Tầng 7)
*   Khi sử dụng `with` hoặc `async with` để quản lý tài nguyên (như xử lý File, PDF, Stream), phải cực kỳ cẩn thận khi trích xuất hoặc xuất dữ liệu thô (bytes/buffer) ra bên ngoài. Phải đảm bảo tiến trình xuất dữ liệu không bị xung đột với cơ chế dọn dẹp tự động của thư viện khi khối lệnh kết thúc, tránh nguy cơ mất hoặc hỏng dữ liệu ngầm.

### 24. 🗄️ Kiểm Tra Migration & Phân Quyền Dữ Liệu (Migration Existence & Ownership Filter — Pre-Flight Tầng 1, 2)
*   Mọi bảng (table) được code tham chiếu (`repository`, `service`, `state store`) PHẢI có migration tương ứng đã tồn tại. Nếu phát hiện code dùng bảng chưa có migration → báo lỗi chặn merge.
*   Mọi hàm `load()`, `get()`, `delete()` truy vấn dữ liệu người dùng PHẢI filter theo `ownership_id` (VD: `resident_id`) để ngăn chặn IDOR — cấm chỉ query theo `conversation_id` hoặc `request_id` mà không kiểm tra quyền sở hữu.

```python
# Ví dụ query lọc phân quyền sở hữu resident_id chống IDOR
def get_repair_request_secure(request_id: str, resident_id: str, db_client):
    # BẮT BUỘC filter theo ownership_id = resident_id
    query = "SELECT * FROM repair_requests WHERE id = %s AND resident_id = %s"
    return db_client.execute(query, (request_id, resident_id))
```

### 25. 🤖 Kiểm Soát Ngữ Nghĩa Trong AI State Machine & Slot-Filling
*   Tuyệt đối cấm sử dụng cơ chế naive catch-all (như gán trực tiếp toàn bộ chuỗi người dùng `state.location = msg.strip()`).
*   Phải có lớp kiểm duyệt ngữ nghĩa (`is_valid_location_text()`) để nhận diện và loại trừ các tin nhắn không hợp tác (chitchat, hỏi giá/quy trình, đổi ý định sang luồng khác, từ chối, câu lệnh hủy báo hỏng).

```python
import re

def is_valid_location_text(msg: str) -> bool:
    """
    §25: Kiểm duyệt ngữ nghĩa slot-filling chống gán chuỗi thô msg.strip()
    """
    cleaned = msg.strip().lower()
    if len(cleaned) < 2 or len(cleaned) > 100:
        return False
    unrelated_patterns = [r"không sửa nữa", r"thôi", r"giá bao nhiêu", r"hỏi tí", r"chào bạn", r"hủy đơn"]
    if any(re.search(pat, cleaned) for pat in unrelated_patterns):
        return False
    return True
```

### 26. 🛡️ Phòng Chống Đứt Gãy Luồng Dữ Liệu & Nuốt Lỗi (Resilient Data Flow & Observability — Pre-Flight Tầng 3)
*   Khi khởi tạo hoặc cập nhật các thực thể quan hệ cha-con (VD: `conversations` trước khi tạo `action_proposals`), cấm nuốt ngoại lệ âm thầm bằng `logger.debug()` khiến lệnh con tiếp theo bị lỗi khóa ngoại (Foreign Key).
*   Sử dụng cơ chế idempotent upsert (`Prefer: resolution=merge-duplicates`) và log chi tiết cảnh báo kèm đầy đủ ngữ cảnh (`entity_id`, `status_code`, response body) để dễ dàng chẩn đoán.

```python
# Idempotent upsert chống lỗi Foreign Key cho Action Proposals
async def create_action_proposal_idempotent(client, conversation_id: str, proposal_data: dict):
    # Đảm bảo conversation cha tồn tại trước khi tạo proposal con
    headers = {"Prefer": "resolution=merge-duplicates"}
    res = await client.table("conversations").upsert({"id": conversation_id}, headers=headers).execute()
    if not res.data:
        raise RuntimeError(f"§26 LỖI: Không thể khởi tạo conversation cha ID={conversation_id}")
    return await client.table("action_proposals").insert(proposal_data).execute()
```

### 27. 🔍 Quét Toàn Bộ Codebase Khi Sửa Thuật Ngữ / Docstring / Hằng Số (Comprehensive Scope Grep — Pre-Flight Tầng 4)
*   Khi sửa bất kỳ thuật ngữ, docstring, hằng số, schema hay tài liệu nào, **BẮT BUỘC phải `grep` toàn bộ codebase** để tìm sạch 100% mọi vị trí xuất hiện (bao gồm file gốc, hàm con, docstrings, schema, và tests).
*   **CẤM** chỉ sửa vị trí đầu tiên nhìn thấy (chống điểm mù *Partial Match Blind Spot*).
</cicd_and_development_standards>
