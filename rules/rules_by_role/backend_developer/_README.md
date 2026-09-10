# 💻 Backend / API Developer Rulebook

## 🎯 Mục Đích & Phạm Vi Trách Nhiệm
Thư mục này chứa toàn bộ các tiêu chuẩn lập trình Backend (Python/FastAPI), quản lý kết nối cơ sở dữ liệu bảo mật, quản lý luồng bất đồng bộ (Asyncio/Concurrency), bảo vệ quyền riêng tư dữ liệu (PII & RLS), và kiến trúc xử lý lỗi/state machine dành riêng cho vai trò **Backend / Database / API Engineer**.

## 📦 Danh Mục Tập Tin Quy Tắc
1. **`backend_coding_standards.md`**:
   - 14 điều khoản doanh nghiệp cốt lõi:
     - §1 (Bảo mật PII & Phân quyền RLS/IDOR)
     - §2 (Quản lý Secrets qua `.env` & `pydantic-settings`)
     - §3 (Phòng chống SQL Injection, Command Injection & Prompt Injection)
     - §6 (Quản lý Asyncio an toàn, cấm `asyncio.run()` trong event loop)
     - §7 (Xử lý đường dẫn động `pathlib.Path`, chống Path Traversal)
     - §8 (Quản lý tài nguyên `with`/`async with`, chống rò rỉ file/socket)
     - §10 (Tạo định danh an toàn với UUID)
     - §14 (Weak Key Guard, không sửa fallback value máy móc)
     - §17 (Connection Pooling ngoài vòng lặp)
     - §18 (Context Manager Lifecycle an toàn dữ liệu)
     - §24 (Database Migration & Bắt buộc filter `ownership_id`)
     - §25 (AI State Machine & Slot-Filling kiểm duyệt ngữ nghĩa)
     - §26 (Data Flow Resilience & Observability, cấm nuốt lỗi foreign key)
     - §27 (Scope Grep toàn bộ codebase khi đổi tên/logic)
2. **`security_and_database.md`**:
   - Nguyên tắc kết nối cơ sở dữ liệu doanh nghiệp, nạp biến môi trường 100% qua DATABASE_URL (.env) và bảo mật (§1, §2).
   - Cẩm nang thực thi kỹ thuật kèm code mẫu:
     - CSR Rule 1: Xử lý đường dẫn động (`pathlib.Path`)
     - CSR Rule 2: Chống SQL Injection & Prompt Injection
     - CSR Rule 3: Quản lý Secrets với `BaseSettings` & log an toàn
     - CSR Rule 5: Quản lý tài nguyên & Exception Handling chuẩn FastAPI
     - CSR Rule 6: Xác thực dữ liệu đầu vào với Pydantic Models & Field constraints
3. **`api_and_async_architecture.md`**:
   - CSR Rule 4: Quản lý luồng bất đồng bộ, `await`, `anyio.to_thread.run_sync()`, `asgiref`.
   - CSR Rule 7: Cấu hình CORS Middleware & Security Headers.
   - CSR Rule 8: 7-point Self-Check Checklist trước khi bàn giao code.
   - Tiêu chuẩn Tech Lead áp dụng cho Backend:
     - Tầng 1: Đồng bộ Migration & Upstream Alignment
     - Tầng 2: Adversarial Auth & Null-Safety (Chặn 401/403 tại gateway)
     - Tầng 3: Zero-Garbage DRAFT & State integrity
     - Tầng 7: Concurrency & Resource Leak Guard

## 📊 Ngân Sách Token (Token Budget)
- **Giới hạn tối đa cho phép:** ≤ 12,000 tokens
- **Mục tiêu tối ưu:** < 7,000 tokens
- **Thực tế đo lường (`cl100k_base`):** 10,155 tokens (4 files, đạt 84.6% ngân sách)
- **Mỗi file đơn lẻ:** Luôn ≤ 4,000 tokens (File lớn nhất: 3,449 tokens)
- **Toàn bộ hệ thống 6 vai trò:** 44,551 tokens

## 🚀 Hướng Dẫn Nạp Context
- **Khi viết API / Endpoints / Async:** Nạp `api_and_async_architecture.md` + `backend_coding_standards.md`.
- **Khi làm việc với Database / SQL / Data Models:** Nạp `security_and_database.md`.
- **Trước khi hoàn thành code:** Chạy 7-point Self-Check trong `api_and_async_architecture.md`.
