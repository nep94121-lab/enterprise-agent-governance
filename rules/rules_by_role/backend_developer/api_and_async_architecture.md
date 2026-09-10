# ⚡ KIẾN TRÚC API, ASYNC & AN TOÀN HỆ THỐNG BACKEND

## 🔀 QUẢN LÝ BẤT ĐỒNG BỘ, CORS & TỰ KIỂM TRA

<asyncio_deadlock_prevention>
### 4. 🔀 Quản Lý Luồng Bất Đồng Bộ & Phòng Chống Deadlock (Asyncio)
*   **QUY TẮC:** Tránh gọi `asyncio.run()` hoặc lồng `ThreadPoolExecutor` trực tiếp bên trong một Event Loop đang hoạt động (ví dụ: trong endpoint của FastAPI). Việc này sẽ gây lỗi crash `RuntimeError: This event loop is already running` hoặc treo cứng hệ thống (Deadlock).
*   **Giải pháp:**
    *   Luôn dùng `await` cho các tác vụ async.
    *   Nếu gọi code đồng bộ (blocking) trong môi trường async, sử dụng `loop.run_in_executor()` hoặc `anyio.to_thread.run_sync()`.
    *   Nếu bắt buộc phải gọi async từ sync context, sử dụng `asgiref.sync.async_to_sync` được cấu hình chuẩn.
*   **Code vi phạm ❌:**
    ```python
    # Sai lầm: Gọi asyncio.run() trong endpoint của FastAPI (đã chạy event loop)
    @app.post("/chat")
    async def chat_endpoint(query: str):
        result = asyncio.run(call_rag_service(query)) # Gây RuntimeError!
        return {"response": result}
    ```
*   **Code chuẩn ✅:**
    ```python
    # Đúng: Dùng await trực tiếp trong môi trường async
    @app.post("/chat")
    async def chat_endpoint(query: str):
        result = await call_rag_service(query)
        return {"response": result}

    # Đúng (khi gọi hàm blocking đồng bộ):
    # @app.post("/sync-db-call")
    # async def db_endpoint():
    #     result = await anyio.to_thread.run_sync(blocking_db_call)
    #     return {"result": result}
    ```
</asyncio_deadlock_prevention>

---

<cors_and_api_headers>
### 7. 🌐 Cấu Hình CORS & Headers Bảo Mật (API Security)
*   **QUY TẮC:** Không bao giờ sử dụng CORS wildcard `allow_origins=["*"]` trong môi trường Production.
*   **Giải pháp:** Cấu hình danh sách domain cho phép cụ thể trong file `.env`/cấu hình hệ thống. Bổ sung các headers bảo mật để chống Clickjacking và các hình thức tấn công Web cơ bản.
*   **Code chuẩn ✅:**
    ```python
    from fastapi.middleware.cors import CORSMiddleware

    # Đọc danh sách origin được phép từ config
    allowed_origins = settings.allowed_origins.split(",") if settings.allowed_origins else []

    app.add_middleware(
        CORSMiddleware,
        allow_origins=allowed_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE"],
        allow_headers=["*"],
    )
    ```
</cors_and_api_headers>

---

<agent_self_check_checklist>
### 8. 🚦 Quy Trình Tự Kiểm Tra Của Agent (Self-Check Checklist)
Trước khi bàn giao code hoặc báo cáo hoàn thành nhiệm vụ, Agent **PHẢI** tự duyệt qua checklist bảo mật này:
- [ ] Code có sử dụng `pathlib.Path` cho tất cả các thao tác với file/thư mục không?
- [ ] Có câu lệnh SQL nào được sinh ra bằng cách cộng chuỗi/f-string không? (Nếu có -> Đổi sang Parameterized Query).
- [ ] Có API Key, Secret hay Token nào bị ghi cứng vào mã nguồn hoặc in ra log không?
- [ ] Có hàm `asyncio.run()` nào được gọi lồng trong một hàm async khác không?
- [ ] Có khối `try-except` nào bị bỏ trống (`pass`) mà không log lỗi không?
- [ ] Mọi đầu vào từ API đã có Pydantic validation chưa?
- [ ] Toàn bộ các kiểm thử (unit test/integration test) liên quan đã chạy qua và đạt 100% pass chưa?
</agent_self_check_checklist>

---

## 🏛️ TIÊU CHUẨN TECH LEAD PRE-FLIGHT CHO BACKEND

### 1. 🗄️ Tầng 1: Đồng Bộ Nhánh Chính & Chống Trùng Lặp Migration (Upstream Alignment)
- **Nguồn gốc Big Tech:** Chuẩn mực Uber Monorepo & Netflix Distributed Schema Management.
- **Mục đích:** Ngăn chặn xung đột ngầm và lỗi deadlock thứ tự chạy migration khi merge vào nhánh chính (`main`/`master`).
- **Quy tắc thực thi:**
  1. Luôn kiểm tra đối chiếu nhánh hiện tại với nhánh chính: `git fetch origin main`.
  2. **Kiểm tra Migration & Version:**
     - Nếu dự án có database migrations (SQL, Prisma, Alembic, Flyway, Supabase...): Quét toàn bộ tiền tố thời gian/số thứ tự file migration mới. **CẤM 100% việc trùng lặp tiền tố với bất kỳ file nào đã tồn tại trên upstream `main`**.
     - Nếu dự án có Version Bump (`package.json`, `pyproject.toml`): Đảm bảo version không bị tụt lùi so với upstream.
  3. **Kiểm tra Configuration Drift:** Đảm bảo các biến môi trường mới đều có giá trị mẫu trong `.env.example` và không làm gãy cấu hình của các môi trường khác.

### 2. 🛡️ Tầng 2: Kiểm Thử Đối Kháng Ca Biên & Thắt Chặt Tầng Xác Thực (Adversarial Auth & Null-Safety)
- **Nguồn gốc Big Tech:** Chuẩn mực Amazon Zero-Trust & Palantir Perimeter Defense.
- **Mục đích:** Chặn đứng lỗ hổng bảo mật, lỗi phân quyền ngang (IDOR/BOLA) và lỗi sập database do dữ liệu khuyết thiếu.
- **Quy tắc thực thi:**
  1. **Thắt chặt tầng cửa ngõ (Auth / Context / Middleware):**
     - Mọi tham số định danh ngữ cảnh tối quan trọng (như `tenant_id`, `property_id`, `user_id`, `organization_id`, `account_role`) khi bị `None`, chuỗi rỗng `""` hoặc thiếu trong token/session $\rightarrow$ **PHẢI lập tức từ chối và ngắt request ngay tại cửa vào** bằng lỗi `401 Unauthorized` hoặc `403 Forbidden`.
     - **CẤM** gán giá trị mặc định dạng `None` hoặc `null` để request đi tiếp vào tầng Controller/Service/Database vì sẽ gây lỗi `NOT NULL constraint` làm sập server hoặc làm mất bộ lọc phân vùng dữ liệu.
  2. **Viết Test Đối Kháng Bắt Buộc (Adversarial Tests):** Bắt buộc phải có ít nhất 1-2 test cases kiểm tra hành vi hệ thống khi truyền dữ liệu rỗng/sai định dạng để xác nhận lỗi 401/403 được kích hoạt đúng chuẩn.

### 3. 🧹 Tầng 3: Bảo Toàn Tính Logic Nghiệp Vụ & Chống Dữ Liệu Ảo (Zero-Garbage & Realistic Data Flow)
- **Nguồn gốc Big Tech:** Chuẩn mực Amazon Transaction Integrity & Zero-Residue State.
- **Mục đích:** Đảm bảo trạng thái hệ thống và dữ liệu trả về phản ánh 100% sự thật thực tế, không sinh rác lưu trữ.
- **Quy tắc thực thi:**
  1. **Nguyên tắc Zero-Garbage khi ở trạng thái tạm (DRAFT / PREVIEW / VALIDATION FAIL):**
     - Khi một thực thể đang ở trạng thái nháp hoặc người dùng cần điền lại đơn: **TUYỆT ĐỐI KHÔNG sinh mã định danh nghiệp vụ ảo** (như `order_number`, `request_number`, `invoice_id`) khi bản ghi chưa thực sự được ghi vào Database. Trả về `None`/`null` cho các trường này.
     - Đảm bảo 0 file nhị phân rác tải lên Storage (PDF, hình ảnh) và 0 bản ghi rác ghi xuống Database nếu giao dịch chưa hoàn tất.

### 4. ⚡ Tầng 7: Quản Lý Bất Đồng Bộ & Chống Rò Rỉ Tài Nguyên (§6, §8, §18 Concurrency & Resource Leak Guard)
- **Nguồn gốc Big Tech:** Chuẩn mực Stripe Async Engine & Uber Resource Lifecycle Management.
- **Mục đích:** Ngăn ngừa deadlock event loop, cạn kiệt file descriptor và rò rỉ bộ nhớ/kết nối.
- **Quy tắc thực thi:**
  1. **Async Lifecycle Safety (§6):**
     - Cấm gọi `asyncio.run()` trong event loop đang chạy; dùng `await` hoặc `loop.run_in_executor()`.
  2. **Connection Pooling (§17):**
     - Khởi tạo Database/HTTP Clients một lần duy nhất ngoài vòng lặp, tái sử dụng qua connection pool.
  3. **Context Manager An Toàn (§8, §18):**
     - Toàn bộ kết nối, file stream, socket phải được bọc trong `with` / `async with`.
     - Cẩn trọng khi xuất bytes/buffer ra ngoài context manager, đảm bảo stream đã hoàn tất trước khi context đóng.
