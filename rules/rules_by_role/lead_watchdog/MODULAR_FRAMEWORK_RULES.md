# 📦 MODULAR FRAMEWORK RULES: 10 CHUẨN CÔNG NGHỆ CHUYÊN BIỆT CHO WORKER SUBAGENTS
**Phiên bản**: 2.0 (Enterprise Modular Standard)
**Phân loại**: Framework Specific Best-Practices
**Mục tiêu**: Cung cấp bộ quy tắc tinh gọn, chính xác theo từng ngôn ngữ/khung làm việc, giúp Worker Sub-agents chỉ nạp đúng module cần thiết, tiết kiệm 38.5% Context Token.

---

## 1. FastAPI (Python Modern Async Backend)
- **BaseSettings V2**: Quản trị biến môi trường qua `pydantic-settings` (`from pydantic_settings import BaseSettings, SettingsConfigDict`). CẤM dùng `os.getenv` rải rác.
- **Asynchronous I/O**: Mọi endpoint có thao tác I/O (Database, Network, Disk) BẮT BUỘC dùng `async def` và gọi `await`. Không chặn Event Loop bằng các hàm đồng bộ nặng (`time.sleep` -> `asyncio.sleep`).
- **Lifespan Context Manager**: Khởi tạo và dọn dẹp tài nguyên (DB connection pools, HTTP client sessions) bằng `@asynccontextmanager async def lifespan(app: FastAPI): ...`. CẤM dùng các sự kiện cũ `on_event("startup")` / `on_event("shutdown")`.
- **Response Model & Status Codes**: Luôn khai báo `response_model` và `status_code` rõ ràng trong decorator. Dùng `HTTPException` có cấu trúc chuẩn.
- **Database Dependency Injection**: Inject database session qua `Depends(get_db)` với yield pattern đóng session trong khối `finally`.

---

## 2. Next.js (React Server Components & App Router)
- **Default Server Components**: Mọi component trong thư mục `app/` mặc định là React Server Component (RSC). Chỉ gắn directive `'use client'` khi thực sự cần tương tác giao diện (useState, useEffect, event listeners).
- **Server Actions & Input Validation**: Sử dụng Server Actions cho các thao tác đột biến dữ liệu (Mutations). BẮT BUỘC xác thực toàn bộ đối số đầu vào bằng thư viện kiểm thực kiểu (`zod`) trước khi ghi vào database.
- **Data Fetching & Cache Revalidation**: Sử dụng `fetch()` gốc kết hợp các tuỳ chọn cache `{ next: { revalidate: 3600 } }` hoặc `cache: 'no-store'`. CẤM gọi API nội bộ bằng HTTP fetch từ Server Component; thay vào đó hãy gọi trực tiếp hàm database service.
- **Metadata & SEO**: Khai báo static metadata `export const metadata: Metadata = { ... }` hoặc dynamic metadata `generateMetadata()` cho mọi trang.
- **Error Boundaries & Loading Skeletons**: Mỗi route segment lớn bắt buộc có `loading.tsx` và `error.tsx` để xử lý trạng thái chờ và lỗi mượt mà.

---

## 3. Django (High-Performance ORM & Enterprise Web)
- **Chống N+1 Queries**: BẮT BUỘC dùng `select_related` cho các quan hệ ForeignKey/OneToOne và `prefetch_related` cho quan hệ ManyToMany. CẤM truy cập quan hệ ORM trong vòng lặp template/view mà không prefetch.
- **Atomic Transactions**: Sử dụng `transaction.atomic()` cho mọi chuỗi thao tác ghi nhiều bảng liên quan để đảm bảo tính toàn vẹn ACID.
- **Database Indexing**: Khai báo tường minh `db_index=True` hoặc `Meta.indexes` cho các trường thường xuyên được lọc hoặc sắp xếp trong truy vấn.
- **QuerySet Chaining & Lazy Evaluation**: Tận dụng tính lười của QuerySet để ghép điều kiện lọc, chỉ kích hoạt query khi thực sự cần dữ liệu (`exists()`, `count()`, slicing).
- **Migration Hygiene**: CẤM sửa trực tiếp các file migration cũ đã áp dụng vào production. Mọi thay đổi schema đều phải tạo migration mới có thể rollback an toàn.

---

## 4. Express.js & NestJS (Node.js Enterprise Services)
- **NestJS Dependency Injection**: Tuân thủ nghiêm ngặt nguyên lý SOLID và kiến trúc Module / Controller / Service. Không tự ý khởi tạo instance bằng từ khoá `new`.
- **Validation Pipe**: Bật `ValidationPipe` toàn cục với các tuỳ chọn `{ whitelist: true, forbidNonWhitelisted: true, transform: true }` để tự động loại bỏ các trường không hợp lệ trong DTO.
- **Asynchronous Error Propagation**: Trong Express, luôn bọc middleware bất đồng bộ bằng wrapper hoặc dùng Express 5 để tránh nuốt unhandled promise rejections.
- **Security Middlewares**: BẮT BUỘC tích hợp `helmet`, `cors` có cấu hình whitelist domain cụ thể, và rate-limiting trên các endpoint nhạy cảm (auth, payment).
- **Graceful Shutdown**: Lắng nghe các tín hiệu `SIGTERM` và `SIGINT` để đóng server, giải phóng socket và hoàn tất các kết nối database đang chờ.

---

## 5. Go (Gin / Chi High-Throughput Microservices)
- **Context Propagation**: Mọi hàm xử lý I/O hoặc truy vấn mạng BẮT BUỘC nhận `ctx context.Context` làm tham số đầu tiên và tôn trọng tín hiệu huỷ `ctx.Done()`.
- **Goroutine Leak Prevention**: Tuyệt đối CẤM khởi chạy goroutine kiểu `go func() { ... }()` mà không có cơ chế dừng (Context, Channel tín hiệu dừng, hoặc `sync.WaitGroup`).
- **Buffered Channels & Deadlock Safety**: Định cỡ channel hợp lý. Không dùng unbuffered channel nếu không có consumer sẵn sàng đọc, tránh deadlock luồng.
- **Error Handling Discipline**: Luôn kiểm tra `if err != nil` ngay sau lời gọi hàm. Tuyệt đối CẤM bỏ qua lỗi bằng dấu gạch dưới `_`. Bọc lỗi bằng `fmt.Errorf("...: %w", err)` để bảo toàn stack trace.
- **Resource Pooling**: Sử dụng `sync.Pool` cho các đối tượng cấp phát thường xuyên (buffers, byte slices) để giảm tải cho bộ thu gom rác Go GC.

---

## 6. Rust (Actix-Web / Axum Systems Safety)
- **Clippy Pedantic Enforcement**: Toàn bộ mã nguồn phải vượt qua `cargo clippy -- -D clippy::pedantic` mà không có cảnh báo.
- **No Unwrap in Production**: TUYỆT ĐỐI CẤM gọi `.unwrap()` hoặc `.expect()` trên mã nguồn chạy sản xuất (trừ unit tests). Mọi lỗi phải được xử lý qua toán tử `?` và custom error enum sử dụng `thiserror`.
- **Zero-Cost Abstraction & Borrowing**: Ưu tiên mượn tham chiếu `&str`, `&[T]` thay vì clone heap allocations (`String`, `Vec<T>`).
- **RAII & Drop Semantics**: Tận dụng cơ chế tự giải phóng tài nguyên khi biến ra khỏi phạm vi. Đảm bảo locks (`tokio::sync::MutexGuard`) được thả càng sớm càng tốt trước điểm `await`.
- **Structured Async Runtime**: Sử dụng runtime `tokio` đa luồng, tránh các tác vụ tính toán nặng chặn luồng worker tokio; đẩy tác vụ CPU nặng sang `tokio::task::spawn_blocking`.

---

## 7. Spring Boot 3 (Java 21 Virtual Threads Enterprise)
- **Project Loom Virtual Threads**: Kích hoạt `spring.threads.virtual.enabled=true` trong `application.properties` để tận dụng hàng triệu luồng ảo Java 21 cho các tác vụ I/O chặn.
- **GraalVM Native Image Readiness**: Tránh dùng reflection không khai báo hoặc dynamic bytecode manipulation phức tạp để đảm bảo khả năng biên dịch AOT Native Image.
- **Declarative HTTP Interfaces**: Sử dụng tính năng `@HttpExchange` của Spring 6 thay vì `RestTemplate` lỗi thời.
- **Immutability with Java Records**: Định nghĩa DTO và Data Transfer Objects bằng Java `record` để bảo toàn tính bất biến và cú pháp tinh gọn.
- **Connection Pool Tuning**: Cấu hình HikariCP tối ưu (`maximumPoolSize`, `connectionTimeout`) phù hợp với số lượng luồng thực thi đồng thời.

---

## 8. PyTorch & CUDA (AI/ML Compute Core)
- **Inference Optimization**: Luôn bọc các khối suy luận (inference/evaluation) trong `with torch.no_grad():` hoặc decorator `@torch.inference_mode()` để giải phóng đồ thị gradient.
- **Device Management Hygiene**: Quản lý thiết bị tường minh (`device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')`). Đảm bảo tensors và model nằm trên cùng một thiết bị trước khi tính toán.
- **CUDA OOM Prevention**: Giải phóng bộ nhớ GPU sau các batch lớn bằng `torch.cuda.empty_cache()` và `gc.collect()`. Xử lý ngoại lệ `torch.cuda.OutOfMemoryError` có kịch bản giảm batch size tự động.
- **Mixed Precision Training/Inference**: Sử dụng `torch.autocast(device_type='cuda', dtype=torch.float16)` để tăng tốc độ tính toán gấp 2-3 lần và giảm 50% VRAM tiêu thụ.
- **DataLoader Multiprocessing**: Cấu hình `num_workers` hợp lý trong DataLoader và thiết lập `pin_memory=True` khi chuyển dữ liệu lên GPU.

---

## 9. Flutter (BLoC Pattern & Clean Mobile Architecture)
- **Unidirectional Data Flow**: Luồng dữ liệu một chiều nghiêm ngặt: `UI -> Event -> BLoC -> State -> UI`. UI chỉ gửi Events và lắng nghe States, không chứa logic nghiệp vụ.
- **Immutable States with Freezed**: Mọi State và Event BẮT BUỘC được định nghĩa bằng class bất biến, sử dụng package `freezed` và `equatable` để so sánh giá trị theo nội dung thay vì tham chiếu địa chỉ.
- **Separation of Concerns**: Phân chia rạch ròi 3 tầng: Presentation Layer (Widgets, Pages), Domain Layer (UseCases, Entities), Data Layer (Repositories, DataSources).
- **Const Constructors**: Sử dụng từ khoá `const` cho mọi Widget không thay đổi để kích hoạt cơ chế tối ưu hoá Virtual DOM của Flutter engine.
- **Resource Disposal**: Luôn ghi đè hàm `dispose()` trong StatefulWidget để huỷ bỏ các `StreamSubscription`, `TextEditingController`, `AnimationController`, chống rò rỉ bộ nhớ.

---

## 10. Docker & Kubernetes (Secure Cloud-Native Manifests)
- **Multi-Stage Scratch Builds**: Luôn sử dụng kỹ thuật multi-stage build để tách biệt môi trường build và môi trường chạy. Image cuối cùng chỉ chứa binary và runtime tối thiểu (alpine, distroless, hoặc scratch).
- **Non-Root Execution**: BẮT BUỘC tạo user và group riêng trong Dockerfile (`RUN adduser -D appuser && USER appuser`). TUYỆT ĐỐI CẤM chạy container dưới quyền `root`.
- **Read-Only Root Filesystem**: Cấu hình `securityContext.readOnlyRootFilesystem: true` trong Kubernetes Pod spec. Chỉ mount các thư mục tạm vào `emptyDir` có giới hạn kích thước bộ nhớ.
- **Resource Requests & Limits**: Mọi Pod spec BẮT BUỘC khai báo đầy đủ `resources.requests` và `resources.limits` cho cả CPU và RAM để bộ lập lịch Kubernetes phân bổ chính xác và chống tràn tài nguyên nút.
- **Zero Hardcoded Secrets**: Tuyệt đối CẤM truyền mật khẩu, token, API keys vào Dockerfile hoặc file YAML manifest thô. Sử dụng Kubernetes Secrets được mã hoá hoặc giải pháp Vault/ExternalSecrets.
