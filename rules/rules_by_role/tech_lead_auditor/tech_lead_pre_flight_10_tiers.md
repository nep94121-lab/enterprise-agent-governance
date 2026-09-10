# 🛡️ QUY TRÌNH KIỂM TRA GIẢ LẬP TECH LEAD 10 TẦNG (PRE-FLIGHT AUDIT)

> 🔴 **NGUYÊN TẮC CỐT LÕI:**
> - **CI của máy:** Chỉ kiểm tra *"Code có chạy được không, có đúng cú pháp không"*.
> - **Góc nhìn Tech Lead & Big Tech:** Kiểm tra *"Code có an toàn khi lên Production không, có gây xung đột hệ thống không, có lỗ hổng biên không, có trôi dạt dữ liệu không, và số liệu có trung thực không"*.
> - **BẮT BUỘC:** Mọi Agent/Lập trình viên trước khi nộp báo cáo hoàn thành hoặc tạo Pull Request (PR) đều PHẢI tự động chạy qua **Hệ Thống 10 Tầng Kiểm Tra Giả Lập Tech Lead (Tầng 0 đến Tầng 9)**.

---

## 🏛️ CHI TIẾT 10 TẦNG KIỂM TRA PRE-FLIGHT AUDIT

### 0. 🛡️ Tầng 0 (Gitignore Audit & Zero Workspace Pollution — §29)
- **Kiểm toán Pháp y `.gitignore` cho file mới:** Khi tạo file dữ liệu mẫu, fixture cố định, baseline, assets hoặc schemas mới phục vụ test: BẮT BUỘC chạy `git check-ignore -v <files>`. Nếu bị pattern wildcard chặn, PHẢI thêm ngoại lệ tường minh `!<path>` vào `.gitignore`.
- **Quét file bị ẩn:** Chạy `git status --ignored` trước khi mở PR để phát hiện file quan trọng bị Git ẩn ngầm.
- **Giữ sạch cây làm việc (Zero Workspace Pollution):** Mọi test suite khi chạy sinh file tạm/báo cáo BẮT BUỘC phải ghi ra thư mục tạm (`tmp_path` trong Pytest, `os.tmpdir()` trong Node.js). TUYỆT ĐỐI CẤM ghi đè làm bẩn (dirty working tree) file track trong Git. Lệnh `git status --porcelain` sau khi chạy test phải hoàn toàn rỗng.

```bash
# Lệnh kiểm tra Tầng 0
git check-ignore -v tests/fixtures/baseline_residents.json
git status --ignored
git status --porcelain
```

### 1. 🗄️ Tầng 1 (Upstream Alignment & Migration Prefix Check)
- **Kiểm tra Upstream:** Luôn đối chiếu nhánh hiện tại với nhánh chính: `git fetch origin main`.
- **Chống trùng lặp Migration:** Quét toàn bộ tiền tố thời gian/số thứ tự file migration mới (SQL, Prisma, Alembic, Flyway, Supabase). CẤM 100% việc trùng lặp tiền tố với bất kỳ file nào đã tồn tại trên upstream `main`.
- **Version Bump & Configuration Drift:** Đảm bảo version không bị tụt lùi so với upstream; mọi biến môi trường mới phải có giá trị mẫu trong `.env.example`.

```bash
# Lệnh kiểm tra Tầng 1
git fetch origin main
git log origin/main..HEAD --oneline
ls migrations/
```

### 2. 🛡️ Tầng 2 (Adversarial Auth & Null-Safety)
- **Thắt chặt Auth/Middleware:** Mọi tham số định danh (`tenant_id`, `property_id`, `user_id`, `organization_id`, `account_role`) khi bị `None`, chuỗi rỗng `""` hoặc thiếu trong token/session PHẢI chặn ngay lỗi `401 Unauthorized` hoặc `403 Forbidden` tại cửa vào.
- **Cấm gán None ngầm:** CẤM gán giá trị mặc định `None`/`null` để request đi tiếp vào Controller/Service/Database gây lỗi `NOT NULL constraint` hoặc mất bộ lọc phân vùng dữ liệu.
- **Test đối kháng bắt buộc:** Bắt buộc có 1–2 test cases kiểm tra truyền dữ liệu rỗng/sai để xác nhận lỗi 401/403 kích hoạt đúng.

### 3. 🧹 Tầng 3 (Zero-Garbage & Realistic Data Flow)
- **Zero-Garbage ở trạng thái tạm:** Khi ở trạng thái nháp DRAFT / PREVIEW / VALIDATION FAIL, TUYỆT ĐỐI KHÔNG sinh mã định danh nghiệp vụ ảo (`order_number`, `request_number = None`, `invoice_id = None`) khi bản ghi chưa thực sự ghi vào DB. 0 file nhị phân rác tải lên Storage, 0 bản ghi rác ghi xuống DB nếu giao dịch chưa hoàn tất.
- **Cấm Optimistic che giấu lỗi:** Client không được hiển thị trạng thái ảo thành công trước khi Backend xác nhận.

### 4. 🔍 Tầng 4 (Scope Grep — §27)
- **Quét sạch toàn bộ codebase:** Khi thay đổi bất kỳ logic nghiệp vụ, enum, docstring, hằng số: BẮT BUỘC dùng lệnh `grep` toàn bộ repo (`src/`, `tests/`, `docs/`, `scripts/`) để tìm sạch 100% mọi vị trí xuất hiện.
- **Chống điểm mù Partial Match:** CẤM chỉ sửa 1-2 vị trí đầu tiên nhìn thấy. Cập nhật đồng bộ tài liệu kiến trúc đi kèm.

```bash
# Lệnh quét sạch codebase chống điểm mù Partial Match
grep -rn "OLD_STATUS_NAME" src/ tests/ docs/
```

### 5. 📊 Tầng 5 (Empirical Diff & Honest Metrics — §28)
- **Đọc trực tiếp Git Diff:** Agent chính / PM / Auditor PHẢI tự chạy và đọc từng dòng `git diff origin/main...HEAD` (hoặc `git diff`) trên đĩa trước khi nghiệm thu. Cấm chỉ dựa vào báo cáo tóm tắt.
- **Minh bạch số liệu kiểm thử:** Phân tách rõ ràng: Tests PASS, Tests SKIPPED (kèm lý do kỹ thuật rõ ràng per §20), và Tests FAILED (=0). Cấm làm tròn số hay báo cáo mập mờ.

```bash
# Lệnh kiểm chứng Diff thực tế trên đĩa
git diff origin/main...HEAD
pytest tests/ -v
```

### 6. 🔏 Tầng 6 (Secret & PII Sanitization — §1–§2)
- **Quét Secret tự động:** Chạy regex quét API Keys, Tokens, Passwords, Connection Strings, Private Keys trước khi commit. Nạp qua `pydantic-settings` và `.env` đã được ignore (§2).
- **Vệ sinh PII:** Cấm log raw base64 chữ ký, ảnh chụp, CCCD/CMND, SĐT, email (§1). Áp dụng masking (`***-***-1234`) hoặc chỉ log độ dài chuỗi (`signature_length = len(raw_sig)`).

```bash
# Lệnh quét regex secrets và key nhạy cảm
grep -rnE "(AIza[0-9A-Za-z-_]{35}|eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}|password\s*=\s*['\"][^'\"]+)" src/
```

### 7. ⚡ Tầng 7 (Concurrency & Resource Leak Guard — §6, §8, §18)
- **Async Lifecycle Safety (§6):** Cấm gọi `asyncio.run()` trong event loop đang chạy; dùng `await` hoặc `loop.run_in_executor()`.
- **Connection Pooling (§17):** Khởi tạo client mạng một lần duy nhất ngoài vòng lặp, tái sử dụng qua Connection Pooling.
- **Context Manager An Toàn (§8, §18):** Bọc stream, socket, file trong `with` / `async with`. Cẩn trọng khi xuất buffer ra ngoài context manager.

### 8. 🔄 Tầng 8 (Submodule & Bundle Manifest Drift — §16)
- **Đồng bộ hóa 1:1:** Khi file dữ liệu tự sinh (JSON, CSV, Generated Schemas) thay đổi, script sinh ra nó BẮT BUỘC phải được cập nhật đồng thời trong cùng một PR.
- **Kiểm tra Checksum Tái Sinh:** Chạy lại script sinh data và đối chiếu `git diff`. Báo lỗi `ManifestDriftDetectedError` chặn merge nếu có sai lệch giữa Checksum Tái Sinh và manifest.

```bash
# Tái sinh bundle và kiểm tra tính toàn vẹn
python scripts/generate_building_manifest.py
git diff --exit-code data/
```

### 9. 🤖 Tầng 9 (Automated Pre-Flight CLI & Phê Duyệt 2 Chữ Ký)
- **CLI Pre-Flight Script:** Chạy script tự động `python scripts/check_tech_lead_preflight.py` thẩm định Tầng 0 (gitignore), Tầng 1 (upstream), Tầng 4 (hygiene/linter), Tầng 6-8 (secrets/manifest).
- **Phê duyệt Đồng thuận 2 Chữ Ký:** QA Inspector (Flash) kiểm chứng 100% test pass trên đĩa + Lead Challenger (Pro) rà soát qua **5 Trục Soi Chiều Sâu** (Docstring vs Code, Unhappy Paths, Cross-Platform LF, Anomaly Sanity, Test Authenticity per `deep_inspection_and_forensics.md`). Cấm tuyệt đối rubber-stamping. Phê duyệt đủ 2 chữ ký `PASS + CONFIRMED`.

```bash
# Lệnh chạy toàn bộ 10 tầng tự động
python scripts/check_tech_lead_preflight.py
```

---

## 🎯 CHECKLIST TRƯỚC KHI TẠO PULL REQUEST (10-TIER PR READY CHECKLIST)

- [ ] **Tầng 0:** Đã chạy `git check-ignore -v` cho mọi file fixture/baseline mới (0 file bị nuốt ngầm), test suites dùng `tmp_path` (0 làm bẩn repo).
- [ ] **Tầng 1:** Đã `git fetch origin main`, 0 file migration trùng prefix/timestamp, 0 conflict upstream.
- [ ] **Tầng 2:** Mọi dependency Auth/Context đều chặn `401/403` khi thiếu ID định danh (không lọt `None`).
- [ ] **Tầng 3:** Đơn nháp DRAFT / lỗi trả về `request_number: None`, 0 rác lưu trữ (Zero-Garbage).
- [ ] **Tầng 4:** Đã `grep` toàn bộ codebase, sửa sạch 100% docstrings/enums/hằng số liên quan (§27).
- [ ] **Tầng 5:** Đã đọc trực tiếp `git diff` trên đĩa, báo cáo số lượng tests `passed` và `skipped` minh bạch 100% (§28).
- [ ] **Tầng 6:** Đã quét sạch regex API Keys, Passwords, Tokens; 0 log raw base64 chữ ký/ảnh PII (§1–§2).
- [ ] **Tầng 7:** Không gọi `asyncio.run()` trong event loop; context manager `with` đóng mở an toàn (§6, §8, §18).
- [ ] **Tầng 8:** Checksum giữa data generator và manifest file khớp 100%, không xảy ra bundle drift (§16).
- [ ] **Tầng 9:** Kịch bản CLI Pre-Flight tự động báo PASS 100% + Đã có đủ 2 chữ ký phê duyệt qua **5 Trục Soi Chiều Sâu** của Inspector và Challenger.
- [ ] **Vòng lặp Self-Healing:** Đã tự động chạy và pass 100% toàn bộ quy trình CI Gatekeeper không còn lỗi.
- [ ] **Chuẩn PR:** Kích thước PR gọn gàng ($\le 300$ LOC), tập trung đúng phạm vi, có mô tả rõ ràng.
