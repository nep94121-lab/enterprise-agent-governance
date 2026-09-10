# 🔬 5 TRỤC SOI CHIỀU SÂU, MA TRẬN 10 TRỤC & KIỂM TOÁN ĐỐI KHÁNG

## ⚖️ ĐỊNH LUẬT GOODHART & CHỐNG GIAN LẬN TRONG KIỂM THỬ

> 🔴 **BÀI HỌC XƯƠNG MÁU & ĐỊNH LUẬT GOODHART:**
> 1. *Khi một thước đo trở thành mục tiêu, nó không còn là thước đo tốt.* Nếu checklist cố định, AI sẽ "học vẹt" chỉ để đối phó pass 10 mục mà nghiệp vụ thật vẫn sai.
> 2. AI tự viết test rất dễ mắc bẫy **Test Ngụy Tạo (Bogus Tests)** hoặc tự bịa ra 2 lỗi vặt vãnh (typo, rename biến) để gian lận đủ chỉ tiêu.
> 3. Các subagent cùng 1 mô hình rất dễ mắc bẫy **Đóng Dấu Mộc Cao Su (Rubber-Stamping Echo Chamber)**.
>
> **Khi nào bắt buộc?** Mọi task liên quan: đo metrics, viết test suite (> 5 tests), sửa logic core, bảo mật, xử lý dữ liệu/API, sign-off hoặc mở Pull Request.

---

## 🔬 5 TRỤC SOI CHIỀU SÂU (DEEP INSPECTION AXES — CHỐNG RUBBER-STAMPING)

- 🔍 **Trục 1 (Đối chiếu Chéo Docstring & Spec vs Code Thật):**
  - Soi từng câu chữ trong docstrings/schemas/rules với từng dòng code trong `git diff`.
  - Bắt lỗi ngay nếu code vi phạm bất kỳ cam kết nào (VD: docstring cam kết cấm lưu raw response nhưng code lại lưu vào trường metadata).

- 💥 **Trục 2 (Soi Ca Thất Bại & Failure Lifecycles - Unhappy Paths):**
  - CẤM chỉ test Happy Path (luồng thành công thuận lợi).
  - Đặt câu hỏi đối kháng: *"Nếu mất mạng giữa chừng, DB timeout, tiến trình bị kill khi đang ghi file thì code ứng xử thế nào?"*.
  - Bắt lỗi ngay nếu phát hiện nuốt ngoại lệ `try...except logger.error` hoặc để trạng thái treo ở `RUNNING` thay vì chuyển sang `FAILED` kèm dọn rác.

- 🌐 **Trục 3 (Soi Tính Nhất Quán Đa Nền Tảng - Cross-Platform & Determinism):**
  - CẤM tin vào kết quả cục bộ chỉ chạy trên Windows.
  - Kiểm tra xem checksum SHA-256, đường dẫn POSIX `/`, và line endings `LF` có bị lệch khi chạy trên Linux CI không.
  - Bắt buộc mọi data generator/manifest phải chuẩn hóa `LF` (`.replace(b"\r\n", b"\n")`).

- 📈 **Trục 4 (Soi Biến Động Số Liệu Bất Thường - Anomaly Sanity Check):**
  - Khi một chỉ số chất lượng giảm đột ngột (như Mypy baseline errors giảm từ 95 về 0, hoặc coverage nhảy vọt 30%), BẮT BUỘC coi đó là Red Flag (Dấu hiệu bất thường).
  - Phải kiểm tra môi trường chạy lệnh có đủ dependencies không, tuyệt đối cấm dùng `--update` / `--fix` bừa bãi khi chưa chứng minh được nguyên nhân.

- 🧪 **Trục 5 (Kiểm Toán Tính Trung Thực Của Chính Bài Test - Test Authenticity):**
  - Đọc trực tiếp file test mới để đảm bảo test case không "thông đồng" assert cho một hành vi sai luật (Zero Self-Serving Assertions).
  - Bắt buộc test phải fail khi logic bị cố tình bóp méo.

---

## 🎭 MA TRẬN 10 TRỤC TƯ DUY ĐỘNG (DYNAMIC SCENARIO GENERATION)

*Không dùng 10 tiêu chí như một checklist cứng! 10 chiêu thức được chuyển hóa thành **10 Trục Thẩm Vấn Sáng Tạo**.*
- **Nguyên tắc Sáng tạo Độc bản:** Với mỗi task cụ thể, Challenger (model: `pro`) BẮT BUỘC tự suy luận và sinh ra **ít nhất 3–5 kịch bản quái dị, độc nhất vô nhị** (Unpredictable Edge Scenarios) phù hợp với ngữ cảnh nghiệp vụ đó (không lặp lại khuôn mẫu cũ).
- **Tiêu chuẩn Bất biến Nghiệp vụ (Business Invariants):** Thiết lập các quy tắc bất biến không thể bị phá vỡ (VD: Tiền không âm, bảo toàn số lượng tồn kho, schema chuẩn hóa) và kiểm chứng trực tiếp trên tập dữ liệu mẫu thật.

---

## 🧬 CHUẨN KIỂM THỬ ĐỘT BIẾN (MUTATION TESTING FRAMEWORK)

*Mục tiêu: Đảm bảo 100% test suite là test THỰC CHẤT, không có test giả mạo.*
- **Tầng 1 (Code Logic Inversion):** Đảo toán tử (`>` ↔ `<`, `==` ↔ `!=`, `and` ↔ `or`), hoán đổi hằng số biên (+1/-1). Test suite **bắt buộc phải FAIL (Kill the mutant)** khi logic bị bóp méo.
- **Tầng 2 (Fault & Exception Injection):** Chủ động tiêm lỗi giả lập (`TimeoutError`, `ConnectionRefusedError`, `None/Null` return, rỗng payload).
- **Tầng 3 (Industrial Tools & Mutation Score):** Tích hợp công cụ chuẩn công nghiệp (`mutmut` cho Python, `stryker` cho JS/TS). Chỉ số **Mutation Score phải đạt ≥ 90%** mới được nghiệm thu.

---

## 🛑 BỘ LỌC PHẢN BIỆN ĐỐI KHÁNG (RED TEAM CHALLENGER)

*Challenger (model: `pro`) BẮT BUỘC đóng vai KẺ PHÁ HOẠI (Red Team) và tuân thủ:*
1. 🌐 **Quét 4 Nhóm Kịch Bản Thực Tế:** Mạng/Timeout/429, Dữ liệu bẩn/Unicode dị tật, Concurrency/Race Condition, Failure Lifecycle/Dọn rác.
2. 🛑 **Bộ Lọc Chống Gian Lận Lỗ Hổng (Severity ≥ MEDIUM/HIGH):**
   - **Thang Điểm Tin Cậy (Confidence Scoring 0–100):** Đánh giá lỗ hổng qua công thức $C = S_{\text{repro}} + S_{\text{impact}} + S_{\text{evidence}} - P_{\text{assumption}}$.
   - **Ngưỡng Chặn PR (Threshold ≥ 80):** Chỉ các phát hiện đạt **Severity ≥ MEDIUM/HIGH** và **Confidence Score $\ge 80$** (làm sai lệch nghiệp vụ, phá vỡ dữ liệu, hỏng an ninh bảo mật, hoặc gây sập/treo hệ thống) mới được chặn PR / Request Changes.
   - **CẤM TUYỆT ĐỐI:** Không tính các lỗi hình thức vô nghĩa (typo comment, đổi tên biến, format code, thiếu docstring) thành lỗi chặn PR.
   - **Bắt buộc viết PoC (Proof of Concept) thực thi:** Challenger **CHỈ viết PoC scripts thực thi cho các phát hiện đạt Confidence Score $\ge 80$** (Pytest FAIL trước khi fix, PASS sau khi fix). Tuyệt đối cấm viết PoC giả tạo cho các giả định không chắc chắn ($C < 80$).
   - **Quy Trình Quyết Định:**
     * **0 phát hiện đạt $C \ge 80$:** Challenger **APPROVE** và xác nhận code sạch. Chuyển các điểm $< 80$ thành Advisory Notes.
     * **$\ge 1$ phát hiện đạt $C \ge 80$:** Challenger **REQUEST CHANGES** kèm PoC thực thi bắt buộc.
