# 💥 PHẢN BIỆN ĐỐI KHÁNG, MUTATION TESTING & KIỂM TOÁN CHUYÊN SÂU

## 👥 CẶP ĐÔI ĐỐI KHÁNG & KHUNG THẨM ĐỊNH ĐỘNG

> 🔴 **BÀI HỌC XƯƠNG MÁU & ĐỊNH LUẬT GOODHART:**
> 1. *Khi một thước đo trở thành mục tiêu, nó không còn là thước đo tốt.* Việc ép chỉ tiêu số lượng cứng nhắc ("bắt buộc tìm ra $\ge 2$ lỗi") dẫn đến việc AI tự bịa lỗi vặt (typo, format) hoặc tạo báo động giả (False Positives).
> 2. AI tự viết test dễ mắc bẫy **Test Ngụy Tạo (Bogus Tests)** — test luôn pass mà không bắt được lỗi.
> 3. Các subagent cùng mô hình dễ rơi vào bẫy **Đóng Dấu Mộc Cao Su (Rubber-Stamping Echo Chamber)** khi duyệt chéo.

---

### 1. Ma Trận 10 Trục Tư Duy Động (Dynamic Scenario Generation)
*Không dùng checklist cứng! Chuyển hóa thành **10 Trục Thẩm Vấn Sáng Tạo**.*
- **Sáng tạo Độc bản:** Với mỗi task, Challenger (`pro`) BẮT BUỘC sinh **3–5 kịch bản quái dị, độc nhất vô nhị** (Unpredictable Edge Scenarios) theo ngữ cảnh nghiệp vụ.
- **Tiêu chuẩn Bất biến Nghiệp vụ (Business Invariants):** Thiết lập quy tắc bất biến không thể phá vỡ (chuyển trạng thái đơn, bảo vệ đa tenant `tenant_id` / `ownership_id`) và kiểm chứng trực tiếp trên dữ liệu thật.

---

### 2. Chuẩn Kiểm Thử Đột Biến Cấp Cao (Mutation Testing Framework)
*Đảm bảo 100% test suite là test THỰC CHẤT, không có test giả mạo.*
- **Tầng 1 (Code Logic Inversion):** Đảo toán tử (`>` ↔ `<`, `==` ↔ `!=`, `and` ↔ `or`), hoán đổi hằng số biên (+1/-1). Test suite **bắt buộc phải FAIL (Kill the mutant)** khi logic bị biến dạng.
- **Tầng 2 (Fault & Exception Injection):** Tiêm lỗi giả lập (`TimeoutError`, `ConnectionRefusedError`, `None/Null` return, payload rỗng).
- **Tầng 3 (Industrial Tools & Mutation Score):** Dùng `mutmut` (Python) hoặc `stryker` (JS/TS). **Mutation Score phải đạt ≥ 90%** mới được nghiệm thu.

```bash
# Lệnh chạy Mutation Testing với mutmut kiểm tra độ nhạy test suite
mutmut run --paths-to-mutate=src/services/repair_service.py --tests-dir=tests/
```

---

### 3. Adversarial Challenger Giả Lập Thực Tế & Chống Gian Lận (Red Team)
*Challenger (`pro`) đóng vai KẺ PHÁ HOẠI (Red Team), triệt tiêu ép KPI số lượng lỗi, tuân thủ:*

#### A. Hệ Thống Chấm Điểm Tin Cậy — Confidence Scoring (0–100)
Mọi phát hiện lỗi được định lượng qua thang điểm tin cậy $C$ (0–100):

$$C = S_{\text{repro}} + S_{\text{impact}} + S_{\text{evidence}} - P_{\text{assumption}}$$

- **1. $S_{\text{repro}}$ (Khả năng Tái hiện Tiên định — Max 40đ):**
  - **40đ:** Tái hiện tất định 100% bằng script test tự động (Pytest FAIL).
  - **25đ:** Tái hiện từng bước qua CLI / HTTP request thủ công.
  - **10đ:** Tái hiện gián tiếp qua phân tích luồng tĩnh (Static Analysis).
  - **0đ:** Suy đoán lý thuyết, không có payload cụ thể.
- **2. $S_{\text{impact}}$ (Mức độ Tác động Nghiệp vụ/Bảo mật — Max 30đ):**
  - **30đ:** Lỗ hổng bảo mật nghiêm trọng (IDOR, SQLi, Bypass RLS, lộ Secret, RCE), crash loop/OOM, hỏng toàn vẹn DB.
  - **20đ:** Sai lệch logic nghiệp vụ cốt lõi (tính sai tiền, duyệt sai trạng thái đơn, sai ràng buộc dữ liệu).
  - **10đ:** Ngoại lệ unhandled exception ở endpoint thứ cấp.
  - **0đ:** Lỗi hình thức, style, comment, docstring.
- **3. $S_{\text{evidence}}$ (Bằng chứng Đối chiếu Rules & Spec — Max 30đ):**
  - **30đ:** Vi phạm điều khoản cấm trong Rules (§1–§29) hoặc Spec contract, kèm stack trace + file location + input cụ thể.
  - **20đ:** Vi phạm tiêu chuẩn ngành hoặc tài liệu API design.
  - **10đ:** Vi phạm quy ước nội bộ / thiếu nhất quán code style.
  - **0đ:** Nhận định cảm tính / phong cách code cá nhân.
- **4. $P_{\text{assumption}}$ (Điểm Phạt Giả định Không Kiểm chứng — Max 20đ trừ):**
  - **-20đ:** Phỏng đoán lý thuyết không gắn với code thật, giả định sai môi trường, mock sai thư viện, data ảo.
  - **-10đ:** Thiếu kiểm tra điều kiện tiên quyết hệ thống.
  - **0đ:** Bằng chứng độc lập 100% trên code và môi trường thật.

---

#### B. Phân Tầng Điểm Số & Hành Động Hệ Thống

| Điểm ($C$) | Phân loại | Định nghĩa | Hành động |
| :-- | :-- | :-- | :-- |
| **0** | **False Positive** | Báo động giả, hiểu sai spec. | Bỏ qua hoàn toàn. |
| **25** | **Needs Investigation** | Nghi vấn mờ nhạt, thiếu chứng cứ. | Ghi Clarification Note, **KHÔNG chặn PR**. |
| **50** | **Minor / Cosmetic** | Lỗi format, comment, docstring phụ. | Ghi Clean-up Backlog, **KHÔNG chặn PR**. |
| **75** | **Important / Regression** | Lỗi logic ca biên, nguy cơ hồi quy. | Ghi Advisory Note khuyến nghị sửa, **KHÔNG chặn PR**. |
| **80** | **BLOCKING THRESHOLD** | Lỗi logic rõ ràng, sai dữ liệu, vi phạm §1–§29. | **CHẶN MERGE PR (REQUEST CHANGES)**. Worker sửa, Challenger re-audit. |
| **100** | **Critical / Crash** | Lỗ hổng bảo mật nghiêm trọng hoặc Crash chắc chắn 100%. | **HARD STOP TOÀN HỆ THỐNG**. Xử lý khẩn cấp. |

---

#### C. Bộ Lọc Chống Gian Lận & Quy Định PoC Thực Thi (Severity ≥ MEDIUM/HIGH)
1. **Bộ lọc Ngưỡng Chặn PR (Severity ≥ MEDIUM/HIGH & Confidence Score ≥ 80):**
   - Chỉ kích hoạt chặn PR khi phát hiện đạt **Severity ≥ MEDIUM/HIGH** VÀ **Confidence Score $\ge 80$**.
   - CẤM TUYỆT ĐỐI biến lỗi hình thức vô nghĩa thành blocker.
2. **Quy Định PoC Thực Thi (Selective PoC Runner):**
   - **Bắt buộc viết PoC (Proof of Concept) thực thi:** Challenger **CHỈ viết PoC scripts thực thi cho các phát hiện đạt Confidence Score $\ge 80$**.
   - **NGHIÊM CẤM:** Tuyệt đối cấm viết PoC giả tạo cho các giả định không chắc chắn ($C < 80$).
   - PoC là file Pytest gửi payload tấn công: Chạy trên code hiện tại là **FAIL** (chứng minh lỗi), sau khi Worker fix là **PASS** (chứng minh hết lỗi).
3. **Quy Trình Quyết Định:**
   - **0 phát hiện đạt $C \ge 80$:** QA Challenger **APPROVE** và xác nhận code sạch. Chuyển điểm $< 80$ thành Advisory Notes.
   - **$\ge 1$ phát hiện đạt $C \ge 80$:** QA Challenger **REQUEST CHANGES** kèm PoC thực thi bắt buộc.

```python
# PoC Red Team phát hiện lỗ hổng IDOR trên API duyệt đề xuất (Confidence = 90)
import pytest
from httpx import AsyncClient

@pytest.mark.asyncio
async def test_poc_idor_unauthorized_proposal_approval(app_client: AsyncClient):
    """PoC RED TEAM: Cư dân B duyệt đơn Cư dân A -> FAIL nếu trả 200 thay vì 403."""
    token_b = "Bearer eyJhbGciOi...resident_b_token"
    res = await app_client.post(
        "/api/v1/proposals/11111111-1111-1111-1111-111111111111/approve",
        headers={"Authorization": token_b},
        json={"notes": "Kẻ tấn công duyệt đơn người khác"}
    )
    assert res.status_code == 403, f"LỖ HỔNG IDOR! Status={res.status_code}"
```

---

### 4. Quy Trình Vòng Lặp Sửa Lỗi Khép Kín (Closed-Loop Re-Audit Loop)
```
[Worker hoàn thành code] ──► [Inspector (flash)] ──► [Challenger (pro) chấm Confidence Score]
                                                              │
                    ┌─────────────────────────────────────────┴─────────────────────────────────────────┐
                    ▼ (Điểm < 80: Không có blocker)                                                    ▼ (Có lỗi Confidence ≥ 80)
      [APPROVE & Xác nhận Code Sạch]                                                     [REQUEST CHANGES kèm PoC bắt buộc]
                    │                                                                                   │
                    ▼                                                                                   ▼
            [Sẵn sàng Merge PR]                                                                   [Worker sửa code]
                                                                                                        │
                                                                                                        ▼
                                                                                   [Challenger RÀ SOÁT LẠI TOÀN BỘ]
                                                                                                        │
                                                                                                        ▼
                                                                                   [PASS 100% Zero-Regression] ──► Merge PR
```
- **Quy tắc bắt buộc:** Challenger **CẤM viết "LGTM"** hoặc duyệt qua loa. Khi có lỗi $C \ge 80$ và Worker sửa xong, Challenger **PHẢI chạy lại toàn bộ test suite, PoC scripts và kịch bản giả lập từ đầu** để đảm bảo 0 lỗi hồi quy (Zero Regression).

---

### 5. 5 Trục Soi Chiều Sâu (Chống Rubber-Stamping)
- 🔍 **Trục 1 (Đối chiếu Chéo Docstring & Spec vs Code Thật):** Soi từng câu chữ trong docstring/spec với từng dòng code `git diff`. Bắt lỗi ngay nếu code vi phạm cam kết.
- 💥 **Trục 2 (Soi Ca Thất Bại & Failure Lifecycles - Unhappy Paths):** CẤM chỉ test Happy Path. Kiểm tra mất mạng, DB timeout, kill process; bắt lỗi nếu nuốt exception hoặc rò rỉ tài nguyên.
- 🌐 **Trục 3 (Soi Tính Nhất Quán Đa Nền Tảng - Cross-Platform & Determinism):** Kiểm tra checksum SHA-256, đường dẫn POSIX `/`, line endings `LF` (`.replace(b"\r\n", b"\n")`), UTF-8 trên Windows PowerShell.
- 📈 **Trục 4 (Soi Biến Động Số Liệu Bất Thường - Anomaly Sanity Check):** Sụt giảm baseline hoặc tăng vọt coverage là Red Flag; cấm làm tròn số liệu đo lường.
- 🧪 **Trục 5 (Kiểm Toán Tính Trung Thực Của Chính Bài Test - Test Authenticity):** Đọc trực tiếp file test mới, đảm bảo test không assert sai luật, không mock vô nghĩa (Zero Self-Serving Assertions).

---

<test_categories_index>
## DANH SÁCH 28 HẠNG MỤC KIỂM THỬ CHI TIẾT (TÀI LIỆU RULE CON)
- `00_test_governance.md` | `01_requirement_test.md` | `02_static_analysis.md` | `03_unit_test.md` | `04_integration_test.md`
- `05_api_test.md` | `06_e2e_test.md` | `07_error_handling_test.md` | `08_edge_case_test.md` | `09_security_test.md`
- `10_database_migration_test.md` | `11_performance_test.md` | `12_concurrency_test.md` | `13_regression_test.md`
- `14_compatibility_test.md` | `15_ui_ux_test.md` | `16_file_pdf_document_test.md` | `17_ai_rag_agent_test.md`
- `18_observability_test.md` | `19_backup_recovery_test.md` | `20_staging_test.md` | `21_smoke_test.md`
- `22_code_review_test.md` | `23_cicd_test.md` | `24_release_candidate_test.md` | `25_production_deployment_test.md`
- `26_production_verification_test.md` | `27_rollback_test.md` | `28_final_quality_gate.md`
</test_categories_index>
