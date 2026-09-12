# 🧪 SWE-BENCH REPRODUCTION PROTOCOL — QUY CHUẨN TÁI LẬP LỖI THỰC NGHIỆM
**Mã Quy Chuẩn:** `SPEC-SWE-BENCH-REPRO-2026`  
**Phiên bản:** `2.0.0 (Princeton SWE-bench Verified Standard)`  
**Cấp độ ưu tiên:** `P0 (CƯỠNG CHẾ TUÂN THỦ TRÊN TOÀN BỘ DEV VÀ QA WORKERS)`  
**Áp dụng:** Backend Developer, Frontend Developer, QA Challenger, Mobile App Developer, Tech Lead Auditor, Data/ML Engineer.

---

## I. TRIẾT LÝ CỐT LÕI: REPRODUCTION-FIRST INVARIANT

> 🔴 **BẤT BIẾN TÁI LẬP TRƯỚC TIÊN (REPRODUCTION-FIRST INVARIANT):**  
> **"KHÔNG CÓ BÀI TEST TÁI LẬP LỖI ĐỘC LẬP CHẠY THẤT BẠI (EXIT CODE != 0) $\rightarrow$ CẤM TUYỆT ĐỐI ĐỘNG TAY SỬA BẤT KỲ DÒNG MÃ NGUỒN SẢN PHẨM NÀO!"**

Trong quy trình phát triển phần mềm chuẩn mực của Đại học Princeton (SWE-bench Verified) và các hệ thống phát triển tự trị hàng đầu thế giới (Aider, Claude Code), hơn 70% các trường hợp "sửa xong đẻ ra bug mới" (regression) hoặc "sửa ảo giác" bắt nguồn từ việc lập trình viên sửa mã nguồn dựa trên phỏng đoán (guesswork) mà không có bằng chứng thực nghiệm.

Quy chuẩn này xóa bỏ hoàn toàn hiện tượng "sửa mò", thiết lập một hàng rào kỷ luật thực nghiệm khách quan: **Mọi lỗi kỹ thuật phải được chứng minh bằng một bài kiểm thử độc lập tái hiện chính xác thất bại trước khi được khắc phục.**

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                     VÒNG ĐỜI KHẮC PHỤC LỖI CHUẨN SWE-BENCH VERIFIED                    │
├────────────────────────────────────────────────────────────────────────────────────────┤
│ [1. Issue / Bug Report]                                                                │
│        │                                                                               │
│        ▼                                                                               │
│ [2. Viết Reproduction Test Độc Lập] ──► Chạy test: BẮT BUỘC THẤT BẠI (Exit Code != 0)  │
│        │                                (Bằng chứng thực nghiệm lỗi tồn tại)           │
│        ▼                                                                               │
│ [3. Phân Tích AST & Root Cause]     ──► Xác định nguyên nhân gốc rễ chính xác          │
│        │                                                                               │
│        ▼                                                                               │
│ [4. Sửa Mã Phẫu Thuật Tối Thiểu]    ──► Áp dụng Minimal Surgical Fix (Minimal Change)  │
│        │                                                                               │
│        ▼                                                                               │
│ [5. Chạy Lại Reproduction Test]     ──► BẮT BUỘC VƯỢT QUA (Exit Code == 0, 100% PASS)  │
│        │                                                                               │
│        ▼                                                                               │
│ [6. Chạy Toàn Bộ Test Suite Hồi Quy]──► 100% Regression Tests PASS (0 broken features) │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## II. 6 GIAI ĐOẠN THỰC THI BẮT BUỘC (6-PHASE EXECUTION PIPELINE)

### Giai Đoạn 1: Phân Tích Báo Cáo Lỗi & Cô Lập Phạm Vi (Issue Analysis & Scope Demarcation)
1. **Đọc hiểu hành vi mong đợi vs hành vi thực tế:**
   * *Hành vi thực tế (Actual Behavior):* Lỗi xảy ra là gì? Mã lỗi (Error Code), Stacktrace, hoặc kết quả sai lệch ở đâu?
   * *Hành vi mong đợi (Expected Behavior):* Kết quả trả về đúng chuẩn phải như thế nào?
2. **Xác định ranh giới ảnh hưởng (Blast Radius):**
   * Module nào chịu trách nhiệm? Những file nào liên quan trực tiếp?
   * Không suy đoán lan man sang các module không liên quan.

---

### Giai Đoạn 2: Xây Dựng Bài Test Tái Lập Độc Lập (Standalone Failing Reproduction Test)
1. **Quy tắc tạo tệp test tái lập:**
   * Tạo một tệp test riêng biệt, ví dụ: `tests/reproduce_issue_<id>.py` hoặc `tests/reproduce_<issue_name>.test.ts`.
   * Tệp test phải độc lập (self-contained), có khả năng chạy riêng rẽ mà không phụ thuộc vào toàn bộ test runner cồng kềnh nếu có thể.
2. **Yêu cầu kiểm thử thất bại (Mandatory Failure Verification):**
   * Chạy bài test vừa tạo bằng terminal command:
     ```bash
     pytest tests/reproduce_issue_123.py -v
     # HOẶC
     npm test -- tests/reproduce_issue_123.test.ts
     ```
   * **ĐIỀU KIỆN TIÊN QUYẾT:** Bài test **BẮT BUỘC PHẢI FAIL** (Exit code khác 0, `AssertionError`, hoặc exception đúng như mô tả trong issue).
   * Ghi lại nhật ký Stacktrace làm bằng chứng thực nghiệm ban đầu (Pre-fix Proof).
3. 🚨 **CẢNH BÁO KIỂM TOÁN PHÁP Y:** Nếu bài test chạy PASS ngay từ đầu $\rightarrow$ Bài test không tái lập đúng lỗi! Subagent cấm tiến hành sửa mã nguồn, phải viết lại bài test cho đến khi tái hiện đúng lỗi.

---

### Giai Đoạn 3: Phân Tích Nguyên Nhân Gốc Rễ (Root Cause Analysis - RCA)
1. Dựa trên Stacktrace và Traceback từ bài test thất bại ở Giai đoạn 2, lần theo call stack đến chính xác dòng mã nguồn gây lỗi.
2. Phân tích nguyên nhân:
   * Do thiếu kiểm tra điều kiện biên (Boundary Condition / Edge Case)?
   * Do sai lệch kiểu dữ liệu (Type Mismatch, NoneType handling)?
   * Do Race Condition hoặc Deadlock bất đồng bộ?
   * Do vi phạm hợp đồng dữ liệu (API Schema Contract drift)?

---

### Giai Đoạn 4: Sửa Mã Phẫu Thuật Tối Thiểu (Minimal Surgical Fix)
1. **Nguyên tắc Minimal Change Invariant (§3 Anti-Overengineering):**
   * Chỉ sửa đúng các dòng mã cần thiết để giải quyết nguyên nhân gốc rễ đã xác định ở Giai đoạn 3.
   * **CẤM TUYỆT ĐỐI:** Tự ý refactor lại toàn bộ file, đổi tên hàm công khai, thay đổi format styling các hàm không liên quan, hoặc viết thêm các tính năng "tương lai" không được yêu cầu.
2. Giữ nguyên toàn bộ cấu trúc docstring, type annotations và comments gốc nếu không bị ảnh hưởng.

---

### Giai Đoạn 5: Kiểm Chứng Lại Bài Test Tái Lập (Reproduction Verification)
1. Chạy lại chính xác bài test tái lập đã tạo ở Giai đoạn 2:
   ```bash
   pytest tests/reproduce_issue_123.py -v
   ```
2. **ĐIỀU KIỆN NGHIỆM THU CỐT LÕI:**
   * Bài test **BẮT BUỘC PHẢI PASS** với `exit code == 0`.
   * 100% assertions được thỏa mãn.
   * Không còn bất kỳ exception ngoài ý muốn nào.

---

### Giai Đoạn 6: Kiểm Thử Hồi Quy Toàn Diện (Full Regression Suite Execution)
1. Chạy toàn bộ test suite hiện có của module hoặc dự án:
   ```bash
   pytest tests/ -v
   # HOẶC
   npm run test
   ```
2. **ĐIỀU KIỆN TIÊN QUYẾT:**
   * 100% test cases cũ tiếp tục PASS (Zero Regression).
   * Không có bất kỳ tính năng cũ nào bị gãy đổ do bản vá mới.
3. Di chuyển bài test tái lập vào bộ test chính thức (nếu phù hợp) để đóng vai trò là bài kiểm thử hồi quy vĩnh viễn (Permanent Regression Test).

---

## III. 5 ĐIỀU CẤM KỴ TUYỆT ĐỐI (STRICT ZERO-TOLERANCE PROHIBITIONS)

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                        5 ĐIỀU CẤM TRỌNG TỘI TRONG TÁI LẬP LỖI                          │
├────────────────────────────────────────────────────────────────────────────────────────┤
│ 1. CẤM SỬA MÒ (GUESSWORK CODING)        │ Sửa mã nguồn khi chưa có reproduction test   │
│ 2. CẤM MOCK GIAN LẬN (MOCK CHEATING)    │ Mock đè logic cốt lõi hoặc assert True       │
│ 3. CẤM SỬA BÀI TEST ĐANG PASS           │ Làm yếu assertion để bài test dễ pass        │
│ 4. CẤM XÓA TEST CŨ (TEST SUPPRESSION)   │ Xóa hoặc comment-out test case cũ đang fail  │
│ 5. CẤM PHÁ VỠ PUBLIC INTERFACE          │ Tự tiện thay đổi chữ ký hàm của hệ thống     │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

1. **Cấm Mock Gian Lận (Mock Cheating):**
   * Không được sử dụng `unittest.mock` hoặc `jest.fn()` để thay thế logic nghiệp vụ đang cần kiểm tra, biến bài test thành vô nghĩa. Mock chỉ được phép dùng cho các I/O bên ngoài (gọi mạng HTTP, gửi email thật, third-party payment gateway).
2. **Cấm Hạ Thấp Tiêu Chuẩn Assertion (Assertion Dilution):**
   * Tuyệt đối không được đổi từ `assert result == {"status": "success", "data": expected}` thành `assert result is not None` hoặc `assert True` để né tránh lỗi logic.
3. **Cấm Xóa Test Cũ Đang Thất Bại:**
   * Nếu việc sửa code làm một bài test cũ bị fail, đó là dấu hiệu của **HỒI QUY LỖI (REGRESSION)**. Cấm xóa hoặc `@pytest.mark.skip` bài test đó; bắt buộc phải tinh chỉnh lại bản vá để cả test mới VÀ test cũ cùng PASS!

---

## IV. MẪU BÀI TEST TÁI LẬP CHUẨN MỰC (REPRODUCTION CODE TEMPLATES)

### 1. Mẫu Python (Pytest Standalone Reproduction Test)
```python
# tests/reproduce_issue_order_total.py
import pytest
from decimal import Decimal
from src.backend.services.order_service import calculate_order_total
from src.backend.models.order import OrderItem

def test_reproduce_order_discount_precision_loss():
    """
    TÁI LẬP LỖI: Khi áp dụng mã giảm giá 15% trên đơn hàng lẻ,
    hệ thống bị lỗi làm tròn Decimal dẫn đến sai lệch 1 cent.
    
    Expected: Tổng tiền sau giảm giá phải làm tròn theo chuẩn ROUND_HALF_UP.
    Bug Hiện Tại: Bị ép kiểu float thô gây mất chính xác.
    """
    items = [
        OrderItem(product_id="P1", price=Decimal("19.99"), quantity=3), # 59.97
        OrderItem(product_id="P2", price=Decimal("10.00"), quantity=1), # 10.00
    ] # Subtotal: 69.97
    discount_rate = Decimal("0.15") # 15% discount = 10.4955 -> 10.50
    
    # Thực thi hàm nghiệp vụ
    final_total = calculate_order_total(items, discount_rate=discount_rate)
    
    # Kỳ vọng chính xác: 69.97 - 10.50 = 59.47
    expected_total = Decimal("59.47")
    
    # Dòng assertion này BẮT BUỘC PHẢI FAIL trước khi sửa code
    assert final_total == expected_total, (
        f"Lỗi chính xác tiền tệ: Kết quả thực tế {final_total} "
        f"không khớp với kỳ vọng {expected_total}"
    )
```

---

### 2. Mẫu TypeScript / Vitest (Frontend & Node.js Reproduction Test)
```typescript
// tests/reproduce_auth_token_refresh.test.ts
import { describe, it, expect, vi } from "vitest";
import { AuthManager } from "../src/frontend/services/auth_manager";

describe("SWE-bench Reproduction: Auth Token Race Condition", () => {
  it("should queue concurrent requests during token refresh without 401 error", async () => {
    // TÁI LẬP LỖI: Khi nhiều API calls xảy ra cùng lúc khi access token hết hạn,
    // refresh token bị gọi 2 lần gây vô hiệu hóa token trên server.
    const authManager = new AuthManager({ autoRefresh: true });
    
    // Giả lập 3 requests đồng thời khi token hết hạn
    const req1 = authManager.authenticatedFetch("/api/user/profile");
    const req2 = authManager.authenticatedFetch("/api/user/orders");
    const req3 = authManager.authenticatedFetch("/api/user/settings");
    
    const results = await Promise.all([req1, req2, req3]);
    
    // Kiểm tra tất cả các request đều thành công 200 OK
    results.forEach((res, index) => {
      expect(res.status, `Request ${index + 1} thất bại với status ${res.status}`).toBe(200);
    });
    
    // Token refresh chỉ được kích hoạt đúng 1 lần duy nhất (Single-flight)
    expect(authManager.getRefreshCount()).toBe(1);
  });
});
```

---

## V. CƠ CHẾ KIỂM TOÁN PHÁP Y (FORENSIC AUDITING FOR REPRODUCTION)

Hội đồng kiểm toán (Lead Watchdog, QA Challenger, Tech Lead Auditor) sẽ kiểm toán pháp y tiến trình sửa lỗi của Worker thông qua các chốt chặn sau:

1. **Kiểm Tra Dấu Thời Gian Tệp (File Timestamp Forensics):**
   * Thời gian tạo và sửa tệp `reproduce_*.py` **PHẢI NẰM TRƯỚC** thời gian sửa đổi tệp mã nguồn nghiệp vụ `src/**`.
   * Mọi trường hợp sửa file mã nguồn trước rồi mới viết test sau đều bị tính là vi phạm quy chuẩn và bị đánh rớt.
2. **Kiểm Tra Lịch Sử Trajectory & Transcript Logs:**
   * Trong nhật ký `transcript.jsonl`, phải có lệnh gọi `run_command` chạy bài test tái lập với kết quả trả về là **THẤT BẠI (Exit code != 0)**.
   * Sau đó mới có các tool calls sửa file (`replace_file_content` / `write_to_file`).
   * Cuối cùng là lệnh `run_command` chạy lại bài test với kết quả trả về là **THÀNH CÔNG (Exit code == 0)**.
3. **Đánh Giá Tính Khách Quan Của Assertions:**
   * QA Challenger sẽ soi từng dòng assertion của bài test tái lập để đảm bảo không có mánh khóe qua mặt kiểm thử.

---

## VI. TIÊU CHÍ HOÀN THÀNH SỬA LỖI (DEFINITION OF BUG RESOLUTION DONE)

Một tác vụ sửa lỗi chỉ được cấp chứng chỉ nghiệm thu khi đạt đủ 6 tiêu chí:
- [x] **Có tệp Reproduction Test độc lập** phản ánh chính xác nội dung issue.
- [x] **Bằng chứng bài test đã FAIL (Exit code != 0)** trước khi sửa code được lưu lại rõ ràng.
- [x] **Bản vá tuân thủ Minimal Change Invariant** (không sửa quá 50 dòng mã không liên quan).
- [x] **Bài test tái lập đạt 100% PASS (Exit code == 0)** sau khi áp dụng bản vá.
- [x] **Toàn bộ Test Suite hồi quy (Regression Tests) của hệ thống đạt 100% PASS.**
- [x] **Không vi phạm bất kỳ điều cấm nào trong 5 Điều Cấm Kỵ Tuyệt Đối.**
