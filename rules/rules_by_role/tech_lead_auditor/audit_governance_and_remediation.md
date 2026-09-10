# 🌍 QUY CHUẨN CODE REVIEW, SELF-HEALING ENGINE & QUẢN TRỊ KIỂM TOÁN

## 🌍 TIÊU CHUẨN CODE REVIEW QUỐC TẾ (BIG TECH & DORA STANDARDS)

> Được đúc kết từ quy chuẩn kỹ thuật của **Google Engineering Practices, Meta, Microsoft, Amazon, Palantir, Netflix & Uber**.

### 1. ⚡ Quy Chuẩn Kích Thước Pull Request (Micro-PRs / Stacked PRs):
- **Nguyên tắc:** PR càng lớn $\rightarrow$ Khả năng bỏ sót bug càng cao, thời gian review càng lâu, rủi ro xung đột nhánh càng lớn.
- **Tiêu chuẩn vàng:**
  - Kích thước lý tưởng: **$\le 100 - 300$ dòng code (LOC)** cho mỗi PR (không quá 400 LOC).
  - Phân tách theo mục tiêu đơn lẻ (Single Responsibility Principle):
    - *PR 1:* Sửa lỗi giao diện / CSS / Typos / Refactor thuần túy.
    - *PR 2:* Sửa logic nghiệp vụ Core / Backend API / Migrations.
    - *PR 3:* Tối ưu hiệu năng / Kịch bản kiểm thử mới.
  - Tuyệt đối tránh gom chung 1 PR khổng lồ vừa refactor, vừa dọn rác, vừa thêm tính năng mới.

### 2. 🤖 Tự Động Hóa 100% "Công Việc Của Máy" (Zero Manual Hygiene):
- Những việc sau **BẮT BUỘC phải để Tool/Script tự làm**, không bắt con người phải dùng mắt soi:
  - Linter & Formatting: Tự động format bằng Pre-commit Hook (`ruff`, `eslint`, `prettier`).
  - Migration Collision: Tự động check bằng script so sánh với `origin/main`.
  - Test Metrics: Tự động xuất bảng Markdown summary phân tách rõ `passed`, `skipped`.
- **Con người (Reviewer/Tech Lead)** chỉ tập trung vào: Kiến trúc hệ thống, Mô hình dữ liệu, Rủi ro bảo mật (PII, Auth), và Khả năng mở rộng (Scalability).

### 3. 🤝 Văn Hóa Code Review Tích Cực & Đối Kháng Lành Mạnh:
- **Phân loại rõ ràng:**
  - 🔴 **Blocker (Bắt buộc sửa):** Lỗ hổng bảo mật, xung đột migration, gãy logic nghiệp vụ cốt lõi, leak resource.
  - 🟡 **Non-blocker / Suggestion (Góp ý tham khảo):** Đặt tên biến dễ đọc hơn, refactor nhỏ (có thể làm ở PR sau).
- **Kèm giải pháp:** Khi chỉ ra lỗi, luôn đề xuất phương án giải quyết cụ thể (code snippet hoặc hướng khắc phục), không chỉ trích mơ hồ.

### 4. ⏱️ Thời Gian Review Chuẩn DORA (Review Velocity SLA):
- **Time-to-First-Review:** $\le 4 - 8$ giờ làm việc.
- **Time-to-Merge:** $\le 24$ giờ kể từ khi mở PR.
- Giúp chu kỳ CI/CD diễn ra liên tục, loại bỏ hoàn toàn tình trạng nhánh bị đóng băng (Stale Branch) do chờ review quá lâu.

---

## 🔄 VÒNG LẶP TỰ SỬA LỖI KÍN & PHẢN BIỆN ĐỐI KHÁNG (AUTONOMOUS CLOSED-LOOP SELF-HEALING ENGINE)

> 🔴 **NGUYÊN TẮC BẮT BUỘC:** Không được dừng lại hay nộp báo cáo cho Sếp khi còn bất kỳ lỗi nào (kể cả lỗi linter nhỏ nhất). Hệ thống phải tự động lặp chu trình sửa lỗi khép kín.

```
 ┌──────────────────────────────────────────────────────────────────────────┐
 │                               BẮT ĐẦU TASK                               │
 └─────────────────────────────────────┬────────────────────────────────────┘
                                       │
                                       ▼
 ┌──────────────────────────────────────────────────────────────────────────┐
 │ 🛠️ BƯỚC 1: WORKER THỰC THI CHỈNH SỬA CODE & TESTS                       │
 └─────────────────────────────────────┬────────────────────────────────────┘
                                       │
                                       ▼
 ┌──────────────────────────────────────────────────────────────────────────┐
 │ 🤖 BƯỚC 2: AUTOMATED GATEKEEPER (CI 10 TẦNG PRE-FLIGHT SCRIPT)           │
 │    - Chạy: Ruff Lint, Whitespace, Gitignore, Migrations, Unit Tests      │
 └─────────────────────────────────────┬────────────────────────────────────┘
                                       │
                      ┌────────────────┴────────────────┐
                      │ Có lỗi (Bất kỳ bước nào FAIL)?  │
                      └───┬─────────────────────────┬───┘
                          │                         │
                  [CÓ LỖI / BỊ FAIL]             [PASS 100%]
                          │                         │
                          ▼                         ▼
         ┌────────────────────────────────┐ ┌───────────────────────────────┐
         │ 🔁 TỰ ĐỘNG BẮT MÃ LỖI & SỬA LẠI │ │ 🔍 BƯỚC 3: QA INSPECTOR (FLASH)│
         │ - Worker phân tích Traceback   │ │ - Tự chạy lệnh soi dữ liệu    │
         │ - Sửa code/test ngay tại chỗ   │ │   thực tế trên đĩa (§28)      │
         │ - Quay lại Bước 2 chạy lại CI  │ └───────────────┬───────────────┘
         └────────────────────────────────┘                 │
                                                            ▼
                                            ┌───────────────────────────────┐
                                            │ 👥 BƯỚC 4: LEAD CHALLENGER PRO│
                                            │ - Phản biện, cố tìm lỗ hổng   │
                                            │   và ca biên sót              │
                                            └───────────────┬───────────────┘
                                                            │
                                           ┌────────────────┴────────────────┐
                                           │ Challenger tìm thấy lỗi/mâu thuẫn?│
                                           └───┬─────────────────────────┬───┘
                                               │                         │
                                       [CÓ ĐIỂM CHƯA CHẶT]       [VICTORY CONFIRMED]
                                               │                         │
                                               ▼                         ▼
                                   ┌───────────────────────┐ ┌───────────────────────┐
                                   │ 🔁 BẮT BUỘC QUAY LẠI  │ │ 🏆 NGHIỆM THU HOÀN TẤT│
                                   │ BƯỚC 1 ĐỂ SỬA DỨT ĐIỂM│ │ - Đẩy Git Commit      │
                                   │ (Vòng lặp không dừng) │ │ - Nộp báo cáo cho Sếp │
                                   └───────────────────────┘ └───────────────────────┘
```

### 1. Cơ chế Tự động Bắt Lỗi & Tự Sửa Ngay (Self-Healing Loop):
- Khi bất kỳ bước nào trong CI báo lỗi (Code 1 / Syntax Error / Assertion Error / Flake8 / Trailing Space):
  1. Trích xuất mã lỗi, file và dòng gây lỗi cụ thể.
  2. Worker phân tích Root Cause và chỉnh sửa dứt điểm tại chỗ.
  3. Tự động chạy lại toàn bộ quy trình CI từ đầu. Lặp lại chu trình cho đến khi **100% các bước đều xanh lá (All Green)**.

### 2. Quy Tắc Phê Duyệt Đồng Thuận 2 Chữ Ký (Inspector + Challenger):
- **QA Inspector (Flash):** Bắt buộc tự chạy command kiểm chứng trực tiếp trên đĩa, không chỉ đọc lại text của Worker.
- **Lead Challenger (Pro - High Reasoning):** Bắt buộc đối soát qua **5 Trục Soi Chiều Sâu** (Docstrings vs Code, Unhappy Paths & Failure Lifecycle, Cross-Platform Determinism, Anomaly Sanity Check, Test Authenticity). CẤM viết "LGTM" hoặc đóng dấu mộc cao su mà không thực hiện phân tích đối kháng.
- **Chỉ khi cả 2 cùng xác nhận `PASS + CONFIRMED`** và script Pre-Flight PASS 100% thì mới được phép bàn giao công việc cho Sếp.

---

## 📋 NGUYÊN TẮC XỬ LÝ CODE REVIEW & KIỂM TOÁN CODEBASE

<cicd_and_development_standards>
### 23. 📋 Liệt Kê Đầy Đủ Issues Từ Reviewer (Zero Issue Left Behind)
*   Khi đọc comment/review trên PR, PHẢI liệt kê **TẤT CẢ** vấn đề reviewer nêu ra thành checklist trước khi lên kế hoạch. Tuyệt đối KHÔNG được chọn lọc chỉ sửa một phần rồi bỏ sót phần còn lại. Mỗi issue phải có trạng thái: ✅ Đã fix / ⏳ Đang làm / ❌ Không sửa (kèm lý do). Auditor PHẢI đối chiếu checklist này với PR comments gốc để phát hiện issue bị bỏ sót.

### 27. 🔍 Quét Toàn Bộ Codebase Khi Sửa Thuật Ngữ / Docstring / Hằng Số (Comprehensive Scope Grep — Pre-Flight Tầng 4)
*   Khi sửa bất kỳ thuật ngữ, docstring, hằng số, schema hay tài liệu nào, **BẮT BUỘC phải `grep` toàn bộ codebase** để tìm sạch 100% mọi vị trí xuất hiện (bao gồm file gốc, hàm con, docstrings, schema, và tests).
*   **CẤM** chỉ sửa vị trí đầu tiên nhìn thấy (chống điểm mù *Partial Match Blind Spot*).

### 28. 🔍 Kiểm Chứng 100% Bằng Git Diff Thực Tế (Empirical Diff Verification — Pre-Flight Tầng 5)
*   Agent chính / PM / Auditor **KHÔNG ĐƯỢC** chỉ dựa vào báo cáo tóm tắt của subagent, inspector hay auditor.
*   **PHẢI TRỰC TIẾP** đọc và soi từng dòng `git diff` thực tế trên đĩa trước khi bàn giao báo cáo cho Sếp hoặc xác nhận hoàn thành task.
</cicd_and_development_standards>

---

## ⛔ NGUYÊN TẮC PHỦ QUYẾT NHỊ PHÂN (BINARY VETO RULES)

- **Quyền phủ quyết tuyệt đối:** Nếu Inspector phát hiện bất kỳ test nào fail, hoặc Challenger chỉ ra ít nhất 1 lỗi nghiêm trọng (Blocker/Medium/High) có script PoC chứng minh $\rightarrow$ **Task bị VETO ngay lập tức**.
- Cấm thỏa hiệp, cấm làm tròn số liệu, cấm bỏ qua lỗi với lý do "sẽ sửa sau".
- Chỉ khi đủ 2 chữ ký `PASS + CONFIRMED` và toàn bộ 10 tầng Pre-Flight đều xanh thì mới được phép merge code.
