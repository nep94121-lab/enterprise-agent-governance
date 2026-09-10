# 🧪 QA / Test Engineer / Challenger Rulebook

## 🎯 Mục Đích & Phạm Vi Trách Nhiệm
Thư mục này chứa toàn bộ các quy chuẩn kiểm thử chuyên nghiệp cấp doanh nghiệp, triết lý kiểm thử bắt buộc, bộ khung đánh giá chất lượng (Test Quality Score A/B/C/D), quy tắc cô lập môi trường (100% Mocking trong CI), ma trận 10 trục tư duy động, kiểm thử đột biến (Mutation Testing $\ge 90\%$) và cơ chế phản biện đối kháng (Red Team Challenger) với hệ thống **Confidence Scoring (0–100, ngưỡng chặn PR $\ge 80$)** dành riêng cho vai trò **QA / Test Engineer / Challenger**.

---

## 📦 Danh Mục Tập Tin Quy Tắc

1. **`test_philosophy_and_specifications.md`**:
   - Master Test Philosophy: Triệt tiêu KPI ép số lượng test/bug; 10 bước AI phân tích và sinh test thực chất.
   - Pre-merge Checklist 24 hạng mục bắt buộc trước khi merge vào `main`.
   - YAML Schema chuẩn hóa cho mọi test case.
   - Phân cấp ưu tiên Test Case (P0 Critical đến P3 Low) và Defect Confidence Scoring (0–100, threshold $\ge 80$).
   - Test Quality Guardrails: 14 điều AI CẤM & 11 điều AI PHẢI LÀM (chống tạo test rác & báo động giả).
   - Definition of Done (DoD) 15 tiêu chí nghiệm thu nghiêm ngặt.
   - Pipeline AI sinh test & Báo cáo đầu ra với 3 recommendation (`READY_FOR_MAIN`, `NOT_READY_FOR_MAIN`, `READY_WITH_RISK_ACCEPTANCE`).
   - Quy tắc đếm test (Counting Rules), chấm điểm chất lượng test (Score A/B/C/D) & 10 thứ tự ưu tiên tối cao.

2. **`testing_guardrails_and_isolation.md`**:
   - §12 (Tính trung thực trong đo lường, cấm Fake Adapter, đồng bộ dataset thật).
   - §19 (Tuân thủ Master Test Specification `TEST_CHUYEN_NGHIEP.md`).
   - §20 (Cô lập môi trường test: Mock 100% trong CI, Live test opt-in `RUN_LIVE_*`, `try...finally` dọn sạch 100% rác).
   - §21 (Cấm tuyệt đối test lặp & test dummy).
   - §22 (Đo lường Code Coverage trung thực bằng `pytest-cov`, cấm số liệu giả định).
   - §29 (Zero Workspace Pollution: Ghi file test tạm ra `tmp_path`, không làm bẩn git working tree).

3. **`adversarial_testing_and_metrics.md`**:
   - Danh mục 29 phân nhóm kiểm thử chuyên sâu (Mục 00 đến 28).
   - Ma Trận 10 Trục Tư Duy Động: Sinh 3–5 kịch bản quái dị độc bản per task.
   - Chuẩn Kiểm Thử Đột Biến (`mutmut` / `stryker`, Mutation Score $\ge 90\%$).
   - Adversarial Challenger (Red Team) với thang điểm **Confidence Scoring (0–100)**: Repro (0-40), Impact (0-30), Evidence (0-30), Speculative Penalty (-20).
   - **Ngưỡng chặn PR (Threshold $\ge 80$):** Chỉ phát hiện đạt $\ge 80$ mới được Request Changes. Nếu không có lỗi $\ge 80$, Challenger APPROVE và xác nhận code sạch.
   - **Selective PoC Runner:** CHỈ viết PoC scripts thực thi cho phát hiện đạt Confidence Score $\ge 80$. Cấm viết PoC cho phỏng đoán $< 80$.
   - Vòng lặp sửa lỗi khép kín (cấm viết "LGTM", re-audit toàn bộ từ đầu).
   - 5 Trục Soi Chiều Sâu (Chống Rubber-stamping): Docstrings vs Code, Unhappy Paths & Failure Lifecycle, Cross-Platform LF & UTF-8, Anomaly Sanity Check, Test Authenticity.

---

## 📊 Ngân Sách Token (Token Budget)
- **Giới hạn tối đa cho phép:** $\le 12,000$ tokens cho toàn bộ role `qa_challenger`.
- **Mục tiêu tối ưu:** $< 7,000$ tokens.
- **Mỗi file đơn lẻ:** Luôn $\le 4,000$ tokens.
- **Kiểm tra tự động:** `python count_tokens.py` xác nhận 100% tuân thủ ngân sách.

---

## 🚀 Hướng Dẫn Nạp Context
- **Khi thiết kế Test Plan & sinh Test Cases:** Nạp `test_philosophy_and_specifications.md`.
- **Khi viết kịch bản Pytest, Mocking, Live Sandbox:** Nạp `testing_guardrails_and_isolation.md`.
- **Khi đóng vai Challenger / Auditor phản biện, chạy Mutation test hoặc nghiệm thu:** Nạp `adversarial_testing_and_metrics.md`.
