# TEAMWORK METHODOLOGY & PROMPT CRAFTING

> Phương pháp luận trích xuất từ `/teamwork-preview` của Antigravity áp dụng cho các dự án phần mềm doanh nghiệp.
> Agent chính **BẮT BUỘC ĐỌC** file này TRƯỚC KHI craft prompt cho subagent.

---

<core_principles>
## 1. BỐN NGUYÊN TẮC CỐT LÕI

| # | Nguyên tắc | Quy tắc |
|---|---|---|
| 1 | **Specify What, Not How** | Chỉ định nghĩa yêu cầu và tiêu chuẩn nghiệm thu. KHÔNG chỉ định chi tiết triển khai (tên file, kiến trúc, thuật toán, thư viện) TRỪ KHI Sếp yêu cầu rõ ràng. |
| 2 | **Objective Verification** | Mọi requirement phải có cơ chế kiểm tra độc lập, không phụ thuộc vào worker tự chấm. Kiểm tra lập trình (test, script) là tốt nhất; agent-as-judge với rubric cụ thể là chấp nhận được. |
| 3 | **Acceptance Criteria = Guardrails** | Tiêu chuẩn nghiệm thu đặt theo nhu cầu thực tế của Sếp. Mục đích: ngăn worker tự chứng nhận kết quả kém. Nếu lần chạy đầu chưa đạt, siết chặt tiêu chuẩn và chạy lại. |
| 4 | **Minimal Requirements** | Chỉ đặt yêu cầu mà Sếp thực sự cần. Nhiều requirement = nhiều ràng buộc = ít không gian cho worker tự xử lý. |
</core_principles>

---

<integrity_mode>
## 2. INTEGRITY MODE — Chống Worker Gian Lận

3 chế độ:

| Mode | Mô tả | Khi nào dùng |
|---|---|---|
| **development** (mặc định) | Worker KHÔNG được: copy code từ open-source cho logic cốt lõi, dùng thư viện sẵn cho chức năng chính, chạy script bên ngoài, đọc test source trước khi implement | Production code, task cần hiểu sâu logic |
| **demo** | Cho phép dùng thư viện/framework nhưng vẫn cấm đọc test trước | Demo, prototype, PoC |
| **benchmark** | Không giới hạn — worker dùng mọi cách | Đo hiệu suất tối đa |

**Cách xác định mode:** Hỏi Sếp câu hỏi hành vi ("Worker có được copy code không?"), KHÔNG hỏi "chọn mode nào".
</integrity_mode>

---

<verification_design>
## 3. VERIFICATION DESIGN BẮT BUỘC

Mỗi Requirement trong Prompt Draft PHẢI có verification method:

| Loại | Khi nào dùng | Ví dụ |
|---|---|---|
| **Programmatic** (ưu tiên) | Có thể tự động hóa | Bot scripts, benchmark, test suite với known I/O, metric scripts |
| **Agent-as-judge** | Khó tự động | Agent độc lập + rubric cụ thể đến mức 2 người chấm cho kết quả giống nhau |

### Verification Anti-patterns (CẤM):
| ❌ Pattern | Rủi ro |
|---|---|
| **Self-assessment** | Worker tự chấm bài của mình |
| **Tiêu chí mơ hồ** ("looks good", "seems correct") | Không thể bác bỏ |
| **Không có tiêu chí** | Worker tự tuyên bố hoàn thành sớm |
| **Ngưỡng quá cao** | Lãng phí vòng lặp |
</verification_design>

---

<acceptance_criteria_calibration>
## 4. ACCEPTANCE CRITERIA THEO MỤC ĐÍCH

| Mục đích | Mức độ |
|---|---|
| **Demo** | Ấn tượng nhưng khả thi trong ngân sách thời gian |
| **Production** | Phải khớp tiêu chuẩn chất lượng hệ thống đích |
| **Eval** | Chính xác và tái lập được — đo lường quan trọng hơn đánh bóng |
| **Exploration** | Lỏng — chỉ cần chứng minh khả thi |
</acceptance_criteria_calibration>

---

<prompt_draft_template>
## 5. PROMPT DRAFT TEMPLATE CHUẨN (NÂNG CẤP)

```markdown
# [Module: ActionProposals] Prompt Draft Template Mẫu

Triển khai API endpoint tạo và phê duyệt đề xuất hành động (Action Proposals) cho người dùng hệ thống.

Working directory: ${PROJECT_ROOT}
Integrity mode: development

## Requirements

### R1. Triển khai Endpoint Đề Xuất Hành Động
- **What:** Viết FastAPI endpoint POST `/api/v1/items/{id}/proposals` nhận thông tin đề xuất (báo giá, phương án, thời gian dự kiến), kiểm tra phân quyền người dùng sở hữu thực thể cha (chặn 403 IDOR nếu không có quyền sở hữu).
- **Verification:** `pytest tests/test_action_proposals_api.py -k "test_create_proposal"`

### R2. Tự Động Phê Duyệt & Ghi Nhận Cơ Sở Dữ Liệu
- **What:** Triển khai endpoint POST `/api/v1/proposals/{proposal_id}/approve` cập nhật trạng thái đơn thành `approved`, kích hoạt idempotent upsert dữ liệu.
- **Verification:** `pytest tests/test_action_proposals_api.py -k "test_approve_proposal"`

## Acceptance Criteria
- [ ] 100% tests trong `tests/test_action_proposals_api.py` PASS
- [ ] Bắt buộc trả về 403 Forbidden khi truy cập đề xuất của người dùng/tài khoản khác
- [ ] Không sinh rác (Zero-Garbage): Trả về `request_number = null` khi đơn ở trạng thái DRAFT
- [ ] Đạt chuẩn 0 trailing whitespace và `ruff check --fix` pass 100%

## Anti-patterns (Worker bị CẤM)
- ❌ Tự báo "xong" mà chưa chạy lệnh `pytest tests/test_action_proposals_api.py`
- ❌ Đọc test source code trước khi viết implementation
- ❌ Hardcode API token/service key trong source code
- ❌ Dùng tiêu chí mơ hồ ("looks good", "seems correct")

## Verification Resources
- `tests/test_action_proposals_api.py`
- `src/schemas/proposals.py`
```
</prompt_draft_template>

---

<nine_step_workflow>
## 6. QUY TRÌNH 9 BƯỚC CRAFT PROMPT (THAY THẾ /grill-me ĐƠN GIẢN)

| Bước | Tên | Mô tả |
|---|---|---|
| 1 | **Elicit Idea** | Hỏi Sếp muốn xây gì, mục đích (demo/production/eval), đối tượng sử dụng |
| 2 | **Identify Ambiguity** | Tìm điểm mơ hồ, đưa lựa chọn cụ thể cho Sếp chọn |
| 3 | **Integrity Mode** | Xác định mức độ nghiêm ngặt (development/demo/benchmark) |
| 4 | **Draft Requirements** | Viết 2-5 requirement blocks (R1, R2...), chỉ WHAT không HOW |
| 5 | **Design Verification** | Thiết kế cách kiểm tra cho mỗi requirement |
| 6 | **Set Acceptance Criteria** | Chuyển verification thành checklist pass/fail cụ thể |
| 7 | **Infrastructure Constraints** | Xác định ràng buộc hạ tầng (DB, API, network...) |
| 8 | **Choose Working Directory** | Chọn thư mục làm việc |
| 9 | **Assemble & Validate** | Tổng hợp, kiểm tra validation checklist, Sếp duyệt |

### Validation Checklist (Bước 9):
- [ ] Không có implementation hints (trừ khi Sếp yêu cầu)
- [ ] Mọi acceptance criterion đều checkable khách quan
- [ ] Requirements theo nhu cầu Sếp, không theo ý agent
- [ ] Kỹ sư giỏi sẽ KHÔNG cảm thấy bị ràng buộc quá mức
- [ ] Worker KHÔNG thể tự chứng nhận kết quả kém
</nine_step_workflow>

---

<anti_patterns>
## 7. ANTI-PATTERNS (CẤM TUYỆT ĐỐI KHI GIAO VIỆC)

| ❌ Anti-pattern | Tại sao |
|---|---|
| Truyền đường dẫn file thay vì copy nội dung | File có thể thay đổi sau khi launch |
| Launch subagent trước khi Sếp duyệt | Sếp phải xác nhận sẵn sàng |
| Bỏ qua tạo artifact/prompt_draft | Artifact là cửa sổ để Sếp nhìn vào prompt |
| Thêm implementation hints mặc định | Thu hẹp không gian giải pháp của worker |
| Worker tự báo "xong" không có verification | Premature self-certification |
</anti_patterns>
