# 🧪 ĐẶC TẢ KIỂM THỬ CHUYÊN NGHIỆP — MASTER TEST SPECIFICATION

<master_test_philosophy>
# MASTER TEST SPECIFICATION — PRE-MERGE / PRE-PRODUCTION

> **Mục đích:** Tài liệu đặc tả kiểm thử để AI tự phân tích codebase, requirements và sinh Test Case / Test Script tự động.
>
> **Nguyên tắc:** Không sinh test cho có. Triệt tiêu hoàn toàn tư duy "chạy KPI số lượng test" hoặc "ép chỉ tiêu số lượng bug". Mỗi bài test phải kiểm chứng một hành vi, business rule, failure mode hoặc rủi ro thực tế. Test phải có input rõ ràng, expected result rõ ràng và phải FAIL khi code vi phạm behavior cần bảo vệ.
>
> **Cách AI sử dụng tài liệu này:**
> 1. Đọc toàn bộ repository.
> 2. Đọc requirements, API contract, database schema, migrations, config, docs.
> 3. Liệt kê modules, endpoints, services, business flows, integrations và data flows.
> 4. Map từng requirement / business rule → test cases.
> 5. Sinh test theo 28 nhóm bên dưới.
> 6. Không tạo test trùng lặp chỉ để tăng số lượng; không tạo báo động giả (False Positives).
> 7. Ưu tiên Critical / High risk trước.
> 8. Nếu một mục không áp dụng, ghi `N/A` và lý do; không tự bịa test.
> 9. Test phải chạy được trên repository hiện tại hoặc ghi rõ dependency/test fixture còn thiếu.
> 10. Sau khi sinh test, phải kiểm tra mutation / failure injection ở các logic quan trọng để xác nhận test thực sự bắt được lỗi.
---
</master_test_philosophy>

<pre_merge_checklist>
# 24-ITEM PRE-MERGE CHECKLIST
Không merge vào `main` nếu bất kỳ điều kiện Critical nào FAIL.

## Required
- [ ] Requirements covered.
- [ ] Static analysis PASS.
- [ ] Unit PASS.
- [ ] Integration PASS.
- [ ] API PASS.
- [ ] E2E critical flows PASS.
- [ ] Error handling PASS.
- [ ] Edge cases PASS.
- [ ] Security PASS.
- [ ] Database/migration PASS.
- [ ] Performance threshold PASS.
- [ ] Regression PASS.
- [ ] Compatibility PASS nếu applicable.
- [ ] File/PDF PASS nếu applicable.
- [ ] AI/RAG/Agent evaluation PASS nếu applicable.
- [ ] Observability PASS.
- [ ] Backup/restore verified nếu data critical.
- [ ] Staging PASS.
- [ ] Smoke PASS.
- [ ] Code review APPROVED.
- [ ] CI PASS.
- [ ] Release candidate verified.
- [ ] Rollback plan verified.
- [ ] Production verification plan ready.
---
</pre_merge_checklist>

<test_case_schema>
# TEST CASE SCHEMA — AI PHẢI DÙNG

Mỗi test case được sinh phải có cấu trúc:

```yaml
id: TC-XXX
category: unit|integration|api|e2e|security|performance|...
priority: P0|P1|P2|P3
risk: critical|high|medium|low
requirement: REQ-XXX
module: module_name
title: "Tên test"
preconditions:
  - "..."
test_data:
  - "..."
steps:
  - "..."
expected_result:
  - "..."
cleanup:
  - "..."
automation: automated|manual|candidate
environment: local|ci|staging|production-safe
dependencies:
  - "..."
```
---
</test_case_schema>

<test_priority_levels>
# TEST PRIORITY LEVELS

## 1. Phân Cấp Ưu Tiên Test Case (Test Priority Levels)

### P0 — Critical
Nếu fail → KHÔNG MERGE / KHÔNG RELEASE.
Ví dụ:
- Login/authentication & Session token.
- Authorization & Multi-tenant boundary (`tenant_id`, `property_id`).
- Data corruption & Database migration failure.
- Payment / transaction & Financial state transitions.
- Critical business flow & Core entity creation.
- Critical Security vulnerability (IDOR, SQLi, RCE, RLS bypass).
- Production startup failure.

### P1 — High
Fail → thường không release nếu liên quan critical feature hoặc flow nghiệp vụ chính.

### P2 — Medium
Có thể release nếu đã documented, có kế hoạch vá và risk accepted.

### P3 — Low
Cosmetic / minor behavior, format hiển thị hoặc comment.

---

## 2. Tiêu Chí Phân Loại Defect Theo Confidence Scoring (0–100)
Đối với các phát hiện lỗi từ QA Challenger:
- **Confidence Score $\ge 80$ (Blocker / Request Changes):** Lỗi logic nghiệp vụ rõ ràng, rò rỉ dữ liệu, vi phạm tiêu chuẩn bảo mật (§1–§29). **BẮT BUỘC CHẶN MERGE PR** và viết PoC thực thi kiểm chứng.
- **Confidence Score $< 80$ (Advisory / Clarification / Cosmetic):** Vấn đề nhỏ, câu hỏi làm rõ hoặc phỏng đoán chưa đủ chứng cứ. **KHÔNG CHẶN PR**, chuyển thành danh mục khuyến nghị (Advisory Notes).
---
</test_priority_levels>

<test_quality_guardrails>
# TEST QUALITY RULES

AI KHÔNG ĐƯỢC:

- Ép chỉ tiêu số lượng bug giả tạo hoặc phóng đại lỗi nhỏ để kiếm KPI.
- Tạo báo động giả (False Positives) hoặc viết PoC cho các giả định mơ hồ ($C < 80$).
- Sinh test chỉ để tăng coverage mà không kiểm chứng hành vi.
- Test implementation detail không có business value.
- Copy/paste cùng một test với dữ liệu khác mà không tạo thêm giá trị.
- Mock toàn bộ dependency trong integration test.
- Chỉ test happy path.
- Chỉ kiểm tra HTTP 200 hoặc function không throw.
- Hard-code expected result sai với requirement.
- Bỏ qua failure path hoặc nuốt lỗi âm thầm.
- Bỏ qua authorization và ràng buộc đa tenant.
- Bỏ qua data integrity và transaction rollback.
- Bỏ qua concurrency ở flow có shared state.
- Bỏ qua rollback/migration khi database thay đổi.

AI PHẢI:

- Định lượng độ tin cậy của lỗi qua Confidence Scoring (0–100) trước khi đề xuất chặn PR.
- Chỉ viết script PoC thực thi cho các phát hiện đạt Confidence Score $\ge 80$.
- Ưu tiên rủi ro thực chất (Risk-based Testing).
- Trace test → requirement rõ ràng.
- Có positive + negative + boundary + unhappy paths.
- Test failure injection cho logic quan trọng.
- Kiểm tra expected result rõ ràng và bất biến nghiệp vụ.
- Giữ regression test cho bug đã phát hiện.
- Không tạo test flaky, đảm bảo tính tất định đa nền tảng.
- Test độc lập và repeatable, dọn dẹp sạch dữ liệu tạm sau test (§29).
- Báo rõ phần không thể test do thiếu environment/dependency.
---
</test_quality_guardrails>

<definition_of_done>
# DEFINITION OF DONE (DoD)

Một change chỉ được coi là READY FOR MAIN khi:

1. Requirement đã được xác định rõ ràng.
2. Test cases đã được sinh theo risk matrix.
3. Critical business flows có automated coverage phù hợp.
4. Unit/integration/API/E2E phù hợp đã PASS.
5. Negative/edge/error cases và Unhappy Paths đã được kiểm tra.
6. Security checks PASS (0 lỗ hổng §1–§29).
7. Database/migration đã được kiểm tra nếu có thay đổi.
8. Performance threshold đạt yêu cầu nếu change ảnh hưởng performance.
9. Regression suite PASS 100%.
10. Staging smoke test PASS.
11. CI PASS.
12. Code review PASS, QA Challenger xác nhận **0 lỗi đạt Confidence Score $\ge 80$**.
13. Rollback plan tồn tại và phù hợp.
14. Không còn P0/P1 defect chưa được chấp nhận.
15. Test report có đầy đủ bằng chứng chạy test trên môi trường thật.
---
</definition_of_done>

<test_generation_workflow>
# AI TEST GENERATION WORKFLOW

AI phải thực hiện theo thứ tự:

```text
Repository
   ↓
Requirements
   ↓
Architecture
   ↓
Modules
   ↓
API endpoints
   ↓
Database schema
   ↓
Business flows
   ↓
External integrations
   ↓
Risk analysis
   ↓
Test matrix
   ↓
Test cases
   ↓
Test scripts
   ↓
Run tests
   ↓
Analyze failures & Confidence Scoring (0-100)
   ↓
Fix/Report (PoC for Score >= 80)
   ↓
Re-run & Closed-loop re-audit
   ↓
Regression
   ↓
Final report
```

## Final report AI phải xuất

```text
Total requirements:
Total test cases:
Total automated tests:
Total manual tests:
Total scripts:
Passed:
Failed:
Skipped:
Blocked:
Coverage:
Critical flows covered:
Security tests:
Performance result:
Regression result:
Confidence Scoring findings (Score >= 80):
Advisory Notes (Score < 80):
Known issues:
P0 issues:
P1 issues:
Rollback status:
Final recommendation:
```

## Final recommendation chỉ được là một trong:

```text
READY_FOR_MAIN
NOT_READY_FOR_MAIN
READY_WITH_RISK_ACCEPTANCE
```

- Không được trả `READY_FOR_MAIN` nếu còn tồn tại phát hiện có Confidence Score $\ge 80$ hoặc P0 defect chưa được xử lý.
- Trả `NOT_READY_FOR_MAIN` (Request Changes) khi có ít nhất 1 lỗi đạt Confidence Score $\ge 80$ kèm PoC thực thi.
- Trả `READY_WITH_RISK_ACCEPTANCE` khi chỉ còn các phát hiện $C < 80$ (Advisory Notes) được ghi nhận và chấp thuận rủi ro.
---
</test_generation_workflow>

<test_counting_and_scoring>
# XIV. QUY TẮC ĐÁNH GIÁ SỐ LƯỢNG (TEST CASE COUNTING RULES)

Không được coi "đạt target số lượng" là đồng nghĩa với "đạt chất lượng". Triệt tiêu tư duy đếm số lượng test case để báo cáo thành tích.

Ví dụ:
API có 5 endpoints.
Không được tự tạo 120 test chỉ để đạt target API.
Phải phân tích:
5 endpoints × input variations × business rules × authentication × authorization × error conditions × boundary × security
Sau đó xác định số test thực tế cần thiết.

Ngược lại:
Nếu có 50 endpoints và nhiều business rules, không được chỉ tạo 40 API tests để đạt "minimum".
Phải tạo đủ test để cover behavior.

---

# XV. TEST QUALITY SCORE (ĐÁNH GIÁ CHẤT LƯỢNG BÀI TEST)

Mỗi test case phải được tự đánh giá theo 7 tiêu chí:
1. Requirement relevance (Tính liên quan yêu cầu)
2. Risk relevance (Tính liên quan rủi ro)
3. Input coverage (Độ bao phủ đầu vào)
4. Expected result clarity (Độ rõ ràng của kết quả mong đợi)
5. Failure detection capability (Khả năng phát hiện lỗi)
6. Automation feasibility (Khả năng tự động hóa)
7. Duplication (Tránh trùng lặp)

Chấm điểm:
- **A** = High quality (Chất lượng rất cao)
- **B** = Good (Tốt)
- **C** = Weak (Yếu — Tránh đưa vào automated suite nếu có thể cải thiện)
- **D** = Reject (Bị loại bỏ)

Mục tiêu: Đạt chất lượng kiểm thử ở mức A/B.
---
</test_counting_and_scoring>

<final_report_schema_and_precedence>
# XVI. FINAL TEST COUNT REPORT SCHEMA

Cuối cùng AI phải xuất báo cáo theo mẫu sau:

| Category | Target Min | Target Rec | Actual Generated | Automated | Manual | Executed | Passed | Failed | Skipped | Blocked | Quality A | Quality B | Quality C | Quality D |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Unit | 60 | 100-180 | ... | ... | ... | ... | ... | ... | ... | ... | ... | ... | ... | ... |
| Integration | 30 | 50-80 | ... | ... | ... | ... | ... | ... | ... | ... | ... | ... | ... | ... |
| ... | ... | ... | ... | ... | ... | ... | ... | ... | ... | ... | ... | ... | ... | ... |

Không được dùng số lượng để che giấu test chất lượng thấp.

---

# XVII. FINAL RULE (QUY TẮC TỐI CAO)

Ưu tiên theo thứ tự:
1. Correctness
2. Critical business behavior
3. Security
4. Data integrity
5. Error handling
6. Integration
7. Regression
8. Performance
9. Compatibility
10. Raw test count

Một test chất lượng cao có giá trị hơn nhiều test trùng lặp hoặc không có khả năng phát hiện lỗi.
</final_report_schema_and_precedence>
