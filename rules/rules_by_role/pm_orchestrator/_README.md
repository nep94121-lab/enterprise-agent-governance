# 👑 PM / Orchestrator Rulebook (7 Phase Gates 2026)

## 🎯 Mục Đích & Phạm Vi Trách Nhiệm
Thư mục này chứa toàn bộ quy tắc quản trị dự án, điều phối subagent, quy trình 7 Phase Gates tuần tự có cổng phê duyệt cứng, phương pháp luận Teamwork Prompt Crafting, quản lý thời gian (Timers), báo cáo tiến độ 2 tầng, và cơ chế kiểm soát chất lượng cho vai trò **PM / Project Orchestrator (Agent Chính)** trong các dự án phát triển phần mềm doanh nghiệp đa tác nhân.

## 📦 Danh Mục Tập Tin Quy Tắc
1. **`pm_governance_and_workflow.md`**:
   - Quy tắc cốt lõi của Agent chính: Tự làm vs Delegate, lựa chọn model (Flash 85% / Pro 15%), Dual-Pool Concurrency (Bể 1: 15–20 subagents song song, Bể 2: Micro-Queue Semaphore 2–3 slots).
   - Quy trình **7 Phase Gates tuần tự** (Discovery → Exploration → Questions & Edge Cases → Architecture Design → Implementation → Quality & Challenger → Summary & Handoff) với Exit Criteria nghiêm ngặt.
   - Cơ chế quản trị: Bảng trạng thái `GATE_STATUS.md`, chống dao động (Oscillation Guard) & nhật ký ngõ cụt (`dead_ends.md`), tự kế nhiệm (Succession Protocol tại 16 spawns).
   - Timer đếm ngược (1p/2p/3p) và báo cáo tiến độ 2 tầng (Subagent → PM → Sếp).
   - Quản trị đa phân hệ (Multi-PM Governance) với bộ 3 file mặc định + 4 file mở rộng, ranh giới ghi tệp độc quyền (Exclusive Write Ownership).
   - Định luật Goodhart và cơ chế kích hoạt "Giải thích đơn giản".
2. **`teamwork_and_prompt_crafting.md`**:
   - 4 Nguyên tắc cốt lõi: Specify What Not How, Objective Verification, Acceptance Criteria Guardrails, Minimal Requirements.
   - 3 Chế độ Integrity Mode (development, demo, benchmark).
   - Phương pháp kiểm chứng bắt buộc (Programmatic vs Agent-as-Judge) & Verification Anti-patterns.
   - Hiệu chuẩn Acceptance Criteria theo mục đích (Demo, Production, Eval, Exploration).
   - Quy trình 9 bước Craft Prompt chuẩn & Mẫu Prompt Draft Template nâng cấp.
   - 5 Anti-patterns bị cấm tuyệt đối khi giao việc.
3. **`quality_gates_and_lifecycle.md`**:
   - Vòng đời tiến trình: Dọn dẹp tiến trình khi xong việc (`<process_cleanup>`).
   - Tự động xin quyền hàng loạt Turn 1 (`<auto_permissions>`).
   - Quản lý Token Google Workspace CLI (`<gws_token_management>`).
   - Cổng chất lượng (Quality Gates) & Cặp đôi đối kháng Inspector (Flash) + Challenger (Pro).
   - Quy tắc kiểm chứng đĩa thật: §27 (Scope Grep) và §28 (Empirical Git Diff).

## 📊 Ngân Sách Token (Token Budget)
- **Giới hạn tối đa cho phép:** ≤ 12,000 tokens per role
- **Mỗi file đơn lẻ:** Luôn ≤ 4,000 tokens
- **Thực tế đo lường:** Đạt 100% compliance ngân sách token

## 🚀 Hướng Dẫn Nạp Context
- **Khi nhận task mới từ Sếp:** Nạp `pm_governance_and_workflow.md` để khởi tạo 7 Phase Gates và `GATE_STATUS.md`.
- **Khi soạn Prompt Draft:** Nạp `teamwork_and_prompt_crafting.md` để áp dụng quy trình 9 bước và ranh giới ghi tệp.
- **Khi nghiệm thu / dọn dẹp:** Nạp `quality_gates_and_lifecycle.md` để kiểm tra diff thực tế (§28) và dọn sạch zombie processes.
