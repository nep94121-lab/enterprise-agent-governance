# 🏛️ Tech Lead / Inspector / Forensic Auditor Rulebook

## 🎯 Mục Đích & Phạm Vi Trách Nhiệm
Thư mục này chứa toàn bộ các quy chuẩn kiểm tra giả lập Tech Lead (10-Tier Pre-Flight Audit), tiêu chuẩn Code Review quốc tế Big Tech (Google, Meta, Amazon, Netflix, Uber, Stripe, Palantir), 5 Trục Soi Chiều Sâu, Ma Trận 10 Trục Tư Duy Động, kiểm toán pháp y mã nguồn và cơ chế phê duyệt 2 chữ ký (`PASS + CONFIRMED`) dành riêng cho vai trò **Tech Lead / Inspector / Reviewer / Forensic Auditor**.

## 📦 Danh Mục Tập Tin Quy Tắc
1. **`tech_lead_pre_flight_10_tiers.md`**:
   - 10 Tầng Kiểm Tra Giả Lập Tech Lead (Tầng 0 đến Tầng 9) nguyên văn đầy đủ:
     - Tầng 0: Pháp y `.gitignore` & Zero Workspace Pollution (§29)
     - Tầng 1: Upstream Alignment & Migration Prefix Collision
     - Tầng 2: Adversarial Auth & Null-Safety (Chặn 401/403 tại gateway)
     - Tầng 3: Zero-Garbage & Realistic Data Flow (DRAFT ID = None, cấm optimistic che giấu lỗi)
     - Tầng 4: Scope Grep 100% codebase (§27)
     - Tầng 5: Soi từng dòng Git Diff & Honest Metrics (§28)
     - Tầng 6: Quét Secret & PII Sanitization (§1–§2)
     - Tầng 7: Async Lifecycle, Connection Pool & Resource Guard (§6, §8, §18)
     - Tầng 8: Manifest & Bundle Drift Prevention (§16)
     - Tầng 9: Automated CLI Pre-Flight Script & Phê duyệt 2 Chữ Ký
   - Quy chuẩn Micro-PRs ($\le 100-300$ LOC) & DORA Review SLA.
   - Vòng lặp tự sửa lỗi kín (Self-Healing Engine).
   - Checklist 12 hạng mục trước khi tạo PR (10-Tier PR Ready Checklist).
2. **`deep_inspection_and_forensics.md`**:
   - 5 Trục Soi Chiều Sâu (Docstring vs Code, Unhappy Paths, Cross-Platform LF/CRLF, Anomaly Sanity, Test Authenticity).
   - Bài học Định luật Goodhart & Chống bẫy Test Ngụy Tạo (Bogus Tests).
   - Ma Trận 10 Trục Tư Duy Động (Dynamic Scenario Generation).
   - Khung kiểm thử đột biến (Mutation Testing $\ge 90\%$).
   - Phản biện đối kháng Red Team (Bắt buộc PoC $\ge 2$ bugs Medium/High).
3. **`audit_governance_and_remediation.md`**:
   - §23 (Zero Issue Left Behind: Liệt kê 100% issues từ reviewer).
   - §27 (Comprehensive Scope Grep khi sửa thuật ngữ/hằng số).
   - §28 (Empirical Diff Verification: Đọc trực tiếp git diff trên đĩa).
   - Quy trình cặp đôi Inspector (Flash) + Challenger (Pro) & Binary Veto Rules.

## 📊 Ngân Sách Token (Token Budget)
- **Giới hạn tối đa cho phép:** ≤ 12,000 tokens
- **Mục tiêu tối ưu:** < 7,000 tokens
- **Thực tế đo lường (`cl100k_base`):** 9,392 tokens (4 files, đạt 78.3% ngân sách)
- **Mỗi file đơn lẻ:** Luôn ≤ 4,000 tokens (File lớn nhất: 3,189 tokens)
- **Toàn bộ hệ thống 6 vai trò:** 44,551 tokens

## 🚀 Hướng Dẫn Nạp Context
- **Khi chạy tiền kiểm tra PR / Kiểm toán toàn diện:** Nạp `tech_lead_pre_flight_10_tiers.md`.
- **Khi rà soát đối kháng sâu / Tìm ca biên / Chống gian lận test:** Nạp `deep_inspection_and_forensics.md`.
- **Khi xử lý PR Review comments / Nghiệm thu kết quả:** Nạp `audit_governance_and_remediation.md`.
