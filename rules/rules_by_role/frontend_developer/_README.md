# 🎨 Frontend / UI Developer Rulebook

## 🎯 Mục Đích & Phạm Vi Trách Nhiệm
Thư mục này chứa toàn bộ các tiêu chuẩn lập trình Frontend (React/TypeScript), nguyên tắc quản lý State và Virtual DOM, phòng chống tấn công XSS, sinh định danh mật mã an toàn (`crypto.randomUUID`), đồng bộ hóa bundle manifest, và bảo vệ luồng giao diện người dùng dành riêng cho vai trò **Frontend / UI Engineer**.

## 📦 Danh Mục Tập Tin Quy Tắc
1. **`frontend_coding_standards.md`**:
   - 6 điều khoản doanh nghiệp bắt buộc:
     - §4 (Cấu hình CORS & Headers bảo mật phía Client/Web)
     - §5 (Phòng chống XSS: Whitelist giao thức an toàn trong iframe, a href, img)
     - §9 (Quản lý State React & Cấm can thiệp DOM trực tiếp qua `document.getElementById`)
     - §10 (Tạo định danh an toàn bằng `crypto.randomUUID()`, cấm tự viết regex polyfill)
     - §13 (Repository Hygiene: Linter, 0 trailing whitespace, `<br>` trong Markdown)
     - §16 (Bundle Drift Prevention: Đồng bộ dữ liệu tĩnh và script tự sinh)
2. **`security_and_dom_guidelines.md`**:
   - Xử lý lỗi giao diện & Thông báo lỗi thân thiện (CSR Rule 5).
   - Xác thực dữ liệu Form đầu vào phía Client (CSR Rule 6).
   - 7-point Self-Check Checklist cho Frontend (CSR Rule 8).
   - Nguyên tắc Tech Lead Tầng 3: Cấm Optimistic UI che giấu lỗi Backend & Zero-Garbage khi ở trạng thái DRAFT.
   - Nguyên tắc Tech Lead Tầng 4: Scope Grep (§27) khi cập nhật enum/state giao diện.

## 📊 Ngân Sách Token (Token Budget)
- **Giới hạn tối đa cho phép:** ≤ 12,000 tokens
- **Mục tiêu tối ưu:** < 7,000 tokens
- **Thực tế đo lường (`cl100k_base`):** 3,604 tokens (3 files, đạt 30.0% ngân sách)
- **Mỗi file đơn lẻ:** Luôn ≤ 4,000 tokens (File lớn nhất: 1,482 tokens)
- **Toàn bộ hệ thống 6 vai trò:** 44,551 tokens

## 🚀 Hướng Dẫn Nạp Context
- **Khi xây dựng UI / Component / Hooks:** Nạp `frontend_coding_standards.md`.
- **Khi xử lý Form, Call API, Validate hoặc Render URL/File:** Nạp `security_and_dom_guidelines.md`.
