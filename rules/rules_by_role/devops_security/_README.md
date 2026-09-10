# 🛡️ DevOps / CI-CD / Security Engineer Rulebook

## 🎯 Mục Đích & Phạm Vi Trách Nhiệm
Thư mục này chứa toàn bộ các quy tắc quản trị Git repository, phân nhánh và commit discipline, quản trị bí mật hệ thống (Secrets Management), bảo vệ dữ liệu cá nhân (PII), cấp quyền tự động Turn 1, quản lý token Google Workspace CLI (`gws`), và cấu hình hạ tầng cơ sở dữ liệu dành riêng cho vai trò **DevOps / CI-CD / Security Engineer**.

## 📦 Danh Mục Tập Tin Quy Tắc
1. **`git_and_repository_hygiene.md`**:
   - Quy tắc Git Push Doanh nghiệp: Quản lý nhánh push theo cấu hình dự án, bảo toàn danh tính commit.
   - §11 (Safe Git Staging & Push: Cấm `git add .`, luôn kiểm tra `git status`).
   - §13 (Repository Hygiene: Chạy `ruff check --fix` + `git diff --check`, cam kết 0 trailing whitespace).
   - §15 (Local Logs Isolation: Thư mục `activity_logs/` và `scratch/` tuyệt đối không đẩy lên Git).
   - §29 (Kiểm toán pháp y `.gitignore` bằng `git check-ignore -v` & Zero Workspace Pollution với `tmp_path`).
2. **`secrets_and_pii_protection.md`**:
   - §1 (Bảo mật tuyệt đối thông tin PII, cấm log base64 chữ ký/sinh trắc học).
   - §2 (Quản lý bí mật qua biến môi trường `.env` và `pydantic-settings`).
   - §14 (Weak Key Guard: Không tùy tiện thay đổi fallback values cấu hình bảo mật).
   - CSR Rule 3 (Cẩm nang Secrets Management với class `Settings(BaseSettings)` và safe logging).
3. **`infrastructure_and_permissions.md`**:
   - Quản lý Token Google Workspace CLI (`<gws_token_management>`).
   - Tự động cấp quyền Turn 1 hàng loạt (`<auto_permissions>`).
   - Dọn dẹp tiến trình khi hoàn thành (`<process_cleanup>`).
   - Quy tắc kết nối cơ sở dữ liệu doanh nghiệp, nạp biến môi trường 100% qua DATABASE_URL (.env) (§1, §2).

## 📊 Ngân Sách Token (Token Budget)
- **Giới hạn tối đa cho phép:** ≤ 12,000 tokens
- **Mục tiêu tối ưu:** < 7,000 tokens
- **Thực tế đo lường (`cl100k_base`):** 5,058 tokens (4 files, đạt 42.1% ngân sách)
- **Mỗi file đơn lẻ:** Luôn ≤ 4,000 tokens (File lớn nhất: 1,400 tokens)
- **Toàn bộ hệ thống 6 vai trò:** 44,551 tokens

## 🚀 Hướng Dẫn Nạp Context
- **Khi thao tác Git, commit, tạo PR, cấu hình CI:** Nạp `git_and_repository_hygiene.md`.
- **Khi rà soát bảo mật, quét secret, kiểm tra PII:** Nạp `secrets_and_pii_protection.md`.
- **Khi thiết lập hạ tầng, token GWS, quyền thực thi, kết nối DB:** Nạp `infrastructure_and_permissions.md`.
