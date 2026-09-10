# 📦 QUY TẮC QUẢN TRỊ GIT & VỆ SINH REPOSITORY

> Quy tắc phân nhánh, quản lý commit, cấu hình danh tính lập trình viên và vệ sinh repository theo tiêu chuẩn Doanh nghiệp.

---

## 🚀 QUY TẮC ĐẨY CODE LÊN GIT (GIT PUSH RULE)

<git_push_rule>
# QUY TẮC PHÂN NHÁNH & ĐẨY CODE DOANH NGHIỆP (ENTERPRISE GIT PUSH POLICY)

Mỗi khi thực hiện đẩy code lên Git (`push` / `đẩy lên git`):
- **Xác định nhánh được phép:** Đọc danh sách nhánh được phép push từ file cấu hình dự án (`project-hooks.yaml` hoặc `governance.config.json`). Mặc định cấm đẩy trực tiếp lên các nhánh bảo vệ (`main`, `master`, `prod`, `production`, `release`).
- **Cấu hình danh tính commit:** Kiểm tra hoặc thiết lập cấu hình Git cục bộ (`user.name`, `user.email`) phù hợp với môi trường hoặc tài khoản dự án:
  ```bash
  git config --local user.email "${USER_EMAIL}"
  git config --local user.name "${USER_NAME}"
  ```
- **Lệnh thực thi đẩy code an toàn:** Đẩy lên đúng nhánh tính năng/dev được phép:
  ```bash
  git push origin <feature-branch>
  ```
</git_push_rule>

---

## 🧹 TIÊU CHUẨN DOANH NGHIỆP VỀ GIT & REPOSITORY HYGIENE

<code_quality_and_performance>
### 11. 📦 Quản Lý Git & Đẩy Code An Toàn (Safe Git Staging & Push)
*   **QUY TẮC:** Tuyệt đối không sử dụng `git add .` một cách thiếu kiểm soát để tự động gom các tệp nháp cục bộ, tệp log, tệp test tạm thời hoặc tệp chứa thông tin cấu hình nhạy cảm (như thư mục `scratch/`, tệp `.zip`, các file test API nháp) đẩy lên repository.
*   **Giải pháp:**
    - Luôn chạy `git status` trước khi stage để kiểm tra kỹ danh sách các tệp tin chuẩn bị commit.
    - Khai báo đầy đủ các thư mục nháp và tệp tin tạm (`scratch/`, `tmp/`, `*.zip`, `.env`) vào tệp tin `.gitignore` để tránh bị đẩy nhầm lên Git.
    - Chỉ commit và push các tệp tin mã nguồn chính thức được kiểm duyệt rõ ràng. Rà soát kỹ bảo mật của từng file mới thêm vào trước khi tiến hành đẩy code.

```bash
# Chuỗi lệnh Git Staging an toàn theo tiêu chuẩn Doanh nghiệp
git status
git add src/services/user_service.py tests/test_user_service.py
git commit -m "feat(user): implement secure user profile lookup with RLS"
git push origin <feature-branch>
```
</code_quality_and_performance>

---

<cicd_and_development_standards>
### 13. 🧹 Repository Hygiene & Format Code Bắt Buộc (Linter & Whitespace — Pre-Flight Tầng 4, 9)
*   Mọi agent TRƯỚC KHI tạo commit ĐỀU PHẢI chạy đồng thời `ruff check --fix` và `git diff --check`.
*   Cam kết đạt **0 trailing whitespace** và **0 dòng trống thừa ở EOF** trên toàn bộ các tệp tin (`.py`, `.md`, `.json`, `.sql`, `.yaml`).
*   Trong Markdown, cấm dùng cú pháp 2 dấu cách cuối dòng để xuống dòng (`  \n`), thay vào đó sử dụng thẻ `<br>` rõ ràng hoặc tách đoạn.

```bash
# Lệnh kiểm tra và tự động dọn dẹp format code trước khi commit
ruff check --fix src/ tests/
git diff --check
```

### 15. 📦 Cách Ly Nhật Ký Làm Việc (Local Logs)
*   Thư mục `activity_logs/` và các file báo cáo tạm thời (`scratch/`, `.bak`) là tài sản phục vụ ghi nhớ cục bộ của Sếp và AI. **TUYỆT ĐỐI CẤM** dùng `git add .` gom các file này đẩy lên nhánh remote (Github). Phải review kỹ qua `git status` trước khi commit.

### 29. 🛡️ Kiểm Toán Pháp Y .gitignore & Giữ Sạch Cây Thư Mục (Gitignore Collision Audit & Zero Workspace Pollution — Pre-Flight Tầng 0)
*   Khi tạo bất kỳ file dữ liệu mẫu, fixture cố định, baseline, assets hoặc schemas mới phục vụ kiểm thử: **BẮT BUỘC chạy `git check-ignore -v <files>`** để kiểm tra. Nếu bị pattern wildcard trong `.gitignore` chặn, **PHẢI thêm ngoại lệ `!<path>` tường minh vào `.gitignore`**.
*   Mọi test suite khi chạy sinh file báo cáo/file tạm **BẮT BUỘC phải ghi ra thư mục tạm** (`tmp_path` trong Pytest hoặc `os.tmpdir()` trong Node.js), **TUYỆT ĐỐI CẤM** ghi đè làm bẩn (dirty working tree) các file đang được track trong Git.

```bash
# Lệnh kiểm toán .gitignore cho file dữ liệu mẫu mới
git check-ignore -v tests/fixtures/sample_test_fixture.json
# Nếu bị ignore ngoài ý muốn, thêm vào .gitignore:
# !tests/fixtures/sample_test_fixture.json
```
</cicd_and_development_standards>
