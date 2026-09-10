# 🛡️ TIÊU CHUẨN AN TOÀN CHUỖI CUNG ỨNG & GHIM MÃ BĂM PHỤ THUỘC
## (SUPPLY CHAIN DEPENDENCY PINNING & INTEGRITY SPECIFICATION)

> 🔴 **MÃ TÀI LIỆU:** `RULE-SEC-P1-SUPPLY-CHAIN-01`
> 🏷️ **CẤP ĐỘ ƯU TIÊN:** **P1 (Quan Trọng / Doanh Nghiệp Bắt Buộc)**
> 🌐 **THAM CHIẾU QUỐC TẾ:** SLSA Level 3/4 (Supply-chain Levels for Software Artifacts), Sigstore Cosign, in-toto Specification, PEP 665 / pip Hashes, npm Subresource Integrity (SRI), OWASP Top 10 Software Component Vulnerabilities.
> 🎯 **PHẠM VI ÁP DỤNG:** Tất cả các vai trò phát triển mã nguồn có sử dụng thư viện bên ngoài: Backend Developer, Frontend Developer, DevOps & Security, Data/ML Engineer, Mobile App Developer.

---

## I. MÔ HÌNH ĐE DỌA CHUỖI CUNG ỨNG (SUPPLY CHAIN THREAT MODEL)

Trong kỷ nguyên phát triển phần mềm hiện đại, hơn 85% mã nguồn của một ứng dụng đến từ các thư viện mã nguồn mở bên ngoài (Open-Source Dependencies). Các cuộc tấn công chuỗi cung ứng nhắm vào tầng phụ thuộc đang gia tăng với tốc độ chóng mặt. Hệ thống quy định 4 vector đe dọa trọng yếu bắt buộc phải triệt tiêu:

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                     4 VECTOR TẤN CÔNG CHUỖI CUNG ỨNG PHỔ BIẾN                           │
├───────────────────────────────┬─────────────────────────────────────────────────────────┤
│ 1. Dependency Confusion       │ Đẩy package độc hại lên Public Registry (PyPI, npm)     │
│    (Xung đột định danh)       │ trùng tên với package nội bộ riêng của doanh nghiệp.     │
├───────────────────────────────┼─────────────────────────────────────────────────────────┤
│ 2. Typosquatting              │ Đặt tên package cố tình sai 1-2 ký tự so với package     │
│    (Đánh lừa lỗi gõ phím)     │ nổi tiếng (VD: requests vs reqeusts, pydantic-fast).    │
├───────────────────────────────┼─────────────────────────────────────────────────────────┤
│ 3. Account Hijacking          │ Chiếm đoạt tài khoản Maintainer trên PyPI/npm qua rò rỉ │
│    (Đoạt quyền Maintainer)    │ token hoặc Credential Stuffing để phát hành bản độc hại. │
├───────────────────────────────┼─────────────────────────────────────────────────────────┤
│ 4. Malicious Lifecycle Script │ Khai thác script cài đặt tự động (setup.py, npm         │
│    (Đoạt quyền khi cài đặt)   │ postinstall) để đánh cắp biến môi trường và SSH keys.   │
└───────────────────────────────┴─────────────────────────────────────────────────────────┘
```

---

## II. QUY CHUẨN GHIM MÃ BĂM CHO HỆ SINH THÁI PYTHON (PIP / UV / POETRY)

### 1. Nguyên Tắc Cốt Lõi: Ghim Mã Băm SHA256 Bắt Buộc (`--require-hashes`)
- Mọi tệp khai báo phụ thuộc chính thức (`requirements.txt`, `requirements-lock.txt`) dùng trong Production, Staging và CI/CD **BẮT BUỘC PHẢI CHỨA MÃ BĂM SHA256** của từng file bánh xe (`.whl`) và mã nguồn nén (`.tar.gz`).
- Lệnh cài đặt bắt buộc phải có cờ `--require-hashes`:
  ```bash
  pip install --require-hashes -r requirements.txt
  ```
- Khi cờ `--require-hashes` được bật:
  * `pip` sẽ từ chối tải bất kỳ package nào không có mã băm được khai báo sẵn.
  * `pip` tự động vô hiệu hóa việc tải đệ quy các dependencies phụ không được liệt kê tường minh trong file (ngăn chặn silent transitive dependency updates).

### 2. Cấu Trúc Tệp `requirements.txt` Chuẩn Ghim Hash
Mỗi dependency phải có ít nhất 1 hoặc nhiều mã băm tương ứng với các nền tảng phân phối (Windows, Linux, sdist):

```text
# ==============================================================================
# Enterprise Pinned Dependencies with SHA256 Hashes
# Generated via pip-compile --generate-hashes
# ==============================================================================

fastapi==0.115.0 \
    --hash=sha256:7b24345f17d3d8a7c64c78fa4bf805d7cb6a42767073169dc3b4f981b7e657c9 \
    --hash=sha256:bb145b23d57e3f890f9b5c39178ad8e61cb05f9cb256bfa099307d6438ee2e3d
pydantic==2.9.2 \
    --hash=sha256:d8291eb8158d60c4a45a322bb2b45cfc9b5d21ba7717466184f47dcfa64d081f \
    --hash=sha256:eb03c5132d7211bf7df38c5b05a6114138e4a90a2a5f57731215bbfcf2e6503c
uvicorn==0.30.6 \
    --hash=sha256:a2a912bb09c95b6a7b73812891334c9c228d423cf9e96df446e507204db9b977 \
    --hash=sha256:fc8ca152345bcfa9e67d26bb45df27d5bf636b13ec8fefcfbc4e578491c6eeb6
```

### 3. Quy Trình Tạo Mã Băm Tự Động (Lockfile Generation)
Tuyệt đối không gõ hash thủ công. Bắt buộc sử dụng các công cụ chuẩn hóa:
- **Dùng `uv` (Khuyến nghị cho tốc độ tối đa trên Windows 11):**
  ```bash
  uv pip compile pyproject.toml --generate-hashes -o requirements.txt
  ```
- **Dùng `pip-tools`:**
  ```bash
  pip-compile --generate-hashes requirements.in -o requirements.txt
  ```

### 4. Phòng Chống Tấn Công Dependency Confusion trên Python
- **CẤM TUYỆT ĐỐI** sử dụng cờ `--extra-index-url` mà không có namespace scoping. Khi dùng `--extra-index-url`, `pip` sẽ tìm kiếm trên cả 2 registry và tự động chọn phiên bản có số version cao hơn (kẻ tấn công có thể publish bản `99.9.9` trên PyPI công khai).
- Nếu sử dụng private repository nội bộ, bắt buộc cấu hình index duy nhất hoặc dùng `--index-url` trỏ về artifact proxy an toàn (như Nexus, Artifactory) có cơ chế phân quyền package namespace.

---

## III. QUY CHUẨN TOÀN VẸN CHO JAVASCRIPT / TYPESCRIPT (NPM / PNPM / YARN)

### 1. Cưỡng Chế Lệnh `npm ci` (Clean Install)
- Trong môi trường kiểm thử (CI), staging và production, **CẤM TUYỆT ĐỐI** chạy `npm install`.
- BẮT BUỘC sử dụng `npm ci`:
  * Đọc chính xác 100% từ `package-lock.json`.
  * Không bao giờ tự ý cập nhật `package.json` hay nâng version `^` hoặc `~`.
  * Nếu phát hiện bất kỳ sự không khớp nào giữa `package.json` và lockfile, `npm ci` lập tức thoát với lỗi.

### 2. Kiểm Tra Thuộc Tính Subresource Integrity (SRI) Trong Lockfile
- Mọi node trong `package-lock.json` (chuẩn lockfileVersion 2 hoặc 3) bắt buộc phải có thuộc tính `integrity` với thuật toán mã băm mạnh (tối thiểu `sha512`):
  ```json
  "node_modules/axios": {
    "version": "1.7.7",
    "resolved": "https://registry.npmjs.org/axios/-/axios-1.7.7.tgz",
    "integrity": "sha512-S4kL7XrjgBmSiNfV28UjwMYAxLiRe97ozsfoVKRx6UrI9R20qnz4wpKyYSgrupQot35n09lMgN/l7KAJb3ITBR==",
    "dependencies": { }
  }
  ```
- Nghiêm cấm xóa hoặc làm rỗng thuộc tính `integrity` để bypass lỗi tải gói.

### 3. Cấu Hình Tệp `.npmrc` An Toàn Bắt Buộc
Mỗi dự án Node.js / Next.js / React bắt buộc phải có tệp `.npmrc` tại thư mục gốc với các chỉ thị bảo mật:

```ini
# Chặn đứng thực thi mã độc qua lifecycle scripts khi cài đặt
ignore-scripts=true

# Cưỡng chế lưu chính xác phiên bản, không dùng ký tự ^ hoặc ~
save-exact=true

# Tự động quét kiểm toán lỗ hổng đã biết
audit=true

# Cưỡng chế bắt buộc HTTPS, cấm HTTP trần
strict-ssl=true
```

> ⚠️ **LƯU Ý VỀ `ignore-scripts=true`:** Một số thư viện C++ native (như `sharp`, `esbuild`, `sqlite3`) cần biên dịch lúc cài. Khi cần chạy script cài đặt cho thư viện hợp lệ, phải khai báo whitelist tường minh qua `pnpm.onlyBuiltDependencies` hoặc chạy lệnh build độc lập dưới sự kiểm soát của DevOps.

---

## IV. QUY CHUẨN CHO CÁC TECH STACKS KHÁC

### 1. Go Concurrency Stack
- Tệp `go.sum` là bắt buộc và phải được commit vào Git.
- Cấu hình biến môi trường an toàn:
  ```bash
  export GONOSUMDB=""
  export GOSUMDB="sum.golang.org"
  export GOPROXY="https://proxy.golang.org,direct"
  ```
- Chạy `go mod verify` để xác minh rằng không có module nào trong local cache bị sửa đổi trái phép so với checksum trong `go.sum`.

### 2. Rust Systems Stack
- Commit bắt buộc tệp `Cargo.lock`.
- Sử dụng `cargo-audit` trong CI/CD để kiểm tra các lỗ hổng đã công bố (RUSTSEC advisory database):
  ```bash
  cargo audit
  cargo verify-project
  ```

### 3. Mobile Flutter / Dart Stack
- Tệp `pubspec.lock` bắt buộc commit vào kho lưu trữ.
- Chạy lệnh kiểm tra tính toàn vẹn:
  ```bash
  flutter pub get --dry-run
  ```

---

## V. CƠ CHẾ PHÒNG VỆ CHỐNG TYPOSQUATTING & DEPENDENCY CONFUSION

### 1. Danh Sách Kiểm Tra Khi Thêm Package Mới (Pre-Install Checklist)
Trước khi thêm bất kỳ thư viện bên ngoài nào vào dự án, Kỹ sư (Worker) phải kiểm tra 5 tiêu chí sau:
1. **Tuổi đời package (Package Age):** Thư viện phải có tuổi đời trên public registry tối thiểu > 30 ngày (trừ các gói nội bộ).
2. **Số lượt tải xuống hàng tháng (Monthly Downloads):** Tối thiểu > 10,000 lượt tải (đối với package tiện ích phổ thông).
3. **Liên kết kho mã nguồn (Repository Link):** Có liên kết GitHub/GitLab chính thống, số stars và commit hoạt động thường xuyên.
4. **Kiểm tra khoảng cách Levenshtein (Typosquatting Check):** Tên package không được sai khác 1-2 ký tự so với các thư viện cốt lõi (`requests` vs `reqeusts`, `cryptography` vs `criptography`).
5. **Cấp phép phần mềm (License Compliance):** Thư viện phải có giấy phép tương thích thương mại (MIT, Apache 2.0, BSD). Tuyệt đối cấm các giấy phép copyleft nghiêm ngặt (GPL-3.0, AGPL) nếu dự án yêu cầu đóng mã nguồn nghiệp vụ.

### 2. Script Tự Động Quét Kiểm Thực Hashes (Pre-Push & CI Hook)
Đoạn mã Python kiểm tra tính toàn vẹn của `requirements.txt` trước khi triển khai:

```python
import sys

def verify_requirements_hashes(file_path: str) -> bool:
    with open(file_path, "r", encoding="utf-8") as f:
        lines = f.readlines()

    current_pkg = None
    has_hash = False
    missing_hashes = []

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        if "==" in line and not line.startswith("--hash"):
            if current_pkg and not has_hash:
                missing_hashes.append(current_pkg)
            current_pkg = line.split("==")[0].strip()
            has_hash = False

        if "--hash=" in line:
            has_hash = True

    if current_pkg and not has_hash:
        missing_hashes.append(current_pkg)

    if missing_hashes:
        print(f"[ERROR] Phát hiện packages thiếu mã băm SHA256: {missing_hashes}")
        return False

    print("[SUCCESS] 100% packages đã được ghim mã băm SHA256 hợp lệ.")
    return True

if __name__ == "__main__":
    req_file = sys.argv[1] if len(sys.argv) > 1 else "requirements.txt"
    if not verify_requirements_hashes(req_file):
        sys.exit(1)
```

---

## VI. BẢNG PHÂN BỔ TRÁCH NHIỆM VAI TRÒ (RESPONSIBILITY MAPPING)

| Vai Trò | Trách Nhiệm Cụ Thể Về Chuỗi Cung Ứng |
|---|---|
| **DevOps & Security** | Duy trì hook chặn lệnh cài package không hash, thiết lập private registry proxy, quản trị `.npmrc` và scan lỗ hổng CI/CD. |
| **Backend Developer** | Ghim hash SHA256 trong `requirements.txt`, khóa lockfile `go.sum` / `Cargo.lock`, kiểm tra typosquatting trước khi cài mới. |
| **Frontend Developer** | Duy trì `package-lock.json` với SRI sha512, dùng `npm ci`, bật `ignore-scripts=true` trong `.npmrc`. |
| **Data & ML Engineer** | Khóa phiên bản CUDA, PyTorch, Hugging Face models với hash SHA256, cấm tải trực tiếp weights chưa qua xác thực. |
| **Mobile App Dev** | Khóa `pubspec.lock` và CocoaPods `Podfile.lock`, xác thực signing certificate của bên thứ ba. |

---
*Tài liệu quy chuẩn được ban hành theo Kiến Trúc Doanh Nghiệp Cấp Cao. 100% các thành viên và Subagents bắt buộc tuân thủ không ngoại lệ.*
