# 🔑 BẢO VỆ DỮ LIỆU CÁ NHÂN (PII) & QUẢN TRỊ BÍ MẬT HỆ THỐNG

> Tiêu chuẩn bảo mật PII, phòng chống lộ lọt secrets, cấu hình JWT weak key guard và logging an toàn theo tiêu chuẩn Doanh nghiệp.

---

## 🔏 TIÊU CHUẨN DOANH NGHIỆP VỀ PII & SECRETS

<data_privacy_pii>
### 1. 🔏 Bảo Mật Tuyệt Đối Thông Tin Cá Nhân (PII Security — Pre-Flight Tầng 6)
*   **QUY TẮC:** Tất cả các thông tin cá nhân của người dùng (Họ tên, Số điện thoại, Email, Căn cước công dân/Hộ chiếu, Địa chỉ, hình ảnh Chữ ký, ảnh tài liệu đính kèm) phải được coi là dữ liệu nhạy cảm mức độ cao nhất.
*   **Không log dữ liệu thô:** Nghiêm cấm in ra console (phía client) hoặc ghi vào file log (phía server) nội dung thô (plaintext) của các chuỗi base64 chứa chữ ký, ảnh chụp, hoặc dữ liệu sinh trắc học của người dùng. Chỉ log độ dài ký tự hoặc trạng thái xử lý để tránh rò rỉ dữ liệu và phòng chống phình dung lượng lưu trữ log (storage bloat).
*   **Phân lập dữ liệu người dùng (Authorization):** Việc truy cập và thao tác dữ liệu phải được xác thực và kiểm tra phân quyền chặt chẽ thông qua ngữ cảnh thực thi ở phía máy chủ (server-side execution context). Tuyệt đối không cho phép client tự truyền ID tài khoản hoặc ID tài nguyên để truy vấn thông tin của thực thể khác mà không qua kiểm tra quyền sở hữu, ngăn chặn triệt để lỗ hổng phân quyền ngang (Bypass RLS / IDOR).

```python
# Helper làm sạch và che giấu PII của người dùng trước khi log
def mask_user_pii(user_data: dict) -> dict:
    """
    Sanitize thông tin PII người dùng: che số điện thoại, CCCD, và không log raw base64 chữ ký.
    """
    sanitized = user_data.copy()
    if "phone" in sanitized and sanitized["phone"]:
        phone = sanitized["phone"]
        sanitized["phone"] = f"{phone[:3]}****{phone[-3:]}" if len(phone) >= 6 else "***"
    if "id_card_number" in sanitized and sanitized["id_card_number"]:
        cccd = sanitized["id_card_number"]
        sanitized["id_card_number"] = f"{cccd[:3]}******{cccd[-3:]}" if len(cccd) >= 6 else "***"
    if "signature_base64" in sanitized:
        sanitized["signature_length"] = len(sanitized.pop("signature_base64") or "")
    return sanitized
```

### 2. 🔑 Quản Lý Thông Tin Nhạy Cảm Hệ Thống (Secrets Management — Pre-Flight Tầng 6)
*   **QUY TẮC:** Tuyệt đối không hardcode API Key, Token, Mật khẩu, Database URL hoặc các chuỗi nhạy cảm khác trong mã nguồn dưới bất kỳ hình thức nào.
*   **Giải pháp:** Đọc từ biến môi trường thông qua cấu hình môi trường bảo mật (như `.env` được nạp qua `pydantic-settings` với Backend, hoặc các biến build-time env với Frontend). File cấu hình `.env` chứa thông tin thực tế phải luôn được khai báo trong `.gitignore` để tránh đẩy lên Git.

### 30. 🇻🇳 Quy Chuẩn Định Danh & Bảo Vệ Dữ Liệu Cá Nhân (PII) Việt Nam (Vietnam PII Protection — Pre-Flight Tầng 6)
*   **QUY TẮC PHÁP LÝ & AN NINH:** Tuân thủ triệt để Nghị định 13/2023/NĐ-CP về Bảo vệ Dữ liệu Cá nhân (PDPD). Mọi thông tin định danh công dân và tài chính tại Việt Nam là dữ liệu nhạy cảm cấp cao. Tuyệt đối cấm ghi log plaintext, cấm hardcode vào mã nguồn, cấm commit vào git repo. Bắt buộc che giấu (masking) khi ghi log chẩn đoán hoặc xuất dữ liệu tóm tắt.
*   **Danh Mục Định Danh & Biểu Thức Chính Quy (Regex Specification):**
    1. **CCCD (Căn cước công dân):** 12 chữ số. Regex: `\b\d{12}\b`. Quy tắc mask: giữ 3 số đầu, 3 số cuối (ví dụ: `001******789`).
    2. **CMND (Chứng minh nhân dân):** 9 chữ số. Regex: `\b\d{9}\b`. Quy tắc mask: giữ 3 số đầu, 3 số cuối (ví dụ: `012***789`).
    3. **MST (Mã số thuế doanh nghiệp / cá nhân):** 10 hoặc 13 chữ số (10 số chuẩn hoặc 10 số kèm gạch nối 3 số chi nhánh). Regex: `\b\d{10}(?:-\d{3})?\b`. Quy tắc mask: che 4 số cuối (ví dụ: `0102****78` hoặc `0102****78-001`).
    4. **SĐT VN (Số điện thoại di động Việt Nam):** Các đầu số chuẩn quốc gia (+84 hoặc 0) của Viettel, VinaPhone, MobiFone, Vietnamobile (đầu số 03x, 05x, 07x, 08x, 09x) gồm 10 số. Regex: `(?:\+84|0)(?:3[2-9]|5[2689]|7[06-9]|8[1-9]|9[0-9])\d{7}\b`. Quy tắc mask: che 4 số giữa (`091****456` hoặc `+8491****456`).
    5. **BHYT / Mã số BHXH:** Thẻ BHYT 15 ký tự (2 chữ cái hoa + 13 chữ số) hoặc mã BHXH 10 chữ số. Regex: `\b[A-Z]{2}\d{13}\b` hoặc `\b\d{10}\b`. Quy tắc mask: giữ 4 ký tự đầu, 3 ký tự cuối, che chuỗi số giữa (ví dụ: `DN401******789`).
*   **Helper Sanitize & Masking Chuẩn Hóa:**

```python
import re

VIETNAM_PII_PATTERNS = {
    "cccd": re.compile(r"\b\d{12}\b"),
    "cmnd": re.compile(r"\b\d{9}\b"),
    "mst": re.compile(r"\b\d{10}(?:-\d{3})?\b"),
    "phone_vn": re.compile(r"(?:\+84|0)(?:3[2-9]|5[2689]|7[06-9]|8[1-9]|9[0-9])\d{7}\b"),
    "bhyt": re.compile(r"\b[A-Z]{2}\d{13}\b"),
    "bhxh": re.compile(r"\b\d{10}\b"),
}

def mask_vietnam_pii(data: dict) -> dict:
    """
    Mask Vietnam PII fields before logging or exporting.
    Tuân thủ Nghị định 13/2023/NĐ-CP (PDPD).
    """
    clean = data.copy()
    for k, v in clean.items():
        if not isinstance(v, str):
            continue
        # CCCD (12 số) & CMND (9 số)
        if any(term in k.lower() for term in ["cccd", "id_card", "citizen_id", "cmnd"]):
            if len(v) == 12:
                clean[k] = f"{v[:3]}******{v[-3:]}"
            elif len(v) == 9:
                clean[k] = f"{v[:3]}***{v[-3:]}"
        # Số điện thoại VN (+84 hoặc 0)
        elif any(term in k.lower() for term in ["phone", "sdt", "tel"]):
            if v.startswith("+84") and len(v) >= 11:
                clean[k] = f"{v[:5]}****{v[-2:]}"
            elif len(v) >= 10:
                clean[k] = f"{v[:3]}****{v[-3:]}"
        # Mã số thuế (10 hoặc 13 số)
        elif any(term in k.lower() for term in ["mst", "tax"]):
            clean[k] = f"{v[:4]}****{v[-2:]}" if len(v) >= 8 else "***"
        # BHYT / BHXH
        elif any(term in k.lower() for term in ["bhyt", "insurance", "bhxh"]):
            clean[k] = f"{v[:4]}******{v[-3:]}" if len(v) >= 10 else "***"
    return clean
```
</data_privacy_pii>

---

<cicd_and_development_standards>
### 14. 🔑 Không Tùy Tiện Thay Đổi Cấu Hình Bảo Mật Mặc Định (Weak Key Guard)
*   Khi rà soát quy tắc "Cấm hardcode", tuyệt đối không được sửa các giá trị hằng số (fallback values) trong file cấu hình (VD: `JWT_SECRET`) thành các chuỗi rác/mock một cách máy móc nếu chưa hiểu rõ ngữ cảnh. Việc này có thể vô tình vô hiệu hóa hệ thống cảnh báo khóa yếu (Weak Key Guard) ở môi trường Production.
</cicd_and_development_standards>

---

## 🛠️ CẨM NANG THỰC THI SECRETS MANAGEMENT & LOGGING AN TOÀN

<secrets_management>
### 3. 🔑 Quản Lý Thông Tin Nhạy Cảm (Secrets Management)
*   **QUY TẮC:** Tuyệt đối không hardcode API Key, Token, Mật khẩu, Database URL hoặc các chuỗi nhạy cảm khác trong code. Cấm ghi log lộ các thông tin này dưới mọi hình thức.
*   **Giải pháp:** Đọc từ biến môi trường qua file cấu hình `.env` sử dụng thư viện `pydantic-settings` (BaseSettings) hoặc `os.getenv` kèm giá trị mặc định an toàn.
*   **Code vi phạm ❌:**
    ```python
    # Sai lầm: Hardcode api key và in log lộ secret
    API_KEY = "sk-d02be6baa44ca9bf-6clngl-7a7b5895"
    print(f"Connecting using API Key: {API_KEY}")
    ```
*   **Code chuẩn ✅:**
    ```python
    from pydantic_settings import BaseSettings
    import logging

    logger = logging.getLogger(__name__)

    class Settings(BaseSettings):
        llm_api_key: str
        llm_base_url: str = "https://api.openai.com/v1"
        database_url: str
        api_service_key: str

        class Config:
            env_file = ".env"
            extra = "ignore"

    settings = Settings()
    # Log an toàn (không ghi thông tin nhạy cảm)
    logger.info("Application service configured with base URL: %s", settings.llm_base_url)
    ```
</secrets_management>
