# 🗄️ BẢO MẬT CƠ SỞ DỮ LIỆU & HƯỚNG DẪN KỸ THUẬT BACKEND

## 🔌 NGUYÊN TẮC KẾT NỐI & QUẢN LÝ CƠ SỞ DỮ LIỆU BẢO MẬT

<database_connection_governance>
# NGUYÊN TẮC KẾT NỐI CƠ SỞ DỮ LIỆU DOANH NGHIỆP (§1, §2)

1. **Nạp biến môi trường 100%:** Mọi kết nối database (PostgreSQL, Supabase, MySQL, v.v.) phải nạp từ biến môi trường (`DATABASE_URL`, `.env`), cấm hardcode credentials (§2).
2. **Quyền truy cập Admin/Bypass RLS:** Chỉ sử dụng service role / admin credentials trong các background jobs, migrations hoặc server-side handlers nội bộ. Tuyệt đối không để lộ service key sang frontend hoặc client-side.
3. **Thao tác Database an toàn:** Sử dụng connection pooling, context managers (`async with` / `with`) và parameterized queries hoặc ORM models (§3, §17, §18).
</database_connection_governance>

---

## 🛠️ CẨM NANG THỰC THI KỸ THUẬT & CODE MẪU

<dynamic_path_handling>
### 1. 📂 Xử Lý Đường Dẫn Động (Path Handling)
*   **QUY TẮC:** Tuyệt đối không hardcode đường dẫn tuyệt đối (ví dụ: `<USER_HOME>\...` hoặc `/var/www/data`).
*   **Giải pháp:** Luôn sử dụng thư viện `pathlib.Path` để định nghĩa đường dẫn tương đối và động dựa trên vị trí file hiện tại hoặc root của dự án.
*   **Code vi phạm ❌:**
    ```python
    # Sai lầm: Hardcode đường dẫn tuyệt đối
    DATA_PATH = "/path/to/data/rules.txt"
    with open(DATA_PATH, "r") as f:
        content = f.read()
    ```
*   **Code chuẩn mẫu (Pathlib) ✅:**
    ```python
    from pathlib import Path

    # Lấy đường dẫn động tương đối so với file hiện tại
    BASE_DIR = Path(__file__).resolve().parent.parent
    DATA_PATH = BASE_DIR / "data" / "rules.txt"

    with DATA_PATH.open("r", encoding="utf-8") as f:
        content = f.read()
    ```
</dynamic_path_handling>

---

<injection_defense>
### 2. 🛡️ Phòng Chống Tấn Công SQL Injection & Prompt Injection
*   **QUY TẮC SQLi:** Tuyệt đối không nối chuỗi (string concatenation) hoặc dùng f-string để chèn biến trực tiếp vào câu truy vấn SQL.
*   **QUY TẮC Prompt Injection:** Phân tách rõ ràng System Prompt (chỉ thị hành vi của AI) và User Prompt (dữ liệu thô từ người dùng). Tuyệt đối không cho phép dữ liệu người dùng ghi đè hoặc thay đổi chỉ thị hệ thống.
*   **Giải pháp SQLi:** Sử dụng tham số hóa truy vấn (Parameterized Queries / Prepared Statements) hoặc ORM (SQLAlchemy / SQLModel).
*   **Code vi phạm SQLi ❌:**
    ```python
    # Sai lầm: Nối chuỗi trực tiếp dễ bị SQL Injection
    query = f"SELECT * FROM knowledge_documents WHERE category = '{user_category}'"
    result = db.execute(query)
    ```
*   **Code chuẩn SQLi ✅:**
    ```python
    # Đúng: Sử dụng Parameterized Queries
    query = "SELECT * FROM knowledge_documents WHERE category = :category"
    result = db.execute(query, {"category": user_category})

    # Hoặc sử dụng ORM/SQLModel:
    # statement = select(KnowledgeDocument).where(KnowledgeDocument.category == user_category)
    # result = session.exec(statement).all()
    ```
</injection_defense>

---

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

        class Config:
            env_file = ".env"
            extra = "ignore"

    settings = Settings()
    # Log an toàn (không ghi thông tin nhạy cảm)
    logger.info("LLM service configured with base URL: %s", settings.llm_base_url)
    ```
</secrets_management>

---

<resource_and_error_handling>
### 5. 🧹 Quản Lý Tài Nguyên & Xử Lý Lỗi (Resource & Exception Handling)
*   **QUY TẮC:** Luôn giải phóng tài nguyên hệ thống (DB Connection, File IO, HTTP Session) sau khi sử dụng. Cấm nuốt lỗi ẩn (`except: pass` mà không ghi log). Không bao giờ trả về stack trace thô cho client qua API.
*   **Giải pháp:** Sử dụng context manager `with` hoặc `async with`. Luôn ghi log lỗi chi tiết qua `logger.exception()` hoặc `logger.error()`. Trả về mã lỗi thân thiện cho client.
*   **Code vi phạm ❌:**
    ```python
    # Sai lầm: Không đóng file, nuốt lỗi và trả về lỗi thô
    def read_config():
        try:
            f = open("config.json", "r")
            return json.loads(f.read())
        except Exception as e:
            return {"error": str(e)} # Lộ stack trace/thông tin hệ thống
    ```
*   **Code chuẩn ✅:**
    ```python
    import logging
    from fastapi import HTTPException
    from pathlib import Path
    import json

    logger = logging.getLogger(__name__)

    def read_config(config_path: Path) -> dict:
        try:
            with config_path.open("r", encoding="utf-8") as f:
                return json.load(f)
        except FileNotFoundError:
            logger.error(f"Configuration file not found at {config_path}")
            raise HTTPException(status_code=500, detail="Internal server configuration error.")
        except json.JSONDecodeError as e:
            logger.exception("Failed to parse config file JSON")
            raise HTTPException(status_code=500, detail="Invalid system configuration format.")
    ```
</resource_and_error_handling>

---

<input_validation>
### 6. 🧪 Xác Thực Dữ Liệu Đầu Vào (Input Validation)
*   **QUY TẮC:** Mọi endpoint API nhận dữ liệu từ client phải định nghĩa schema kiểm tra kiểu và định dạng dữ liệu đầu vào. Không tin tưởng dữ liệu thô.
*   **Giải pháp:** Sử dụng Pydantic Model để tự động validate kiểu dữ liệu, độ dài chuỗi, định dạng số, email...
*   **Code chuẩn ✅:**
    ```python
    from pydantic import BaseModel, Field, EmailStr

    class ChatRequest(BaseModel):
        # Giới hạn độ dài câu hỏi để chống spam/DDoS RAG
        query: str = Field(..., min_length=1, max_length=500, description="Nội dung câu hỏi của người dùng")
        user_email: EmailStr = Field(..., description="Email người dùng gửi yêu cầu")
    ```
</input_validation>
