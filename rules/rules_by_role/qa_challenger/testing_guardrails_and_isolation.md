# 🛡️ HÀNG RÀO KIỂM THỬ, CÔ LẬP MÔI TRƯỜNG & ĐO LƯỜNG TRUNG THỰC

> Các điều khoản tiêu chuẩn kiểm thử bắt buộc cấp doanh nghiệp dành cho QA / Test Engineer / Challenger theo tiêu chuẩn Doanh nghiệp.

---

<code_quality_and_performance>
### 12. 📊 Tính Trung Thực Trong Đo Lường & Bảo Trì Khung Kiểm Thử (Measurement Integrity & Test Harness Assurance — Pre-Flight Tầng 5)
*   **QUY TẮC:**
    - **Không báo cáo chỉ số ảo:** Tuyệt đối cấm sử dụng số liệu từ các Mock/Fake Adapter (như `FakeAnswerAdapter`) để báo cáo làm chỉ số chất lượng của hệ thống live. Mọi báo cáo về độ chính xác (accuracy), độ trễ (latency) và tỷ lệ lỗi phải được đo trực tiếp trên live stack thật.
    - **Đồng bộ hóa dữ liệu test:** Tất cả các tệp dataset đánh giá (như `evaluation.json`) phải luôn trỏ vào các Document ID/thực thể thật tồn tại trong database thực tế (`users`, `orders`, `documents`), không được sử dụng ID cũ hoặc ảo.
    - **Bảo trì test harness:** Mọi sửa đổi cấu hình hoặc dọn dẹp mã nguồn (ví dụ: gỡ bỏ demo auth) tuyệt đối không được làm gãy hỏng bộ script đánh giá (`evaluate_sprint*.py` hoặc các test harnesses). Phải chạy kiểm thử tự động lại toàn bộ harness khi có thay đổi cấu hình.
*   **Giải pháp:** Viết các script validation để kiểm tra xem ID tài liệu trong tệp kiểm thử có tồn tại trong database thật hay không trước khi thực hiện đo.

```python
# Script kiểm tra Measurement Integrity trước khi chạy benchmark kiểm thử
import os
import pytest

def verify_evaluation_dataset_integrity(eval_data: list[dict], existing_ids: set[str]):
    """Kiểm tra sự tồn tại trên database live stack thật (§12)."""
    doc_ids = [item["document_id"] for item in eval_data if "document_id" in item]
    missing_ids = set(doc_ids) - existing_ids
    if missing_ids:
        raise ValueError(f"§12 VI PHẠM: Dataset chứa Document ID ảo/không tồn tại: {missing_ids}")
```
</code_quality_and_performance>

---

<cicd_and_development_standards>
### 19. 🧪 Quy Tắc Kiểm Thử Chuyên Nghiệp (Master Test Specification)
*   Mọi hoạt động sinh test, viết kịch bản kiểm thử (Test Cases/Test Scripts), đo lường chất lượng và xuất báo cáo nghiệm thu phải tuân thủ tuyệt đối các quy định, phương pháp và biểu mẫu schema định nghĩa tại [TEST_CHUYEN_NGHIEP.md](~/.gemini/config/references/TEST_CHUYEN_NGHIEP.md). Bắt buộc phải đọc và đối chiếu file này trước khi thực hiện viết test.

### 20. 🧪 Cô Lập Test & Môi Trường CI (Test Isolation & Live Sandboxing — Pre-Flight Tầng 0)
*   Mặc định ở môi trường Unit Test / PR CI: Toàn bộ test suite phải chạy **Mock HTTP 100%**, phát ra chính xác 0 cuộc gọi mạng thật ra ngoài.
*   Mọi bài test có tương tác live với Database/Storage thật **BẮT BUỘC phải là Opt-in** (gắn cờ kiểm tra như `RUN_LIVE_DATABASE_TESTS=1` + `@pytest.mark.skipif(...)`).
*   Tất cả thao tác ghi live **BẮT BUỘC bọc trong khối `try ... finally`** để tự động dọn sạch 100% row và file rác, kể cả khi assertion thất bại.

```python
# Fixture Pytest chuẩn cho Live Sandboxing với cơ chế dọn dẹp tự động 100%
import os
import pytest

@pytest.fixture
def live_database_record(test_db_client):
    # §20: Kiểm tra cờ opt-in cho live testing
    if os.getenv("RUN_LIVE_DATABASE_TESTS") != "1":
        pytest.skip("Bỏ qua live test do thiếu biến môi trường RUN_LIVE_DATABASE_TESTS=1")

    created_id = None
    try:
        res = test_db_client.table("test_items").insert({
            "user_id": "00000000-0000-0000-0000-000000000001",
            "category": "general",
            "description": "Live Sandboxing Test Item",
            "status": "draft"
        }).execute()
        created_id = res.data[0]["id"]
        yield res.data[0]
    finally:
        # Bắt buộc bọc trong try ... finally: Dọn sạch 100% dữ liệu rác
        if created_id:
            test_db_client.table("test_items").delete().eq("id", created_id).execute()
```

### 21. 🚫 Cấm Test Lặp & Test Dummy (No Duplicated/Filler Test Logic)
*   Tuyệt đối cấm tạo các hàm test có cấu trúc logic trùng lặp hoàn toàn (chỉ thay đổi ID test hoặc string kiểm thử) để tăng số lượng test ảo. Mọi test case phải tương ứng với hành vi nghiệp vụ hoặc kịch bản riêng biệt (ví dụ: test phân quyền người dùng Authorization, test chống SQL Injection, test slot-filling khi người dùng đổi ý).

### 22. 📊 Báo Cáo Coverage Trung Thực (Genuinely Verified Coverage)
*   Mọi chỉ số phần trăm Code Coverage công bố trong báo cáo phải được chạy và đo thực tế bằng công cụ đo lường (`pytest-cov`) để xuất ra tệp tin cấu trúc (`.coverage`, `coverage.xml`, HTML report), tuyệt đối không dùng con số giả định hay placeholder.

```bash
# Lệnh đo Coverage trung thực xuất XML phục vụ CI/CD
pytest tests/ --cov=src --cov-report=xml:coverage.xml --cov-report=term-missing
```

### 29. 🛡️ Kiểm Toán Pháp Y .gitignore & Giữ Sạch Cây Thư Mục (Gitignore Collision Audit & Zero Workspace Pollution — Pre-Flight Tầng 0)
*   Khi tạo bất kỳ file dữ liệu mẫu, fixture cố định, baseline, assets hoặc schemas mới phục vụ kiểm thử: **BẮT BUỘC chạy `git check-ignore -v <files>`** để kiểm tra. Nếu bị pattern wildcard trong `.gitignore` chặn, **PHẢI thêm ngoại lệ `!<path>` tường minh vào `.gitignore`**.
*   Mọi test suite khi chạy sinh file báo cáo/file tạm **BẮT BUỘC phải ghi ra thư mục tạm** (`tmp_path` trong Pytest hoặc `os.tmpdir()` trong Node.js), **TUYỆT ĐỐI CẤM** ghi đè làm bẩn (dirty working tree) các file đang được track trong Git.

```python
# Ví dụ ghi báo cáo kiểm thử ra tmp_path chống ô nhiễm working tree
def test_generate_audit_report_to_tmp(tmp_path):
    report_file = tmp_path / "audit_report.json"
    report_file.write_text('{"total_items": 5, "status": "verified"}', encoding="utf-8")
    assert report_file.exists()
    # tmp_path được pytest tự động giải phóng, không để lại file rác trong workspace
```
</cicd_and_development_standards>
