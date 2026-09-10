# 🏗️ QUẢN TRỊ HẠ TẦNG, QUYỀN TRUY CẬP & DỊCH VỤ

> Hướng dẫn cấu hình hạ tầng, quản lý token Google Workspace CLI, cấp quyền tự động Turn 1, dọn dẹp tiến trình và kết nối cơ sở dữ liệu doanh nghiệp an toàn.

---

## 🔑 QUẢN LÝ TOKEN GOOGLE WORKSPACE CLI (GWS)

<gws_token_management>
## 🔑 Google Workspace CLI (gws)
- Tài khoản: `user@example.com` | Credentials: `~/.config/gws/credentials.enc`
- Cấm backup token ra ngoài `.config/gws/`. Phát hiện file cũ → dọn ngay.
- Token hết hạn → chạy `gws auth login` nền, gửi link OAuth2 lên chat. KHÔNG mở browser ngầm.
- Dự án GCloud trạng thái `In production` → token vĩnh viễn.
</gws_token_management>

```powershell
# Ví dụ gọi gws từ PowerShell bắt buộc escape JSON qua cmd /c
cmd /c 'gws drive files list --params "{\"pageSize\":10}"'
cmd /c 'gws sheets spreadsheets values get --params "{\"spreadsheetId\":\"1AbC...\", \"range\":\"Sheet1!A1:E10\"}"'
```

---

## 🔓 CẤP QUYỀN TỰ ĐỘNG (AUTO-PERMISSIONS)

<auto_permissions>
## 🔓 Auto-Permissions — Turn 1 mỗi chat
Tự động xin quyền hàng loạt (parallel) cho: `python`, `node`, `npm`, `npx`, `git`, `ssh`, `cmd`, `docker`, `curl`, `Start-Process`, `Copy-Item`, `Remove-Item`, `Move-Item`, `Invoke-Item`, `Get-Content`, `Set-Content`, `Invoke-WebRequest` | MCP: `browser-use/*`, `ssh-remote/*`, `firecrawl/*`, `obsidian/*`, `codebase-memory/*` | File: `Desktop`, `.gemini`, `.config`.
</auto_permissions>

---

## 🧹 DỌN DẸP TIẾN TRÌNH KHI HOÀN THÀNH

<process_cleanup>
## 🧹 Dọn dẹp tiến trình — BẮT BUỘC khi xong việc
Hoàn thành công việc → kill_all subagents + kill tất cả background tasks. Không để zombie chiếm CPU/RAM.
</process_cleanup>

```powershell
# PowerShell script dọn dẹp các subagents và process zombie chạy ngầm
Get-Process python -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -like "*subagent*" } | Stop-Process -Force
Get-Process node -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -like "*worker*" } | Stop-Process -Force
```

---

## 🔌 CẤU HÌNH & KẾT NỐI CƠ SỞ DỮ LIỆU DOANH NGHIỆP

<database_infrastructure_governance>
# NGUYÊN TẮC KẾT NỐI CƠ SỞ DỮ LIỆU DOANH NGHIỆP (§1, §2)

1. **Nạp biến môi trường 100%:** Mọi kết nối cơ sở dữ liệu phải nạp từ biến môi trường (`DATABASE_URL`, `.env`), cấm hardcode credentials (§2).
2. **Bảo mật chuỗi kết nối:** Sử dụng `DATABASE_URL` dạng `postgresql://user:password@host:port/dbname` hoặc các biến môi trường riêng biệt (`DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`).
3. **Thao tác Database an toàn:** Sử dụng connection pooling và context manager để đảm bảo tự động đóng kết nối sau khi sử dụng (§8, §17).
</database_infrastructure_governance>

```python
# Script Python chuẩn kết nối trực tiếp Cơ sở dữ liệu qua biến môi trường
import os
import psycopg2
from psycopg2.extras import RealDictCursor

def execute_direct_query(sql_query: str, params: tuple = None):
    """
    Thực thi truy vấn SQL an toàn nạp thông tin từ biến môi trường.
    """
    conn_str = os.environ.get("DATABASE_URL")
    if conn_str:
        conn = psycopg2.connect(conn_str)
    else:
        conn = psycopg2.connect(
            host=os.environ.get("DB_HOST", "localhost"),
            port=int(os.environ.get("DB_PORT", 5432)),
            user=os.environ.get("DB_USER", "postgres"),
            password=os.environ.get("DB_PASSWORD", ""),
            dbname=os.environ.get("DB_NAME", "postgres")
        )
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(sql_query, params)
            if cur.description:
                return cur.fetchall()
            conn.commit()
            return []
    finally:
        conn.close()
```
