# 🛡️ QUALITY GATES, LIFECYCLE & VERIFICATION MANAGEMENT

> Hướng dẫn quản trị cổng chất lượng, vòng đời tiến trình, dọn dẹp subagents zombie, quản lý token GWS và quy trình nghiệm thu độc lập theo tiêu chuẩn Doanh nghiệp.

---

## 🔑 QUẢN TRỊ MÔI TRƯỜNG & VÒNG ĐỜI TIẾN TRÌNH

<gws_token_management>
## 🔑 Google Workspace CLI (gws)
- Tài khoản: `user@example.com` | Credentials: `~/.config/gws/credentials.enc`
- Cấm backup token ra ngoài `.config/gws/`. Phát hiện file cũ → dọn ngay.
- Token hết hạn → chạy `gws auth login` nền, gửi link OAuth2 lên chat. KHÔNG mở browser ngầm.
- Dự án GCloud trạng thái `In production` → token vĩnh viễn.
</gws_token_management>

```powershell
# Ghi nhật ký tiến độ dự án tự động lên Google Sheets thông qua gws
cmd /c 'gws sheets spreadsheets values append --params "{\"spreadsheetId\":\"1AbC...\", \"range\":\"ActivityLog!A1\", \"valueInputOption\":\"USER_ENTERED\"}" --data "{\"values\":[[\"2026-09-02T18:00:00Z\", \"Orchestrator\", \"Completed Milestone 1\"]]}"'
```

---

<auto_permissions>
## 🔓 Auto-Permissions — Turn 1 mỗi chat
Tự động xin quyền hàng loạt (parallel) cho: `python`, `node`, `npm`, `npx`, `git`, `ssh`, `cmd`, `docker`, `curl`, `Start-Process`, `Copy-Item`, `Remove-Item`, `Move-Item`, `Invoke-Item`, `Get-Content`, `Set-Content`, `Invoke-WebRequest` | MCP: `browser-use/*`, `ssh-remote/*`, `firecrawl/*`, `obsidian/*`, `codebase-memory/*` | File: `Desktop`, `.gemini`, `.config`.
</auto_permissions>

---

<process_cleanup>
## 🧹 Dọn dẹp tiến trình — BẮT BUỘC khi xong việc
Hoàn thành công việc → kill_all subagents + kill tất cả background tasks. Không để zombie chiếm CPU/RAM.
</process_cleanup>

```powershell
# Lệnh PowerShell bắt buộc chạy khi kết thúc phiên điều phối PM
Get-Process python -ErrorAction SilentlyContinue | Where-Object { $_.CommandLine -like "*subagent*" } | Stop-Process -Force
```

---

## 🛡️ CỔNG CHẤT LƯỢNG & CẶP ĐÔI ĐỐI KHÁNG (QUALITY GATES)

<quality_gate_reference>
## 🛡️ Quy Trình Chất Lượng (Inspector + Challenger + Tech Lead Pre-flight)
> **CHI TIẾT ĐẦY ĐỦ:** Đọc file `~/.gemini/config/references/pm-audit-detail.md`
> **BẮT BUỘC đọc file trên** trước khi: audit code, viết test suite > 5 tests, sửa logic core, mở PR, hoặc sign-off nghiệm thu.

**Tóm tắt nhanh:**
- Cặp Inspector (flash) + Challenger (pro) bắt buộc cho mọi task quan trọng.
- Challenger tính Confidence Score (0–100), chỉ chặn PR khi Confidence ≥ 80 và viết PoC thực thi (cấm lỗi vặt). Cấm "LGTM".
- Sửa thuật ngữ/docstring → grep toàn codebase (§27). PM phải soi git diff thật (§28).
- Tech Lead Pre-flight 10 tầng (§29 Gitignore → §1 PII → §13 Hygiene → Merge).
</quality_gate_reference>

---

## 🔍 KIỂM TOÁN THỰC TẾ & BẢO ĐẢM TÍNH TRUNG THỰC

### 1. Quét Toàn Bộ Codebase Khi Sửa Thuật Ngữ / Docstring / Hằng Số (§27)
- Khi sửa bất kỳ thuật ngữ, docstring, hằng số, schema hay tài liệu nào, **BẮT BUỘC phải `grep` toàn bộ codebase** để tìm sạch 100% mọi vị trí xuất hiện (bao gồm file gốc, hàm con, docstrings, schema, và tests).
- **CẤM** chỉ sửa vị trí đầu tiên nhìn thấy (chống điểm mù *Partial Match Blind Spot*).

```bash
# Quét toàn bộ codebase khi thay đổi tên enum / thuật ngữ
grep -rn "ACTION_PROPOSAL_STATUS" src/ tests/ docs/
```

### 2. Kiểm Chứng 100% Bằng Git Diff Thực Tế (§28)
- Agent chính / PM **KHÔNG ĐƯỢC** chỉ dựa vào báo cáo tóm tắt của subagent, inspector hay auditor.
- **PHẢI TRỰC TIẾP** đọc và soi từng dòng `git diff` thực tế trên đĩa trước khi bàn giao báo cáo cho Sếp hoặc xác nhận hoàn thành task.

```bash
# Lệnh PM soi trực tiếp diff thực tế trên đĩa
git diff HEAD~1..HEAD
```

### 3. Quy Trình Vòng Lặp Sửa Lỗi Khép Kín (Closed-Loop Re-Audit Flow)
```
[Worker hoàn thành code]
        │
        ▼
[Inspector (flash)] ──► Tự chạy command build/test trên máy thật, đo exit code
        │
        ▼
[Challenger (pro)] ──► Kích hoạt Ma Trận 10 Trục Tư Duy Động
        │              Chấm điểm Confidence Scoring (0–100, threshold >= 80)
        │              Viết PoC test thật cho phát hiện đạt Confidence >= 80
        │
        ├─► [Có lỗi C >= 80 / REQUEST CHANGES] ──► Chuyển danh sách PoC cho Worker sửa
        │                                                ▲
        │                                                │ (Worker sửa xong)
        │                                                └───────┘ (Challenger RÀ SOÁT LẠI TOÀN BỘ từ đầu)
        │
        └─► [0 lỗi C >= 80 & PASS 100% Zero-Regression] ──► APPROVE & Cho phép Bàn giao/Merge PR
```
