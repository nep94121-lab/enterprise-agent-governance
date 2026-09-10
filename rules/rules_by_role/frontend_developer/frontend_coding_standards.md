# 🎨 TIÊU CHUẨN LẬP TRÌNH FRONTEND DOANH NGHIỆP

> Các điều khoản tiêu chuẩn chất lượng cấp doanh nghiệp bắt buộc cho lập trình viên Frontend / UI / React trong các dự án web doanh nghiệp.

---

<cybersecurity_defense>
## PHẦN I: AN NINH MẠNG & BẢO VỆ PHÍA FRONTEND

### 4. 🌐 Cấu Hình CORS & Headers Bảo Mật (API Security)
*   **QUY TẮC:** Tuyệt đối không sử dụng CORS wildcard `allow_origins=["*"]` trong môi trường sản xuất khi bật `allow_credentials=True`.
*   **Giải pháp:** Cấu hình danh sách tên miền (origins) được phép rõ ràng thông qua biến môi trường (`VITE_ALLOWED_ORIGINS` hoặc `NEXT_PUBLIC_ALLOWED_ORIGINS`). Bổ sung các header bảo mật phía web/reverse proxy để phòng chống Clickjacking, MIME-sniffing và các hình thức tấn công Web cơ bản (`X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Content-Security-Policy`).

```typescript
// Cấu hình headers bảo mật trong Next.js / Vite / Express Gateway cho Web Application
export const securityHeaders = [
  { key: 'X-Frame-Options', value: 'DENY' }, // Chống Clickjacking
  { key: 'X-Content-Type-Options', value: 'nosniff' },
  { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  {
    key: 'Content-Security-Policy',
    value: "default-src 'self'; script-src 'self' 'unsafe-inline'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline';",
  },
];
```

### 5. 🛡️ Phòng Chống Tấn Công XSS Phía Frontend (Frontend XSS Prevention)
*   **QUY TẮC:** Tuyệt đối không nhúng trực tiếp các URL động từ bên ngoài hoặc từ API trả về vào các thẻ như `<iframe src={...} />`, `<a href={...} />`, hoặc `<img src={...} />` mà không qua bước kiểm duyệt giao thức an toàn.
*   **Giải pháp:** Thiết lập hàm helper kiểm soát URL (chỉ cho phép các giao thức an toàn `http:`, `https:`, hoặc base64 ảnh an toàn `data:image/png;base64,` / `data:image/jpeg;base64,`). Chặn hoàn toàn các schema nguy hiểm như `javascript:` hoặc `vbscript:` để tránh hacker thực thi mã độc trên trình duyệt của người dùng.

```typescript
/**
 * §5: Kiểm soát giao thức URL đầu vào, phòng chống tấn công Frontend XSS.
 * Chỉ cho phép http:, https: và data:image/... Chặn triệt để javascript:.
 */
export function sanitizeMediaUrl(url: string | null | undefined): string {
  if (!url) return '';
  const trimmed = url.trim();
  const safeProtocols = ['http://', 'https://', 'data:image/png;base64,', 'data:image/jpeg;base64,', 'data:image/webp;base64,'];
  const hasSafeProtocol = safeProtocols.some((prefix) => trimmed.toLowerCase().startsWith(prefix));

  if (!hasSafeProtocol || trimmed.toLowerCase().includes('javascript:')) {
    console.warn(`[SECURITY] Blocked potentially malicious URL schema: ${trimmed.slice(0, 30)}...`);
    return '';
  }
  return trimmed;
}
```
</cybersecurity_defense>

---

<code_quality_and_performance>
## PHẦN II: TIÊU CHUẨN CHẤT LƯỢNG REACT & QUẢN LÝ DOM

### 9. ⚛️ Quản Lý State React & Cấm Can Thiệp DOM Trực Tiếp
*   **QUY TẮC:** Tuyệt đối không sử dụng các lệnh JavaScript thuần để trực tiếp thay đổi giao diện thực tế (DOM) như `document.getElementById()`, `document.querySelector()`, hoặc sửa đổi trực tiếp `el.style.display` trong React component. Việc này phá vỡ cơ chế hoạt động của Virtual DOM, gây ra lỗi không đồng bộ giao diện khi re-render.
*   **Giải pháp:** Mọi hành vi ẩn/hiện, thay đổi màu sắc, cập nhật giá trị phải được điều phối thông qua State của React (`useState`, `useRef`, custom hooks, context).

```tsx
// ❌ SAI: Can thiệp DOM trực tiếp làm hỏng Virtual DOM
function BadRepairStatus({ isUrgent }: { isUrgent: boolean }) {
  useEffect(() => {
    // VI PHẠM §9: document.getElementById() phá vỡ Virtual DOM
    const badge = document.getElementById('urgent-badge');
    if (badge) badge.style.display = isUrgent ? 'block' : 'none';
  }, [isUrgent]);
  return <div id="urgent-badge">Khẩn cấp</div>;
}

// ✅ ĐÚNG: Điều phối qua React State & Declarative JSX
export function ResidentRepairBadge({ isUrgent, status }: { isUrgent: boolean; status: string }) {
  return (
    <div className="flex items-center space-x-2">
      {isUrgent && (
        <span className="px-2 py-1 text-xs font-semibold bg-red-100 text-red-800 rounded-full animate-pulse">
          Khẩn cấp
        </span>
      )}
      <span className="text-sm font-medium text-gray-700">Trạng thái: {status}</span>
    </div>
  );
}
```

### 10. 🔐 Tạo Định Danh Cực Kỳ An Toàn (Secure UUID Generation)
*   **QUY TẮC:** Tuyệt đối không tự viết thuật toán sinh ID ngẫu nhiên thủ công (manual polyfills) ở Frontend bằng cách sử dụng các hàm regex thay thế ký tự (VD: `'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(...)`). Các thuật toán tự chế không đảm bảo phân phối ngẫu nhiên an toàn (cryptographic randomness) và dễ gây lỗi trùng lặp ID (collision).
*   **Giải pháp:** Sử dụng API tiêu chuẩn của trình duyệt `crypto.randomUUID()` hoặc thư viện UUID v4 chuẩn hóa đã qua kiểm tra chất lượng.

```typescript
/**
 * §10: Sinh Client-side Draft ID an toàn chống collision trước khi gửi đơn/yêu cầu.
 */
export function generateClientDraftId(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  throw new Error('Trình duyệt không hỗ trợ Web Cryptography API crypto.randomUUID().');
}
```
</code_quality_and_performance>

---

<cicd_and_development_standards>
## PHẦN III: REPOSITORY HYGIENE, BUNDLE MANIFEST & SCOPE GREP

### 13. 🧹 Repository Hygiene & Format Code Bắt Buộc (Linter & Whitespace — Pre-Flight Tầng 4, 9)
*   Mọi agent TRƯỚC KHI tạo commit ĐỀU PHẢI chạy đồng thời `ruff check --fix` (với Python) hoặc `npm run lint` / `npx prettier --check` (với Frontend) và `git diff --check`.
*   Cam kết đạt **0 trailing whitespace** và **0 dòng trống thừa ở EOF** trên toàn bộ các tệp tin (`.tsx`, `.ts`, `.jsx`, `.js`, `.css`, `.md`, `.json`).
*   Trong Markdown, cấm dùng cú pháp 2 dấu cách cuối dòng để xuống dòng (`  \n`), thay vào đó sử dụng thẻ `<br>` rõ ràng hoặc tách đoạn văn bản độc lập.

### 16. 🔄 Đồng Bộ File Tự Sinh & Chống Trôi Dạt Dữ Liệu (Bundle Drift Prevention — Pre-Flight Tầng 8)
*   Bất cứ khi nào cập nhật hoặc ghi đè một file dữ liệu (JSON/CSV/Assets) được sinh ra bằng Script (VD: file cấu hình biểu mẫu cư dân `building_forms.json` hoặc danh mục RAG tòa nhà), thì **BẮT BUỘC phải cập nhật luôn cả đoạn Script sinh ra nó**. Không được để xảy ra tình trạng "Bundle Drift" (Script sinh một đằng, file Data hiện tại một nẻo). Đảm bảo manifest file và checksum giữa data generator và manifest file khớp 100%.

```json
// Ví dụ cấu trúc building_docs_manifest.json đảm bảo tính toàn vẹn bundle:
{
  "manifest_version": "1.0.0",
  "generated_at": "2026-09-02T12:00:00Z",
  "generator_script": "scripts/generate_building_manifest.py",
  "checksum": "sha256-a1b2c3d4e5f67890123456789abcdef0",
  "files": [
    { "path": "data/building_regulations_sample.json", "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" },
    { "path": "data/bieu_mau_sua_chua.json", "sha256": "f4c8996fb92427ae41e4649b934ca495991b7852b855e3b0c44298fc1c149afb" }
  ]
}
```

### 27. 🔍 Quét Toàn Bộ Codebase Khi Sửa Thuật Ngữ / Docstring / Hằng Số (Comprehensive Scope Grep — Pre-Flight Tầng 4)
*   Khi sửa bất kỳ enum hiển thị (VD: `REPAIR_STATUS_LABEL`), tên trường API (`resident_id`), hay nhãn giao diện:
*   **BẮT BUỘC dùng lệnh `grep` toàn bộ repo** để tìm sạch 100% mọi vị trí xuất hiện (bao gồm forms, types, stores, tests).
*   Tuyệt đối loại bỏ điểm mù **Partial Match Blind Spot** (chỉ sửa 1 file thấy trước mắt và bỏ sót các view liên quan).
</cicd_and_development_standards>
