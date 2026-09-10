# 🛡️ BẢO MẬT GIAO DIỆN, DOM & QUY CHUẨN XỬ LÝ LỖI FRONTEND

> Hướng dẫn bảo mật UI, phòng chống dữ liệu ảo, xử lý lỗi thân thiện và xác thực form dành riêng cho Frontend Engineer trong các dự án web doanh nghiệp.

---

## 🌐 HƯỚNG DẪN BẢO MẬT & KIỂM SOÁT DỮ LIỆU ĐẦU VÀO

### 1. 🧹 Quản Lý Xử Lý Lỗi & Hiển Thị Thân Thiện (Error Handling)
*   **QUY TẮC:** Tuyệt đối không hiển thị trực tiếp stack trace thô, câu truy vấn SQL hay thông báo lỗi kỹ thuật của backend lên màn hình người dùng.
*   **Giải pháp:** Bắt lỗi bằng Error Boundaries trong React hoặc `try-catch` trong async API handlers. Hiển thị thông báo lỗi thân thiện (user-friendly toast/alert) và ghi log debug an toàn.

```tsx
// Pattern xử lý lỗi API an toàn và hiển thị UI thông báo thân thiện
export async function submitUserRequest(payload: RequestInput) {
  try {
    const res = await apiClient.post('/api/v1/requests', payload);
    return { success: true, data: res.data };
  } catch (err: any) {
    // Không hiển thị err.stack hoặc raw response body nguy hiểm
    const userMessage = err.response?.data?.detail || 'Không thể gửi yêu cầu. Vui lòng kiểm tra lại kết nối mạng.';
    showToastNotification({ type: 'error', title: 'Lỗi gửi yêu cầu', message: userMessage });
    return { success: false, error: userMessage };
  }
}
```

### 2. 🧪 Xác Thực Dữ Liệu Form Đầu Vào (Client-Side Input Validation với Zod)
*   **QUY TẮC:** Mọi form nhập liệu của người dùng phải được validate chặt chẽ về định dạng, độ dài chuỗi tối thiểu/tối đa trước khi gửi request lên API để ngăn chặn spam, dữ liệu rác hoặc tải quá mức.
*   **Kiểm tra bắt buộc:**
    - Email người dùng hợp lệ theo chuẩn RFC 5322.
    - Giới hạn độ dài text input/textarea (`min_length`, `max_length`).
    - Khử trùng ký tự đặc biệt nguy hiểm trước khi render.

```typescript
import { z } from 'zod';

// Zod schema kiểm thực form yêu cầu hỗ trợ người dùng mẫu
export const userRequestFormSchema = z.object({
  user_id: z.string().uuid('Định danh người dùng không hợp lệ'),
  account_id: z.string().uuid('Mã tài khoản không hợp lệ'),
  category: z.enum(['plumbing', 'electrical', 'appliance', 'structural'], {
    errorMap: () => ({ message: 'Danh mục sửa chữa phải thuộc: điện, nước, thiết bị hoặc kết cấu' }),
  }),
  location_in_unit: z
    .string()
    .min(2, 'Vị trí trong phòng tối thiểu 2 ký tự')
    .max(100, 'Vị trí trong phòng tối đa 100 ký tự')
    .refine((val) => !/^(thôi|không sửa|hỏi tí|test)$/i.test(val.trim()), {
      message: 'Vui lòng nhập vị trí cụ thể trong căn hộ (VD: Nhà vệ sinh phòng ngủ chính)',
    }),
  description: z
    .string()
    .min(10, 'Mô tả hư hỏng chi tiết tối thiểu 10 ký tự')
    .max(1000, 'Mô tả tối đa 1000 ký tự'),
  priority: z.enum(['low', 'medium', 'high', 'emergency']).default('medium'),
});

export type RepairRequestFormData = z.infer<typeof repairRequestFormSchema>;
```

---

## 🏛️ TIÊU CHUẨN TECH LEAD PRE-FLIGHT CHO FRONTEND

### 1. 🧹 Tầng 3: Bảo Toàn Tính Logic Nghiệp Vụ & Chống Dữ Liệu Ảo (Zero-Garbage & Realistic Data Flow)
- **Nguồn gốc Big Tech:** Chuẩn mực Amazon Transaction Integrity & Zero-Residue State.
- **Mục đích:** Đảm bảo trạng thái hệ thống và dữ liệu trả về phản ánh 100% sự thật thực tế, không sinh rác lưu trữ.
- **Quy tắc thực thi:**
   1. **Nguyên tắc Zero-Garbage khi ở trạng thái tạm (DRAFT / PREVIEW / VALIDATION FAIL):**
      - Khi một thực thể đang ở trạng thái nháp hoặc người dùng cần điền lại đơn: **TUYỆT ĐỐI KHÔNG sinh mã định danh nghiệp vụ ảo** (như `request_number = "REQ-0001"`, `invoice_id`) khi bản ghi chưa thực sự được lưu trữ vào Cơ sở dữ liệu. Luôn gán `request_number: null` cho các state nháp này.
   2. **Cấm Optimistic UI Che Giấu Lỗi:** Frontend không được hiển thị trạng thái ảo thành công trước khi Backend xác nhận, tránh trường hợp client báo "Đã gửi thành công" nhưng server thực tế trả lỗi 500/422.

### 2. 🔍 Tầng 4: Quét Toàn Bộ Phạm Vi Codebase Khi Đổi Thuật Ngữ/Logic (§27 Scope Grep)
- **Nguồn gốc Big Tech:** Chuẩn mực Palantir Global Scope Refactoring.
- **Quy tắc thực thi:**
  - Khi thay đổi bất kỳ enum hiển thị, trạng thái đơn, nhãn giao diện (labels), hoặc docstring:
    - **BẮT BUỘC dùng lệnh `grep` toàn bộ repo** để tìm sạch 100% mọi vị trí xuất hiện (bao gồm component con, router, state, mock tests).
    - **CẤM** chỉ sửa 1 vị trí đầu tiên nhìn thấy mà bỏ sót các component khác.

### 3. 🔄 Tầng 8: Đồng Bộ File Tự Sinh & Chống Trôi Dạt Dữ Liệu (§16 Bundle Drift Prevention)
- Khi chỉnh sửa dữ liệu tĩnh hiển thị trên giao diện (danh mục biểu mẫu, cấu hình hệ thống), phải đảm bảo script sinh bundle và file manifest đi kèm được cập nhật đồng thời.

---

## 🚦 QUY TRÌNH TỰ KIỂM TRA FRONTEND (SELF-CHECK CHECKLIST)

Trước khi bàn giao code UI hoặc báo cáo hoàn thành nhiệm vụ, Frontend Developer **PHẢI** tự duyệt qua checklist này:
- [ ] Có sử dụng `document.getElementById` hoặc can thiệp DOM trực tiếp không? (Nếu có -> Đổi sang `useState`/`useRef`).
- [ ] Có URL động nào được gán vào `<iframe>`, `<a>`, `<img>` mà chưa qua whitelist giao thức an toàn `sanitizeMediaUrl` không?
- [ ] Các ID ngẫu nhiên có được sinh bằng `crypto.randomUUID()` thay vì tự viết regex không?
- [ ] Code có đạt chuẩn **0 trailing whitespace** và **0 dòng trống thừa ở EOF** không?
- [ ] Có hiển thị stack trace lỗi thô của backend lên giao diện không? (Bắt buộc dùng toast/alert thân thiện).
- [ ] Form nhập liệu đã được validate qua Zod Schema (`userRequestFormSchema`) với ràng buộc kiểu dữ liệu và độ dài chưa?
- [ ] Đã kiểm tra giao diện không dùng optimistic update che giấu lỗi API thất bại chưa? (Đảm bảo Zero-Garbage ở state DRAFT).
- [ ] Đã chạy `grep -rn` quét sạch toàn bộ codebase khi thay đổi tên enum/trạng thái chưa (§27)?
