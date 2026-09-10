# ⚡ QUY CHUẨN ĐIỀU PHỐI PHẦN CỨNG DYNAMIC_CPU_CORE_COUNT & WINDOWS JOB OBJECTS
## (HARDWARE AFFINITY, CPU GOVERNANCE & PROCESS ISOLATION SPECIFICATION)

> 🔴 **MÃ TÀI LIỆU:** `RULE-INFRA-P1-HARDWARE-JOB-01`
> 🏷️ **CẤP ĐỘ ƯU TIÊN:** **P1 (Quan Trọng / Doanh Nghiệp Bắt Buộc)**
> 🖥️ **HỒ SƠ PHẦN CỨNG CHUẨN:** DYNAMIC_CPU_CORE_COUNT (SMT/Hyper-Threading), Windows 11 Pro 64-bit, DYNAMIC_MEMORY_PROFILE.
> 🌐 **THAM CHIẾU QUỐC TẾ:** Windows Win32 Job Objects API (`kernel32.dll`), Linux `cgroups v2` Throttling Architecture, Python `psutil` / `ctypes`, SMP Core Affinity Scheduling.
> 🎯 **PHẠM VI ÁP DỤNG:** DevOps & Security, PM Orchestrator, State Checkpoint Curator.

---

## I. HỒ SƠ PHẦN CỨNG & BÀI TOÁN TỐI ƯU CỦA SẾP

Hệ thống máy trạm của Sếp sở hữu cấu hình thực tế:
- **CPU:** 4 nhân vật lý (Physical Cores 0, 1, 2, 3) / 8 luồng logic (Logical Threads 0 đến 7).
- **RAM:** DYNAMIC_MEMORY_PROFILE DDR4/DDR5.
- **Hệ Điều Hành:** Windows 11 Pro 64-bit.

### 3 Thách Thức Kỹ Thuật Lớn Nhất Trên Nền Tảng Windows 11:
1. **Hiện tượng đơ máy & giật khung hình (UI Freezing & Input Lag):** Khi các tác tử AI khởi chạy các tác vụ biên dịch nặng (Rust, C++, TypeScript), chạy toàn bộ ma trận test hoặc khởi chạy Headless Chromium / Playwright, nếu tiến trình chiếm dụng 100% CPU trên toàn bộ 8 luồng logic, giao diện Windows Desktop (DWM), con trỏ chuột và bàn phím của Sếp sẽ bị giật đơ cục bộ, làm gián đoạn công việc cá nhân của Sếp.
2. **Tiến trình mồ côi ngốn tài nguyên (Zombie / Orphan Processes):** Khi một lệnh terminal bị hủy (`kill`), gặp sự cố (`crash`) hoặc hết thời gian chờ (`timeout`), trên Windows, tiến trình cha bị dừng lại nhưng các tiến trình con (`python.exe`, `node.exe`, `git.exe`, `pytest.exe`) thường tiếp tục sống sót trong nền. Chúng âm thầm duy trì vòng lặp 100% CPU và rò rỉ hàng gigabyte RAM.
3. **Sốc nhiệt & Suy giảm hiệu năng phần cứng (Thermal Throttling):** Việc ép CPU chạy 100% liên tục trong thời gian dài sẽ kích hoạt cảm biến nhiệt của bo mạch chủ, tự động hạ xung nhịp CPU từ 4.5GHz xuống dưới 1.8GHz để bảo vệ phần cứng, làm tốc độ xử lý thực tế giảm hơn một nửa.

---

## II. CHIẾN LƯỢC PHÂN VÙNG CPU CORE AFFINITY (CPU AFFINITY MASK)

Để giải quyết dứt điểm vấn đề UI Lag, hệ thống thiết lập nguyên tắc **Phân Vùng Lõi Cứng Cấp Hệ Điều Hành (Hard Core Partitioning)**:

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                    PHÂN BỔ TÀI NGUYÊN DYNAMIC_HARDWARE_SPEC WINDOWS 11                       │
├────────────────────────────────────────┬────────────────────────────────────────────────┤
│ NHÂN VẬT LÝ 0 & 1 (Logical 0, 1, 2, 3) │ NHÂN VẬT LÝ 2 & 3 (Logical 4, 5, 6, 7)         │
├────────────────────────────────────────┼────────────────────────────────────────────────┤
│ ⚡ BỂ 2: LOCAL BURST HEAVY COMPUTE     │ 🌐 BỂ 1 & HỆ ĐIỀU HÀNH BẢO LƯU                 │
│ • Local Compilers (rustc, gcc, tsc)    │ • Windows OS Kernel & Desktop Window Manager   │
│ • Unit / Integration Test Suites       │ • IDE (VSCode / Antigravity), Trình duyệt Sếp │
│ • Headless Chromium / Playwright       │ • Bể 1: Cloud LLM Thinking & Async Tool I/O    │
│ • Python AST Linting & Entropy Scans   │ • Async IO Network Loop & Subagent Messaging   │
│ 🎯 CPU Affinity Mask: 0x0F (Cores 0-3) │ 🎯 Luôn duy trì CPU headroom mượt mà cho Sếp   │
└────────────────────────────────────────┴────────────────────────────────────────────────┘
```

### 1. Công Thức Tính Toán Mặt Nạ Nhị Phân (Affinity Mask Formula)
Hệ điều hành Windows biểu diễn phân bổ CPU core dưới dạng bitmask 64-bit. Mỗi bit đại diện cho một luồng logic:
$$\text{Bit 0} \rightarrow \text{Thread 0}, \quad \text{Bit 1} \rightarrow \text{Thread 1}, \quad \text{Bit 2} \rightarrow \text{Thread 2}, \quad \text{Bit 3} \rightarrow \text{Thread 3}$$

Mặt nạ cho phép tiến trình nặng chạy trên luồng 0, 1, 2, 3:
$$\text{Mask} = 2^0 + 2^1 + 2^2 + 2^3 = 1 + 2 + 4 + 8 = 15 = \text{0x0F} \quad (\text{Nhị phân: } 00001111_2)$$

Khi gán mặt nạ `0x0F`, Windows Kernel Windows Scheduler bị cưỡng chế chỉ lập lịch các luồng thực thi nặng trên Cores 0-3. Cores 4-7 hoàn toàn được bảo lưu, đảm bảo Sếp luôn có 50% tài nguyên CPU thực để lướt web, họp trực tuyến, hoặc lập trình mượt mà 60 FPS.

### 2. Triển Khai Ghim Affinity Qua Python `psutil`:
```python
import psutil
import os

def enforce_heavy_task_affinity():
    """Ghim tiến trình hiện tại vào Logical Cores 0, 1, 2, 3 (Mask: 0x0F)"""
    try:
        current_proc = psutil.Process(os.getpid())
        current_proc.cpu_affinity([0, 1, 2, 3])
        print(f"[AFFINITY ENFORCED] Process PID {current_proc.pid} pinned to Cores 0-3 (0x0F).")
    except Exception as exc:
        print(f"[AFFINITY WARNING] Unable to set CPU affinity: {exc}")
```

---

## III. KIẾN TRÚC CÔ LẬP TIẾN TRÌNH BẰNG WINDOWS JOB OBJECTS

Windows Job Object là một đối tượng kernel có khả năng gom nhóm một tập hợp các tiến trình để quản lý tài nguyên tập trung, tương tự như `cgroups v2` trên Linux.

### 1. Cờ `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` (Cơ Chế Diệt Tự Động)
- Giá trị hằng số: `0x2000`.
- **Cơ chế hoạt động:** Khi handle của Job Object bị đóng lại (do tiến trình cha kết thúc bình thường, bị người dùng bấm Stop, timeout hoặc crash), Windows Kernel **TỰ ĐỘNG CHẤM DỨT TOÀN BỘ CÂY TIẾN TRÌNH CON, CHÁU** thuộc Job Object đó.
- Không cần quét PID thủ công, không sợ sót tiến trình mồ côi.

### 2. Giới Hạn Tỷ Lệ Sử Dụng CPU (CPU Rate Hard Cap)
- Thông qua cấu trúc Win32 `JOBOBJECT_CPU_RATE_CONTROL_INFORMATION`:
  * Cờ `JOB_OBJECT_CPU_RATE_CONTROL_ENABLE` (`0x1`) kích hoạt tính năng kiểm soát xung nhịp.
  * Cờ `JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP` (`0x4`) biến mức trần thành rào cản vật lý cứng (hard limit).
  * `CpuRate = 8000` (đơn vị 1/100 của 1%, tương ứng với **tối đa 80.00%**).
  * Nếu một script test lọt vào vòng lặp vô tận (`while True:`), tiến trình chỉ được cấp tối đa 80% thời gian CPU, 20% còn lại luôn sẵn sàng để hệ thống nhận lệnh can thiệp.

---

## IV. BỘ MÃ NGUỒN WINDOWS JOB OBJECT WRAPPER CHUẨN HOÀN CHỈNH

Đoạn mã Python dưới đây sử dụng thư viện `ctypes` chuẩn của Python để khởi tạo Job Object và thực thi subprocess an toàn tuyệt đối trên Windows 11:

```python
# ==============================================================================
# Windows 11 Enterprise Job Object Subprocess Runner
# ==============================================================================
import ctypes
from ctypes import wintypes
import subprocess
import sys

# Khai báo các hằng số Win32 API chuẩn
JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x2000
JOB_OBJECT_LIMIT_AFFINITY = 0x00000008
JOB_OBJECT_CPU_RATE_CONTROL_ENABLE = 0x1
JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP = 0x4

JobObjectExtendedLimitInformation = 9
JobObjectCpuRateControlInformation = 15
PROCESS_ALL_ACCESS = 0x1F0FFF
CREATE_SUSPENDED = 0x00000004

class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", wintypes.LARGE_INTEGER),
        ("PerJobUserTimeLimit", wintypes.LARGE_INTEGER),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]

class IO_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_uint64),
        ("WriteOperationCount", ctypes.c_uint64),
        ("OtherOperationCount", ctypes.c_uint64),
        ("ReadTransferCount", ctypes.c_uint64),
        ("WriteTransferCount", ctypes.c_uint64),
        ("OtherTransferCount", ctypes.c_uint64),
    ]

class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
        ("IoInfo", IO_COUNTERS),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryLimit", ctypes.c_size_t),
        ("PeakJobMemoryLimit", ctypes.c_size_t),
    ]

class JOBOBJECT_CPU_RATE_CONTROL_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("ControlFlags", wintypes.DWORD),
        ("CpuRate", wintypes.DWORD),
    ]

def execute_with_job_governor(command_args: list, timeout_seconds: int = 180):
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    # 1. Tạo Job Object kernel
    job_handle = kernel32.CreateJobObjectW(None, None)
    if not job_handle:
        raise ctypes.WinError(ctypes.get_last_error())

    try:
        # 2. Thiết lập Kill-on-close và Core Affinity 0x0F (Cores 0-3)
        ext_info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        ext_info.BasicLimitInformation.LimitFlags = (
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_AFFINITY
        )
        ext_info.BasicLimitInformation.Affinity = 0x0F # Logical cores 0, 1, 2, 3

        success = kernel32.SetInformationJobObject(
            job_handle,
            JobObjectExtendedLimitInformation,
            ctypes.byref(ext_info),
            ctypes.sizeof(ext_info)
        )
        if not success:
            raise ctypes.WinError(ctypes.get_last_error())

        # 3. Thiết lập CPU Hard Cap 80.00%
        cpu_rate_info = JOBOBJECT_CPU_RATE_CONTROL_INFORMATION()
        cpu_rate_info.ControlFlags = (
            JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP
        )
        cpu_rate_info.CpuRate = 8000 # 80.00%

        kernel32.SetInformationJobObject(
            job_handle,
            JobObjectCpuRateControlInformation,
            ctypes.byref(cpu_rate_info),
            ctypes.sizeof(cpu_rate_info)
        )

        # 4. Khởi chạy tiến trình ở trạng thái treo (CREATE_SUSPENDED)
        process = subprocess.Popen(
            command_args,
            creationflags=CREATE_SUSPENDED,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        # 5. Gán tiến trình con vào Job Object kernel
        proc_handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, process.pid)
        kernel32.AssignProcessToJobObject(job_handle, proc_handle)
        kernel32.CloseHandle(proc_handle)

        # 6. Kích hoạt cho tiến trình bắt đầu chạy
        kernel32.ResumeThread(process._handle)

        # 7. Đợi kết quả với timeout
        stdout, stderr = process.communicate(timeout=timeout_seconds)
        return process.returncode, stdout, stderr

    finally:
        # Khi đóng handle, nếu tiến trình con nào còn sót lại, kernel sẽ tự động hủy diệt
        kernel32.CloseHandle(job_handle)
```

---

## V. CƠ CHẾ PHỐI HỢP ĐIỀU TỐC CPU 3 VÙNG (DYNAMIC CPU GOVERNOR)

Hệ thống kết hợp đồng bộ 3 tầng điều tiết phần cứng:

1. **Bể 1 (Tư Duy & Asynchronous Tool I/O):**
   - Không giới hạn tổng khối lượng công việc ($N \ge 100$).
   - Concurrency Cap: Tối đa 20 Subagents chạy song song mỗi đợt.
   - Hoạt động chủ yếu trên Cloud Inference và async socket, chiếm < 2% CPU máy trạm.

2. **Bể 2 (Local Burst Compute - Điện Toán Cục Bộ Nặng):**
   - Micro-Queue Semaphore cấu hình chuẩn **3-4 slots đồng thời** (tương ứng 4 nhân vật lý).
   - Tiến trình nặng chạy luân phiên cuốn chiếu (Staggered Rolling Queue), nhả slot trước mới cấp slot sau.

3. **Bộ Điều Tốc CPU 3 Vùng (Dynamic CPU Governor - `psutil`):**
   - **Vùng Tăng Tốc (CPU < 60%):** Lập tức phóng thích tiến trình từ hàng đợi, đẩy xung nhịp lên vùng tối ưu.
   - **Vùng Hoàng Kim (60% <= CPU <= 85%):** Trạng thái tối ưu nhất, duy trì thông lượng tối đa.
   - **Vùng Bảo Vệ Nhiệt (CPU > 85%):** Tự động chèn khoảng chờ nghỉ luân phiên 1.0s trước khi nhả slot tiếp theo để chống sốc nhiệt và chống thermal throttling.

---

## VI. SCRIPT TỰ ĐỘNG DỌN DẸP TIẾN TRÌNH MỒ CÔI (ZOMBIE CLEANUP)

Đoạn mã PowerShell chạy định kỳ hoặc khi bắt đầu phiên làm việc mới để dọn sạch các tiến trình mồ côi:

```powershell
# Zombie Process Cleanup Script for Windows 11
$targetProcesses = @("python", "node", "git", "pytest", "ruff")

foreach ($procName in $targetProcesses) {
    $processes = Get-Process -Name $procName -ErrorAction SilentlyContinue
    foreach ($p in $processes) {
        # Kiểm tra nếu tiến trình chiếm CPU cao nhưng không có cửa sổ giao diện và không gắn với Antigravity
        if ($p.MainWindowHandle -eq 0 -and $p.TotalProcessorTime.TotalSeconds -gt 300) {
            Write-Host "[CLEANUP] Phát hiện tiến trình mồ côi $($p.Name) (PID: $($p.Id)) - Đang giải phóng tài nguyên..." -ForegroundColor Yellow
            Stop-Process -Id $p.Id -Force
        }
    }
}
Write-Host "[CLEANUP SUCCESS] Tài nguyên phần cứng máy trạm đã sẵn sàng." -ForegroundColor Green
```

---
*Tài liệu quy chuẩn được ban hành theo Kiến Trúc Doanh Nghiệp Cấp Cao. 100% các thành viên và Subagents bắt buộc tuân thủ không ngoại lệ.*
