import tempfile
from pathlib import Path
from tool_version_registry import ToolVersionRegistry, Version

def run_tests():
    with tempfile.TemporaryDirectory() as tmpdir:
        reg_file = Path(tmpdir) / "test_reg.json"
        registry = ToolVersionRegistry(reg_file)

        # TEST 1: UTF-8 Encoding (Tiếng Việt & Unicode)
        registry.register_tool("công_cụ_phân_tích", "1.0.0", metadata={"mô_tả": "Hỗ trợ đa ngôn ngữ 🚀"})
        reloaded_reg = ToolVersionRegistry(reg_file)
        tool = reloaded_reg.get_tool("công_cụ_phân_tích")
        assert tool is not None
        assert tool.metadata["mô_tả"] == "Hỗ trợ đa ngôn ngữ 🚀"
        print("✅ TEST 1 PASSED: UTF-8 encoding an toàn trên Windows!")

        # TEST 2: Bảo tồn path và checksum khi update phiên bản không truyền path
        test_bin = Path(tmpdir) / "dummy.exe"
        test_bin.write_bytes(b"A" * 1000)
        registry.register_tool("sample_tool", "1.0.0", installed_path=test_bin)
        
        saved_tool = registry.get_tool("sample_tool")
        initial_path = saved_tool.installed_path
        initial_checksum = saved_tool.checksum
        assert initial_path == str(test_bin)
        assert initial_checksum is not None

        # Update phiên bản mà KHÔNG truyền installed_path
        registry.register_tool("sample_tool", "1.0.1")
        updated_tool = registry.get_tool("sample_tool")
        assert updated_tool.installed_path == initial_path, "Lỗi: installed_path bị xóa trắng!"
        assert updated_tool.checksum == initial_checksum, "Lỗi: checksum bị xóa trắng!"
        print("✅ TEST 2 PASSED: Path và Checksum được bảo tồn an toàn!")

        # TEST 3: Không ghi đè vết lịch sử khi vừa bump version vừa đổi checksum
        test_bin.write_bytes(b"B" * 2000) # Thay đổi tệp nhị phân
        registry.register_tool("sample_tool", "1.1.0") # Vừa bump version vừa checksum mismatch
        
        changes = registry.get_changes_for_tool("sample_tool")
        change_types = [c.change_type for c in changes]
        assert "version_bump" in change_types, "Lỗi: version_bump bị ghi đè mất dấu!"
        assert "checksum_mismatch" in change_types, "Lỗi: checksum_mismatch bị mất dấu!"
        print("✅ TEST 3 PASSED: Lưu đầy đủ cả version_bump và checksum_mismatch trong history!")

        # TEST 4: Chunked Hashing (OOM Guard)
        large_file = Path(tmpdir) / "large.bin"
        large_file.write_bytes(b"Z" * (256 * 1024))
        h = registry._compute_checksum(large_file)
        assert len(h) == 64
        print("✅ TEST 4 PASSED: Chunked buffer hashing hoạt động hoàn hảo!")

if __name__ == "__main__":
    run_tests()