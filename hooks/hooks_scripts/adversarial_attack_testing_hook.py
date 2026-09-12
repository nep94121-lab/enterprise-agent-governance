import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("AdversarialHook")

class AdversarialHook:
    """Mô phỏng đợt tấn công và bắt lỗi/log"""
    
    def simulate_sqli(self, payload: str):
        logger.info(f"Simulating SQLi: {payload}")
        if "DROP" in payload.upper() or "OR 1=1" in payload.upper():
            return {"status": "BLOCKED", "reason": "SQL Injection detected"}
        return {"status": "PASSED"}
        
    def simulate_os_injection(self, payload: str):
        logger.info(f"Simulating OS Injection: {payload}")
        if "&&" in payload or ";" in payload:
            return {"status": "BLOCKED", "reason": "OS Command Injection detected"}
        return {"status": "PASSED"}
        
    def simulate_prompt_injection(self, payload: str):
        logger.info(f"Simulating Prompt Injection: {payload}")
        if "ignore previous instructions" in payload.lower():
            return {"status": "BLOCKED", "reason": "Prompt Injection detected"}
        return {"status": "PASSED"}
        
    def simulate_path_traversal(self, payload: str):
        logger.info(f"Simulating Path Traversal: {payload}")
        if "../" in payload:
            return {"status": "BLOCKED", "reason": "Path Traversal detected"}
        return {"status": "PASSED"}
