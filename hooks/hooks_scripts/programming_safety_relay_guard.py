"""
Hook Script: Integrates the Safety Relays Framework into the system.
"""
import sys
import psutil
import logging
from hook_utils.safety_relays import SafetyRelayException

logger = logging.getLogger(__name__)

def check_system_resources(max_cpu_percent=90.0, max_ram_percent=85.0):
    """
    Checks system resources and throws SafetyRelayException if thresholds are exceeded.
    """
    cpu_usage = psutil.cpu_percent(interval=0.1)
    if cpu_usage > max_cpu_percent:
        raise SafetyRelayException(f"CPU spike detected: {cpu_usage}% exceeds limit {max_cpu_percent}%")
    
    ram_usage = psutil.virtual_memory().percent
    if ram_usage > max_ram_percent:
        raise SafetyRelayException(f"RAM overflow detected: {ram_usage}% exceeds limit {max_ram_percent}%")

def pre_execution_guard(*args, **kwargs):
    """
    Called before a task is executed to ensure safe resource limits.
    """
    try:
        check_system_resources()
    except SafetyRelayException as e:
        logger.error(f"Pre-execution safety check failed: {e}")
        raise
    return True
