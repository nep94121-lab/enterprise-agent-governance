# PROGRAMMING SAFETY RELAYS SPECIFICATION (SSOT)

## 1. Overview
This document outlines the safety relays and circuit breakers for Domain A to prevent infinite loops, RAM overflow, CPU spikes, cascading failures, and lock timeouts.

## 2. Relay Breakers
1. **Infinite Loop Breaker:** Limits the maximum iterations of critical loops.
2. **RAM Overflow Guard:** Tracks memory usage. Triggers when usage exceeds 85% limit.
3. **CPU Spike Arrester:** Pauses execution if CPU usage remains above 90% for a sustained period.
4. **Cascade Failure Preventer:** Circuit breaker pattern that trips after multiple failures.
5. **Lock Timeout:** Maximum wait time for acquiring system locks (e.g., 5 seconds) to prevent deadlocks.
