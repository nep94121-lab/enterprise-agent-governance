# ADVERSARIAL ATTACK TESTING SPEC

## 1. Mục Tiêu
Domain B chịu trách nhiệm tấn công và thử nghiệm các rơ-le phòng thủ của Domain A (bảo mật, input validation).

## 2. Các Vector Tấn Công
1. SQL Injection (SQLi)
2. OS Command Injection
3. Prompt Injection
4. Path Traversal

## 3. Quy Định
- Test suite sử dụng mock relay/hooks để verify.
- Tuyệt đối cấm hardcode credentials.
- Test phải độc lập và chứng minh được rơ-le đã chặn đợt tấn công hiệu quả.
