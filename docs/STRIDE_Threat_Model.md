# STRIDE Threat Model Analysis

## Overview
This document analyzes potential security threats to the Secure Web Application using the STRIDE methodology. The analysis helps identify and mitigate security risks across the application architecture.

## STRIDE Categories

### **S**poofing Threats

#### 1. User Identity Spoofing
- **Threat**: Attacker impersonates legitimate user to gain unauthorized access
- **Risk Level**: Medium
- **Mitigation**:
  - Secure session-based authentication with HTTP-only cookies
  - bcrypt password hashing with salt
  - Session timeout and invalidation
  - Multi-factor authentication (future enhancement)
  - Account lockout after failed attempts

#### 2. Admin Role Spoofing
- **Threat**: Attacker gains administrative privileges
- **Risk Level**: High
- **Mitigation**:
  - Role-Based Access Control (RBAC) implementation
  - Server-side role validation for all admin endpoints
  - Secure session management with role verification
  - Admin action logging and audit trails

#### 3. API Endpoint Spoofing
- **Threat**: Attacker masquerades as legitimate API client
- **Risk Level**: Medium
- **Mitigation**:
  - Request validation and sanitization
  - CSRF protection for state-changing operations
  - Origin and referrer header validation
  - API rate limiting

### **T**ampering Threats

#### 1. Data Tampering
- **Threat**: Unauthorized modification of user data or secret notes
- **Risk Level**: High
- **Mitigation**:
  - AES-256 encryption for sensitive data at rest
  - Database integrity checks
  - Input validation and sanitization
  - Audit logging for all data modifications
  - Database connection encryption (TLS)

#### 2. Session Tampering
- **Threat**: Manipulation of session cookies or tokens
- **Risk Level**: Medium
- **Mitigation**:
  - Cryptographically secure session tokens
  - HTTP-only and secure cookie attributes
  - SameSite cookie policy
  - Session validation on each request

#### 3. HTTP Header Tampering
- **Threat**: Modification of request headers for bypassing security
- **Risk Level**: Low
- **Mitigation**:
  - Server-side validation of critical headers
  - Security headers implementation (CSP, X-Frame-Options)
  - Trusted host middleware

### **R**epudiation Threats

#### 1. Action Repudiation
- **Threat**: User denies performing actions (e.g., deleting data)
- **Risk Level**: Medium
- **Mitigation**:
  - Comprehensive audit logging system
  - User action tracking with timestamps
  - IP address and user agent logging
  - Immutable audit trail (append-only)

#### 2. Data Modification Repudiation
- **Threat**: User denies modifying their secret notes
- **Risk Level**: Low
- **Mitigation**:
  - Change history tracking
  - User attribution for all modifications
  - Timestamped audit entries
  - Backup and recovery mechanisms

### **I**nformation Disclosure Threats

#### 1. Data Breach
- **Threat**: Unauthorized access to user data and secret notes
- **Risk Level**: High
- **Mitigation**:
  - AES-256 encryption for sensitive data
  - Secure database access controls
  - Principle of least privilege
  - Data masking in logs and error messages

#### 2. Credential Disclosure
- **Threat**: Exposure of user passwords or session tokens
- **Risk Level**: High
- **Mitigation**:
  - bcrypt password hashing (never store plain passwords)
  - Secure session token generation
  - HTTPS enforcement in production
  - Secure cookie attributes

#### 3. Error Information Disclosure
- **Threat**: Error messages reveal sensitive system information
- **Risk Level**: Medium
- **Mitigation**:
  - Generic error messages for users
  - Detailed error logging for administrators
  - Custom error pages
  - Stack trace protection

#### 4. Directory Traversal
- **Threat**: Access to files outside web root
- **Risk Level**: Low
- **Mitigation**:
  - Secure file path validation
  - Static file serving restrictions
  - Proper directory permissions
  - Input sanitization

### **D**enial of Service Threats

#### 1. Resource Exhaustion
- **Threat**: Attacker overwhelms system resources
- **Risk Level**: Medium
- **Mitigation**:
  - Request rate limiting
  - Connection timeout management
  - Resource usage monitoring
  - Database connection pooling

#### 2. Authentication Flooding
- **Threat**: Brute force attacks on login endpoints
- **Risk Level**: Medium
- **Mitigation**:
  - Account lockout after failed attempts
  - Login rate limiting
  - CAPTCHA integration (future enhancement)
  - IP-based blocking

#### 3. Database Exhaustion
- **Threat**: Overwhelming database with requests
- **Risk Level**: Low
- **Mitigation**:
  - Database query optimization
  - Connection pooling
  - Query timeout limits
  - Database monitoring

### **E**levation of Privilege Threats

#### 1. Privilege Escalation
- **Threat**: User gains higher privileges than intended
- **Risk Level**: High
- **Mitigation**:
  - Strict RBAC implementation
  - Server-side role validation
  - Minimal privilege principle
  - Regular privilege audits

#### 2. Admin Access Compromise
- **Threat**: Attacker gains administrative control
- **Risk Level**: Critical
- **Mitigation**:
  - Strong admin password requirements
  - Separate admin accounts
  - Admin session timeout
  - Admin action logging and monitoring

#### 3. Database Privilege Escalation
- **Threat**: Gaining elevated database access
- **Risk Level**: Medium
- **Mitigation**:
  - Limited database user permissions
  - Separate database users for different functions
  - Stored procedures for sensitive operations
  - Database access logging

## Threat Prioritization

### Critical (Immediate Action Required)
1. **Admin Access Compromise** - Could compromise entire system
2. **Data Breach** - Sensitive user data exposure
3. **Privilege Escalation** - Unauthorized system control

### High (Address Soon)
1. **User Identity Spoofing** - Unauthorized account access
2. **Data Tampering** - Integrity of user information
3. **Credential Disclosure** - Password and session exposure

### Medium (Plan to Address)
1. **Information Disclosure** - System information leakage
2. **Denial of Service** - System availability
3. **Action Repudiation** - Audit trail integrity

### Low (Monitor and Maintain)
1. **API Endpoint Spoofing** - Limited attack surface
2. **HTTP Header Tampering** - Minimal impact
3. **Directory Traversal** - Well-mitigated

## Security Controls Implemented with Code Mappings

### Authentication Controls (Rubric: Authentication & Password Hashing)
- ✅ **bcrypt password hashing with salt** 
  - Code: `security.py:hash_password()` and `security.py:verify_password()`
  - Implementation: `salt = bcrypt.gensalt(); hashed = bcrypt.hashpw(password.encode('utf-8'), salt)`
- ✅ **Secure session management**
  - Code: `main.py:create_session()` and `main.py:get_session_user()`
  - Implementation: `session_id = secrets.token_urlsafe(32); sessions[session_id] = {...}`
- ✅ **Account lockout protection**
  - Code: `database.py:increment_login_attempts()`
  - Implementation: `if new_attempts >= 5: lockout_time = datetime.now() + timedelta(minutes=15)`
- ✅ **Session timeout management**
  - Code: `main.py:get_session_user()` expiration check
  - Implementation: `if datetime.now() - session["last_activity"] > SESSION_DURATION: del sessions[session_id]`

### Authorization Controls (Rubric: Role-Based Access Control)
- ✅ **Role-Based Access Control (RBAC)**
  - Code: `main.py:require_admin()` decorator
  - Implementation: `if user.role != "admin": raise HTTPException(status_code=403)`
- ✅ **Server-side role validation**
  - Code: `main.py:admin_panel()` endpoint
  - Implementation: `admin_user = require_admin(request)`
- ✅ **Admin-only endpoint protection**
  - Code: `main.py:@app.get("/admin")` with RBAC
  - Implementation: `@app.get("/admin")` with `require_admin()` validation
- ✅ **Least privilege principle**
  - Code: Database schema with role-based permissions
  - Implementation: `CREATE TABLE users (role TEXT DEFAULT 'user')`

### Data Protection Controls (Rubric: Data Encryption At Rest)
- ✅ **AES-256 encryption for sensitive data**
  - Code: `security.py:encrypt_data()` and `security.py:decrypt_data()`
  - Implementation: `cipher = Cipher(algorithms.AES(self.encryption_key), modes.CBC(iv))`
- ✅ **Secure database access controls**
  - Code: `database.py:Database` class with parameterized queries
  - Implementation: `cursor.execute("SELECT * FROM users WHERE username = ?", (username,))`
- ✅ **Principle of least privilege**
  - Code: `main.py:require_auth()` and `main.py:require_admin()`
  - Implementation: Role-based access control with server-side validation
- ✅ **Data masking in logs and error messages**
  - Code: `main.py:sanitize_html()` function
  - Implementation: `html_escape_table = {"&": "&amp;", "<": "&lt;", ">": "&gt"}`

### Infrastructure Controls (Rubric: Security Headers & Input Validation)
- ✅ **Security headers implementation**
  - Code: `security.py:SecurityHeaders` class
  - Implementation: `response.headers["Content-Security-Policy"] = "default-src 'self'..."`
- ✅ **Trusted host validation**
  - Code: `main.py` TrustedHostMiddleware
  - Implementation: `app.add_middleware(TrustedHostMiddleware, allowed_hosts=["localhost", "127.0.0.1"])`
- ✅ **Request rate limiting**
  - Code: `database.py:increment_login_attempts()` lockout mechanism
  - Implementation: Account lockout after 5 failed attempts for 15 minutes
- ✅ **Comprehensive audit logging**
  - Code: `database.py:log_security_event()` method
  - Implementation: `cursor.execute("INSERT INTO audit_log (user_id, action, ...) VALUES (?, ?, ...)"`

## Monitoring and Detection

### Real-time Monitoring
- Failed login attempts tracking
- Unusual access pattern detection
- Admin action monitoring
- System resource usage

### Alerting
- Account lockout notifications
- Admin privilege usage alerts
- Security event logging
- System health monitoring

## Future Enhancements

### Short-term (Next 3 months)
- Multi-factor authentication (MFA)
- Advanced rate limiting
- IP-based geo-blocking
- Security scanning automation

### Long-term (6-12 months)
- Zero-trust architecture
- Advanced threat detection
- Security information and event management (SIEM)
- Regular penetration testing

## Conclusion

The STRIDE threat model analysis identifies key security risks and provides a comprehensive mitigation strategy. The implemented controls address the most critical threats while maintaining system usability. Regular security assessments and updates are essential to maintain security posture against evolving threats.

## References

- OWASP Top 10 Web Application Security Risks
- NIST Cybersecurity Framework
- Microsoft STRIDE Threat Modeling
- ISO 27001 Security Standards
