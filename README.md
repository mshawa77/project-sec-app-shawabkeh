# Secure Web Application

A comprehensive full-stack secure web application demonstrating enterprise-grade security features including AES encryption, Role-Based Access Control (RBAC), and comprehensive security measures.

## 🛡️ Security Features

### Authentication & Authorization
- **Secure Authentication**: bcrypt password hashing with salt
- **Role-Based Access Control (RBAC)**: Separate views for Admin and User roles
- **Session Management**: Secure HTTP-only cookies with session expiration
- **Account Lockout**: Automatic lockout after 5 failed login attempts (15 minutes)

### Data Protection
- **AES-256 Encryption**: Military-grade encryption for sensitive data (secret notes)
- **Input Validation**: Comprehensive validation using Pydantic models
- **XSS Protection**: HTML sanitization and Content Security Policy
- **SQL Injection Prevention**: Parameterized queries and input sanitization

### Security Headers & Infrastructure
- **Security Headers**: CSP, X-Frame-Options, X-Content-Type-Options, HSTS
- **Trusted Host**: Host validation middleware
- **Audit Logging**: Complete security event tracking
- **Rate Limiting**: Protection against brute force attacks

## 🏗️ Project Structure

```
secure-web-app/
├── main.py              # FastAPI application with routes and middleware
├── database.py          # SQLite database management and models
├── security.py          # AES encryption, password hashing, security utilities
├── requirements.txt     # Python dependencies
├── templates/           # HTML templates with Bootstrap styling
│   ├── index.html       # Landing page
│   ├── login.html       # User login page
│   ├── register.html    # User registration page
│   ├── dashboard.html   # User dashboard with encrypted notes
│   └── admin.html       # Admin panel (RBAC protected)
├── docs/               # Security documentation
│   ├── STRIDE_Threat_Model.md
│   └── DREAD_Risk_Assessment.md
├── static/             # Static files (CSS, JS, images)
└── secure_app.db       # SQLite database (created automatically)
└── encryption.key      # AES encryption key (created automatically)
```

## 🚀 Quick Start (Rubric: Setup Instructions)

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Installation

1. **Clone or download the project**
   ```bash
   # If using git
   git clone <repository-url>
   cd secure-web-app
   ```

2. **Set up environment variables**
   ```bash
   # Copy environment template
   cp .env.example .env
   
   # Edit .env with your secure values
   # Generate SECRET_KEY: python -c "import secrets; print(secrets.token_urlsafe(32))"
   # Generate ENCRYPTION_KEY: python -c "import os; print(os.urandom(32).hex())"
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the application**
   ```bash
   python main.py
   ```

5. **Access the application**
   - Main application: `http://localhost:8000`
   - Security Dashboard: `http://localhost:8000/security-dashboard`
   - API documentation: `http://localhost:8000/docs`

### Default Credentials (Rubric: Demo Accounts)
- **Admin User**: `admin` / `Admin123!@#`
- **Regular Users**: Register through the registration page
- **Demo Accounts**: `mohammadshawabekh`, `ahmadsrahan`, `mohammed_shuwabkeh` (password: username + "123!")

### Default Credentials
- **Admin User**: `admin` / `Admin123!@#`
- **Regular Users**: Register through the registration page

## � Security Implementations (Rubric: Security Features)

### Authentication & Session Management (Rubric: Authentication)
```python
# bcrypt password hashing with salt
salt = bcrypt.gensalt()
hashed = bcrypt.hashpw(password.encode('utf-8'), salt)

# Secure session tokens
session_id = secrets.token_urlsafe(32)
sessions[session_id] = {"user_id": user.id, "role": user.role}
```

### Role-Based Access Control (Rubric: Authorization)
```python
def require_admin(request: Request) -> User:
    user = require_auth(request)
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    return user
```

### AES-256 Data Encryption (Rubric: Data Encryption At Rest)
```python
def encrypt_data(self, data: str) -> str:
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(self.encryption_key), modes.CBC(iv))
    encrypted_data = cipher.encryptor().update(padded_data) + cipher.encryptor().finalize()
    return base64.b64encode(iv + encrypted_data).decode('utf-8')
```

### Input Validation & XSS Protection (Rubric: Input Validation)
```python
def sanitize_html(input_string: str) -> str:
    html_escape_table = {"&": "&amp;", "<": "&lt;", ">": "&gt;"}
    return "".join(html_escape_table.get(c, c) for c in input_string)
```

### Security Headers (Rubric: Security Headers)
```python
security_headers = {
    "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "X-XSS-Protection": "1; mode=block"
}
```

## �📱 Application Features

### User Features
- **Secure Registration**: Password strength validation and email verification
- **Encrypted Secret Notes**: Create and manage notes with AES-256 encryption
- **Dashboard**: View encrypted vs decrypted data demonstration
- **Session Management**: Secure logout and session timeout

### Admin Features
- **User Management**: View, search, and manage all user accounts
- **Account Lockout**: Monitor and manage locked accounts
- **System Statistics**: Real-time user and security metrics
- **Audit Trail**: View security events and user activities

### Security Demonstrations
- **Encryption Visualization**: See encrypted vs decrypted data side-by-side
- **Security Headers**: View implemented security measures
- **Audit Logging**: Complete security event tracking
- **RBAC Enforcement**: Role-based access control demonstration

## 🔧 Configuration

### Environment Variables (Optional)
```bash
# Database location (default: secure_app.db)
DATABASE_PATH="secure_app.db"

# Session duration in hours (default: 2)
SESSION_DURATION_HOURS=2

# Maximum login attempts before lockout (default: 5)
MAX_LOGIN_ATTEMPTS=5

# Lockout duration in minutes (default: 15)
LOCKOUT_DURATION_MINUTES=15
```

### Production Deployment
For production deployment, ensure:
1. **HTTPS**: Enable SSL/TLS encryption
2. **Environment Variables**: Use environment variables for sensitive configuration
3. **Database Security**: Use PostgreSQL or MySQL with proper encryption
4. **Key Management**: Use a dedicated key management service
5. **Monitoring**: Implement comprehensive logging and monitoring

## 🔒 Security Implementation Details

### AES Encryption
- **Algorithm**: AES-256-CBC
- **Key Management**: Local key file with restricted permissions
- **Data Protection**: Secret notes encrypted before database storage
- **Key Storage**: `encryption.key` file with 600 permissions

### Password Security
- **Hashing**: bcrypt with automatic salt generation
- **Strength Requirements**: 8+ chars, uppercase, lowercase, numbers, special chars
- **Storage**: Only hashes stored, never plain passwords

### Session Management
- **Tokens**: Cryptographically secure session IDs
- **Cookies**: HTTP-only, secure, same-site=strict
- **Expiration**: 2-hour session timeout
- **Invalidation**: Manual logout and automatic cleanup

### Input Validation
- **Pydantic Models**: Type validation and serialization
- **XSS Protection**: HTML escaping and sanitization
- **SQL Injection**: Parameterized queries
- **File Upload**: Type and size validation (if implemented)

## 📊 Security Documentation

### STRIDE Threat Model
- **Location**: `docs/STRIDE_Threat_Model.md`
- **Content**: Comprehensive threat analysis using STRIDE methodology
- **Coverage**: Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege

### DREAD Risk Assessment
- **Location**: `docs/DREAD_Risk_Assessment.md`
- **Content**: Quantified risk assessment with DREAD scoring
- **Coverage**: Damage, Reproducibility, Exploitability, Affected Users, Discoverability

## 🧪 Testing

### Security Testing
```bash
# Test authentication endpoints
curl -X POST "http://localhost:8000/login" -H "Content-Type: application/x-www-form-urlencoded" -d "username=admin&password=Admin123!@#"

# Test security headers
curl -I "http://localhost:8000/"

# Test API endpoints
curl "http://localhost:8000/security-info"
curl "http://localhost:8000/health"
```

### Manual Testing Checklist
- [ ] Registration with weak passwords (should fail)
- [ ] Login with incorrect credentials (should fail)
- [ ] Access admin panel as regular user (should fail)
- [ ] XSS injection attempts (should be sanitized)
- [ ] Session hijacking attempts (should fail)
- [ ] Direct URL access without authentication (should fail)

## 🐛 Troubleshooting

### Common Issues

1. **Database Connection Error**
   ```bash
   # Check if database file exists
   ls -la secure_app.db
   
   # Recreate database
   rm secure_app.db
   python main.py
   ```

2. **Encryption Key Error**
   ```bash
   # Check encryption key permissions
   ls -la encryption.key
   
   # Regenerate key (will lose existing encrypted data)
   rm encryption.key
   python main.py
   ```

3. **Port Already in Use**
   ```bash
   # Kill existing process
   lsof -ti:8000 | xargs kill -9
   
   # Or use different port
   python main.py --port 8001
   ```

### Logging
- **Application Logs**: Console output during development
- **Security Events**: Stored in `audit_log` database table
- **Error Messages**: Generic for users, detailed for logs

## 🚀 API Endpoints

### Public Endpoints
- `GET /` - Landing page
- `GET /login` - Login page
- `GET /register` - Registration page
- `POST /login` - Authentication
- `POST /register` - User creation

### Protected Endpoints (Authentication Required)
- `GET /dashboard` - User dashboard
- `POST /dashboard/update-note` - Update secret note
- `GET /logout` - Session termination

### Admin Endpoints (Admin Role Required)
- `GET /admin` - Admin panel
- `POST /admin/delete-user/{user_id}` - Delete user

### Utility Endpoints
- `GET /health` - System health check
- `GET /security-info` - Security features information

## 🔄 Development

### Adding New Features
1. **Security First**: Always consider security implications
2. **Input Validation**: Use Pydantic models for all inputs
3. **Authorization**: Implement proper role-based access control
4. **Logging**: Add security event logging for sensitive operations
5. **Testing**: Include security testing in development process

### Code Style
- **Python**: Follow PEP 8 guidelines
- **Security**: Use secure coding practices
- **Documentation**: Comment security-critical code
- **Error Handling**: Generic errors for users, detailed for logs

## 📈 Performance Considerations

### Database Optimization
- **Indexes**: Proper indexing on frequently queried columns
- **Connection Pooling**: Database connection management
- **Query Optimization**: Efficient SQL queries

### Security vs Performance
- **Encryption**: Minimal performance impact with AES-256
- **Validation**: Input validation overhead is minimal
- **Logging**: Asynchronous logging for better performance
- **Session Management**: Memory-efficient session storage

## 🌟 Future Enhancements

### Short-term (Next 3 months)
- [ ] Multi-Factor Authentication (MFA)
- [ ] Advanced rate limiting
- [ ] Email verification for registration
- [ ] Password reset functionality

### Medium-term (6 months)
- [ ] Two-Factor Authentication (2FA)
- [ ] Advanced audit dashboard
- [ ] API rate limiting per user
- [ ] Database encryption at rest

### Long-term (1 year)
- [ ] Zero-trust architecture
- [ ] Advanced threat detection
- [ ] Security automation
- [ ] Compliance reporting

## 📞 Support

### Security Issues
For security vulnerabilities or concerns:
1. Do not create public issues
2. Email security details to: security@example.com
3. Include detailed reproduction steps
4. Allow reasonable time for response

### General Issues
- **Documentation**: Check this README and docs folder
- **Common Issues**: See troubleshooting section
- **Feature Requests**: Create GitHub issues with detailed descriptions

## 📄 License

This project is for educational purposes to demonstrate security best practices. Use responsibly and in accordance with applicable laws and regulations.

## 🙏 Acknowledgments

- **OWASP**: For security best practices and guidelines
- **FastAPI**: For the modern web framework
- **Bootstrap**: For responsive UI components
- **Cryptography.io**: For AES encryption implementation

---

**⚠️ Important**: This is a demonstration project. For production use, conduct a thorough security assessment and implement additional security measures as needed.

**🔐 Built for**: Application Security Project Demonstration
**👥 By**: Secure Development Team
**📅 Version**: 1.0.0
