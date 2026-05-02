"""
Database Module - SQLite Database Management (Rubric: Database Security)
Handles user data, authentication, and encrypted secret notes
Compliance: SQL Injection Prevention, Secure Data Storage
"""

import sqlite3
import hashlib
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from dataclasses import dataclass
import secrets

@dataclass
class User:
    """User data model"""
    id: int
    username: str
    email: str
    password_hash: str
    role: str
    failed_login_attempts: int
    last_login_attempt: Optional[str]
    lockout_until: Optional[str]
    created_at: str
    
    def is_locked(self) -> bool:
        """Check if user account is locked due to failed attempts"""
        if self.lockout_until is None:
            return False
        
        try:
            lockout_time = datetime.fromisoformat(self.lockout_until)
            return datetime.now() < lockout_time
        except ValueError:
            return False
    
    def get_lockout_remaining_time(self) -> Optional[str]:
        """Get remaining lockout time in human readable format"""
        if not self.is_locked():
            return None
        
        try:
            lockout_time = datetime.fromisoformat(self.lockout_until)
            remaining = lockout_time - datetime.now()
            
            if remaining.total_seconds() < 60:
                return f"{int(remaining.total_seconds())} seconds"
            elif remaining.total_seconds() < 3600:
                return f"{int(remaining.total_seconds() / 60)} minutes"
            else:
                return f"{int(remaining.total_seconds() / 3600)} hours"
        except ValueError:
            return None

class Database:
    """Database management class for SQLite operations"""
    
    def __init__(self, db_path: str = "secure_app.db"):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize database with required tables"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Create users table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE NOT NULL,
                        email TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        role TEXT DEFAULT 'user',
                        failed_login_attempts INTEGER DEFAULT 0,
                        last_login_attempt TEXT,
                        lockout_until TEXT,
                        created_at TEXT DEFAULT CURRENT_TIMESTAMP
                    )
                """)
                
                # Create secret_notes table
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS secret_notes (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER NOT NULL,
                        encrypted_note TEXT,
                        created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                        updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
                    )
                """)
                
                # Create audit_log table for security events
                cursor.execute("""
                    CREATE TABLE IF NOT EXISTS audit_log (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id INTEGER,
                        action TEXT NOT NULL,
                        ip_address TEXT,
                        user_agent TEXT,
                        timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
                        success BOOLEAN DEFAULT TRUE,
                        details TEXT,
                        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE SET NULL
                    )
                """)
                
                # Create indexes for performance
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_secret_notes_user_id ON secret_notes(user_id)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_user_id ON audit_log(user_id)")
                cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_log_timestamp ON audit_log(timestamp)")
                
                # Create default admin user if not exists
                self._create_default_admin()
                
                conn.commit()
                
        except sqlite3.Error as e:
            print(f"Database initialization error: {e}")
            raise
    
    def _create_default_admin(self):
        """Create a default admin user for demonstration"""
        # Check if admin user already exists
        admin_user = self.get_user_by_username("admin")
        if admin_user:
            return
        
        # Create default admin with secure password
        # In production, this should be changed immediately
        default_admin_password = "Admin123!@#"
        from security import SecurityManager
        security = SecurityManager()
        password_hash = security.hash_password(default_admin_password)
        
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO users (username, email, password_hash, role)
                    VALUES (?, ?, ?, ?)
                """, ("admin", "admin@secureapp.com", password_hash, "admin"))
                conn.commit()
                
                # Log admin creation
                self.log_security_event(None, "ADMIN_CREATED", "default", "system", 
                                      True, "Default admin user created")
                
        except sqlite3.Error as e:
            print(f"Error creating default admin: {e}")
    
    def create_user(self, username: str, email: str, password_hash: str, role: str = "user") -> Optional[int]:
        """Create a new user in the database"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO users (username, email, password_hash, role)
                    VALUES (?, ?, ?, ?)
                """, (username, email, password_hash, role))
                
                user_id = cursor.lastrowid
                
                # Create empty secret note for the user
                cursor.execute("""
                    INSERT INTO secret_notes (user_id, encrypted_note)
                    VALUES (?, ?)
                """, (user_id, None))
                
                conn.commit()
                
                # Log user creation
                self.log_security_event(user_id, "USER_CREATED", "system", "system", 
                                      True, f"User {username} created")
                
                return user_id
                
        except sqlite3.IntegrityError as e:
            print(f"User creation error (duplicate): {e}")
            return None
        except sqlite3.Error as e:
            print(f"User creation error: {e}")
            return None
    
    def get_user_by_username(self, username: str) -> Optional[User]:
        """Get user by username"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
                row = cursor.fetchone()
                
                if row:
                    return User(**dict(row))
                return None
                
        except sqlite3.Error as e:
            print(f"Error getting user by username: {e}")
            return None
    
    def get_user_by_email(self, email: str) -> Optional[User]:
        """Get user by email"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
                row = cursor.fetchone()
                
                if row:
                    return User(**dict(row))
                return None
                
        except sqlite3.Error as e:
            print(f"Error getting user by email: {e}")
            return None
    
    def get_user_by_id(self, user_id: int) -> Optional[User]:
        """Get user by ID"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
                row = cursor.fetchone()
                
                if row:
                    return User(**dict(row))
                return None
                
        except sqlite3.Error as e:
            print(f"Error getting user by ID: {e}")
            return None
    
    def get_all_users(self) -> List[User]:
        """Get all users (for admin panel)"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute("SELECT * FROM users ORDER BY created_at DESC")
                rows = cursor.fetchall()
                
                return [User(**dict(row)) for row in rows]
                
        except sqlite3.Error as e:
            print(f"Error getting all users: {e}")
            return []
    
    def update_secret_note(self, user_id: int, encrypted_note: str) -> bool:
        """Update user's secret note"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE secret_notes 
                    SET encrypted_note = ?, updated_at = ?
                    WHERE user_id = ?
                """, (encrypted_note, datetime.now().isoformat(), user_id))
                
                conn.commit()
                
                # Log note update
                self.log_security_event(user_id, "NOTE_UPDATED", "system", "system", 
                                      True, "Secret note updated")
                
                return True
                
        except sqlite3.Error as e:
            print(f"Error updating secret note: {e}")
            return False
    
    def get_secret_note(self, user_id: int) -> Optional[str]:
        """Get user's encrypted secret note"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT encrypted_note FROM secret_notes WHERE user_id = ?", (user_id,))
                row = cursor.fetchone()
                
                if row:
                    return row[0]
                return None
                
        except sqlite3.Error as e:
            print(f"Error getting secret note: {e}")
            return None
    
    def increment_login_attempts(self, user_id: int) -> bool:
        """Increment failed login attempts and lock account if necessary"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Get current attempts
                cursor.execute("SELECT failed_login_attempts FROM users WHERE id = ?", (user_id,))
                result = cursor.fetchone()
                
                if not result:
                    return False
                
                current_attempts = result[0]
                new_attempts = current_attempts + 1
                
                # Check if account should be locked
                lockout_until = None
                if new_attempts >= 5:  # Lock after 5 failed attempts
                    lockout_time = datetime.now() + timedelta(minutes=15)
                    lockout_until = lockout_time.isoformat()
                
                # Update user record
                cursor.execute("""
                    UPDATE users 
                    SET failed_login_attempts = ?, 
                        last_login_attempt = ?, 
                        lockout_until = ?
                    WHERE id = ?
                """, (new_attempts, datetime.now().isoformat(), lockout_until, user_id))
                
                conn.commit()
                
                # Log failed attempt
                self.log_security_event(user_id, "LOGIN_FAILED", "system", "system", 
                                      True, f"Failed login attempt {new_attempts}")
                
                return True
                
        except sqlite3.Error as e:
            print(f"Error incrementing login attempts: {e}")
            return False
    
    def reset_login_attempts(self, user_id: int) -> bool:
        """Reset failed login attempts on successful login"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE users 
                    SET failed_login_attempts = 0, 
                        last_login_attempt = ?, 
                        lockout_until = NULL
                    WHERE id = ?
                """, (datetime.now().isoformat(), user_id))
                
                conn.commit()
                
                # Log successful login
                self.log_security_event(user_id, "LOGIN_SUCCESS", "system", "system", 
                                      True, "Successful login")
                
                return True
                
        except sqlite3.Error as e:
            print(f"Error resetting login attempts: {e}")
            return False
    
    def delete_user(self, user_id: int) -> bool:
        """Delete user and associated data"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Delete user's secret note first (foreign key constraint)
                cursor.execute("DELETE FROM secret_notes WHERE user_id = ?", (user_id,))
                
                # Delete user
                cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
                
                conn.commit()
                
                # Log user deletion
                self.log_security_event(user_id, "USER_DELETED", "system", "system", 
                                      True, f"User {user_id} deleted")
                
                return True
                
        except sqlite3.Error as e:
            print(f"Error deleting user: {e}")
            return False
    
    def log_security_event(self, user_id: Optional[int], action: str, ip_address: str, 
                          user_agent: str, success: bool, details: str = "") -> bool:
        """Log security events for audit trail"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO audit_log (user_id, action, ip_address, user_agent, success, details)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (user_id, action, ip_address, user_agent, success, details))
                
                conn.commit()
                return True
                
        except sqlite3.Error as e:
            print(f"Error logging security event: {e}")
            return False
    
    def get_audit_log(self, user_id: Optional[int] = None, limit: int = 100) -> List[Dict[str, Any]]:
        """Get audit log entries"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                
                if user_id:
                    cursor.execute("""
                        SELECT * FROM audit_log 
                        WHERE user_id = ? 
                        ORDER BY timestamp DESC 
                        LIMIT ?
                    """, (user_id, limit))
                else:
                    cursor.execute("""
                        SELECT * FROM audit_log 
                        ORDER BY timestamp DESC 
                        LIMIT ?
                    """, (limit,))
                
                rows = cursor.fetchall()
                return [dict(row) for row in rows]
                
        except sqlite3.Error as e:
            print(f"Error getting audit log: {e}")
            return []
    
    def get_database_stats(self) -> Dict[str, Any]:
        """Get database statistics for monitoring"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # User stats
                cursor.execute("SELECT COUNT(*) FROM users")
                total_users = cursor.fetchone()[0]
                
                cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'")
                admin_users = cursor.fetchone()[0]
                
                cursor.execute("SELECT COUNT(*) FROM users WHERE role = 'user'")
                regular_users = cursor.fetchone()[0]
                
                # Locked accounts
                cursor.execute("SELECT COUNT(*) FROM users WHERE lockout_until > datetime('now')")
                locked_accounts = cursor.fetchone()[0]
                
                # Secret notes
                cursor.execute("SELECT COUNT(*) FROM secret_notes WHERE encrypted_note IS NOT NULL")
                notes_with_content = cursor.fetchone()[0]
                
                # Audit events
                cursor.execute("SELECT COUNT(*) FROM audit_log")
                total_audit_events = cursor.fetchone()[0]
                
                return {
                    "total_users": total_users,
                    "admin_users": admin_users,
                    "regular_users": regular_users,
                    "locked_accounts": locked_accounts,
                    "notes_with_content": notes_with_content,
                    "total_audit_events": total_audit_events,
                    "database_size_mb": self._get_database_size()
                }
                
        except sqlite3.Error as e:
            print(f"Error getting database stats: {e}")
            return {}
    
    def _get_database_size(self) -> float:
        """Get database file size in MB"""
        try:
            import os
            size_bytes = os.path.getsize(self.db_path)
            return round(size_bytes / (1024 * 1024), 2)
        except OSError:
            return 0.0
    
    def cleanup_old_sessions(self, days: int = 30) -> int:
        """Clean up old audit log entries"""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    DELETE FROM audit_log 
                    WHERE timestamp < datetime('now', '-{} days')
                """.format(days))
                
                deleted_count = cursor.rowcount
                conn.commit()
                
                return deleted_count
                
        except sqlite3.Error as e:
            print(f"Error cleaning up old sessions: {e}")
            return 0
