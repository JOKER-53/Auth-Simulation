import uuid
import time
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

@dataclass
class SimulatedUser:
    email: str
    name: str
    google_id: str
    role: str = "Student"
    department: str = "Computer Science"
    gpa: str = "3.92"
    academic_status: str = "Enrolled (Good Standing)"

@dataclass
class TokenRecord:
    token_id: str
    email: str
    name: str
    google_id: str
    issued_at: float
    expires_at: float
    nonce: str
    client_ip: str
    user_agent: str
    used_count: int = 0
    is_revoked: bool = False
    revocation_reason: Optional[str] = None

@dataclass
class AuditLog:
    timestamp: str
    client_ip: str
    token_id_short: str
    event_type: str  # 'ISSUED', 'LEGITIMATE_ACCESS', 'REPLAY_ATTACK_SUCCESS', 'REPLAY_ATTACK_BLOCKED', 'REVOKED'
    message: str
    status: str      # 'SUCCESS', 'WARNING', 'BLOCKED'

class OAuthSimulationEngine:
    def __init__(self, mode: str = "vulnerable", token_ttl: int = 180):
        self.mode = mode  # 'vulnerable' or 'secure'
        self.token_ttl = token_ttl
        self.users: Dict[str, SimulatedUser] = {
            "student1@gmail.com": SimulatedUser(
                email="student1@gmail.com",
                name="Student One",
                google_id="google-uid-101",
                role="Undergraduate",
                department="Computer Science & Engineering",
                gpa="3.94",
                academic_status="Active / Enrolled"
            ),
            "student2@gmail.com": SimulatedUser(
                email="student2@gmail.com",
                name="Student Two",
                google_id="google-uid-102",
                role="Graduate Researcher",
                department="Cybersecurity & Information Assurance",
                gpa="3.88",
                academic_status="Active / Candidate"
            ),
            "faculty@university.edu": SimulatedUser(
                email="faculty@university.edu",
                name="Dr. Alan Turing",
                google_id="google-uid-007",
                role="Faculty Advisor",
                department="School of Computing",
                gpa="N/A",
                academic_status="Tenured Professor"
            ),
        }
        self.tokens: Dict[str, TokenRecord] = {}
        self.audit_logs: List[AuditLog] = []

    def set_mode(self, mode: str):
        if mode in ("vulnerable", "secure"):
            old_mode = self.mode
            self.mode = mode
            self._log(
                client_ip="system",
                token_id_short="SYSTEM",
                event_type="CONFIG_CHANGE",
                message=f"Simulation defense mode changed from '{old_mode}' to '{mode}'.",
                status="SUCCESS"
            )

    def _log(self, client_ip: str, token_id_short: str, event_type: str, message: str, status: str):
        entry = AuditLog(
            timestamp=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            client_ip=client_ip,
            token_id_short=token_id_short,
            event_type=event_type,
            message=message,
            status=status
        )
        self.audit_logs.insert(0, entry)
        if len(self.audit_logs) > 200:
            self.audit_logs.pop()

    def issue_token(self, email: str, client_ip: str = "127.0.0.1", user_agent: str = "Browser") -> Optional[TokenRecord]:
        user = self.users.get(email)
        if not user:
            return None

        now = time.time()
        token_id = str(uuid.uuid4())
        nonce = str(uuid.uuid4())[:8]

        record = TokenRecord(
            token_id=token_id,
            email=user.email,
            name=user.name,
            google_id=user.google_id,
            issued_at=now,
            expires_at=now + self.token_ttl,
            nonce=nonce,
            client_ip=client_ip,
            user_agent=user_agent,
            used_count=0,
            is_revoked=False
        )
        self.tokens[token_id] = record
        self._log(
            client_ip=client_ip,
            token_id_short=token_id[:8] + "...",
            event_type="ISSUED",
            message=f"Issued token for {user.email} (TTL: {self.token_ttl}s, Nonce: {nonce})",
            status="SUCCESS"
        )
        return record

    def verify_token(self, token_str: str, client_ip: str = "127.0.0.1", is_replay_test: bool = False) -> Tuple[bool, str, Optional[SimulatedUser]]:
        token_str = (token_str or "").strip()
        if not token_str:
            return False, "Missing token parameter", None

        record = self.tokens.get(token_str)
        token_prefix = token_str[:8] + "..." if len(token_str) >= 8 else token_str

        if not record:
            self._log(
                client_ip=client_ip,
                token_id_short=token_prefix,
                event_type="INVALID_TOKEN",
                message="Access rejected: Token not found in active registry.",
                status="BLOCKED"
            )
            return False, "Invalid or non-existent token", None

        if record.is_revoked:
            self._log(
                client_ip=client_ip,
                token_id_short=token_prefix,
                event_type="REVOKED_TOKEN",
                message=f"Access rejected: Token is revoked ({record.revocation_reason or 'manual revocation'}).",
                status="BLOCKED"
            )
            return False, f"Token revoked: {record.revocation_reason or 'Manually revoked'}", None

        user = self.users.get(record.email)
        now = time.time()

        # Check Expiration (applicable in secure mode or when TTL is strictly enforced)
        if self.mode == "secure" and now > record.expires_at:
            record.is_revoked = True
            record.revocation_reason = "Token expired (TTL exceeded)"
            self._log(
                client_ip=client_ip,
                token_id_short=token_prefix,
                event_type="EXPIRED_TOKEN",
                message="Access rejected: Token lifetime expired.",
                status="BLOCKED"
            )
            return False, "Token expired (TTL exceeded)", None

        # Replay Attack Detection
        is_replay = record.used_count > 0

        if self.mode == "secure":
            if is_replay:
                # In secure mode, single-use token enforcement blocks replayed tokens immediately
                # and revokes the compromised credential (RFC 6749 single-use authorization grant rule)
                record.is_revoked = True
                record.revocation_reason = "Replay attack detected: Token reuse violation"
                self._log(
                    client_ip=client_ip,
                    token_id_short=token_prefix,
                    event_type="REPLAY_ATTACK_BLOCKED",
                    message=f"REPLAY BLOCKED: Token was already used {record.used_count} time(s). Revoking token.",
                    status="BLOCKED"
                )
                return False, f"Replay Attack Blocked: Token was already consumed (Used {record.used_count}x). Credential auto-revoked.", None

            # Check client binding in secure mode
            if record.client_ip != client_ip and client_ip not in ("127.0.0.1", "localhost"):
                record.is_revoked = True
                record.revocation_reason = f"Client IP mismatch: bound {record.client_ip}, received {client_ip}"
                self._log(
                    client_ip=client_ip,
                    token_id_short=token_prefix,
                    event_type="IP_MISMATCH_BLOCKED",
                    message=f"Access rejected: IP binding mismatch ({record.client_ip} != {client_ip}).",
                    status="BLOCKED"
                )
                return False, f"Client Binding Mismatch: Expected {record.client_ip}, received {client_ip}.", None

            # First legitimate use in secure mode
            record.used_count += 1
            self._log(
                client_ip=client_ip,
                token_id_short=token_prefix,
                event_type="LEGITIMATE_ACCESS",
                message=f"Legitimate initial access granted for {record.email}.",
                status="SUCCESS"
            )
            return True, "Access Granted (Secure mode single-use validated)", user

        else:
            # Vulnerable Mode: No replay detection or single-use enforcement!
            record.used_count += 1
            if is_replay:
                self._log(
                    client_ip=client_ip,
                    token_id_short=token_prefix,
                    event_type="REPLAY_ATTACK_SUCCESS",
                    message=f"VULNERABILITY EXPLOITED: Token replayed successfully! Reuse count: {record.used_count}.",
                    status="WARNING"
                )
                verdict = f"VULNERABILITY EXPLOITED: Replayed token accepted! (Reuse count: {record.used_count})"
            else:
                self._log(
                    client_ip=client_ip,
                    token_id_short=token_prefix,
                    event_type="LEGITIMATE_ACCESS",
                    message=f"Initial access granted for {record.email}.",
                    status="SUCCESS"
                )
                verdict = "Access Granted (Vulnerable mode: token remains reusable)"

            return True, verdict, user

    def revoke_token(self, token_str: str, reason: str = "Manual revocation") -> bool:
        record = self.tokens.get(token_str)
        if record:
            record.is_revoked = True
            record.revocation_reason = reason
            self._log(
                client_ip="admin",
                token_id_short=token_str[:8] + "...",
                event_type="REVOKED",
                message=f"Token revoked manually: {reason}",
                status="WARNING"
            )
            return True
        return False

    def reset(self):
        self.tokens.clear()
        self.audit_logs.clear()
        self._log(
            client_ip="system",
            token_id_short="SYSTEM",
            event_type="RESET",
            message="Simulation reset: Cleared all active tokens and audit trails.",
            status="SUCCESS"
        )
