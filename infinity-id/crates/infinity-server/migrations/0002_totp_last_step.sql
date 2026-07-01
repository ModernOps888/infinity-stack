-- Track the highest TOTP time-step accepted per user so a single 6-digit code
-- cannot be replayed within its skew window (one-time-use enforcement).
ALTER TABLE users ADD COLUMN mfa_last_step INTEGER;
