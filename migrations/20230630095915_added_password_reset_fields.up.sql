-- Add up migration script here
ALTER TABLE users ADD COLUMN password_reset_token VARCHAR(50);
CREATE INDEX idx_password_reset_token ON users(password_reset_token);

ALTER TABLE users ADD COLUMN password_reset_at TIMESTAMP;
CREATE INDEX idx_password_reset_at ON users(password_reset_at);