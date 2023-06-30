-- Add down migration script here
ALTER TABLE users DROP COLUMN password_reset_token;
DROP INDEX idx_password_reset_token;

ALTER TABLE users DROP COLUMN password_reset_at;
DROP INDEX idx_password_reset_at;