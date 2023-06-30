-- Add up migration script here

ALTER TABLE users
ADD
    COLUMN photo VARCHAR(255) DEFAULT 'default.png';

ALTER TABLE users ADD COLUMN verified BOOLEAN DEFAULT FALSE;

ALTER TABLE users ADD COLUMN verification_code VARCHAR(255);
CREATE INDEX idx_verification_code ON users(verification_code);

ALTER TABLE users ADD COLUMN role VARCHAR(50) DEFAULT 'user';
