-- Add down migration script here

ALTER TABLE users DROP COLUMN photo;

ALTER TABLE users DROP COLUMN verified;

ALTER TABLE users DROP COLUMN verification_code;

ALTER TABLE users DROP COLUMN role;

DROP INDEX idx_verification_code;