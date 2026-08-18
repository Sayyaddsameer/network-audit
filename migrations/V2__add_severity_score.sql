-- V2__add_severity_score.sql
-- Simulates schema evolution by adding a new column to the policy_violations table.
-- Keeping this in a separate migration demonstrates how we handle iterative schema changes
-- in a production environment without losing existing data.

ALTER TABLE policy_violations
ADD COLUMN severity_score INTEGER;
