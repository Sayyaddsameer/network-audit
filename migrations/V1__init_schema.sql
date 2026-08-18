-- V1__init_schema.sql
-- Initial schema for the Zero-Trust Kubernetes Policy Audit Engine

-- Enable the pgcrypto extension for gen_random_uuid() if it's not already enabled
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Table: network_policies
-- Purpose: Stores the actual network policies discovered in the Kubernetes cluster.
-- This serves as the source of truth for what is currently applied.
CREATE TABLE network_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    namespace TEXT NOT NULL,
    policy_name TEXT NOT NULL,
    spec_json JSONB NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Table: expected_policies
-- Purpose: A reference table for expected/approved policies.
-- It acts as a baseline to compare discovered policies against for auditing.
CREATE TABLE expected_policies (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    namespace TEXT NOT NULL,
    policy_name TEXT NOT NULL,
    description TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Table: policy_violations
-- Purpose: Records instances where a network policy deviates from the expected baseline,
-- or otherwise violates the zero-trust rules.
CREATE TABLE policy_violations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_id UUID REFERENCES network_policies(id),
    violation_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    detected_at TIMESTAMP NOT NULL DEFAULT NOW()
);
