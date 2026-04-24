-- db/schema.sql
-- PostgreSQL schema for LLM Hallucination Firewall
-- Tables: claims, validation_results, decisions, audit_log, analyst_overrides, policy_profiles

-- Claims table: extracted claims from LLM output
CREATE TABLE IF NOT EXISTS claims (
    id SERIAL PRIMARY KEY,
    claim_id UUID NOT NULL UNIQUE,
    text TEXT NOT NULL,
    claim_type VARCHAR(50),  -- CVE_ID, ATTACK_TECHNIQUE, SEVERITY, VERSION, etc.
    confidence FLOAT CHECK (confidence >= 0.0 AND confidence <= 1.0),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_claims_claim_id ON claims(claim_id);
CREATE INDEX idx_claims_type ON claims(claim_type);

-- Validation results table: outcomes of validation rules
CREATE TABLE IF NOT EXISTS validation_results (
    id SERIAL PRIMARY KEY,
    validation_result_id UUID NOT NULL UNIQUE,
    decision_id UUID NOT NULL,
    rule_id VARCHAR(100),
    rule_name VARCHAR(255),
    passed BOOLEAN,
    evidence TEXT,
    confidence FLOAT CHECK (confidence >= 0.0 AND confidence <= 1.0),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_validation_results_decision_id ON validation_results(decision_id);
CREATE INDEX idx_validation_results_rule_id ON validation_results(rule_id);

-- Decisions table: final validation outcomes
CREATE TABLE IF NOT EXISTS decisions (
    id SERIAL PRIMARY KEY,
    decision_id UUID NOT NULL UNIQUE,
    alert_id VARCHAR(255),
    llm_output TEXT,
    outcome VARCHAR(20),  -- ALLOW, FLAG, BLOCK, CORRECT
    risk_score FLOAT CHECK (risk_score >= 0.0 AND risk_score <= 1.0),
    component_scores JSONB,  -- {cve_validity: float, severity_accuracy: float, ...}
    correction_candidate TEXT,
    analyst_rationale TEXT,
    policy_profile_name VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_by UUID
);

CREATE INDEX idx_decisions_decision_id ON decisions(decision_id);
CREATE INDEX idx_decisions_alert_id ON decisions(alert_id);
CREATE INDEX idx_decisions_outcome ON decisions(outcome);
CREATE INDEX idx_decisions_created_at ON decisions(created_at);

-- Audit log table: hash-chained immutable audit trail
CREATE TABLE IF NOT EXISTS audit_log (
    id SERIAL PRIMARY KEY,
    decision_id UUID NOT NULL,
    record_data JSONB,  -- Full decision + validation chain snapshot
    prev_hash VARCHAR(64),  -- SHA-256 hex of previous entry
    curr_hash VARCHAR(64),  -- SHA-256 hex of this entry
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_audit_log_decision_id ON audit_log(decision_id);
CREATE INDEX idx_audit_log_created_at ON audit_log(created_at);
CREATE UNIQUE INDEX idx_audit_log_curr_hash ON audit_log(curr_hash);

-- Analyst overrides table: SOC_ADMIN decisions to override automated outcomes
CREATE TABLE IF NOT EXISTS analyst_overrides (
    id SERIAL PRIMARY KEY,
    override_id UUID NOT NULL UNIQUE,
    decision_id UUID NOT NULL,
    original_outcome VARCHAR(20),
    new_outcome VARCHAR(20),
    rationale TEXT,
    correction_suggestion TEXT,
    overridden_by UUID NOT NULL,  -- SOC_ADMIN user ID
    override_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    audit_hash VARCHAR(64)  -- Reference to audit_log entry
);

CREATE INDEX idx_analyst_overrides_decision_id ON analyst_overrides(decision_id);
CREATE INDEX idx_analyst_overrides_overridden_by ON analyst_overrides(overridden_by);
CREATE INDEX idx_analyst_overrides_timestamp ON analyst_overrides(override_timestamp);

-- Policy profiles table: decision policy configurations
CREATE TABLE IF NOT EXISTS policy_profiles (
    id SERIAL PRIMARY KEY,
    profile_id UUID NOT NULL UNIQUE,
    name VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    thresholds JSONB,  -- {allow_min: float, flag_min: float, block_max: float}
    rule_weights JSONB,  -- {cve_validity: float, severity_accuracy: float, ...}
    active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_policy_profiles_name ON policy_profiles(name);
CREATE INDEX idx_policy_profiles_active ON policy_profiles(active);

-- Users table for RBAC
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    username VARCHAR(100) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    role VARCHAR(50),  -- SOC_ANALYST, SOC_ADMIN, SYSTEM
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP
);

CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_role ON users(role);
