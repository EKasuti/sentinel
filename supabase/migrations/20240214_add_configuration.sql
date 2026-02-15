-- Migration: Add configuration column to security_runs
-- Created: 2024-02-14
-- Description: Stores authentication credentials and instructions for agents

ALTER TABLE security_runs ADD COLUMN IF NOT EXISTS configuration JSONB;
