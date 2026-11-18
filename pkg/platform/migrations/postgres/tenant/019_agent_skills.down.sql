-- 019_agent_skills.down.sql — drop the Agent Skill tables (epic gibson#1364).
DROP TABLE IF EXISTS agent_skill_mission_pins;
DROP TABLE IF EXISTS agent_skill_files;
DROP INDEX IF EXISTS agent_skills_current_idx;
DROP INDEX IF EXISTS agent_skills_name_idx;
DROP TABLE IF EXISTS agent_skills;
