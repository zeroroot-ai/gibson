-- 001_create_tenant_neo4j_endpoints.down.sql
-- Rollback: drop the Neo4j endpoint registry table.

DROP TABLE IF EXISTS tenant_neo4j_endpoints;
