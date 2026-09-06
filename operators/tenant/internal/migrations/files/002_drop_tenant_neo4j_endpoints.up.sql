-- The tenant_neo4j_endpoints registry table is superseded by the unified
-- Neo4j credentials payload at infra/neo4j in each tenant's Vault namespace.
-- Neither the daemon nor the operator references this table any longer.
DROP TABLE IF EXISTS tenant_neo4j_endpoints;
