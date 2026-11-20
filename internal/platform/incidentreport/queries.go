// SPDX-License-Identifier: Elastic-2.0
// Copyright 2026 Zero Root AI

package incidentreport

// The queries carry no tenant. The graph is one database for each tenant, and
// the reader runs each query on the connection of the tenant of the call. A
// tenant id predicate would match no row, because the projector writes none.
//
// An alert joins its incident with PART_OF and names what it is about with
// AFFECTS (taxonomy version 6). The Incident node names its cause with
// CAUSED_BY. A fix is a FIXED_BY edge from the finding to a MergeRequest, and
// VERIFIED_BY joins a finding to the pipeline that verified it.

const alertsCypher = `
MATCH (i:Incident)
WHERE coalesce(i.key, i.brain_id) = $incident
OPTIONAL MATCH (a:Alert)-[:PART_OF]->(i)
RETURN
  coalesce(a.key, a.brain_id, '') AS alert_key,
  coalesce(a.title, a.name, '')   AS title,
  coalesce(a.source, '')          AS source,
  coalesce(a.severity, '')        AS severity
ORDER BY alert_key
LIMIT $limit`

const reachedCypher = `
MATCH (i:Incident)<-[:PART_OF]-(a:Alert)-[:AFFECTS]->(p)
WHERE coalesce(i.key, i.brain_id) = $incident
RETURN DISTINCT
  coalesce(a.key, a.brain_id, '')   AS alert_key,
  head(labels(p))                    AS label,
  coalesce(p.key, p.brain_id, '')   AS key
ORDER BY alert_key, label, key
LIMIT $limit`

const causesCypher = `
MATCH (i:Incident)-[:CAUSED_BY]->(f:Finding)
WHERE coalesce(i.key, i.brain_id) = $incident
RETURN
  coalesce(f.brain_id, f.key, '') AS finding_key,
  coalesce(f.title, '')           AS title,
  coalesce(f.severity, '')        AS severity,
  coalesce(f.status, '')          AS status
ORDER BY finding_key
LIMIT $limit`

const fixesCypher = `
MATCH (i:Incident)-[:CAUSED_BY]->(f:Finding)
WHERE coalesce(i.key, i.brain_id) = $incident
OPTIONAL MATCH (f)-[:FIXED_BY]->(mr:MergeRequest)
OPTIONAL MATCH (f)-[:VERIFIED_BY]->(p:Pipeline)
RETURN
  coalesce(f.brain_id, f.key, '')  AS finding_key,
  coalesce(mr.key, mr.brain_id, '') AS mr_key,
  coalesce(mr.url, '')             AS mr_url,
  coalesce(mr.ref, '')             AS mr_ref,
  coalesce(p.key, p.brain_id, '')  AS pipeline_key
ORDER BY finding_key, mr_key
LIMIT $limit`

// maxLines bounds each query. An incident has tens of lines. The cap keeps one
// call from walking a graph that grew by mistake.
const maxLines = 500
