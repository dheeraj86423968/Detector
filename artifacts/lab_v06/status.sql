SELECT e.name, e.phase, e.last_seen::timestamp(0),
 (SELECT string_agg(b.date || ':' || coalesce(b.events,0), ' ' ORDER BY b.date) FROM baseline_days b WHERE b.endpoint_id=e.id) AS days,
 (SELECT string_agg(j.kind || '/' || j.state, ' ') FROM jobs j WHERE j.endpoint_id=e.id) AS jobs
FROM endpoints e WHERE e.name IN ('darpa-clearscope-e3','darpa-fivedirections-e3');
