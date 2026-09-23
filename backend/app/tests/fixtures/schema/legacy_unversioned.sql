-- Frozen V1/V2 create-all schema reconstructed from f6583ecb4aa439f77296022cec91ed20ac92685b; profile precomparison.

CREATE TABLE alerts (
	id INTEGER NOT NULL,
	job_id VARCHAR NOT NULL,
	alert_id VARCHAR NOT NULL,
	host_ip VARCHAR NOT NULL,
	community_id VARCHAR,
	severity VARCHAR NOT NULL,
	engine VARCHAR,
	signature TEXT NOT NULL,
	category VARCHAR,
	sid VARCHAR,
	src_ip VARCHAR,
	src_port INTEGER,
	dest_ip VARCHAR,
	dest_port INTEGER,
	proto VARCHAR,
	refs_json TEXT,
	tags_json TEXT,
	ts VARCHAR NOT NULL,
	pcap_label VARCHAR,
	analyst_status VARCHAR,
	analyst_notes TEXT,
	reviewed_at VARCHAR,
	reviewer_id VARCHAR,
	PRIMARY KEY (id),
	UNIQUE (job_id, alert_id),
	FOREIGN KEY(job_id) REFERENCES jobs (job_id) ON DELETE CASCADE
)

;
CREATE INDEX idx_alerts_analyst_status ON alerts (job_id, analyst_status);
CREATE INDEX idx_alerts_community ON alerts (job_id, community_id);
CREATE INDEX idx_alerts_job_host ON alerts (job_id, host_ip);
CREATE INDEX idx_alerts_severity ON alerts (job_id, severity);

CREATE TABLE artifacts (
	id INTEGER NOT NULL,
	job_id VARCHAR NOT NULL,
	artifact_id VARCHAR NOT NULL,
	type VARCHAR NOT NULL,
	status VARCHAR NOT NULL,
	filename TEXT,
	sha256 VARCHAR,
	size_bytes INTEGER,
	error TEXT,
	created_at VARCHAR NOT NULL,
	PRIMARY KEY (id),
	UNIQUE (job_id, artifact_id),
	FOREIGN KEY(job_id) REFERENCES jobs (job_id) ON DELETE CASCADE
)

;
CREATE INDEX idx_artifacts_job ON artifacts (job_id);

CREATE TABLE bluescrub_audit (
	id INTEGER NOT NULL,
	actor VARCHAR,
	at VARCHAR NOT NULL,
	action VARCHAR NOT NULL,
	project_id VARCHAR,
	job_id VARCHAR,
	old_json TEXT,
	new_json TEXT,
	reason TEXT,
	session VARCHAR,
	PRIMARY KEY (id)
)

;
CREATE INDEX ix_bluescrub_audit_project_id ON bluescrub_audit (project_id);

CREATE TABLE bluescrub_baselines (
	id INTEGER NOT NULL,
	project_id VARCHAR NOT NULL,
	job_id VARCHAR,
	active BOOLEAN DEFAULT '0' NOT NULL,
	label VARCHAR,
	compatibility_signature VARCHAR NOT NULL,
	findings_json TEXT NOT NULL,
	metrics_json TEXT NOT NULL,
	created_at VARCHAR NOT NULL,
	created_by VARCHAR,
	PRIMARY KEY (id),
	FOREIGN KEY(job_id) REFERENCES jobs (job_id) ON DELETE SET NULL
)

;
CREATE INDEX ix_bluescrub_baselines_project_id ON bluescrub_baselines (project_id);
CREATE UNIQUE INDEX uq_bs_active_baseline ON bluescrub_baselines (project_id) WHERE active = 1;

CREATE TABLE bluescrub_job_lineage (
	job_id VARCHAR NOT NULL,
	project_id VARCHAR,
	lineage_parent_job_id VARCHAR,
	signature_fields_json TEXT,
	derived_from_job_id VARCHAR,
	derived_from_file_id VARCHAR,
	artifact_sha256 VARCHAR,
	analysis_kind VARCHAR NOT NULL,
	compatibility_signature VARCHAR NOT NULL,
	PRIMARY KEY (job_id),
	FOREIGN KEY(job_id) REFERENCES jobs (job_id) ON DELETE CASCADE
)

;
CREATE INDEX ix_bluescrub_job_lineage_project_id ON bluescrub_job_lineage (project_id);

CREATE TABLE bluescrub_projects (
	project_id VARCHAR NOT NULL,
	display_name VARCHAR NOT NULL,
	created_at VARCHAR NOT NULL,
	archived BOOLEAN DEFAULT '0' NOT NULL,
	PRIMARY KEY (project_id)
)

;

CREATE TABLE bluescrub_score_history (
	id INTEGER NOT NULL,
	project_id VARCHAR NOT NULL,
	job_id VARCHAR NOT NULL,
	scanned_at VARCHAR NOT NULL,
	profile VARCHAR NOT NULL,
	scoring_model VARCHAR NOT NULL,
	compatibility_signature VARCHAR NOT NULL,
	coverage_json TEXT NOT NULL,
	pillars_json TEXT NOT NULL,
	overall_score INTEGER,
	grade VARCHAR,
	scoped_score INTEGER NOT NULL,
	severity_counts_json TEXT NOT NULL,
	PRIMARY KEY (id),
	UNIQUE (job_id)
)

;
CREATE INDEX ix_bluescrub_score_history_project_id ON bluescrub_score_history (project_id);

CREATE TABLE bluescrub_triage_ledger (
	project_id VARCHAR NOT NULL,
	finding_id VARCHAR NOT NULL,
	status VARCHAR NOT NULL,
	notes TEXT,
	rule_version VARCHAR,
	fingerprint_scheme VARCHAR NOT NULL,
	decided_at VARCHAR NOT NULL,
	decided_by VARCHAR,
	origin_job_id VARCHAR,
	PRIMARY KEY (project_id, finding_id)
)

;
CREATE INDEX idx_bs_triage_project ON bluescrub_triage_ledger (project_id);

CREATE TABLE bluescrub_wordlists (
	id VARCHAR NOT NULL,
	name VARCHAR NOT NULL,
	builtin BOOLEAN DEFAULT '0' NOT NULL,
	category VARCHAR,
	entries_json TEXT NOT NULL,
	case_sensitive BOOLEAN DEFAULT '0' NOT NULL,
	enabled BOOLEAN DEFAULT '1' NOT NULL,
	created_at VARCHAR NOT NULL,
	updated_at VARCHAR,
	PRIMARY KEY (id),
	UNIQUE (name)
)

;

CREATE TABLE chat_conversations (
	id VARCHAR NOT NULL,
	job_id VARCHAR NOT NULL,
	title TEXT,
	created_at VARCHAR NOT NULL,
	updated_at VARCHAR NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(job_id) REFERENCES jobs (job_id) ON DELETE CASCADE
)

;
CREATE INDEX idx_chat_conv_job ON chat_conversations (job_id);

CREATE TABLE chat_messages (
	id VARCHAR NOT NULL,
	conversation_id VARCHAR NOT NULL,
	role VARCHAR NOT NULL,
	content TEXT NOT NULL,
	citations_json TEXT,
	created_at VARCHAR NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(conversation_id) REFERENCES chat_conversations (id) ON DELETE CASCADE
)

;
CREATE INDEX idx_chat_msg_conv ON chat_messages (conversation_id);

CREATE TABLE connections (
	id INTEGER NOT NULL,
	job_id VARCHAR NOT NULL,
	connection_id VARCHAR NOT NULL,
	community_id VARCHAR,
	host_ip VARCHAR NOT NULL,
	src_ip VARCHAR NOT NULL,
	src_port INTEGER,
	dest_ip VARCHAR NOT NULL,
	dest_port INTEGER,
	proto VARCHAR NOT NULL,
	duration_seconds FLOAT,
	bytes_sent INTEGER,
	bytes_recv INTEGER,
	service VARCHAR,
	ts VARCHAR NOT NULL,
	pcap_label VARCHAR,
	PRIMARY KEY (id),
	UNIQUE (job_id, connection_id),
	FOREIGN KEY(job_id) REFERENCES jobs (job_id) ON DELETE CASCADE
)

;
CREATE INDEX idx_conn_community ON connections (job_id, community_id);
CREATE INDEX idx_conn_job_host ON connections (job_id, host_ip);
CREATE INDEX idx_conn_ts ON connections (job_id, ts);

CREATE TABLE context_annotations (
	id INTEGER NOT NULL,
	job_id VARCHAR NOT NULL,
	annotation_id VARCHAR NOT NULL,
	host_ip VARCHAR NOT NULL,
	metric_name VARCHAR NOT NULL,
	metric_category VARCHAR NOT NULL,
	baseline_value FLOAT,
	observed_value FLOAT,
	deviation_factor FLOAT,
	population_size INTEGER,
	severity VARCHAR NOT NULL,
	confidence FLOAT NOT NULL,
	title TEXT NOT NULL,
	description TEXT NOT NULL,
	why_unusual TEXT NOT NULL,
	related_alert_ids_json TEXT,
	related_finding_ids_json TEXT,
	pcap_label VARCHAR,
	created_at VARCHAR NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(job_id) REFERENCES jobs (job_id) ON DELETE CASCADE,
	UNIQUE (annotation_id)
)

;
CREATE INDEX idx_annotations_host ON context_annotations (job_id, host_ip);
CREATE INDEX idx_annotations_job ON context_annotations (job_id);
CREATE INDEX idx_annotations_metric ON context_annotations (job_id, metric_name);
CREATE INDEX idx_annotations_pcap_label ON context_annotations (job_id, pcap_label);
CREATE INDEX idx_annotations_severity ON context_annotations (job_id, severity);

CREATE TABLE dns_queries (
	id INTEGER NOT NULL,
	job_id VARCHAR NOT NULL,
	dns_id VARCHAR NOT NULL,
	host_ip VARCHAR NOT NULL,
	community_id VARCHAR,
	src_ip VARCHAR NOT NULL,
	"query" TEXT NOT NULL,
	qtype VARCHAR,
	answers_json TEXT,
	rcode VARCHAR,
	ttl_seconds INTEGER,
	dest_ip VARCHAR,
	ts VARCHAR NOT NULL,
	pcap_label VARCHAR,
	PRIMARY KEY (id),
	UNIQUE (job_id, dns_id),
	FOREIGN KEY(job_id) REFERENCES jobs (job_id) ON DELETE CASCADE
)

;
CREATE INDEX idx_dns_community ON dns_queries (job_id, community_id);
CREATE INDEX idx_dns_job_host ON dns_queries (job_id, host_ip);
CREATE INDEX idx_dns_query ON dns_queries (job_id, "query");

CREATE TABLE files (
	id INTEGER NOT NULL,
	job_id VARCHAR NOT NULL,
	file_id VARCHAR NOT NULL,
	filename VARCHAR,
	host_ip VARCHAR,
	community_id VARCHAR,
	sha256 VARCHAR NOT NULL,
	md5 VARCHAR,
	ssdeep VARCHAR,
	size_bytes INTEGER NOT NULL,
	mime VARCHAR,
	entropy FLOAT,
	source VARCHAR,
	extracted_path TEXT,
	yara_matches_json TEXT,
	download_artifact_id VARCHAR,
	ts VARCHAR,
	pcap_label VARCHAR,
	PRIMARY KEY (id),
	UNIQUE (job_id, file_id),
	FOREIGN KEY(job_id) REFERENCES jobs (job_id) ON DELETE CASCADE
)

;
CREATE INDEX idx_files_community ON files (job_id, community_id);
CREATE INDEX idx_files_job ON files (job_id);
CREATE INDEX idx_files_sha256 ON files (job_id, sha256);

CREATE TABLE findings (
	id INTEGER NOT NULL,
	job_id VARCHAR NOT NULL,
	finding_id VARCHAR NOT NULL,
	sensor VARCHAR NOT NULL,
	severity VARCHAR NOT NULL,
	category VARCHAR,
	title TEXT NOT NULL,
	summary TEXT,
	community_id VARCHAR,
	evidence_json TEXT,
	pcap_label VARCHAR,
	feedback VARCHAR,
	explanation_feedback VARCHAR,
	confidence FLOAT DEFAULT '0.0' NOT NULL,
	ts VARCHAR,
	src_ip VARCHAR,
	dest_ip VARCHAR,
	evidence_status VARCHAR DEFAULT 'observed' NOT NULL,
	corroboration_score FLOAT DEFAULT '0.0' NOT NULL,
	corroborating_sources_json TEXT,
	analyst_status VARCHAR,
	analyst_notes TEXT,
	reviewed_at VARCHAR,
	reviewer_id VARCHAR,
	PRIMARY KEY (id),
	UNIQUE (job_id, finding_id),
	FOREIGN KEY(job_id) REFERENCES jobs (job_id) ON DELETE CASCADE
)

;
CREATE INDEX idx_findings_analyst_status ON findings (job_id, analyst_status);
CREATE INDEX idx_findings_evidence_status ON findings (job_id, evidence_status);
CREATE INDEX idx_findings_job ON findings (job_id);
CREATE INDEX idx_findings_sensor ON findings (job_id, sensor);
CREATE INDEX idx_findings_severity ON findings (job_id, severity);

CREATE TABLE global_hosts (
	ip VARCHAR NOT NULL,
	hostname VARCHAR,
	first_seen VARCHAR,
	last_seen VARCHAR,
	job_count INTEGER,
	total_alerts INTEGER,
	total_findings INTEGER,
	seen_as_internal BOOLEAN,
	roles_json TEXT,
	history_json TEXT,
	PRIMARY KEY (ip)
)

;
CREATE INDEX idx_global_hosts_last_seen ON global_hosts (last_seen);

CREATE TABLE hosts (
	id INTEGER NOT NULL,
	job_id VARCHAR NOT NULL,
	ip VARCHAR NOT NULL,
	role VARCHAR,
	conn_count INTEGER,
	bytes_sent INTEGER,
	bytes_recv INTEGER,
	alert_count INTEGER,
	finding_count INTEGER,
	first_seen VARCHAR,
	last_seen VARCHAR,
	top_domains_json TEXT,
	top_services_json TEXT,
	dns_query_count INTEGER,
	tls_session_count INTEGER,
	alerts_by_severity_json TEXT,
	pcap_label VARCHAR,
	PRIMARY KEY (id),
	UNIQUE (job_id, ip, pcap_label),
	FOREIGN KEY(job_id) REFERENCES jobs (job_id) ON DELETE CASCADE
)

;
CREATE INDEX idx_hosts_job ON hosts (job_id);
CREATE INDEX idx_hosts_role ON hosts (job_id, role);

CREATE TABLE incident_slices (
	id INTEGER NOT NULL,
	job_id VARCHAR NOT NULL,
	slice_id VARCHAR NOT NULL,
	label TEXT NOT NULL,
	slice_type VARCHAR NOT NULL,
	severity VARCHAR NOT NULL,
	confidence FLOAT NOT NULL,
	community_ids_json TEXT,
	host_ips_json TEXT,
	time_start VARCHAR,
	time_end VARCHAR,
	alert_ids_json TEXT,
	finding_ids_json TEXT,
	ioc_ids_json TEXT,
	connection_ids_json TEXT,
	summary TEXT,
	rank INTEGER NOT NULL,
	pcap_label VARCHAR,
	created_at VARCHAR NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(job_id) REFERENCES jobs (job_id) ON DELETE CASCADE,
	UNIQUE (slice_id)
)

;
CREATE INDEX idx_slices_job ON incident_slices (job_id);
CREATE INDEX idx_slices_pcap_label ON incident_slices (job_id, pcap_label);
CREATE INDEX idx_slices_rank ON incident_slices (job_id, rank);
CREATE INDEX idx_slices_severity ON incident_slices (job_id, severity);

CREATE TABLE iocs (
	id INTEGER NOT NULL,
	job_id VARCHAR NOT NULL,
	ioc_id VARCHAR NOT NULL,
	ioc_type VARCHAR NOT NULL,
	value TEXT NOT NULL,
	severity VARCHAR,
	confidence FLOAT,
	source_sensor VARCHAR,
	sources_json TEXT,
	context TEXT,
	pcap_label VARCHAR,
	PRIMARY KEY (id),
	UNIQUE (job_id, ioc_id),
	FOREIGN KEY(job_id) REFERENCES jobs (job_id) ON DELETE CASCADE
)

;
CREATE INDEX idx_iocs_job ON iocs (job_id);
CREATE INDEX idx_iocs_type ON iocs (job_id, ioc_type);
CREATE INDEX idx_iocs_value ON iocs (value);

CREATE TABLE job_log_sources (
	id INTEGER NOT NULL,
	job_id VARCHAR NOT NULL,
	upload_id VARCHAR,
	label VARCHAR,
	filename TEXT NOT NULL,
	source_system VARCHAR,
	parser_hint VARCHAR,
	ordinal INTEGER NOT NULL,
	size_bytes INTEGER,
	sha256 VARCHAR,
	PRIMARY KEY (id),
	FOREIGN KEY(job_id) REFERENCES jobs (job_id) ON DELETE CASCADE
)

;
CREATE INDEX idx_job_log_sources_job ON job_log_sources (job_id);
CREATE INDEX idx_job_log_sources_ordinal ON job_log_sources (job_id, ordinal);

CREATE TABLE job_pcaps (
	id INTEGER NOT NULL,
	job_id VARCHAR NOT NULL,
	upload_id VARCHAR NOT NULL,
	label VARCHAR,
	filename TEXT NOT NULL,
	ordinal INTEGER NOT NULL,
	size_bytes INTEGER,
	sha256 VARCHAR,
	PRIMARY KEY (id),
	FOREIGN KEY(job_id) REFERENCES jobs (job_id) ON DELETE CASCADE,
	FOREIGN KEY(upload_id) REFERENCES uploads (upload_id)
)

;
CREATE INDEX idx_job_pcaps_job ON job_pcaps (job_id);
CREATE INDEX idx_job_pcaps_ordinal ON job_pcaps (job_id, ordinal);

CREATE TABLE job_sensors (
	id INTEGER NOT NULL,
	job_id VARCHAR NOT NULL,
	sensor VARCHAR NOT NULL,
	status VARCHAR NOT NULL,
	started_at VARCHAR,
	completed_at VARCHAR,
	duration_ms INTEGER,
	error TEXT,
	error_code VARCHAR,
	timeout_seconds INTEGER,
	provenance_json TEXT,
	stats_json TEXT,
	PRIMARY KEY (id),
	UNIQUE (job_id, sensor),
	FOREIGN KEY(job_id) REFERENCES jobs (job_id) ON DELETE CASCADE
)

;
CREATE INDEX idx_job_sensors_job ON job_sensors (job_id);

CREATE TABLE jobs (
	job_id VARCHAR NOT NULL,
	job_name TEXT,
	notes TEXT,
	status VARCHAR NOT NULL,
	execution_profile VARCHAR NOT NULL,
	priority VARCHAR NOT NULL,
	source_type VARCHAR NOT NULL,
	exercise_id VARCHAR,
	upload_id VARCHAR,
	pcap_filename TEXT,
	pcap_size_bytes INTEGER,
	pcap_sha256 VARCHAR,
	source_manifest_json TEXT,
	error_summary TEXT,
	created_at VARCHAR NOT NULL,
	started_at VARCHAR,
	completed_at VARCHAR,
	metrics_json TEXT,
	PRIMARY KEY (job_id)
)

;
CREATE INDEX idx_jobs_created ON jobs (created_at);
CREATE INDEX idx_jobs_profile ON jobs (execution_profile);
CREATE INDEX idx_jobs_status ON jobs (status);

CREATE TABLE kb_documents (
	id VARCHAR NOT NULL,
	job_id VARCHAR,
	name VARCHAR NOT NULL,
	doc_type VARCHAR NOT NULL,
	description TEXT,
	filename VARCHAR,
	content TEXT NOT NULL,
	content_sha256 VARCHAR,
	chunk_count INTEGER,
	status VARCHAR,
	error_message TEXT,
	created_at VARCHAR NOT NULL,
	updated_at VARCHAR NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(job_id) REFERENCES jobs (job_id)
)

;
CREATE INDEX idx_kb_doc_job_id ON kb_documents (job_id);
CREATE INDEX idx_kb_doc_sha ON kb_documents (content_sha256);
CREATE INDEX idx_kb_doc_status ON kb_documents (status);
CREATE INDEX idx_kb_doc_type ON kb_documents (doc_type);

CREATE TABLE normalized_events (
	id INTEGER NOT NULL,
	event_id VARCHAR NOT NULL,
	job_id VARCHAR NOT NULL,
	event_type VARCHAR NOT NULL,
	timestamp VARCHAR NOT NULL,
	source_type VARCHAR NOT NULL,
	source_system VARCHAR,
	source_filename VARCHAR,
	parser_name VARCHAR,
	parser_version VARCHAR,
	raw_ref TEXT,
	evidence_status VARCHAR NOT NULL,
	corroboration_score FLOAT,
	community_id VARCHAR,
	hostname VARCHAR,
	username VARCHAR,
	session_id VARCHAR,
	process_guid VARCHAR,
	src_ip VARCHAR,
	src_port INTEGER,
	dest_ip VARCHAR,
	dest_port INTEGER,
	proto VARCHAR,
	exercise_id VARCHAR,
	data_json TEXT,
	correlation_keys_json TEXT,
	tags_json TEXT,
	pcap_label VARCHAR,
	PRIMARY KEY (id),
	UNIQUE (event_id),
	FOREIGN KEY(job_id) REFERENCES jobs (job_id) ON DELETE CASCADE
)

;
CREATE INDEX idx_ne_community ON normalized_events (job_id, community_id);
CREATE INDEX idx_ne_dest_ip ON normalized_events (job_id, dest_ip);
CREATE INDEX idx_ne_evidence ON normalized_events (job_id, evidence_status);
CREATE INDEX idx_ne_exercise ON normalized_events (exercise_id);
CREATE INDEX idx_ne_hostname ON normalized_events (job_id, hostname);
CREATE INDEX idx_ne_job_ts ON normalized_events (job_id, timestamp);
CREATE INDEX idx_ne_job_type ON normalized_events (job_id, event_type);
CREATE INDEX idx_ne_source_type ON normalized_events (job_id, source_type);
CREATE INDEX idx_ne_src_ip ON normalized_events (job_id, src_ip);
CREATE INDEX idx_ne_username ON normalized_events (job_id, username);

CREATE TABLE proof_items (
	id INTEGER NOT NULL,
	proof_id VARCHAR NOT NULL,
	item_id VARCHAR NOT NULL,
	entity_type VARCHAR NOT NULL,
	entity_id VARCHAR NOT NULL,
	role VARCHAR NOT NULL,
	analyst_note TEXT,
	"order" INTEGER NOT NULL,
	label TEXT,
	severity VARCHAR,
	created_at VARCHAR NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(proof_id) REFERENCES proofs (proof_id) ON DELETE CASCADE,
	UNIQUE (item_id)
)

;
CREATE INDEX idx_proof_items_entity ON proof_items (entity_type, entity_id);
CREATE INDEX idx_proof_items_proof ON proof_items (proof_id);

CREATE TABLE proofs (
	id INTEGER NOT NULL,
	job_id VARCHAR NOT NULL,
	proof_id VARCHAR NOT NULL,
	title TEXT NOT NULL,
	conclusion TEXT,
	status VARCHAR NOT NULL,
	severity VARCHAR NOT NULL,
	confidence FLOAT NOT NULL,
	mode VARCHAR NOT NULL,
	narrative_markdown TEXT,
	item_count INTEGER NOT NULL,
	created_at VARCHAR NOT NULL,
	updated_at VARCHAR NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(job_id) REFERENCES jobs (job_id) ON DELETE CASCADE,
	UNIQUE (proof_id)
)

;
CREATE INDEX idx_proofs_job ON proofs (job_id);
CREATE INDEX idx_proofs_status ON proofs (job_id, status);

CREATE TABLE reports (
	id INTEGER NOT NULL,
	job_id VARCHAR NOT NULL,
	report_id VARCHAR NOT NULL,
	mode VARCHAR NOT NULL,
	pcap_label VARCHAR,
	title TEXT NOT NULL,
	threat_level VARCHAR NOT NULL,
	confidence FLOAT NOT NULL,
	content_markdown TEXT NOT NULL,
	content_json TEXT NOT NULL,
	theory_count INTEGER NOT NULL,
	slice_count INTEGER NOT NULL,
	finding_count INTEGER NOT NULL,
	alert_count INTEGER NOT NULL,
	ioc_count INTEGER NOT NULL,
	host_count INTEGER NOT NULL,
	annotation_count INTEGER NOT NULL,
	evidence_refs_json TEXT,
	created_at VARCHAR NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(job_id) REFERENCES jobs (job_id) ON DELETE CASCADE,
	UNIQUE (report_id)
)

;
CREATE INDEX idx_reports_job ON reports (job_id);
CREATE INDEX idx_reports_mode ON reports (job_id, mode);
CREATE INDEX idx_reports_pcap_label ON reports (job_id, pcap_label);

CREATE TABLE temporal_correlations (
	id INTEGER NOT NULL,
	job_id VARCHAR NOT NULL,
	log_event_id VARCHAR NOT NULL,
	log_source VARCHAR,
	log_source_filename VARCHAR,
	log_event_type VARCHAR,
	log_timestamp VARCHAR NOT NULL,
	log_summary TEXT,
	pcap_entity_type VARCHAR NOT NULL,
	pcap_entity_id VARCHAR NOT NULL,
	pcap_summary TEXT,
	pcap_timestamp VARCHAR NOT NULL,
	shared_ip VARCHAR NOT NULL,
	time_delta_seconds FLOAT NOT NULL,
	match_score FLOAT NOT NULL,
	match_type VARCHAR NOT NULL,
	community_id VARCHAR,
	match_keys_json TEXT,
	log_label VARCHAR,
	pcap_label VARCHAR,
	clock_offset_seconds FLOAT,
	adjusted_time_delta_seconds FLOAT,
	confidence_band VARCHAR,
	PRIMARY KEY (id),
	FOREIGN KEY(job_id) REFERENCES jobs (job_id) ON DELETE CASCADE
)

;
CREATE INDEX idx_tc_job ON temporal_correlations (job_id);
CREATE INDEX idx_tc_job_score ON temporal_correlations (job_id, match_score);
CREATE INDEX idx_tc_log_event ON temporal_correlations (job_id, log_event_id);
CREATE INDEX idx_tc_pcap_entity ON temporal_correlations (job_id, pcap_entity_type, pcap_entity_id);
CREATE INDEX ix_temporal_correlations_log_event_id ON temporal_correlations (log_event_id);
CREATE INDEX ix_temporal_correlations_pcap_entity_id ON temporal_correlations (pcap_entity_id);

CREATE TABLE theories (
	id INTEGER NOT NULL,
	job_id VARCHAR NOT NULL,
	theory_id VARCHAR NOT NULL,
	scope_type VARCHAR NOT NULL,
	scope_id VARCHAR,
	label TEXT NOT NULL,
	hypothesis_type VARCHAR NOT NULL,
	score FLOAT NOT NULL,
	confidence VARCHAR NOT NULL,
	rank INTEGER NOT NULL,
	supporting_evidence_json TEXT,
	contradicting_evidence_json TEXT,
	score_breakdown_json TEXT,
	explanation TEXT,
	next_steps_json TEXT,
	pcap_label VARCHAR,
	created_at VARCHAR NOT NULL,
	analyst_status VARCHAR,
	analyst_notes TEXT,
	reviewed_at VARCHAR,
	reviewer_id VARCHAR,
	PRIMARY KEY (id),
	FOREIGN KEY(job_id) REFERENCES jobs (job_id) ON DELETE CASCADE,
	UNIQUE (theory_id)
)

;
CREATE INDEX idx_theories_analyst_status ON theories (job_id, analyst_status);
CREATE INDEX idx_theories_job ON theories (job_id);
CREATE INDEX idx_theories_pcap_label ON theories (job_id, pcap_label);
CREATE INDEX idx_theories_rank ON theories (job_id, scope_type, scope_id, rank);
CREATE INDEX idx_theories_scope ON theories (job_id, scope_type, scope_id);

CREATE TABLE timeline_events (
	id INTEGER NOT NULL,
	job_id VARCHAR NOT NULL,
	ts VARCHAR NOT NULL,
	type VARCHAR NOT NULL,
	severity VARCHAR,
	title TEXT NOT NULL,
	details_json TEXT,
	pcap_label VARCHAR,
	PRIMARY KEY (id),
	FOREIGN KEY(job_id) REFERENCES jobs (job_id) ON DELETE CASCADE
)

;
CREATE INDEX idx_timeline_job ON timeline_events (job_id);
CREATE INDEX idx_timeline_ts ON timeline_events (job_id, ts);
CREATE INDEX idx_timeline_type ON timeline_events (job_id, type);

CREATE TABLE tls_sessions (
	id INTEGER NOT NULL,
	job_id VARCHAR NOT NULL,
	tls_id VARCHAR NOT NULL,
	host_ip VARCHAR NOT NULL,
	community_id VARCHAR,
	src_ip VARCHAR NOT NULL,
	dest_ip VARCHAR NOT NULL,
	dest_port INTEGER,
	sni VARCHAR,
	ja3 VARCHAR,
	ja3s VARCHAR,
	alpn VARCHAR,
	version VARCHAR,
	cert_subject VARCHAR,
	cert_issuer VARCHAR,
	cert_fingerprint_sha1 VARCHAR,
	ts VARCHAR NOT NULL,
	pcap_label VARCHAR,
	PRIMARY KEY (id),
	UNIQUE (job_id, tls_id),
	FOREIGN KEY(job_id) REFERENCES jobs (job_id) ON DELETE CASCADE
)

;
CREATE INDEX idx_tls_community ON tls_sessions (job_id, community_id);
CREATE INDEX idx_tls_ja3 ON tls_sessions (job_id, ja3);
CREATE INDEX idx_tls_job_host ON tls_sessions (job_id, host_ip);
CREATE INDEX idx_tls_sni ON tls_sessions (job_id, sni);

CREATE TABLE uploads (
	upload_id VARCHAR NOT NULL,
	filename TEXT NOT NULL,
	size_bytes INTEGER NOT NULL,
	sha256 VARCHAR NOT NULL,
	is_valid INTEGER,
	format VARCHAR,
	packet_count INTEGER,
	capture_duration_seconds FLOAT,
	artifact_class VARCHAR,
	created_at VARCHAR NOT NULL,
	PRIMARY KEY (upload_id)
)

;

CREATE TABLE alertdb (
	id VARCHAR NOT NULL,
	job_id VARCHAR NOT NULL,
	timestamp DATETIME NOT NULL,
	src_ip VARCHAR,
	dst_ip VARCHAR,
	src_port INTEGER,
	dst_port INTEGER,
	alert_source VARCHAR NOT NULL,
	signature_id VARCHAR,
	signature_name VARCHAR NOT NULL,
	severity VARCHAR NOT NULL,
	category VARCHAR,
	flow_id VARCHAR,
	extra JSON NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(job_id) REFERENCES jobdb (id)
)

;
CREATE INDEX ix_alertdb_dst_ip ON alertdb (dst_ip);
CREATE INDEX ix_alertdb_job_id ON alertdb (job_id);
CREATE INDEX ix_alertdb_severity ON alertdb (severity);
CREATE INDEX ix_alertdb_signature_id ON alertdb (signature_id);
CREATE INDEX ix_alertdb_src_ip ON alertdb (src_ip);

CREATE TABLE chatmessagedb (
	id VARCHAR NOT NULL,
	conversation_id VARCHAR NOT NULL,
	role VARCHAR NOT NULL,
	content VARCHAR NOT NULL,
	citations JSON NOT NULL,
	created_at DATETIME NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(conversation_id) REFERENCES conversationdb (id)
)

;
CREATE INDEX ix_chatmessagedb_conversation_id ON chatmessagedb (conversation_id);
CREATE INDEX ix_chatmessagedb_id ON chatmessagedb (id);

CREATE TABLE conversationdb (
	id VARCHAR NOT NULL,
	job_id VARCHAR NOT NULL,
	created_at DATETIME NOT NULL,
	updated_at DATETIME NOT NULL,
	title VARCHAR,
	PRIMARY KEY (id),
	FOREIGN KEY(job_id) REFERENCES jobdb (id)
)

;
CREATE INDEX ix_conversationdb_id ON conversationdb (id);
CREATE INDEX ix_conversationdb_job_id ON conversationdb (job_id);

CREATE TABLE evidencedb (
	id VARCHAR NOT NULL,
	finding_id VARCHAR NOT NULL,
	flow_id VARCHAR NOT NULL,
	relationship VARCHAR NOT NULL,
	snippet VARCHAR,
	PRIMARY KEY (id),
	FOREIGN KEY(finding_id) REFERENCES findingdb (id),
	FOREIGN KEY(flow_id) REFERENCES flowdb (id)
)

;
CREATE INDEX ix_evidencedb_finding_id ON evidencedb (finding_id);
CREATE INDEX ix_evidencedb_flow_id ON evidencedb (flow_id);

CREATE TABLE findingdb (
	id VARCHAR NOT NULL,
	job_id VARCHAR NOT NULL,
	mitre_technique_id VARCHAR,
	mitre_technique_name VARCHAR,
	classification VARCHAR,
	severity VARCHAR NOT NULL,
	title VARCHAR NOT NULL,
	description VARCHAR NOT NULL,
	evidence JSON NOT NULL,
	affected_hosts JSON NOT NULL,
	confidence FLOAT NOT NULL,
	analyzer_source VARCHAR NOT NULL,
	attack_chain_stage VARCHAR,
	created_at DATETIME NOT NULL,
	analyst_status VARCHAR NOT NULL,
	analyst_notes VARCHAR,
	PRIMARY KEY (id),
	FOREIGN KEY(job_id) REFERENCES jobdb (id)
)

;
CREATE INDEX ix_findingdb_analyst_status ON findingdb (analyst_status);
CREATE INDEX ix_findingdb_classification ON findingdb (classification);
CREATE INDEX ix_findingdb_id ON findingdb (id);
CREATE INDEX ix_findingdb_job_id ON findingdb (job_id);
CREATE INDEX ix_findingdb_mitre_technique_id ON findingdb (mitre_technique_id);
CREATE INDEX ix_findingdb_severity ON findingdb (severity);

CREATE TABLE flowdb (
	id VARCHAR NOT NULL,
	job_id VARCHAR NOT NULL,
	src_ip VARCHAR NOT NULL,
	src_port INTEGER NOT NULL,
	dst_ip VARCHAR NOT NULL,
	dst_port INTEGER NOT NULL,
	transport_proto VARCHAR NOT NULL,
	app_proto VARCHAR NOT NULL,
	start_time DATETIME NOT NULL,
	end_time DATETIME NOT NULL,
	duration_sec FLOAT NOT NULL,
	bytes_from_src INTEGER NOT NULL,
	bytes_from_dst INTEGER NOT NULL,
	packets_from_src INTEGER NOT NULL,
	packets_from_dst INTEGER NOT NULL,
	tcp_flags_summary VARCHAR,
	state VARCHAR,
	extra JSON NOT NULL,
	PRIMARY KEY (id),
	FOREIGN KEY(job_id) REFERENCES jobdb (id)
)

;
CREATE INDEX ix_flowdb_dst_ip ON flowdb (dst_ip);
CREATE INDEX ix_flowdb_job_id ON flowdb (job_id);
CREATE INDEX ix_flowdb_src_ip ON flowdb (src_ip);

CREATE TABLE jobdb (
	id VARCHAR NOT NULL,
	source VARCHAR NOT NULL,
	mode VARCHAR NOT NULL,
	exercise_id VARCHAR,
	created_at DATETIME NOT NULL,
	updated_at DATETIME NOT NULL,
	status VARCHAR(9) NOT NULL,
	job_metadata JSON NOT NULL,
	error_message VARCHAR,
	PRIMARY KEY (id)
)

;
CREATE INDEX ix_jobdb_id ON jobdb (id);
CREATE INDEX ix_jobdb_status ON jobdb (status);

CREATE TABLE jobresultdb (
	job_id VARCHAR NOT NULL,
	result JSON NOT NULL,
	PRIMARY KEY (job_id),
	FOREIGN KEY(job_id) REFERENCES jobdb (id)
)

;

CREATE TABLE jobstepdb (
	id VARCHAR NOT NULL,
	job_id VARCHAR NOT NULL,
	name VARCHAR NOT NULL,
	status VARCHAR(9) NOT NULL,
	message VARCHAR,
	started_at DATETIME,
	finished_at DATETIME,
	PRIMARY KEY (id),
	FOREIGN KEY(job_id) REFERENCES jobdb (id)
)

;
CREATE INDEX ix_jobstepdb_id ON jobstepdb (id);
CREATE INDEX ix_jobstepdb_job_id ON jobstepdb (job_id);

CREATE TABLE mitrectibundledb (
	domain VARCHAR NOT NULL,
	source_url VARCHAR,
	bundle_sha256 VARCHAR,
	bundle_version VARCHAR,
	bundle_modified DATETIME,
	ingested_at DATETIME,
	PRIMARY KEY (domain)
)

;

CREATE TABLE mitretechniquedb (
	id VARCHAR NOT NULL,
	domain VARCHAR NOT NULL,
	technique_id VARCHAR NOT NULL,
	name VARCHAR NOT NULL,
	description VARCHAR,
	tactics JSON NOT NULL,
	revoked BOOLEAN NOT NULL,
	deprecated BOOLEAN NOT NULL,
	is_subtechnique BOOLEAN NOT NULL,
	version VARCHAR,
	created_at DATETIME,
	modified_at DATETIME,
	source_url VARCHAR,
	bundle_sha256 VARCHAR,
	ingested_at DATETIME,
	PRIMARY KEY (id)
)

;
CREATE INDEX ix_mitretechniquedb_domain ON mitretechniquedb (domain);
CREATE INDEX ix_mitretechniquedb_technique_id ON mitretechniquedb (technique_id);

CREATE TABLE partialjobresultdb (
	job_id VARCHAR NOT NULL,
	result JSON NOT NULL,
	updated_at DATETIME NOT NULL,
	PRIMARY KEY (job_id),
	FOREIGN KEY(job_id) REFERENCES jobdb (id)
)

;

CREATE TABLE pipelinecheckpointdb (
	id VARCHAR NOT NULL,
	job_id VARCHAR NOT NULL,
	step_name VARCHAR NOT NULL,
	state_data JSON NOT NULL,
	completed_at DATETIME,
	PRIMARY KEY (id),
	FOREIGN KEY(job_id) REFERENCES jobdb (id)
)

;
CREATE INDEX ix_pipelinecheckpointdb_job_id ON pipelinecheckpointdb (job_id);

CREATE TABLE settingsdb (
	id INTEGER NOT NULL,
	"values" JSON NOT NULL,
	PRIMARY KEY (id)
)

;
