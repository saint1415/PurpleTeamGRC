-- Purple Team GRC Platform - PostgreSQL Database Schema
-- Initializes all tables required by the application modules
-- Auto-executed by docker-compose on first database creation

-- =============================================================================
-- Evidence Module Tables
-- =============================================================================

CREATE TABLE IF NOT EXISTS evidence (
    id SERIAL PRIMARY KEY,
    evidence_id TEXT UNIQUE NOT NULL,
    session_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    type TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    source_tool TEXT,
    file_path TEXT,
    file_hash TEXT,
    raw_data TEXT,
    metadata TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS control_mappings (
    id SERIAL PRIMARY KEY,
    evidence_id TEXT NOT NULL,
    framework TEXT NOT NULL,
    control_id TEXT NOT NULL,
    control_name TEXT,
    control_family TEXT,
    mapping_type TEXT DEFAULT 'supports',
    notes TEXT,
    FOREIGN KEY (evidence_id) REFERENCES evidence(evidence_id)
);

CREATE TABLE IF NOT EXISTS findings (
    id SERIAL PRIMARY KEY,
    finding_id TEXT UNIQUE NOT NULL,
    session_id TEXT NOT NULL,
    evidence_id TEXT,
    timestamp TEXT NOT NULL,
    severity TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    affected_asset TEXT,
    cvss_score REAL,
    cve_ids TEXT,
    remediation TEXT,
    status TEXT DEFAULT 'open',
    metadata TEXT,
    FOREIGN KEY (evidence_id) REFERENCES evidence(evidence_id)
);

CREATE TABLE IF NOT EXISTS sessions (
    id SERIAL PRIMARY KEY,
    session_id TEXT UNIQUE NOT NULL,
    start_time TEXT NOT NULL,
    end_time TEXT,
    scan_type TEXT,
    target_networks TEXT,
    status TEXT DEFAULT 'running',
    summary TEXT,
    metadata TEXT
);

CREATE TABLE IF NOT EXISTS attestations (
    id SERIAL PRIMARY KEY,
    attestation_id TEXT UNIQUE NOT NULL,
    framework TEXT NOT NULL,
    control_id TEXT NOT NULL,
    period_start TEXT NOT NULL,
    period_end TEXT NOT NULL,
    status TEXT DEFAULT 'draft',
    evidence_ids TEXT DEFAULT '[]',
    attestor TEXT,
    attestor_title TEXT,
    notes TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

-- =============================================================================
-- Asset Inventory Tables
-- =============================================================================

CREATE TABLE IF NOT EXISTS assets (
    id SERIAL PRIMARY KEY,
    asset_id TEXT UNIQUE NOT NULL,
    hostname TEXT,
    ip_address TEXT,
    mac_address TEXT,
    os_type TEXT,
    os_version TEXT,
    business_unit TEXT,
    owner TEXT,
    criticality TEXT DEFAULT 'medium',
    asset_type TEXT DEFAULT 'server',
    location TEXT,
    tags TEXT DEFAULT '[]',
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    last_scanned TEXT,
    status TEXT DEFAULT 'active',
    notes TEXT,
    metadata TEXT DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS asset_findings (
    id SERIAL PRIMARY KEY,
    finding_id TEXT NOT NULL,
    asset_id TEXT NOT NULL,
    linked_at TEXT NOT NULL,
    UNIQUE(finding_id, asset_id),
    FOREIGN KEY (asset_id) REFERENCES assets(asset_id)
);

-- =============================================================================
-- Remediation Tracking Tables
-- =============================================================================

CREATE TABLE IF NOT EXISTS remediation_items (
    id SERIAL PRIMARY KEY,
    item_id TEXT UNIQUE NOT NULL,
    finding_id TEXT,
    asset_id TEXT,
    title TEXT NOT NULL,
    description TEXT,
    severity TEXT NOT NULL,
    assigned_to TEXT,
    status TEXT DEFAULT 'open',
    priority TEXT DEFAULT 'P3',
    sla_days INTEGER,
    due_date TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    resolved_at TEXT,
    verified_at TEXT,
    resolution_notes TEXT,
    ticket_ref TEXT
);

CREATE TABLE IF NOT EXISTS remediation_history (
    id SERIAL PRIMARY KEY,
    history_id TEXT UNIQUE NOT NULL,
    item_id TEXT NOT NULL,
    action TEXT NOT NULL,
    old_value TEXT,
    new_value TEXT,
    changed_by TEXT DEFAULT 'system',
    changed_at TEXT NOT NULL,
    FOREIGN KEY (item_id) REFERENCES remediation_items(item_id)
);

-- =============================================================================
-- Risk Register Tables
-- =============================================================================

CREATE TABLE IF NOT EXISTS risks (
    id SERIAL PRIMARY KEY,
    risk_id TEXT UNIQUE NOT NULL,
    title TEXT NOT NULL,
    description TEXT,
    risk_category TEXT DEFAULT 'technical',
    likelihood INTEGER DEFAULT 3,
    impact INTEGER DEFAULT 3,
    risk_score INTEGER DEFAULT 9,
    inherent_risk_score INTEGER,
    residual_risk_score INTEGER,
    risk_owner TEXT,
    business_unit TEXT,
    status TEXT DEFAULT 'identified',
    mitigation_plan TEXT,
    related_findings TEXT DEFAULT '[]',
    related_controls TEXT DEFAULT '[]',
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    review_date TEXT,
    notes TEXT
);

CREATE TABLE IF NOT EXISTS risk_snapshots (
    id SERIAL PRIMARY KEY,
    snapshot_date TEXT NOT NULL,
    total_risks INTEGER,
    avg_score REAL,
    critical_count INTEGER,
    high_count INTEGER,
    medium_count INTEGER,
    low_count INTEGER,
    data TEXT DEFAULT '{}'
);

-- =============================================================================
-- Audit Trail Tables
-- =============================================================================

CREATE TABLE IF NOT EXISTS audit_log (
    log_id SERIAL PRIMARY KEY,
    timestamp TEXT NOT NULL,
    action TEXT NOT NULL,
    actor TEXT DEFAULT 'system',
    target_type TEXT,
    target_id TEXT,
    details TEXT DEFAULT '{}',
    ip_address TEXT,
    session_id TEXT
);

-- =============================================================================
-- Exception Management Tables
-- =============================================================================

CREATE TABLE IF NOT EXISTS exceptions (
    id SERIAL PRIMARY KEY,
    exception_id TEXT UNIQUE NOT NULL,
    finding_type TEXT,
    title_pattern TEXT NOT NULL,
    asset_pattern TEXT,
    exception_type TEXT NOT NULL,
    justification TEXT NOT NULL,
    approved_by TEXT,
    approved_at TEXT,
    expires_at TEXT,
    status TEXT NOT NULL DEFAULT 'pending',
    compensating_control TEXT,
    created_at TEXT NOT NULL,
    created_by TEXT,
    reviewed_at TEXT
);

CREATE TABLE IF NOT EXISTS exception_history (
    id SERIAL PRIMARY KEY,
    exception_id TEXT NOT NULL,
    action TEXT NOT NULL,
    actor TEXT,
    timestamp TEXT NOT NULL,
    notes TEXT,
    FOREIGN KEY (exception_id) REFERENCES exceptions(exception_id)
);

-- =============================================================================
-- Scheduler Tables
-- =============================================================================

CREATE TABLE IF NOT EXISTS schedules (
    id SERIAL PRIMARY KEY,
    schedule_id TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    description TEXT DEFAULT '',
    scanner_type TEXT NOT NULL,
    scan_type TEXT NOT NULL DEFAULT 'standard',
    targets TEXT DEFAULT '[]',
    cron_expression TEXT NOT NULL,
    enabled INTEGER DEFAULT 1,
    last_run TEXT,
    next_run TEXT,
    run_count INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT NOW(),
    created_by TEXT DEFAULT 'system'
);

CREATE TABLE IF NOT EXISTS schedule_runs (
    id SERIAL PRIMARY KEY,
    run_id TEXT UNIQUE NOT NULL,
    schedule_id TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    status TEXT NOT NULL DEFAULT 'running',
    session_id TEXT,
    summary TEXT DEFAULT '{}',
    FOREIGN KEY (schedule_id) REFERENCES schedules(schedule_id)
);

-- =============================================================================
-- Notification System Tables
-- =============================================================================

CREATE TABLE IF NOT EXISTS notification_channels (
    id SERIAL PRIMARY KEY,
    channel_id TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    channel_type TEXT NOT NULL,
    config TEXT NOT NULL DEFAULT '{}',
    enabled INTEGER DEFAULT 1,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS notifications (
    id SERIAL PRIMARY KEY,
    notification_id TEXT UNIQUE NOT NULL,
    channel_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    severity TEXT DEFAULT 'INFO',
    subject TEXT NOT NULL,
    body TEXT DEFAULT '',
    status TEXT DEFAULT 'pending',
    sent_at TEXT,
    error_message TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    FOREIGN KEY (channel_id) REFERENCES notification_channels(channel_id)
);

-- =============================================================================
-- Discovery Engine Tables
-- =============================================================================

CREATE TABLE IF NOT EXISTS discovered_hosts (
    id SERIAL PRIMARY KEY,
    host_id TEXT UNIQUE NOT NULL,
    ip_address TEXT NOT NULL,
    hostname TEXT,
    mac_address TEXT,
    os_guess TEXT DEFAULT 'unknown',
    os_confidence INTEGER DEFAULT 0,
    open_ports TEXT DEFAULT '[]',
    services TEXT DEFAULT '{}',
    discovery_method TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    status TEXT DEFAULT 'live',
    auto_registered INTEGER DEFAULT 0
);

-- =============================================================================
-- Vulnerability Database Tables
-- =============================================================================

CREATE TABLE IF NOT EXISTS nvd_cves (
    cve_id TEXT PRIMARY KEY,
    description TEXT,
    cvss_v31_score REAL,
    cvss_v31_vector TEXT,
    cvss_v31_severity TEXT,
    cvss_v2_score REAL,
    cwe_ids TEXT,
    references_json TEXT,
    published TEXT,
    last_modified TEXT,
    configurations TEXT,
    cached_at REAL
);

CREATE TABLE IF NOT EXISTS cwe_details (
    cwe_id TEXT PRIMARY KEY,
    name TEXT,
    description TEXT,
    extended_description TEXT,
    likelihood_of_exploit TEXT,
    common_consequences TEXT,
    detection_methods TEXT,
    mitigations TEXT,
    related_cwes TEXT,
    cached_at REAL
);

CREATE TABLE IF NOT EXISTS update_log (
    id SERIAL PRIMARY KEY,
    source TEXT NOT NULL,
    update_type TEXT,
    records_count INTEGER,
    timestamp TIMESTAMP DEFAULT NOW(),
    status TEXT,
    details TEXT
);

-- =============================================================================
-- Indexes for Performance
-- =============================================================================

-- Evidence indexes
CREATE INDEX IF NOT EXISTS idx_evidence_session ON evidence(session_id);
CREATE INDEX IF NOT EXISTS idx_findings_session ON findings(session_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_sessions_status ON sessions(status);

-- Asset indexes
CREATE INDEX IF NOT EXISTS idx_assets_hostname ON assets(hostname);
CREATE INDEX IF NOT EXISTS idx_assets_ip ON assets(ip_address);
CREATE INDEX IF NOT EXISTS idx_assets_status ON assets(status);
CREATE INDEX IF NOT EXISTS idx_assets_criticality ON assets(criticality);
CREATE INDEX IF NOT EXISTS idx_assets_bu ON assets(business_unit);
CREATE INDEX IF NOT EXISTS idx_assets_os ON assets(os_type);
CREATE INDEX IF NOT EXISTS idx_af_asset ON asset_findings(asset_id);
CREATE INDEX IF NOT EXISTS idx_af_finding ON asset_findings(finding_id);

-- Remediation indexes
CREATE INDEX IF NOT EXISTS idx_ri_status ON remediation_items(status);
CREATE INDEX IF NOT EXISTS idx_ri_severity ON remediation_items(severity);
CREATE INDEX IF NOT EXISTS idx_ri_assigned ON remediation_items(assigned_to);
CREATE INDEX IF NOT EXISTS idx_ri_due ON remediation_items(due_date);
CREATE INDEX IF NOT EXISTS idx_ri_finding ON remediation_items(finding_id);
CREATE INDEX IF NOT EXISTS idx_rh_item ON remediation_history(item_id);

-- Risk indexes
CREATE INDEX IF NOT EXISTS idx_risks_category ON risks(risk_category);
CREATE INDEX IF NOT EXISTS idx_risks_status ON risks(status);
CREATE INDEX IF NOT EXISTS idx_risks_score ON risks(risk_score);
CREATE INDEX IF NOT EXISTS idx_risks_bu ON risks(business_unit);
CREATE INDEX IF NOT EXISTS idx_snap_date ON risk_snapshots(snapshot_date);

-- Audit indexes
CREATE INDEX IF NOT EXISTS idx_al_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_al_action ON audit_log(action);
CREATE INDEX IF NOT EXISTS idx_al_actor ON audit_log(actor);
CREATE INDEX IF NOT EXISTS idx_al_target ON audit_log(target_type, target_id);
CREATE INDEX IF NOT EXISTS idx_al_session ON audit_log(session_id);

-- Exception indexes
CREATE INDEX IF NOT EXISTS idx_exc_status ON exceptions(status);
CREATE INDEX IF NOT EXISTS idx_exc_type ON exceptions(exception_type);
CREATE INDEX IF NOT EXISTS idx_exc_expires ON exceptions(expires_at);
CREATE INDEX IF NOT EXISTS idx_exh_exception ON exception_history(exception_id);

-- Scheduler indexes
CREATE INDEX IF NOT EXISTS idx_schedules_enabled ON schedules(enabled);
CREATE INDEX IF NOT EXISTS idx_schedules_next_run ON schedules(next_run);
CREATE INDEX IF NOT EXISTS idx_runs_schedule ON schedule_runs(schedule_id);
CREATE INDEX IF NOT EXISTS idx_runs_status ON schedule_runs(status);

-- Notification indexes
CREATE INDEX IF NOT EXISTS idx_notifications_channel ON notifications(channel_id);
CREATE INDEX IF NOT EXISTS idx_notifications_event ON notifications(event_type);
CREATE INDEX IF NOT EXISTS idx_notifications_status ON notifications(status);
CREATE INDEX IF NOT EXISTS idx_channels_type ON notification_channels(channel_type);
CREATE INDEX IF NOT EXISTS idx_channels_enabled ON notification_channels(enabled);

-- Discovery indexes
CREATE INDEX IF NOT EXISTS idx_dh_ip ON discovered_hosts(ip_address);
CREATE INDEX IF NOT EXISTS idx_dh_status ON discovered_hosts(status);
CREATE INDEX IF NOT EXISTS idx_dh_os ON discovered_hosts(os_guess);
CREATE INDEX IF NOT EXISTS idx_dh_last_seen ON discovered_hosts(last_seen);

-- Vulnerability database indexes
CREATE INDEX IF NOT EXISTS idx_nvd_cwe ON nvd_cves(cwe_ids);
CREATE INDEX IF NOT EXISTS idx_nvd_severity ON nvd_cves(cvss_v31_severity);
CREATE INDEX IF NOT EXISTS idx_nvd_cached ON nvd_cves(cached_at);
