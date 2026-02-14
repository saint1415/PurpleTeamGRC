#!/usr/bin/env python3
"""
Purple Team GRC - REST API Server
Uses Python stdlib http.server by default; Flask if available.
All endpoints return JSON. Dashboard served at GET /.
"""

import json
import os
import re
import sys
import traceback
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

# ---------------------------------------------------------------------------
# Ensure lib/ is on the Python path
# ---------------------------------------------------------------------------
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT / 'lib'))
sys.path.insert(0, str(_PROJECT_ROOT))

# ---------------------------------------------------------------------------
# Import lib modules (all have singleton getters)
# ---------------------------------------------------------------------------
try:
    from lib.evidence import get_evidence_manager
except ImportError:
    get_evidence_manager = None

try:
    from lib.asset_inventory import get_asset_inventory
except ImportError:
    get_asset_inventory = None

try:
    from lib.remediation import get_remediation_tracker
except ImportError:
    get_remediation_tracker = None

try:
    from lib.risk_register import get_risk_register
except ImportError:
    get_risk_register = None

try:
    from lib.audit import get_audit_trail
except ImportError:
    get_audit_trail = None

try:
    from lib.exceptions import get_exception_manager
except ImportError:
    get_exception_manager = None

try:
    from lib.export import ExportManager
except ImportError:
    ExportManager = None

try:
    from lib.discovery import get_discovery_engine
except ImportError:
    get_discovery_engine = None

try:
    from lib.executive_report import get_report_generator
except ImportError:
    get_report_generator = None

try:
    from lib.compliance import get_compliance_mapper
except ImportError:
    get_compliance_mapper = None

from web.auth import get_auth, APIKeyAuth
from web.dashboard import generate_dashboard_html

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _json_serial(obj: Any) -> Any:
    """JSON serialiser for objects not handled by default."""
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, bytes):
        return obj.decode('utf-8', errors='replace')
    if hasattr(obj, '__dict__'):
        return obj.__dict__
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


def json_response(data: Any, status: int = 200) -> Tuple[bytes, int, str]:
    """Return (body_bytes, status_code, content_type)."""
    body = json.dumps(data, default=_json_serial, indent=2)
    return body.encode('utf-8'), status, 'application/json'


def error_response(message: str, status: int = 400) -> Tuple[bytes, int, str]:
    """Return a JSON error response."""
    return json_response({'error': True, 'message': message}, status)


def html_response(html: str, status: int = 200) -> Tuple[bytes, int, str]:
    """Return an HTML response."""
    return html.encode('utf-8'), status, 'text/html; charset=utf-8'


# ---------------------------------------------------------------------------
# Route registry
# ---------------------------------------------------------------------------

class Route:
    """Represents a single API route with method, pattern, and handler."""

    def __init__(self, method: str, pattern: str, handler: Callable):
        self.method = method.upper()
        self.handler = handler
        # Convert /api/v1/assets/<id> to a regex with named groups
        regex = re.sub(r'<(\w+)>', r'(?P<\1>[^/]+)', pattern)
        self.regex = re.compile(f'^{regex}$')

    def match(self, method: str, path: str) -> Optional[Dict[str, str]]:
        """Return path params dict if this route matches, else None."""
        if method.upper() != self.method:
            return None
        m = self.regex.match(path)
        return m.groupdict() if m else None


# ---------------------------------------------------------------------------
# PurpleTeamAPI  --  core API logic (framework-agnostic)
# ---------------------------------------------------------------------------

class PurpleTeamAPI:
    """
    Core API logic. Registers routes and dispatches requests.
    Independent of transport layer (stdlib or Flask).
    """

    def __init__(self, auth: Optional[APIKeyAuth] = None):
        self.auth = auth or get_auth()
        self.routes: List[Route] = []
        self._start_time = datetime.utcnow()
        self._agents: Dict[str, Dict] = {}  # agent_id -> last check-in
        self._register_routes()

    # ---- route registration helpers -------------------------------------

    def _get(self, pattern: str, handler: Callable):
        self.routes.append(Route('GET', pattern, handler))

    def _post(self, pattern: str, handler: Callable):
        self.routes.append(Route('POST', pattern, handler))

    def _put(self, pattern: str, handler: Callable):
        self.routes.append(Route('PUT', pattern, handler))

    # ---- dispatch -------------------------------------------------------

    def dispatch(self, method: str, path: str, query: Dict[str, str],
                 body: Optional[Dict], api_key: Optional[str] = None,
                 ) -> Tuple[bytes, int, str]:
        """
        Route a request and return (body_bytes, status, content_type).
        """
        # --- Authentication -----------------------------------------------
        if not self.auth.authenticate(path, api_key):
            return json_response(self.auth.get_auth_error_response(), 401)

        # --- Dashboard ----------------------------------------------------
        if method == 'GET' and path == '/':
            return html_response(generate_dashboard_html())

        # --- Route matching -----------------------------------------------
        for route in self.routes:
            params = route.match(method, path)
            if params is not None:
                try:
                    return route.handler(params=params, query=query, body=body)
                except Exception as exc:
                    tb = traceback.format_exc()
                    sys.stderr.write(f"API error on {method} {path}: {tb}\n")
                    return error_response(str(exc), 500)

        return error_response(f"Not found: {method} {path}", 404)

    # =====================================================================
    # Route handlers
    # =====================================================================

    def _register_routes(self):
        # -- Health / Stats ------------------------------------------------
        self._get('/api/v1/health', self._health)
        self._get('/api/v1/stats', self._stats)

        # -- Assets --------------------------------------------------------
        self._get('/api/v1/assets', self._list_assets)
        self._post('/api/v1/assets', self._create_asset)
        self._get('/api/v1/assets/<id>', self._get_asset)
        self._put('/api/v1/assets/<id>', self._update_asset)

        # -- Scans ---------------------------------------------------------
        self._post('/api/v1/scans', self._start_scan)
        self._get('/api/v1/scans', self._list_scans)
        self._get('/api/v1/scans/<session_id>', self._get_scan)
        self._get('/api/v1/scans/<session_id>/findings', self._scan_findings)

        # -- Findings ------------------------------------------------------
        self._get('/api/v1/findings', self._list_findings)
        self._get('/api/v1/findings/<id>', self._get_finding)

        # -- Remediation ---------------------------------------------------
        self._get('/api/v1/remediation', self._list_remediation)
        self._post('/api/v1/remediation', self._create_remediation)
        self._put('/api/v1/remediation/<id>', self._update_remediation)
        self._get('/api/v1/remediation/metrics', self._remediation_metrics)

        # -- Risk Register -------------------------------------------------
        self._get('/api/v1/risks', self._list_risks)
        self._post('/api/v1/risks', self._create_risk)
        self._get('/api/v1/risks/posture', self._risk_posture)
        self._get('/api/v1/risks/matrix', self._risk_matrix)

        # -- Exceptions ----------------------------------------------------
        self._get('/api/v1/exceptions', self._list_exceptions)
        self._post('/api/v1/exceptions', self._create_exception)
        self._put('/api/v1/exceptions/<id>/approve', self._approve_exception)

        # -- Reports -------------------------------------------------------
        self._get('/api/v1/reports/executive', self._executive_report)
        self._get('/api/v1/reports/compliance/<fw>', self._compliance_report)

        # -- Export --------------------------------------------------------
        self._post('/api/v1/export', self._export_data)

        # -- Agents --------------------------------------------------------
        self._post('/api/v1/agents/checkin', self._agent_checkin)
        self._get('/api/v1/agents', self._list_agents)

        # -- Discovery -----------------------------------------------------
        self._post('/api/v1/discovery/scan', self._discovery_scan)
        self._get('/api/v1/discovery/hosts', self._discovery_hosts)

        # -- Audit ---------------------------------------------------------
        self._get('/api/v1/audit', self._audit_log)

    # ------------------------------------------------------------------
    # Health / Stats
    # ------------------------------------------------------------------

    def _health(self, **kw) -> Tuple[bytes, int, str]:
        uptime = (datetime.utcnow() - self._start_time).total_seconds()
        modules = {
            'evidence': get_evidence_manager is not None,
            'asset_inventory': get_asset_inventory is not None,
            'remediation': get_remediation_tracker is not None,
            'risk_register': get_risk_register is not None,
            'audit': get_audit_trail is not None,
            'exceptions': get_exception_manager is not None,
            'export': ExportManager is not None,
            'discovery': get_discovery_engine is not None,
            'reports': get_report_generator is not None,
            'compliance': get_compliance_mapper is not None,
        }
        return json_response({
            'status': 'healthy',
            'version': '7.0',
            'uptime_seconds': round(uptime, 2),
            'timestamp': datetime.utcnow().isoformat(),
            'modules': modules,
        })

    def _stats(self, **kw) -> Tuple[bytes, int, str]:
        stats: Dict[str, Any] = {}
        if get_asset_inventory:
            try:
                stats['assets'] = get_asset_inventory().get_statistics()
            except Exception as e:
                stats['assets'] = {'error': str(e)}
        if get_evidence_manager:
            try:
                em = get_evidence_manager()
                sessions = em.get_all_sessions(limit=1)
                stats['sessions_total'] = len(em.get_all_sessions(limit=10000))
                findings = em.get_findings_by_severity(status='open')
                stats['open_findings'] = len(findings)
                by_sev: Dict[str, int] = {}
                for f in findings:
                    s = f.get('severity', 'INFO')
                    by_sev[s] = by_sev.get(s, 0) + 1
                stats['findings_by_severity'] = by_sev
            except Exception as e:
                stats['evidence'] = {'error': str(e)}
        if get_remediation_tracker:
            try:
                stats['remediation'] = get_remediation_tracker().get_statistics()
            except Exception as e:
                stats['remediation'] = {'error': str(e)}
        if get_risk_register:
            try:
                stats['risks'] = get_risk_register().get_statistics()
            except Exception as e:
                stats['risks'] = {'error': str(e)}
        if get_exception_manager:
            try:
                stats['exceptions'] = get_exception_manager().get_statistics()
            except Exception as e:
                stats['exceptions'] = {'error': str(e)}
        if get_audit_trail:
            try:
                stats['audit'] = get_audit_trail().get_statistics()
            except Exception as e:
                stats['audit'] = {'error': str(e)}
        if get_discovery_engine:
            try:
                stats['discovery'] = get_discovery_engine().get_statistics()
            except Exception as e:
                stats['discovery'] = {'error': str(e)}
        stats['agents'] = {
            'connected': len(self._agents),
            'agent_ids': list(self._agents.keys()),
        }
        return json_response(stats)

    # ------------------------------------------------------------------
    # Assets
    # ------------------------------------------------------------------

    def _list_assets(self, query: Dict, **kw) -> Tuple[bytes, int, str]:
        if not get_asset_inventory:
            return error_response('Asset inventory module not available', 503)
        inv = get_asset_inventory()
        assets = inv.find_assets(
            business_unit=query.get('business_unit'),
            os_type=query.get('os_type'),
            status=query.get('status', 'active'),
        )
        return json_response({'count': len(assets), 'assets': assets})

    def _create_asset(self, body: Optional[Dict], **kw) -> Tuple[bytes, int, str]:
        if not get_asset_inventory:
            return error_response('Asset inventory module not available', 503)
        if not body:
            return error_response('Request body required')
        hostname = body.get('hostname')
        ip_address = body.get('ip_address')
        if not hostname or not ip_address:
            return error_response('hostname and ip_address are required')
        inv = get_asset_inventory()
        asset_id = inv.add_asset(hostname, ip_address, **{
            k: v for k, v in body.items() if k not in ('hostname', 'ip_address')
        })
        if get_audit_trail:
            get_audit_trail().log('asset_created', target_type='asset',
                                 target_id=asset_id,
                                 details={'hostname': hostname, 'ip': ip_address})
        return json_response({'asset_id': asset_id}, 201)

    def _get_asset(self, params: Dict, **kw) -> Tuple[bytes, int, str]:
        if not get_asset_inventory:
            return error_response('Asset inventory module not available', 503)
        asset = get_asset_inventory().get_asset(params['id'])
        if not asset:
            return error_response('Asset not found', 404)
        return json_response(asset)

    def _update_asset(self, params: Dict, body: Optional[Dict], **kw) -> Tuple[bytes, int, str]:
        if not get_asset_inventory:
            return error_response('Asset inventory module not available', 503)
        if not body:
            return error_response('Request body required')
        get_asset_inventory().update_asset(params['id'], **body)
        if get_audit_trail:
            get_audit_trail().log('asset_updated', target_type='asset',
                                 target_id=params['id'],
                                 details=body)
        return json_response({'updated': True, 'asset_id': params['id']})

    # ------------------------------------------------------------------
    # Scans
    # ------------------------------------------------------------------

    def _start_scan(self, body: Optional[Dict], **kw) -> Tuple[bytes, int, str]:
        if not get_evidence_manager:
            return error_response('Evidence module not available', 503)
        if not body:
            return error_response('Request body required')
        scan_type = body.get('scan_type', 'manual')
        targets = body.get('targets', [])
        if isinstance(targets, str):
            targets = [targets]
        em = get_evidence_manager()
        session_id = em.start_session(scan_type, targets, metadata=body.get('metadata'))
        if get_audit_trail:
            get_audit_trail().log('scan_started', target_type='scan',
                                 target_id=session_id,
                                 details={'scan_type': scan_type, 'targets': targets})
        return json_response({'session_id': session_id, 'status': 'running'}, 201)

    def _list_scans(self, query: Dict, **kw) -> Tuple[bytes, int, str]:
        if not get_evidence_manager:
            return error_response('Evidence module not available', 503)
        limit = int(query.get('limit', '50'))
        sessions = get_evidence_manager().get_all_sessions(limit=limit)
        return json_response({'count': len(sessions), 'sessions': sessions})

    def _get_scan(self, params: Dict, **kw) -> Tuple[bytes, int, str]:
        if not get_evidence_manager:
            return error_response('Evidence module not available', 503)
        summary = get_evidence_manager().get_session_summary(params['session_id'])
        if not summary:
            return error_response('Session not found', 404)
        return json_response(summary)

    def _scan_findings(self, params: Dict, **kw) -> Tuple[bytes, int, str]:
        if not get_evidence_manager:
            return error_response('Evidence module not available', 503)
        findings = get_evidence_manager().get_findings_for_session(params['session_id'])
        return json_response({'count': len(findings), 'findings': findings})

    # ------------------------------------------------------------------
    # Findings
    # ------------------------------------------------------------------

    def _list_findings(self, query: Dict, **kw) -> Tuple[bytes, int, str]:
        if not get_evidence_manager:
            return error_response('Evidence module not available', 503)
        em = get_evidence_manager()
        severity = query.get('severity')
        session_id = query.get('session_id')
        status = query.get('status', 'open')

        if session_id:
            findings = em.get_findings_for_session(session_id)
            if severity:
                findings = [f for f in findings if f.get('severity', '').upper() == severity.upper()]
        else:
            findings = em.get_findings_by_severity(severity=severity, status=status)

        # Optional asset filter
        asset_filter = query.get('asset')
        if asset_filter:
            findings = [f for f in findings
                        if asset_filter.lower() in (f.get('affected_asset', '') or '').lower()]

        return json_response({'count': len(findings), 'findings': findings})

    def _get_finding(self, params: Dict, **kw) -> Tuple[bytes, int, str]:
        if not get_evidence_manager:
            return error_response('Evidence module not available', 503)
        import sqlite3
        em = get_evidence_manager()
        with sqlite3.connect(str(em.db_path)) as conn:
            conn.row_factory = sqlite3.Row
            row = conn.execute(
                'SELECT * FROM findings WHERE finding_id = ?', (params['id'],)
            ).fetchone()
        if not row:
            return error_response('Finding not found', 404)
        return json_response(dict(row))

    # ------------------------------------------------------------------
    # Remediation
    # ------------------------------------------------------------------

    def _list_remediation(self, query: Dict, **kw) -> Tuple[bytes, int, str]:
        if not get_remediation_tracker:
            return error_response('Remediation module not available', 503)
        rt = get_remediation_tracker()
        status_filter = query.get('status')
        assigned_to = query.get('assigned_to')
        overdue = query.get('overdue', '').lower() in ('true', '1', 'yes')

        if overdue:
            items = rt.get_overdue_items()
        else:
            items = rt.get_open_items(assigned_to=assigned_to)

        if status_filter:
            items = [i for i in items if i.get('status') == status_filter]

        return json_response({'count': len(items), 'items': items})

    def _create_remediation(self, body: Optional[Dict], **kw) -> Tuple[bytes, int, str]:
        if not get_remediation_tracker:
            return error_response('Remediation module not available', 503)
        if not body:
            return error_response('Request body required')
        finding_id = body.get('finding_id', '')
        title = body.get('title')
        severity = body.get('severity', 'medium')
        if not title:
            return error_response('title is required')
        rt = get_remediation_tracker()
        item_id = rt.create_item(finding_id=finding_id, title=title,
                                 severity=severity, **{
            k: v for k, v in body.items()
            if k not in ('finding_id', 'title', 'severity')
        })
        if get_audit_trail:
            get_audit_trail().log('remediation_created', target_type='remediation',
                                 target_id=item_id, details=body)
        return json_response({'item_id': item_id}, 201)

    def _update_remediation(self, params: Dict, body: Optional[Dict], **kw) -> Tuple[bytes, int, str]:
        if not get_remediation_tracker:
            return error_response('Remediation module not available', 503)
        if not body:
            return error_response('Request body required')
        rt = get_remediation_tracker()
        item_id = params['id']

        # Check the item exists
        item = rt.get_item(item_id)
        if not item:
            return error_response('Remediation item not found', 404)

        new_status = body.get('status')
        assigned_to = body.get('assigned_to')
        notes = body.get('notes')
        changed_by = body.get('changed_by', 'api')

        if assigned_to:
            rt.assign(item_id, assigned_to, changed_by=changed_by)
        if new_status:
            rt.update_status(item_id, new_status, notes=notes,
                             changed_by=changed_by)

        if get_audit_trail:
            get_audit_trail().log('remediation_updated', target_type='remediation',
                                 target_id=item_id, details=body)
        updated = rt.get_item(item_id)
        return json_response(updated or {'updated': True})

    def _remediation_metrics(self, **kw) -> Tuple[bytes, int, str]:
        if not get_remediation_tracker:
            return error_response('Remediation module not available', 503)
        rt = get_remediation_tracker()
        return json_response({
            'sla': rt.get_sla_status(),
            'metrics': rt.get_remediation_metrics(),
            'statistics': rt.get_statistics(),
        })

    # ------------------------------------------------------------------
    # Risk Register
    # ------------------------------------------------------------------

    def _list_risks(self, query: Dict, **kw) -> Tuple[bytes, int, str]:
        if not get_risk_register:
            return error_response('Risk register module not available', 503)
        rr = get_risk_register()
        risks = rr.get_risks(
            category=query.get('category'),
            status=query.get('status'),
            business_unit=query.get('business_unit'),
            min_score=int(query['min_score']) if query.get('min_score') else None,
        )
        return json_response({'count': len(risks), 'risks': risks})

    def _create_risk(self, body: Optional[Dict], **kw) -> Tuple[bytes, int, str]:
        if not get_risk_register:
            return error_response('Risk register module not available', 503)
        if not body:
            return error_response('Request body required')
        title = body.get('title')
        category = body.get('category', 'technical')
        likelihood = int(body.get('likelihood', 3))
        impact = int(body.get('impact', 3))
        if not title:
            return error_response('title is required')
        rr = get_risk_register()
        risk_id = rr.add_risk(title=title, category=category,
                              likelihood=likelihood, impact=impact, **{
            k: v for k, v in body.items()
            if k not in ('title', 'category', 'likelihood', 'impact')
        })
        if get_audit_trail:
            get_audit_trail().log('risk_created', target_type='risk',
                                 target_id=risk_id, details=body)
        return json_response({'risk_id': risk_id}, 201)

    def _risk_posture(self, **kw) -> Tuple[bytes, int, str]:
        if not get_risk_register:
            return error_response('Risk register module not available', 503)
        return json_response(get_risk_register().calculate_risk_posture())

    def _risk_matrix(self, **kw) -> Tuple[bytes, int, str]:
        if not get_risk_register:
            return error_response('Risk register module not available', 503)
        matrix = get_risk_register().get_risk_matrix()
        return json_response({'matrix': matrix})

    # ------------------------------------------------------------------
    # Exceptions
    # ------------------------------------------------------------------

    def _list_exceptions(self, query: Dict, **kw) -> Tuple[bytes, int, str]:
        if not get_exception_manager:
            return error_response('Exception module not available', 503)
        em = get_exception_manager()
        status_filter = query.get('status')
        if status_filter == 'pending':
            exceptions = em.get_pending_exceptions()
        elif status_filter == 'active':
            exceptions = em.get_active_exceptions()
        elif status_filter == 'expiring':
            exceptions = em.get_expiring_soon(days=30)
        else:
            exceptions = em.get_all_exceptions()
        return json_response({'count': len(exceptions), 'exceptions': exceptions})

    def _create_exception(self, body: Optional[Dict], **kw) -> Tuple[bytes, int, str]:
        if not get_exception_manager:
            return error_response('Exception module not available', 503)
        if not body:
            return error_response('Request body required')
        required = ('title_pattern', 'exception_type', 'justification')
        for field in required:
            if not body.get(field):
                return error_response(f'{field} is required')
        em = get_exception_manager()
        exc_id = em.create_exception(
            finding_type=body.get('finding_type', ''),
            title_pattern=body['title_pattern'],
            exception_type=body['exception_type'],
            justification=body['justification'],
            **{k: v for k, v in body.items() if k not in required and k != 'finding_type'}
        )
        if get_audit_trail:
            get_audit_trail().log('exception_created', target_type='exception',
                                 target_id=exc_id, details=body)
        return json_response({'exception_id': exc_id}, 201)

    def _approve_exception(self, params: Dict, body: Optional[Dict], **kw) -> Tuple[bytes, int, str]:
        if not get_exception_manager:
            return error_response('Exception module not available', 503)
        body = body or {}
        approved_by = body.get('approved_by', 'api')
        notes = body.get('notes', '')
        em = get_exception_manager()
        try:
            em.approve_exception(params['id'], approved_by=approved_by, notes=notes)
        except ValueError as e:
            return error_response(str(e), 400)
        return json_response({'approved': True, 'exception_id': params['id']})

    # ------------------------------------------------------------------
    # Reports
    # ------------------------------------------------------------------

    def _executive_report(self, query: Dict, **kw) -> Tuple[bytes, int, str]:
        if not get_report_generator:
            return error_response('Report module not available', 503)
        days = int(query.get('days', '30'))
        rg = get_report_generator()
        html = rg.generate_executive_summary(days=days)
        return html_response(html)

    def _compliance_report(self, params: Dict, query: Dict, **kw) -> Tuple[bytes, int, str]:
        if not get_report_generator:
            return error_response('Report module not available', 503)
        rg = get_report_generator()
        html = rg.generate_compliance_report(framework=params['fw'])
        return html_response(html)

    # ------------------------------------------------------------------
    # Export
    # ------------------------------------------------------------------

    def _export_data(self, body: Optional[Dict], **kw) -> Tuple[bytes, int, str]:
        if not ExportManager:
            return error_response('Export module not available', 503)
        if not body:
            return error_response('Request body required')
        session_id = body.get('session_id')
        formats = body.get('formats')
        if not session_id:
            return error_response('session_id is required')
        exporter = ExportManager()
        try:
            results = exporter.export_all(session_id, formats=formats)
            output = {fmt: str(path) for fmt, path in results.items()}
            if get_audit_trail:
                get_audit_trail().log('export_performed', target_type='export',
                                     details={'session_id': session_id,
                                              'formats': list(output.keys())})
            return json_response({'exported': output})
        except ValueError as e:
            return error_response(str(e), 404)
        except Exception as e:
            return error_response(str(e), 500)

    # ------------------------------------------------------------------
    # Agents
    # ------------------------------------------------------------------

    def _agent_checkin(self, body: Optional[Dict], **kw) -> Tuple[bytes, int, str]:
        if not body:
            return error_response('Request body required')
        agent_id = body.get('agent_id')
        if not agent_id:
            return error_response('agent_id is required')
        self._agents[agent_id] = {
            'agent_id': agent_id,
            'last_checkin': datetime.utcnow().isoformat(),
            'hostname': body.get('hostname', ''),
            'ip_address': body.get('ip_address', ''),
            'results': body.get('results', {}),
        }
        # Ingest any findings from the agent
        findings_count = 0
        if get_evidence_manager and body.get('results'):
            em = get_evidence_manager()
            results = body['results']
            session_id = results.get('session_id')
            if session_id and results.get('findings'):
                for f in results['findings']:
                    em.add_finding(
                        session_id=session_id,
                        severity=f.get('severity', 'INFO'),
                        title=f.get('title', 'Agent finding'),
                        description=f.get('description', ''),
                        affected_asset=f.get('affected_asset', body.get('hostname', '')),
                        cvss_score=float(f.get('cvss_score', 0)),
                        cve_ids=f.get('cve_ids', []),
                        remediation=f.get('remediation', ''),
                    )
                    findings_count += 1

        return json_response({
            'acknowledged': True,
            'agent_id': agent_id,
            'findings_ingested': findings_count,
        })

    def _list_agents(self, **kw) -> Tuple[bytes, int, str]:
        agents = list(self._agents.values())
        # Strip raw results from listing for brevity
        for a in agents:
            a.pop('results', None)
        return json_response({'count': len(agents), 'agents': agents})

    # ------------------------------------------------------------------
    # Discovery
    # ------------------------------------------------------------------

    def _discovery_scan(self, body: Optional[Dict], **kw) -> Tuple[bytes, int, str]:
        if not get_discovery_engine:
            return error_response('Discovery module not available', 503)
        body = body or {}
        cidr = body.get('cidr', 'auto')
        methods = body.get('methods', ['arp', 'icmp', 'tcp'])
        engine = get_discovery_engine()
        hosts = engine.discover_network(cidr=cidr, methods=methods)
        if get_audit_trail:
            get_audit_trail().log('scan_started', actor='api',
                                 target_type='discovery',
                                 details={'cidr': cidr, 'hosts_found': len(hosts)})
        return json_response({
            'cidr': cidr,
            'hosts_found': len(hosts),
            'hosts': hosts,
        })

    def _discovery_hosts(self, query: Dict, **kw) -> Tuple[bytes, int, str]:
        if not get_discovery_engine:
            return error_response('Discovery module not available', 503)
        engine = get_discovery_engine()
        hosts = engine.get_discovered_hosts(
            status=query.get('status'),
            os_guess=query.get('os'),
        )
        return json_response({'count': len(hosts), 'hosts': hosts})

    # ------------------------------------------------------------------
    # Audit Log
    # ------------------------------------------------------------------

    def _audit_log(self, query: Dict, **kw) -> Tuple[bytes, int, str]:
        if not get_audit_trail:
            return error_response('Audit module not available', 503)
        at = get_audit_trail()
        entries = at.get_log(
            limit=int(query.get('limit', '100')),
            action=query.get('action'),
            actor=query.get('actor'),
            since=query.get('since'),
        )
        return json_response({'count': len(entries), 'entries': entries})


# =========================================================================
# Stdlib HTTP Server (zero-dependency mode)
# =========================================================================

class PurpleTeamHTTPHandler(BaseHTTPRequestHandler):
    """HTTP request handler backed by PurpleTeamAPI."""

    api: PurpleTeamAPI = None  # set by server factory

    def log_message(self, format, *args):
        """Override to use a cleaner log format."""
        sys.stderr.write(
            f"[{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}] "
            f"{self.address_string()} - {format % args}\n"
        )

    # ---- CORS -----------------------------------------------------------

    def _send_cors_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods',
                         'GET, POST, PUT, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers',
                         'Content-Type, X-API-Key, Authorization')
        self.send_header('Access-Control-Max-Age', '86400')

    def do_OPTIONS(self):
        """Handle CORS preflight."""
        self.send_response(204)
        self._send_cors_headers()
        self.end_headers()

    # ---- Request parsing ------------------------------------------------

    def _parse_request(self) -> Tuple[str, Dict[str, str], Optional[Dict]]:
        """Parse the URL and body, return (path, query_dict, body_dict)."""
        parsed = urlparse(self.path)
        path = parsed.path.rstrip('/')
        if not path:
            path = '/'

        # Parse query string (take first value for each key)
        qs = parse_qs(parsed.query)
        query = {k: v[0] for k, v in qs.items()}

        # Parse JSON body for POST/PUT
        body = None
        content_length = int(self.headers.get('Content-Length', 0))
        if content_length > 0:
            raw = self.rfile.read(content_length)
            try:
                body = json.loads(raw.decode('utf-8'))
            except (json.JSONDecodeError, UnicodeDecodeError):
                body = {}

        return path, query, body

    def _get_api_key(self) -> Optional[str]:
        """Extract API key from X-API-Key header or query param."""
        key = self.headers.get('X-API-Key')
        if not key:
            parsed = urlparse(self.path)
            qs = parse_qs(parsed.query)
            keys = qs.get('api_key', [])
            key = keys[0] if keys else None
        return key

    def _handle(self, method: str):
        """Dispatch the request to the API."""
        path, query, body = self._parse_request()
        api_key = self._get_api_key()

        resp_body, status, content_type = self.api.dispatch(
            method, path, query, body, api_key
        )

        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(resp_body)))
        self._send_cors_headers()
        self.end_headers()
        self.wfile.write(resp_body)

    def do_GET(self):
        self._handle('GET')

    def do_POST(self):
        self._handle('POST')

    def do_PUT(self):
        self._handle('PUT')

    def do_DELETE(self):
        self._handle('DELETE')


def create_stdlib_server(host: str = '0.0.0.0', port: int = 8443,
                         auth: Optional[APIKeyAuth] = None) -> HTTPServer:
    """Create an HTTPServer using stdlib only (zero dependencies)."""
    api = PurpleTeamAPI(auth=auth)
    PurpleTeamHTTPHandler.api = api
    server = HTTPServer((host, port), PurpleTeamHTTPHandler)
    return server


# =========================================================================
# Flask mode (production, if Flask is available)
# =========================================================================

def create_flask_app(auth: Optional[APIKeyAuth] = None):
    """Create a Flask application if Flask is installed."""
    try:
        from flask import Flask, request, jsonify, Response
    except ImportError:
        return None

    app = Flask(__name__)
    api = PurpleTeamAPI(auth=auth)

    @app.before_request
    def _cors_preflight():
        if request.method == 'OPTIONS':
            resp = Response('', 204)
            resp.headers['Access-Control-Allow-Origin'] = '*'
            resp.headers['Access-Control-Allow-Methods'] = \
                'GET, POST, PUT, DELETE, OPTIONS'
            resp.headers['Access-Control-Allow-Headers'] = \
                'Content-Type, X-API-Key, Authorization'
            return resp

    @app.after_request
    def _cors_headers(response):
        response.headers['Access-Control-Allow-Origin'] = '*'
        return response

    @app.route('/', defaults={'path': ''})
    @app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
    def catch_all(path):
        full_path = '/' + path if path else '/'
        method = request.method
        query = {k: v for k, v in request.args.items()}
        body = request.get_json(silent=True)
        api_key = request.headers.get('X-API-Key')

        resp_body, status, content_type = api.dispatch(
            method, full_path, query, body, api_key
        )

        return Response(resp_body, status=status,
                        content_type=content_type)

    return app


# =========================================================================
# Server factory (auto-detects Flask)
# =========================================================================

def start_server(host: str = '0.0.0.0', port: int = 8443,
                 no_auth: bool = False, prefer_flask: bool = True):
    """
    Start the Purple Team GRC web server.

    Tries Flask first (if installed and preferred), falls back to stdlib.
    """
    auth = get_auth(enabled=not no_auth)

    flask_app = None
    if prefer_flask:
        flask_app = create_flask_app(auth=auth)

    if flask_app is not None:
        print(f"[Purple Team GRC] Starting Flask server on {host}:{port}")
        print(f"[Purple Team GRC] Dashboard: http://{host}:{port}/")
        print(f"[Purple Team GRC] API Base:  http://{host}:{port}/api/v1/")
        print(f"[Purple Team GRC] Auth: {'enabled' if auth.enabled else 'DISABLED'}")
        flask_app.run(host=host, port=port, debug=False)
    else:
        print(f"[Purple Team GRC] Starting stdlib HTTP server on {host}:{port}")
        print(f"[Purple Team GRC] (Flask not found - using http.server)")
        print(f"[Purple Team GRC] Dashboard: http://{host}:{port}/")
        print(f"[Purple Team GRC] API Base:  http://{host}:{port}/api/v1/")
        print(f"[Purple Team GRC] Auth: {'enabled' if auth.enabled else 'DISABLED'}")
        server = create_stdlib_server(host, port, auth)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\n[Purple Team GRC] Server stopped.")
            server.server_close()


# =========================================================================
# CLI entry point
# =========================================================================
if __name__ == '__main__':
    start_server()
