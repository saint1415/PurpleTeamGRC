#!/usr/bin/env python3
"""
Purple Team Portable - Compliance Framework Mapper
Maps security findings to compliance controls across all major frameworks.
Exceeds requirements for NIST, HIPAA, SOC 1/2, PCI-DSS, ISO 27001, etc.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Set
from enum import Enum


class Framework(Enum):
    """Supported compliance frameworks."""
    NIST_800_53 = "NIST-800-53"
    NIST_CSF = "NIST-CSF"
    HIPAA = "HIPAA"
    SOC1_TYPE2 = "SOC1-Type2"
    SOC2_TYPE2 = "SOC2-Type2"
    PCI_DSS_V4 = "PCI-DSS-v4"
    ISO27001_2022 = "ISO27001-2022"
    CMMC = "CMMC"
    FEDRAMP = "FedRAMP"
    GDPR = "GDPR"
    SOX = "SOX"
    HITRUST = "HITRUST"
    CIS = "CIS"


@dataclass
class Control:
    """Represents a compliance control."""
    framework: str
    control_id: str
    control_name: str
    family: str
    description: str
    audit_procedures: List[str]
    evidence_types: List[str]


@dataclass
class ControlMapping:
    """Maps a finding type to controls across frameworks."""
    finding_type: str
    description: str
    controls: Dict[str, List[str]]  # framework -> [control_ids]


class ComplianceMapper:
    """Maps security findings to compliance controls across all frameworks."""

    def __init__(self):
        self._load_control_definitions()
        self._load_mappings()

    def _load_control_definitions(self):
        """Load control definitions for all frameworks."""
        self.controls: Dict[str, Dict[str, Control]] = {}

        # NIST 800-53 Rev 5 Controls (key security controls)
        self.controls['NIST-800-53'] = {
            'AC-1': Control('NIST-800-53', 'AC-1', 'Policy and Procedures', 'Access Control',
                           'Access control policy and procedures', ['Policy review', 'Document inspection'],
                           ['policy_document', 'procedure_document']),
            'AC-2': Control('NIST-800-53', 'AC-2', 'Account Management', 'Access Control',
                           'Manage system accounts', ['Account listing review', 'Access review'],
                           ['user_list', 'access_report', 'account_audit']),
            'AC-3': Control('NIST-800-53', 'AC-3', 'Access Enforcement', 'Access Control',
                           'Enforce approved authorizations', ['Access testing', 'Permission review'],
                           ['access_test_results', 'permission_matrix']),
            'AC-6': Control('NIST-800-53', 'AC-6', 'Least Privilege', 'Access Control',
                           'Employ least privilege principle', ['Privilege review', 'Role analysis'],
                           ['privilege_report', 'role_mapping']),
            'AU-2': Control('NIST-800-53', 'AU-2', 'Event Logging', 'Audit and Accountability',
                           'Define auditable events', ['Log configuration review'],
                           ['log_config', 'audit_policy']),
            'AU-6': Control('NIST-800-53', 'AU-6', 'Audit Record Review', 'Audit and Accountability',
                           'Review and analyze audit records', ['Log review process'],
                           ['log_review_report', 'siem_alerts']),
            'CA-7': Control('NIST-800-53', 'CA-7', 'Continuous Monitoring', 'Assessment',
                           'Continuous monitoring strategy', ['Monitoring review'],
                           ['monitoring_report', 'dashboard_screenshot']),
            'CM-2': Control('NIST-800-53', 'CM-2', 'Baseline Configuration', 'Configuration Management',
                           'Establish baseline configurations', ['Configuration review'],
                           ['baseline_config', 'config_comparison']),
            'CM-6': Control('NIST-800-53', 'CM-6', 'Configuration Settings', 'Configuration Management',
                           'Establish configuration settings', ['Settings review'],
                           ['config_settings', 'hardening_report']),
            'CM-7': Control('NIST-800-53', 'CM-7', 'Least Functionality', 'Configuration Management',
                           'Restrict system functions', ['Service review'],
                           ['service_list', 'port_scan']),
            'IA-2': Control('NIST-800-53', 'IA-2', 'Identification and Authentication', 'Identification',
                           'Uniquely identify users', ['Authentication testing'],
                           ['auth_config', 'mfa_status']),
            'IA-5': Control('NIST-800-53', 'IA-5', 'Authenticator Management', 'Identification',
                           'Manage authenticators', ['Password policy review'],
                           ['password_policy', 'credential_audit']),
            'RA-3': Control('NIST-800-53', 'RA-3', 'Risk Assessment', 'Risk Assessment',
                           'Conduct risk assessments', ['Risk assessment review'],
                           ['risk_assessment', 'threat_analysis']),
            'RA-5': Control('NIST-800-53', 'RA-5', 'Vulnerability Monitoring and Scanning', 'Risk Assessment',
                           'Monitor and scan for vulnerabilities', ['Vulnerability scan review'],
                           ['vuln_scan_report', 'remediation_tracking']),
            'SC-7': Control('NIST-800-53', 'SC-7', 'Boundary Protection', 'System and Communications',
                           'Monitor communications at boundaries', ['Firewall review'],
                           ['firewall_rules', 'network_diagram']),
            'SC-8': Control('NIST-800-53', 'SC-8', 'Transmission Confidentiality', 'System and Communications',
                           'Protect transmitted information', ['Encryption testing'],
                           ['ssl_scan', 'encryption_config']),
            'SC-12': Control('NIST-800-53', 'SC-12', 'Cryptographic Key Management', 'System and Communications',
                            'Establish cryptographic keys', ['Key management review'],
                            ['key_inventory', 'key_rotation_log']),
            'SC-13': Control('NIST-800-53', 'SC-13', 'Cryptographic Protection', 'System and Communications',
                            'Implement cryptography', ['Crypto implementation review'],
                            ['crypto_config', 'cipher_audit']),
            'SI-2': Control('NIST-800-53', 'SI-2', 'Flaw Remediation', 'System and Information Integrity',
                           'Identify and correct flaws', ['Patch management review'],
                           ['patch_status', 'remediation_report']),
            'SI-3': Control('NIST-800-53', 'SI-3', 'Malicious Code Protection', 'System and Information Integrity',
                           'Implement malicious code protection', ['AV/EDR review'],
                           ['av_status', 'malware_scan']),
            'SI-4': Control('NIST-800-53', 'SI-4', 'System Monitoring', 'System and Information Integrity',
                           'Monitor system events', ['Monitoring configuration'],
                           ['siem_config', 'alert_rules']),
        }

        # HIPAA Security Rule Controls
        self.controls['HIPAA'] = {
            '164.308(a)(1)': Control('HIPAA', '164.308(a)(1)', 'Security Management Process', 'Administrative',
                                    'Implement policies to prevent security violations',
                                    ['Policy review', 'Risk analysis review'],
                                    ['security_policy', 'risk_analysis']),
            '164.308(a)(3)': Control('HIPAA', '164.308(a)(3)', 'Workforce Security', 'Administrative',
                                    'Implement procedures for workforce access',
                                    ['Access control procedures review'],
                                    ['access_procedures', 'workforce_access_list']),
            '164.308(a)(4)': Control('HIPAA', '164.308(a)(4)', 'Information Access Management', 'Administrative',
                                    'Implement access authorization policies',
                                    ['Authorization review'],
                                    ['access_policy', 'authorization_matrix']),
            '164.308(a)(5)': Control('HIPAA', '164.308(a)(5)', 'Security Awareness Training', 'Administrative',
                                    'Security awareness and training program',
                                    ['Training records review'],
                                    ['training_records', 'awareness_materials']),
            '164.308(a)(6)': Control('HIPAA', '164.308(a)(6)', 'Security Incident Procedures', 'Administrative',
                                    'Implement security incident procedures',
                                    ['Incident response review'],
                                    ['incident_procedures', 'incident_log']),
            '164.308(a)(7)': Control('HIPAA', '164.308(a)(7)', 'Contingency Plan', 'Administrative',
                                    'Establish contingency operations plan',
                                    ['Contingency plan review'],
                                    ['contingency_plan', 'backup_test_results']),
            '164.308(a)(8)': Control('HIPAA', '164.308(a)(8)', 'Evaluation', 'Administrative',
                                    'Perform periodic evaluations',
                                    ['Evaluation review'],
                                    ['evaluation_report', 'assessment_results']),
            '164.310(a)(1)': Control('HIPAA', '164.310(a)(1)', 'Facility Access Controls', 'Physical',
                                    'Limit physical access to ePHI systems',
                                    ['Physical access review'],
                                    ['access_logs', 'facility_controls']),
            '164.310(b)': Control('HIPAA', '164.310(b)', 'Workstation Use', 'Physical',
                                 'Implement workstation use policies',
                                 ['Workstation policy review'],
                                 ['workstation_policy', 'endpoint_config']),
            '164.310(d)(1)': Control('HIPAA', '164.310(d)(1)', 'Device and Media Controls', 'Physical',
                                    'Implement device and media controls',
                                    ['Media control review'],
                                    ['media_policy', 'disposal_log']),
            '164.312(a)(1)': Control('HIPAA', '164.312(a)(1)', 'Access Control', 'Technical',
                                    'Implement technical access controls',
                                    ['Access control testing'],
                                    ['access_control_config', 'user_access_report']),
            '164.312(b)': Control('HIPAA', '164.312(b)', 'Audit Controls', 'Technical',
                                 'Implement audit controls',
                                 ['Audit log review'],
                                 ['audit_config', 'audit_logs']),
            '164.312(c)(1)': Control('HIPAA', '164.312(c)(1)', 'Integrity Controls', 'Technical',
                                    'Implement integrity mechanisms',
                                    ['Integrity control review'],
                                    ['integrity_config', 'change_log']),
            '164.312(d)': Control('HIPAA', '164.312(d)', 'Person or Entity Authentication', 'Technical',
                                 'Verify identity of persons/entities',
                                 ['Authentication testing'],
                                 ['auth_config', 'identity_verification']),
            '164.312(e)(1)': Control('HIPAA', '164.312(e)(1)', 'Transmission Security', 'Technical',
                                    'Implement transmission security',
                                    ['Encryption testing'],
                                    ['encryption_config', 'ssl_scan_results']),
        }

        # PCI-DSS v4.0 Requirements
        self.controls['PCI-DSS-v4'] = {
            '1.1': Control('PCI-DSS-v4', '1.1', 'Network Security Controls', 'Requirement 1',
                          'Install and maintain network security controls',
                          ['Firewall configuration review'],
                          ['firewall_config', 'network_diagram']),
            '1.2': Control('PCI-DSS-v4', '1.2', 'Network Security Control Configuration', 'Requirement 1',
                          'Configure network security controls',
                          ['Ruleset review'],
                          ['firewall_rules', 'acl_config']),
            '2.1': Control('PCI-DSS-v4', '2.1', 'Secure Configurations', 'Requirement 2',
                          'Apply secure configurations',
                          ['Configuration review'],
                          ['hardening_report', 'baseline_comparison']),
            '2.2': Control('PCI-DSS-v4', '2.2', 'System Components Security', 'Requirement 2',
                          'Securely configure system components',
                          ['System configuration review'],
                          ['system_config', 'security_settings']),
            '3.1': Control('PCI-DSS-v4', '3.1', 'Account Data Storage', 'Requirement 3',
                          'Account data storage is kept to minimum',
                          ['Data retention review'],
                          ['data_inventory', 'retention_policy']),
            '3.5': Control('PCI-DSS-v4', '3.5', 'Primary Account Number Protection', 'Requirement 3',
                          'PAN is secured wherever stored',
                          ['Encryption review'],
                          ['encryption_config', 'key_management']),
            '4.1': Control('PCI-DSS-v4', '4.1', 'Strong Cryptography in Transit', 'Requirement 4',
                          'Protect cardholder data with strong cryptography during transmission',
                          ['SSL/TLS testing'],
                          ['ssl_scan', 'certificate_inventory']),
            '5.1': Control('PCI-DSS-v4', '5.1', 'Anti-Malware', 'Requirement 5',
                          'Protect systems from malware',
                          ['AV deployment review'],
                          ['av_status', 'malware_scan_results']),
            '5.2': Control('PCI-DSS-v4', '5.2', 'Anti-Malware Mechanisms', 'Requirement 5',
                          'Anti-malware mechanisms and processes are active',
                          ['AV configuration review'],
                          ['av_config', 'update_status']),
            '6.1': Control('PCI-DSS-v4', '6.1', 'Security Vulnerabilities Identified', 'Requirement 6',
                          'Identify and address security vulnerabilities',
                          ['Vulnerability management review'],
                          ['vuln_scan_report', 'patch_status']),
            '6.2': Control('PCI-DSS-v4', '6.2', 'Custom Software Security', 'Requirement 6',
                          'Bespoke and custom software developed securely',
                          ['Secure development review'],
                          ['code_review', 'sast_results']),
            '6.3': Control('PCI-DSS-v4', '6.3', 'Security Vulnerabilities in Software', 'Requirement 6',
                          'Security vulnerabilities are identified and addressed',
                          ['Vulnerability scanning'],
                          ['vuln_report', 'remediation_tracking']),
            '7.1': Control('PCI-DSS-v4', '7.1', 'Access Limited to Need to Know', 'Requirement 7',
                          'Access to system components limited to those with need',
                          ['Access review'],
                          ['access_matrix', 'role_definitions']),
            '7.2': Control('PCI-DSS-v4', '7.2', 'Access Control Systems', 'Requirement 7',
                          'Access control systems configured to restrict access',
                          ['Access control review'],
                          ['access_control_config', 'permission_audit']),
            '8.1': Control('PCI-DSS-v4', '8.1', 'User Identification', 'Requirement 8',
                          'User identification and related accounts managed',
                          ['Account management review'],
                          ['user_list', 'account_audit']),
            '8.3': Control('PCI-DSS-v4', '8.3', 'Strong Authentication', 'Requirement 8',
                          'Strong authentication for users and administrators',
                          ['Authentication testing'],
                          ['auth_config', 'mfa_status']),
            '10.1': Control('PCI-DSS-v4', '10.1', 'Audit Logs', 'Requirement 10',
                           'Audit logs capture all access',
                           ['Log configuration review'],
                           ['log_config', 'audit_sample']),
            '10.2': Control('PCI-DSS-v4', '10.2', 'Audit Log Content', 'Requirement 10',
                           'Audit logs record required information',
                           ['Log content review'],
                           ['log_sample', 'log_analysis']),
            '10.3': Control('PCI-DSS-v4', '10.3', 'Audit Log Protection', 'Requirement 10',
                           'Audit logs are protected from modification',
                           ['Log protection review'],
                           ['log_integrity', 'access_controls']),
            '11.3': Control('PCI-DSS-v4', '11.3', 'Vulnerabilities Identified', 'Requirement 11',
                           'Vulnerabilities are identified and addressed',
                           ['Vulnerability scanning'],
                           ['vuln_scan_report', 'pentest_report']),
            '11.4': Control('PCI-DSS-v4', '11.4', 'Penetration Testing', 'Requirement 11',
                           'Penetration testing performed regularly',
                           ['Pentest review'],
                           ['pentest_report', 'remediation_status']),
            '12.1': Control('PCI-DSS-v4', '12.1', 'Security Policy', 'Requirement 12',
                           'Security policy is established and maintained',
                           ['Policy review'],
                           ['security_policy', 'policy_acknowledgements']),
        }

        # SOC 2 Trust Services Criteria
        self.controls['SOC2-Type2'] = {
            'CC1.1': Control('SOC2-Type2', 'CC1.1', 'Control Environment', 'Common Criteria',
                            'COSO principle: integrity and ethical values',
                            ['Code of conduct review'],
                            ['code_of_conduct', 'ethics_policy']),
            'CC2.1': Control('SOC2-Type2', 'CC2.1', 'Communication and Information', 'Common Criteria',
                            'COSO principle: generate quality information',
                            ['Information quality review'],
                            ['data_quality_report', 'communication_policy']),
            'CC3.1': Control('SOC2-Type2', 'CC3.1', 'Risk Assessment', 'Common Criteria',
                            'COSO principle: specify suitable objectives',
                            ['Risk assessment review'],
                            ['risk_assessment', 'objective_documentation']),
            'CC3.2': Control('SOC2-Type2', 'CC3.2', 'Risk Identification', 'Common Criteria',
                            'Identify and analyze risks',
                            ['Risk identification review'],
                            ['risk_register', 'threat_analysis']),
            'CC4.1': Control('SOC2-Type2', 'CC4.1', 'Monitoring Activities', 'Common Criteria',
                            'COSO principle: ongoing and separate evaluations',
                            ['Monitoring review'],
                            ['monitoring_report', 'evaluation_schedule']),
            'CC5.1': Control('SOC2-Type2', 'CC5.1', 'Control Activities', 'Common Criteria',
                            'Select and develop control activities',
                            ['Control activity review'],
                            ['control_matrix', 'control_documentation']),
            'CC6.1': Control('SOC2-Type2', 'CC6.1', 'Logical Access Security', 'Logical Access',
                            'Implement logical access security software',
                            ['Access control review'],
                            ['access_control_config', 'user_provisioning']),
            'CC6.2': Control('SOC2-Type2', 'CC6.2', 'Registration and Authorization', 'Logical Access',
                            'Prior to granting access, users are registered',
                            ['User registration review'],
                            ['registration_process', 'authorization_workflow']),
            'CC6.3': Control('SOC2-Type2', 'CC6.3', 'Access Removal', 'Logical Access',
                            'Remove access when no longer needed',
                            ['Access termination review'],
                            ['termination_process', 'access_review_log']),
            'CC6.6': Control('SOC2-Type2', 'CC6.6', 'System Boundaries', 'Logical Access',
                            'Restrict access from system boundaries',
                            ['Boundary protection review'],
                            ['firewall_config', 'network_diagram']),
            'CC6.7': Control('SOC2-Type2', 'CC6.7', 'Data Transmission', 'Logical Access',
                            'Restrict data transmission, movement and removal',
                            ['Data transmission review'],
                            ['encryption_config', 'dlp_config']),
            'CC6.8': Control('SOC2-Type2', 'CC6.8', 'Malicious Software', 'Logical Access',
                            'Prevent or detect malicious software',
                            ['Malware protection review'],
                            ['av_config', 'edr_status']),
            'CC7.1': Control('SOC2-Type2', 'CC7.1', 'Vulnerability Detection', 'System Operations',
                            'Detect vulnerabilities in a timely manner',
                            ['Vulnerability scanning review'],
                            ['vuln_scan_report', 'scan_schedule']),
            'CC7.2': Control('SOC2-Type2', 'CC7.2', 'Security Event Monitoring', 'System Operations',
                            'Monitor system components for anomalies',
                            ['Monitoring review'],
                            ['siem_config', 'alert_review']),
            'CC7.3': Control('SOC2-Type2', 'CC7.3', 'Security Event Evaluation', 'System Operations',
                            'Evaluate security events to determine impact',
                            ['Event evaluation review'],
                            ['incident_reports', 'event_analysis']),
            'CC7.4': Control('SOC2-Type2', 'CC7.4', 'Security Incident Response', 'System Operations',
                            'Respond to identified security incidents',
                            ['Incident response review'],
                            ['incident_response_plan', 'incident_log']),
            'CC8.1': Control('SOC2-Type2', 'CC8.1', 'Change Management', 'Change Management',
                            'Authorize, design, develop, configure, document changes',
                            ['Change management review'],
                            ['change_policy', 'change_log']),
            'CC9.1': Control('SOC2-Type2', 'CC9.1', 'Risk Mitigation', 'Risk Mitigation',
                            'Identify and assess risks through vendor management',
                            ['Vendor management review'],
                            ['vendor_risk_assessment', 'vendor_inventory']),
        }

        # SOC 1 Type 2 - SSAE 18 ICOFR Controls
        self.controls['SOC1-Type2'] = {
            'ITGC-01': Control('SOC1-Type2', 'ITGC-01', 'Logical Access - User Access Management', 'IT General Controls',
                              'Access to systems is appropriately restricted',
                              ['User access review'],
                              ['user_access_list', 'access_provisioning']),
            'ITGC-02': Control('SOC1-Type2', 'ITGC-02', 'Logical Access - Privileged Access', 'IT General Controls',
                              'Privileged access is restricted and monitored',
                              ['Privileged access review'],
                              ['admin_list', 'privilege_audit']),
            'ITGC-03': Control('SOC1-Type2', 'ITGC-03', 'Logical Access - Authentication', 'IT General Controls',
                              'Authentication mechanisms are in place',
                              ['Authentication testing'],
                              ['auth_config', 'password_policy']),
            'ITGC-04': Control('SOC1-Type2', 'ITGC-04', 'Change Management - Authorization', 'IT General Controls',
                              'Changes are properly authorized before implementation',
                              ['Change authorization review'],
                              ['change_approvals', 'change_log']),
            'ITGC-05': Control('SOC1-Type2', 'ITGC-05', 'Change Management - Testing', 'IT General Controls',
                              'Changes are tested before production deployment',
                              ['Testing review'],
                              ['test_results', 'qa_signoff']),
            'ITGC-06': Control('SOC1-Type2', 'ITGC-06', 'Change Management - Segregation', 'IT General Controls',
                              'Segregation of duties in change management',
                              ['SOD review'],
                              ['role_matrix', 'sod_report']),
            'ITGC-07': Control('SOC1-Type2', 'ITGC-07', 'Operations - Job Scheduling', 'IT General Controls',
                              'Batch jobs are scheduled and monitored',
                              ['Job scheduling review'],
                              ['job_schedule', 'job_logs']),
            'ITGC-08': Control('SOC1-Type2', 'ITGC-08', 'Operations - Backup and Recovery', 'IT General Controls',
                              'Backup and recovery procedures are established',
                              ['Backup review'],
                              ['backup_config', 'restore_test_results']),
            'ITGC-09': Control('SOC1-Type2', 'ITGC-09', 'Operations - Incident Management', 'IT General Controls',
                              'Incidents are tracked and resolved',
                              ['Incident management review'],
                              ['incident_log', 'resolution_tracking']),
        }

        # ISO 27001:2022 Controls
        self.controls['ISO27001-2022'] = {
            '5.1': Control('ISO27001-2022', '5.1', 'Policies for Information Security', 'Organizational',
                          'Information security policy defined and approved',
                          ['Policy review'],
                          ['security_policy', 'policy_approval']),
            '5.15': Control('ISO27001-2022', '5.15', 'Access Control', 'Organizational',
                           'Access control rules established and implemented',
                           ['Access control review'],
                           ['access_policy', 'access_matrix']),
            '5.17': Control('ISO27001-2022', '5.17', 'Authentication Information', 'Organizational',
                           'Management of authentication information',
                           ['Authentication review'],
                           ['auth_policy', 'credential_management']),
            '8.1': Control('ISO27001-2022', '8.1', 'User Endpoint Devices', 'Technological',
                          'Information stored on, processed by or accessible via user endpoint devices',
                          ['Endpoint review'],
                          ['endpoint_policy', 'device_inventory']),
            '8.5': Control('ISO27001-2022', '8.5', 'Secure Authentication', 'Technological',
                          'Secure authentication technologies and procedures',
                          ['Authentication testing'],
                          ['auth_config', 'mfa_status']),
            '8.7': Control('ISO27001-2022', '8.7', 'Protection Against Malware', 'Technological',
                          'Protection against malware implemented',
                          ['Malware protection review'],
                          ['av_config', 'malware_scan']),
            '8.8': Control('ISO27001-2022', '8.8', 'Management of Technical Vulnerabilities', 'Technological',
                          'Timely identification and remediation of vulnerabilities',
                          ['Vulnerability management review'],
                          ['vuln_scan', 'patch_status']),
            '8.9': Control('ISO27001-2022', '8.9', 'Configuration Management', 'Technological',
                          'Configurations established, documented, implemented, monitored',
                          ['Configuration review'],
                          ['config_baseline', 'config_audit']),
            '8.15': Control('ISO27001-2022', '8.15', 'Logging', 'Technological',
                           'Logs recording activities, exceptions, faults, events produced and protected',
                           ['Logging review'],
                           ['log_config', 'log_samples']),
            '8.16': Control('ISO27001-2022', '8.16', 'Monitoring Activities', 'Technological',
                           'Networks, systems, applications monitored for anomalies',
                           ['Monitoring review'],
                           ['siem_config', 'monitoring_report']),
            '8.20': Control('ISO27001-2022', '8.20', 'Networks Security', 'Technological',
                           'Networks secured, managed, controlled',
                           ['Network security review'],
                           ['network_config', 'firewall_rules']),
            '8.21': Control('ISO27001-2022', '8.21', 'Security of Network Services', 'Technological',
                           'Security mechanisms, service levels, management requirements identified',
                           ['Network services review'],
                           ['service_config', 'sla_documentation']),
            '8.24': Control('ISO27001-2022', '8.24', 'Use of Cryptography', 'Technological',
                           'Effective use of cryptography',
                           ['Cryptography review'],
                           ['crypto_config', 'key_management']),
        }

    def _load_mappings(self):
        """Load finding-to-control mappings."""
        # Maps finding types to controls across all frameworks
        self.mappings: Dict[str, ControlMapping] = {
            'open_port': ControlMapping(
                'open_port',
                'Open network port detected',
                {
                    'NIST-800-53': ['CM-7', 'SC-7'],
                    'HIPAA': ['164.312(e)(1)'],
                    'PCI-DSS-v4': ['1.1', '1.2'],
                    'SOC2-Type2': ['CC6.6'],
                    'SOC1-Type2': ['ITGC-01'],
                    'ISO27001-2022': ['8.20', '8.21']
                }
            ),
            'ssl_vulnerability': ControlMapping(
                'ssl_vulnerability',
                'SSL/TLS vulnerability or misconfiguration',
                {
                    'NIST-800-53': ['SC-8', 'SC-13'],
                    'HIPAA': ['164.312(e)(1)'],
                    'PCI-DSS-v4': ['4.1'],
                    'SOC2-Type2': ['CC6.7'],
                    'ISO27001-2022': ['8.24']
                }
            ),
            'weak_cipher': ControlMapping(
                'weak_cipher',
                'Weak cryptographic cipher in use',
                {
                    'NIST-800-53': ['SC-12', 'SC-13'],
                    'HIPAA': ['164.312(e)(1)'],
                    'PCI-DSS-v4': ['4.1', '3.5'],
                    'SOC2-Type2': ['CC6.7'],
                    'ISO27001-2022': ['8.24']
                }
            ),
            'expired_certificate': ControlMapping(
                'expired_certificate',
                'Expired or soon-to-expire SSL certificate',
                {
                    'NIST-800-53': ['SC-12'],
                    'PCI-DSS-v4': ['4.1'],
                    'SOC2-Type2': ['CC6.7'],
                    'ISO27001-2022': ['8.24']
                }
            ),
            'cve_vulnerability': ControlMapping(
                'cve_vulnerability',
                'Known CVE vulnerability detected',
                {
                    'NIST-800-53': ['RA-5', 'SI-2'],
                    'HIPAA': ['164.308(a)(1)', '164.308(a)(8)'],
                    'PCI-DSS-v4': ['6.1', '6.3', '11.3'],
                    'SOC2-Type2': ['CC7.1'],
                    'SOC1-Type2': ['ITGC-09'],
                    'ISO27001-2022': ['8.8']
                }
            ),
            'missing_patch': ControlMapping(
                'missing_patch',
                'Missing security patch or update',
                {
                    'NIST-800-53': ['SI-2'],
                    'HIPAA': ['164.308(a)(1)'],
                    'PCI-DSS-v4': ['6.1', '6.3'],
                    'SOC2-Type2': ['CC7.1'],
                    'ISO27001-2022': ['8.8']
                }
            ),
            'web_vulnerability': ControlMapping(
                'web_vulnerability',
                'Web application vulnerability detected',
                {
                    'NIST-800-53': ['RA-5', 'SI-2'],
                    'PCI-DSS-v4': ['6.2', '6.3', '11.3'],
                    'SOC2-Type2': ['CC7.1'],
                    'ISO27001-2022': ['8.8']
                }
            ),
            'authentication_weakness': ControlMapping(
                'authentication_weakness',
                'Weak authentication configuration',
                {
                    'NIST-800-53': ['IA-2', 'IA-5'],
                    'HIPAA': ['164.312(d)'],
                    'PCI-DSS-v4': ['8.3'],
                    'SOC2-Type2': ['CC6.1'],
                    'SOC1-Type2': ['ITGC-03'],
                    'ISO27001-2022': ['8.5']
                }
            ),
            'default_credentials': ControlMapping(
                'default_credentials',
                'Default or weak credentials in use',
                {
                    'NIST-800-53': ['IA-5'],
                    'HIPAA': ['164.312(d)'],
                    'PCI-DSS-v4': ['2.1', '8.3'],
                    'SOC2-Type2': ['CC6.1'],
                    'SOC1-Type2': ['ITGC-03'],
                    'ISO27001-2022': ['5.17', '8.5']
                }
            ),
            'insecure_configuration': ControlMapping(
                'insecure_configuration',
                'Insecure system or service configuration',
                {
                    'NIST-800-53': ['CM-2', 'CM-6'],
                    'HIPAA': ['164.312(a)(1)'],
                    'PCI-DSS-v4': ['2.1', '2.2'],
                    'SOC2-Type2': ['CC6.1'],
                    'ISO27001-2022': ['8.9']
                }
            ),
            'missing_logging': ControlMapping(
                'missing_logging',
                'Insufficient logging or monitoring',
                {
                    'NIST-800-53': ['AU-2', 'AU-6', 'SI-4'],
                    'HIPAA': ['164.312(b)'],
                    'PCI-DSS-v4': ['10.1', '10.2'],
                    'SOC2-Type2': ['CC7.2'],
                    'ISO27001-2022': ['8.15', '8.16']
                }
            ),
            'information_disclosure': ControlMapping(
                'information_disclosure',
                'Sensitive information disclosure',
                {
                    'NIST-800-53': ['AC-3', 'SC-8'],
                    'HIPAA': ['164.312(e)(1)', '164.312(c)(1)'],
                    'PCI-DSS-v4': ['3.1', '3.5'],
                    'SOC2-Type2': ['CC6.7'],
                    'ISO27001-2022': ['8.24']
                }
            ),
            'network_service': ControlMapping(
                'network_service',
                'Network service discovery',
                {
                    'NIST-800-53': ['CM-7', 'SC-7'],
                    'PCI-DSS-v4': ['1.1', '1.2'],
                    'SOC2-Type2': ['CC6.6'],
                    'ISO27001-2022': ['8.20', '8.21']
                }
            ),
            'host_discovery': ControlMapping(
                'host_discovery',
                'Host/asset discovery',
                {
                    'NIST-800-53': ['CM-8'],
                    'PCI-DSS-v4': ['1.1'],
                    'SOC2-Type2': ['CC6.1'],
                    'ISO27001-2022': ['8.1']
                }
            ),
        }

    def get_controls_for_finding(self, finding_type: str, frameworks: List[str] = None) -> Dict[str, List[str]]:
        """Get applicable controls for a finding type."""
        if finding_type not in self.mappings:
            return {}

        mapping = self.mappings[finding_type]

        if frameworks:
            return {fw: ctrls for fw, ctrls in mapping.controls.items() if fw in frameworks}
        return mapping.controls

    def get_all_controls_for_framework(self, framework: str) -> Dict[str, Control]:
        """Get all controls for a specific framework."""
        return self.controls.get(framework, {})

    def get_control(self, framework: str, control_id: str) -> Optional[Control]:
        """Get a specific control."""
        framework_controls = self.controls.get(framework, {})
        return framework_controls.get(control_id)

    def get_supported_frameworks(self) -> List[str]:
        """Get list of supported frameworks."""
        return list(self.controls.keys())

    def map_finding_to_controls(self, finding_type: str, evidence_id: str,
                                 evidence_manager, frameworks: List[str] = None):
        """Map a finding's evidence to all applicable controls."""
        controls = self.get_controls_for_finding(finding_type, frameworks)

        for framework, control_ids in controls.items():
            for control_id in control_ids:
                control = self.get_control(framework, control_id)
                if control:
                    evidence_manager.map_to_control(
                        evidence_id,
                        framework,
                        control_id,
                        control.control_name,
                        control.family
                    )

    def generate_compliance_summary(self, evidence_manager, framework: str) -> Dict:
        """Generate compliance summary for a framework."""
        all_controls = self.get_all_controls_for_framework(framework)
        summary = {
            'framework': framework,
            'total_controls': len(all_controls),
            'controls_with_evidence': 0,
            'controls_without_evidence': 0,
            'control_details': []
        }

        for control_id, control in all_controls.items():
            evidence = evidence_manager.get_evidence_for_control(framework, control_id)
            has_evidence = len(evidence) > 0

            if has_evidence:
                summary['controls_with_evidence'] += 1
            else:
                summary['controls_without_evidence'] += 1

            summary['control_details'].append({
                'control_id': control_id,
                'control_name': control.control_name,
                'family': control.family,
                'evidence_count': len(evidence),
                'has_evidence': has_evidence
            })

        return summary


# Singleton
_mapper: Optional[ComplianceMapper] = None


def get_compliance_mapper() -> ComplianceMapper:
    """Get the compliance mapper singleton."""
    global _mapper
    if _mapper is None:
        _mapper = ComplianceMapper()
    return _mapper


if __name__ == '__main__':
    mapper = get_compliance_mapper()
    print(f"Supported frameworks: {mapper.get_supported_frameworks()}")
    print(f"\nControls for 'cve_vulnerability':")
    for fw, controls in mapper.get_controls_for_finding('cve_vulnerability').items():
        print(f"  {fw}: {controls}")
