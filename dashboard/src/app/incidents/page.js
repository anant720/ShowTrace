"use client";

import { useEffect, useState } from 'react';
import { apiRequest } from '@/utils/api';
import DashboardLayout from '@/components/DashboardLayout';

export default function IncidentsPage() {
    const [incidents, setIncidents] = useState([]);
    const [selectedIncident, setSelectedIncident] = useState(null);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [updating, setUpdating] = useState(false);

    const fetchIncidents = async () => {
        try {
            setError(null);
            const data = await apiRequest('/incidents?page=1&page_size=50');
            setIncidents(data.items || []);
        } catch (err) {
            console.error('Failed to fetch incidents:', err);
            setError(err.message || 'Failed to fetch incidents');
        } finally {
            setLoading(false);
        }
    };

    const fetchIncidentDetail = async (id) => {
        try {
            const data = await apiRequest(`/incidents/${id}`);
            setSelectedIncident(data);
        } catch (err) {
            console.error('Failed to fetch incident detail:', err);
            alert(`Failed to load incident: ${err.message}`);
        }
    };

    useEffect(() => {
        fetchIncidents();
    }, []);

    const transitionIncident = async (incident, nextStatus) => {
        setUpdating(true);
        try {
            await apiRequest(`/incidents/${incident.id}`, 'PATCH', {
                status: nextStatus,
                version: incident.version,
            });
            await fetchIncidents();
            if (selectedIncident) {
                await fetchIncidentDetail(incident.id);
            }
        } catch (err) {
            console.error('Failed to update incident:', err);
            alert(err.message || 'Incident update failed (state machine or version conflict)');
        } finally {
            setUpdating(false);
        }
    };

    const exportIncident = async (id) => {
        try {
            const res = await apiRequest(`/incidents/${id}/export`);
            console.log('Export bundle verification:', res);
            alert(`Export created.\nSHA256: ${res.sha256}`);
        } catch (err) {
            console.error('Export failed:', err);
            alert(`Export failed: ${err.message}`);
        }
    };

    const allowedNextStatus = (status) => {
        switch ((status || '').toUpperCase()) {
            case 'OPEN':
                return 'INVESTIGATING';
            case 'INVESTIGATING':
                return 'CONTAINED';
            case 'CONTAINED':
                return 'RESOLVED';
            case 'RESOLVED':
                return 'CLOSED';
            default:
                return null;
        }
    };

    const formatTime = (ts) => {
        if (!ts) return '—';
        return new Date(ts).toLocaleString();
    };

    return (
        <DashboardLayout>
            <div style={{ padding: '20px 0 60px 0' }}>
                <h1 style={{ fontSize: 'var(--hero-font-size)', fontWeight: '800', letterSpacing: '-4px', lineHeight: 1, color: 'var(--text-main)', marginBottom: '16px', transition: 'font-size 0.3s ease' }}>
                    Incident Response
                </h1>
                <p style={{ fontSize: 'clamp(16px, 2vw, 20px)', color: 'var(--text-muted)', maxWidth: '600px', fontWeight: '500' }}>
                    Tamper-aware, state-machine enforced incident lifecycle over forensic events.
                </p>
            </div>

            <div className="st-card" style={{ padding: '32px', marginBottom: '32px' }}>
                {error && (
                    <div style={{ marginBottom: '16px', padding: '12px 16px', borderRadius: '12px', background: 'rgba(255,59,48,0.08)', color: 'var(--secondary)', fontSize: '13px', fontWeight: '600' }}>
                        API Error: {error}
                    </div>
                )}

                {loading ? (
                    <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)' }}>
                        Assembling incident queue from scan logs...
                    </div>
                ) : incidents.length === 0 ? (
                    <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)' }}>
                        No incidents have been raised yet.
                    </div>
                ) : (
                    <div style={{ overflowX: 'auto' }}>
                        <table style={{ width: '100%', borderCollapse: 'separate', borderSpacing: '0 8px' }}>
                            <thead>
                                <tr style={{ textAlign: 'left' }}>
                                    <th style={{ padding: '12px 16px', fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '1px' }}>ID</th>
                                    <th style={{ padding: '12px 16px', fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '1px' }}>INSTALLATION</th>
                                    <th style={{ padding: '12px 16px', fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '1px' }}>STATUS</th>
                                    <th style={{ padding: '12px 16px', fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '1px' }}>SEVERITY</th>
                                    <th style={{ padding: '12px 16px', fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '1px' }}>RISK</th>
                                    <th style={{ padding: '12px 16px', fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '1px' }}>CREATED</th>
                                    <th style={{ padding: '12px 16px', fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '1px' }}>ACTIONS</th>
                                </tr>
                            </thead>
                            <tbody>
                                {incidents.map((i) => {
                                    const next = allowedNextStatus(i.status);
                                    return (
                                        <tr key={i.id} style={{ background: 'var(--bg-main)' }}>
                                            <td style={{ padding: '16px', fontFamily: 'monospace', fontSize: '12px', maxWidth: '160px', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                                                {i.id}
                                            </td>
                                            <td style={{ padding: '16px', fontFamily: 'monospace', fontSize: '12px' }}>
                                                {i.installation_id}
                                            </td>
                                            <td style={{ padding: '16px', fontSize: '12px', fontWeight: '700' }}>
                                                {i.status}
                                            </td>
                                            <td style={{ padding: '16px', fontSize: '12px', fontWeight: '700', color: i.initial_severity === 'CRITICAL' ? 'var(--secondary)' : i.initial_severity === 'HIGH' ? 'var(--warning)' : 'var(--primary)' }}>
                                                {i.initial_severity}
                                            </td>
                                            <td style={{ padding: '16px', fontFamily: 'monospace', fontSize: '13px', fontWeight: '700' }}>
                                                {Math.round(i.risk_score ?? 0)}
                                            </td>
                                            <td style={{ padding: '16px', fontSize: '12px', color: 'var(--text-muted)' }}>
                                                {formatTime(i.created_at)}
                                            </td>
                                            <td style={{ padding: '16px', display: 'flex', gap: '8px', alignItems: 'center' }}>
                                                <button
                                                    className="st-btn-secondary"
                                                    style={{ fontSize: '11px', padding: '6px 12px' }}
                                                    onClick={() => fetchIncidentDetail(i.id)}
                                                >
                                                    Inspect
                                                </button>
                                                {next && (
                                                    <button
                                                        className="st-btn-primary"
                                                        style={{ fontSize: '11px', padding: '6px 12px' }}
                                                        disabled={updating}
                                                        onClick={() => transitionIncident(i, next)}
                                                    >
                                                        Advance → {next}
                                                    </button>
                                                )}
                                                <button
                                                    className="st-btn-secondary"
                                                    style={{ fontSize: '11px', padding: '6px 12px' }}
                                                    onClick={() => exportIncident(i.id)}
                                                >
                                                    Export
                                                </button>
                                            </td>
                                        </tr>
                                    );
                                })}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>

            {selectedIncident && (
                <div className="st-card" style={{ padding: '32px' }}>
                    <h3 style={{ fontSize: '20px', fontWeight: '800', marginBottom: '16px' }}>
                        Incident Forensics — {selectedIncident.incident?.id}
                    </h3>
                    <p style={{ fontSize: '13px', color: 'var(--text-muted)', marginBottom: '24px' }}>
                        All values shown are backend-verified. Any signature or nonce failures will be surfaced during export, not hidden.
                    </p>
                    <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '24px' }}>
                        <div>
                            <h4 style={{ fontSize: '14px', fontWeight: '800', marginBottom: '8px' }}>Linked Events</h4>
                            <pre style={{ maxHeight: '260px', overflow: 'auto', background: 'var(--bg-main)', borderRadius: '12px', padding: '12px', fontSize: '11px' }}>
                                {JSON.stringify(selectedIncident.events || [], null, 2)}
                            </pre>
                        </div>
                        <div>
                            <h4 style={{ fontSize: '14px', fontWeight: '800', marginBottom: '8px' }}>Chain Slice</h4>
                            <pre style={{ maxHeight: '260px', overflow: 'auto', background: 'var(--bg-main)', borderRadius: '12px', padding: '12px', fontSize: '11px' }}>
                                {JSON.stringify(selectedIncident.chain || [], null, 2)}
                            </pre>
                        </div>
                    </div>
                </div>
            )}
        </DashboardLayout>
    );
}

