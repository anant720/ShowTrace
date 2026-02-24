"use client";

import { useEffect, useState } from 'react';
import { apiRequest } from '@/utils/api';
import DashboardLayout from '@/components/DashboardLayout';

export default function DevicesPage() {
    const [devices, setDevices] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);

    const fetchDevices = async () => {
        try {
            setError(null);
            const data = await apiRequest('/devices?page=1&page_size=50');
            setDevices(data.items || []);
        } catch (err) {
            console.error('Failed to fetch devices:', err);
            setError(err.message || 'Failed to fetch devices');
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchDevices();
    }, []);

    const formatTime = (ts) => {
        if (!ts) return '—';
        return new Date(ts).toLocaleString();
    };

    return (
        <DashboardLayout>
            <div style={{ padding: '20px 0 60px 0' }}>
                <h1 style={{ fontSize: 'var(--hero-font-size)', fontWeight: '800', letterSpacing: '-4px', lineHeight: 1, color: 'var(--text-main)', marginBottom: '16px', transition: 'font-size 0.3s ease' }}>
                    Device Integrity
                </h1>
                <p style={{ fontSize: 'clamp(16px, 2vw, 20px)', color: 'var(--text-muted)', maxWidth: '600px', fontWeight: '500' }}>
                    Backend-authoritative view of all enrolled endpoints, including tamper, gap, and offline status.
                </p>
            </div>

            <div className="st-card" style={{ padding: '32px' }}>
                {error && (
                    <div style={{ marginBottom: '16px', padding: '12px 16px', borderRadius: '12px', background: 'rgba(255,59,48,0.08)', color: 'var(--secondary)', fontSize: '13px', fontWeight: '600' }}>
                        API Error: {error}
                    </div>
                )}

                {loading ? (
                    <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)' }}>
                        Resolving device integrity from forensic chain...
                    </div>
                ) : devices.length === 0 ? (
                    <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)' }}>
                        No devices observed for this organization yet.
                    </div>
                ) : (
                    <div style={{ overflowX: 'auto' }}>
                        <table style={{ width: '100%', borderCollapse: 'separate', borderSpacing: '0 8px' }}>
                            <thead>
                                <tr style={{ textAlign: 'left' }}>
                                    <th style={{ padding: '12px 16px', fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '1px' }}>INSTALLATION</th>
                                    <th style={{ padding: '12px 16px', fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '1px' }}>LAST SEEN</th>
                                    <th style={{ padding: '12px 16px', fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '1px' }}>INTEGRITY</th>
                                    <th style={{ padding: '12px 16px', fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '1px' }}>RISK</th>
                                    <th style={{ padding: '12px 16px', fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '1px' }}>GAPS</th>
                                    <th style={{ padding: '12px 16px', fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '1px' }}>REPLAYS</th>
                                    <th style={{ padding: '12px 16px', fontSize: '11px', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '1px' }}>STATUS</th>
                                </tr>
                            </thead>
                            <tbody>
                                {devices.map((d) => (
                                    <tr key={d.installation_id} style={{ background: 'var(--bg-main)' }}>
                                        <td style={{ padding: '16px', fontFamily: 'monospace', fontSize: '12px', fontWeight: '600', color: 'var(--text-secondary)' }}>
                                            {d.installation_id}
                                        </td>
                                        <td style={{ padding: '16px', fontSize: '12px', color: 'var(--text-muted)' }}>
                                            {formatTime(d.last_seen)}
                                        </td>
                                        <td style={{ padding: '16px', fontSize: '12px', fontWeight: '700', color: d.integrity_status === 'COMPROMISED' ? 'var(--secondary)' : d.integrity_status === 'DEGRADED' ? 'var(--warning)' : 'var(--primary)' }}>
                                            {d.integrity_status || 'UNKNOWN'}
                                        </td>
                                        <td style={{ padding: '16px', fontFamily: 'monospace', fontSize: '13px', fontWeight: '700', color: 'var(--text-main)' }}>
                                            {Math.round(d.risk_score ?? 0)}
                                        </td>
                                        <td style={{ padding: '16px', fontSize: '12px', color: 'var(--text-main)', fontWeight: '600' }}>
                                            {d.sequence_gap_count ?? 0}
                                        </td>
                                        <td style={{ padding: '16px', fontSize: '12px', color: 'var(--text-main)', fontWeight: '600' }}>
                                            {d.replay_attempt_count ?? 0}
                                        </td>
                                        <td style={{ padding: '16px', fontSize: '12px', fontWeight: '700' }}>
                                            {d.offline ? (
                                                <span style={{ color: 'var(--secondary)' }}>OFFLINE</span>
                                            ) : (
                                                <span style={{ color: 'var(--primary)' }}>ONLINE</span>
                                            )}
                                        </td>
                                    </tr>
                                ))}
                            </tbody>
                        </table>
                    </div>
                )}
            </div>
        </DashboardLayout>
    );
}

