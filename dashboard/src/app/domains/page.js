"use client";

import { useEffect, useState } from 'react';
import { apiRequest } from '@/utils/api';
import DashboardLayout from '@/components/DashboardLayout';

export default function DomainsPage() {
    const [domains, setDomains] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const fetchData = async () => {
            try {
                const data = await apiRequest('/analytics/top-domains?limit=50&days=30');
                setDomains(data.domains);
            } catch (err) {
                console.error('Failed to fetch domains:', err);
            } finally {
                setLoading(false);
            }
        };
        fetchData();
    }, []);

    if (loading) return (
        <DashboardLayout>
            <div style={{ color: 'var(--secondary)' }}>Intercepting High-Risk Traffic...</div>
        </DashboardLayout>
    );

    return (
        <DashboardLayout>
            <div style={{ marginBottom: '32px' }}>
                <h1 style={{ fontSize: '24px' }}>High Risk Domains</h1>
                <p style={{ color: 'var(--secondary)' }}>Domains with the highest cumulative risk scores across the network</p>
            </div>

            <div className="glass" style={{ borderRadius: '12px', overflow: 'hidden' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
                    <thead>
                        <tr style={{ background: 'rgba(255,255,255,0.03)', color: 'var(--secondary)', fontSize: '13px' }}>
                            <th style={{ padding: '16px 24px' }}>Domain</th>
                            <th style={{ padding: '16px 24px' }}>Avg Risk</th>
                            <th style={{ padding: '16px 24px' }}>Scans</th>
                            <th style={{ padding: '16px 24px' }}>Risk Distribution</th>
                            <th style={{ padding: '16px 24px' }}>Last Activity</th>
                        </tr>
                    </thead>
                    <tbody>
                        {domains.map((d, i) => (
                            <tr key={i} style={{ borderBottom: '1px solid #1f1f23', fontSize: '14px' }}>
                                <td style={{ padding: '16px 24px', fontWeight: 'bold' }}>{d.domain}</td>
                                <td style={{ padding: '16px 24px', color: d.avg_score > 60 ? 'var(--accent-red)' : 'var(--accent-amber)' }}>
                                    {d.avg_score}
                                </td>
                                <td style={{ padding: '16px 24px' }}>{d.scan_count}</td>
                                <td style={{ padding: '16px 24px' }}>
                                    <div style={{ display: 'flex', gap: '4px', height: '6px', width: '120px', borderRadius: '3px', overflow: 'hidden', background: '#2a2a2e' }}>
                                        <div style={{ flex: d.risk_breakdown.Dangerous || 0, background: 'var(--accent-red)' }} />
                                        <div style={{ flex: d.risk_breakdown.Suspicious || 0, background: 'var(--accent-amber)' }} />
                                        <div style={{ flex: d.risk_breakdown.Safe || 0, background: 'var(--accent-green)' }} />
                                    </div>
                                </td>
                                <td style={{ padding: '16px 24px', color: 'var(--secondary)', fontSize: '12px' }}>
                                    {new Date(d.last_scan).toLocaleString()}
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </DashboardLayout>
    );
}
