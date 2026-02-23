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
            <div style={{ padding: '20px 0 60px 0' }}>
                <h1 style={{ fontSize: 'var(--hero-font-size)', fontWeight: '800', letterSpacing: '-4px', lineHeight: 1, color: 'var(--text-main)', marginBottom: '16px', transition: 'font-size 0.3s ease' }}>
                    Network Intelligence
                </h1>
                <p style={{ fontSize: 'clamp(16px, 2vw, 20px)', color: 'var(--text-muted)', maxWidth: '600px', fontWeight: '500' }}>
                    Tracking high-risk domains and cumulative security vulnerabilities across the environment.
                </p>
            </div>

            <div className="st-card" style={{ padding: '40px' }}>
                <table style={{ width: '100%', borderCollapse: 'separate', borderSpacing: '0 12px', textAlign: 'left' }}>
                    <thead>
                        <tr style={{ color: 'var(--text-muted)', fontSize: '12px', fontWeight: '800', textTransform: 'uppercase', letterSpacing: '1px' }}>
                            <th style={{ padding: '0 24px' }}>DOMAIN</th>
                            <th style={{ padding: '0 24px' }}>RISK</th>
                            <th style={{ padding: '0 24px' }}>SIGNALS</th>
                            <th style={{ padding: '0 24px', display: (typeof window !== 'undefined' && window.innerWidth <= 768) ? 'none' : 'table-cell' }}>MATRIX</th>
                            <th style={{ padding: '0 24px' }}>LAST SEEN</th>
                        </tr>
                    </thead>
                    <tbody>
                        {domains.map((d, i) => (
                            <tr key={i} style={{ background: 'var(--bg-main)', transition: '0.2s' }}>
                                <td style={{ padding: '24px', fontWeight: '800', fontSize: 'clamp(13px, 2vw, 16px)', borderRadius: '20px 0 0 20px' }}>{d.domain}</td>
                                <td style={{ padding: '24px', color: d.avg_score > 60 ? 'var(--danger)' : 'var(--warning)', fontWeight: '900', fontSize: '18px' }}>
                                    {d.avg_score}
                                </td>
                                <td style={{ padding: '24px', fontWeight: '700', color: 'var(--text-main)' }}>{d.scan_count}</td>
                                <td style={{ padding: '24px', display: (typeof window !== 'undefined' && window.innerWidth <= 768) ? 'none' : 'table-cell' }}>
                                    <div style={{ display: 'flex', gap: '6px', height: '10px', width: '100px', borderRadius: '5px', overflow: 'hidden', background: 'rgba(0,0,0,0.05)' }}>
                                        <div style={{ flex: d.risk_breakdown.Dangerous || 0, background: 'var(--danger)' }} />
                                        <div style={{ flex: d.risk_breakdown.Suspicious || 0, background: 'var(--warning)' }} />
                                        <div style={{ flex: d.risk_breakdown.Safe || 0, background: 'var(--success)' }} />
                                    </div>
                                </td>
                                <td style={{ padding: '24px', color: 'var(--text-muted)', fontSize: '12px', fontWeight: '600', borderRadius: '0 20px 20px 0' }}>
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
