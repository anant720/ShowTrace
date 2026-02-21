"use client";

import { useEffect, useState } from 'react';
import { apiRequest } from '@/utils/api';
import DashboardLayout from '@/components/DashboardLayout';

export default function AnomaliesPage() {
    const [anomalies, setAnomalies] = useState([]);
    const [loading, setLoading] = useState(true);

    const fetchAnomalies = async () => {
        try {
            const data = await apiRequest('/analytics/anomalies?unacknowledged_only=false');
            setAnomalies(data.anomalies);
        } catch (err) {
            console.error('Failed to fetch anomalies:', err);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchAnomalies();
    }, []);

    const acknowledge = async (id) => {
        try {
            await apiRequest(`/analytics/anomalies/${id}/acknowledge`, 'POST');
            fetchAnomalies();
        } catch (err) {
            alert('Action failed');
        }
    };

    if (loading) return (
        <DashboardLayout>
            <div style={{ color: 'var(--secondary)' }}>Analyzing Behavioral Outliers...</div>
        </DashboardLayout>
    );

    return (
        <DashboardLayout>
            <div style={{ marginBottom: '32px' }}>
                <h1 style={{ fontSize: '24px' }}>ML Anomaly Alerts</h1>
                <p style={{ color: 'var(--secondary)' }}>Automated detection of statistical spikes and suspicious campaigns</p>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                {anomalies.map((a, i) => (
                    <div key={i} className="glass" style={{
                        padding: '20px',
                        borderRadius: '12px',
                        display: 'flex',
                        justifyContent: 'space-between',
                        alignItems: 'center',
                        borderLeft: `4px solid ${a.severity === 'high' ? 'var(--accent-red)' : 'var(--accent-amber)'}`
                    }}>
                        <div>
                            <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '8px' }}>
                                <span style={{
                                    fontSize: '10px',
                                    textTransform: 'uppercase',
                                    background: a.severity === 'high' ? '#4a1111' : '#4a3311',
                                    color: a.severity === 'high' ? '#ff4d4d' : '#ffaa00',
                                    padding: '2px 8px',
                                    borderRadius: '4px',
                                    fontWeight: 'bold'
                                }}>
                                    {a.type} | {a.severity}
                                </span>
                                <span style={{ fontWeight: '600' }}>{a.domain || 'Global Spike'}</span>
                                <span style={{ fontSize: '12px', color: 'var(--secondary)' }}>{new Date(a.detected_at).toLocaleString()}</span>
                            </div>
                            <p style={{ color: 'var(--foreground)', fontSize: '14px' }}>{a.details}</p>
                        </div>

                        {!a.acknowledged ? (
                            <button
                                onClick={() => acknowledge(a._id)}
                                style={{ background: 'var(--primary)', color: 'black', padding: '8px 16px', fontSize: '13px' }}
                            >
                                Acknowledge
                            </button>
                        ) : (
                            <span style={{ color: 'var(--accent-green)', fontSize: '13px' }}>✓ Acknowledged</span>
                        )}
                    </div>
                ))}
                {anomalies.length === 0 && (
                    <div className="glass" style={{ padding: '40px', textAlign: 'center', borderRadius: '12px', color: 'var(--secondary)' }}>
                        No anomalies detected in the last 24 hours. System stable.
                    </div>
                )}
            </div>
        </DashboardLayout>
    );
}
