"use client";

import { useEffect, useState } from 'react';
import { apiRequest } from '@/utils/api';
import DashboardLayout from '@/components/DashboardLayout';
import {
    BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
    LineChart, Line, AreaChart, Area
} from 'recharts';

export default function AnalyticsPage() {
    const [trends, setTrends] = useState([]);
    const [tlds, setTlds] = useState([]);
    const [engines, setEngines] = useState({});
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const fetchData = async () => {
            try {
                const [trendData, tldData, engineData] = await Promise.all([
                    apiRequest('/analytics/trends?days=30'),
                    apiRequest('/analytics/tld-distribution'),
                    apiRequest('/analytics/engine-breakdown')
                ]);
                setTrends(trendData.trends);
                setTlds(tldData.tlds);
                setEngines(engineData.engines);
            } catch (err) {
                console.error('Failed to fetch analytics:', err);
            } finally {
                setLoading(false);
            }
        };
        fetchData();
    }, []);

    if (loading) return (
        <DashboardLayout>
            <div style={{ color: 'var(--secondary)' }}>Aggregating Global Threat Data...</div>
        </DashboardLayout>
    );

    return (
        <DashboardLayout>
            <div style={{ marginBottom: '32px' }}>
                <h1 style={{ fontSize: '24px' }}>Security Analytics</h1>
                <p style={{ color: 'var(--secondary)' }}>Deep dive into threat vectors and detection patterns</p>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '20px', marginBottom: '32px' }}>
                <div className="glass" style={{ padding: '24px', borderRadius: '12px', height: '350px' }}>
                    <h3 style={{ marginBottom: '24px', fontSize: '16px' }}>Risk Score Evolution (30 Days)</h3>
                    <ResponsiveContainer width="100%" height="100%">
                        <AreaChart data={trends}>
                            <defs>
                                <linearGradient id="colorRisk" x1="0" y1="0" x2="0" y2="1">
                                    <stop offset="5%" stopColor="var(--primary)" stopOpacity={0.3} />
                                    <stop offset="95%" stopColor="var(--primary)" stopOpacity={0} />
                                </linearGradient>
                            </defs>
                            <CartesianGrid strokeDasharray="3 3" stroke="#2a2a2e" />
                            <XAxis dataKey="date" stroke="var(--secondary)" fontSize={10} />
                            <YAxis stroke="var(--secondary)" fontSize={10} domain={[0, 100]} />
                            <Tooltip contentStyle={{ background: '#131316', border: '1px solid #1f1f23' }} />
                            <Area type="monotone" dataKey="avg_risk" stroke="var(--primary)" fillOpacity={1} fill="url(#colorRisk)" />
                        </AreaChart>
                    </ResponsiveContainer>
                </div>

                <div className="glass" style={{ padding: '24px', borderRadius: '12px', height: '350px' }}>
                    <h3 style={{ marginBottom: '24px', fontSize: '16px' }}>Threat Concentration by TLD</h3>
                    <ResponsiveContainer width="100%" height="100%">
                        <BarChart data={tlds} layout="vertical">
                            <CartesianGrid strokeDasharray="3 3" stroke="#2a2a2e" horizontal={false} />
                            <XAxis type="number" stroke="var(--secondary)" fontSize={10} />
                            <YAxis dataKey="tld" type="category" stroke="var(--secondary)" fontSize={11} width={60} />
                            <Tooltip contentStyle={{ background: '#131316', border: '1px solid #1f1f23' }} />
                            <Bar dataKey="suspicious_scans" fill="var(--accent-red)" radius={[0, 4, 4, 0]} />
                        </BarChart>
                    </ResponsiveContainer>
                </div>
            </div>

            <div className="glass" style={{ padding: '24px', borderRadius: '12px' }}>
                <h3 style={{ marginBottom: '24px', fontSize: '16px' }}>Engine Performance Matrix</h3>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px' }}>
                    {Object.entries(engines).map(([name, data]) => (
                        <div key={name} style={{ border: '1px solid #1f1f23', padding: '16px', borderRadius: '8px' }}>
                            <p style={{ color: 'var(--secondary)', fontSize: '12px', textTransform: 'capitalize' }}>
                                {name.replace('_', ' ')}
                            </p>
                            <div style={{ display: 'flex', alignItems: 'baseline', gap: '8px', margin: '8px 0' }}>
                                <h4 style={{ fontSize: '24px' }}>{data.avg_score}</h4>
                                <span style={{ fontSize: '12px', color: 'var(--secondary)' }}>/ {data.max_score}</span>
                            </div>
                            <div style={{ height: '4px', background: '#1c1c21', borderRadius: '2px', overflow: 'hidden' }}>
                                <div style={{
                                    height: '100%',
                                    width: `${(data.avg_score / data.max_score) * 100}%`,
                                    background: 'var(--primary)'
                                }} />
                            </div>
                            <p style={{ fontSize: '11px', color: 'var(--secondary)', marginTop: '8px' }}>Weight: {data.weight}</p>
                        </div>
                    ))}
                </div>
            </div>
        </DashboardLayout>
    );
}
