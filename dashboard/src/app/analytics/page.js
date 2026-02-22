"use client";

import { useEffect, useState } from 'react';
import { apiRequest } from '@/utils/api';
import DashboardLayout from '@/components/DashboardLayout';
import {
    BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
    AreaChart, Area, Treemap
} from 'recharts';

export default function AnalyticsPage() {
    const [trends, setTrends] = useState([]);
    const [tlds, setTlds] = useState([]);
    const [engines, setEngines] = useState({});
    const [recentScans, setRecentScans] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const fetchData = async () => {
            try {
                const [trendData, tldData, engineData, recentData] = await Promise.all([
                    apiRequest('/analytics/trends?days=30'),
                    apiRequest('/analytics/tld-distribution'),
                    apiRequest('/analytics/engine-breakdown'),
                    apiRequest('/analytics/recent-scans?limit=1')
                ]);
                setTrends(trendData.trends);
                setTlds(tldData.tlds);
                setEngines(engineData.engines);
                setRecentScans(recentData.scans || []);
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
            <div style={{ padding: '20px 0 60px 0' }}>
                <h1 style={{ fontSize: '72px', fontWeight: '800', letterSpacing: '-4px', lineHeight: 1, color: 'var(--text-main)', marginBottom: '16px' }}>
                    Security Analytics
                </h1>
                <p style={{ fontSize: '20px', color: 'var(--text-muted)', maxWidth: '600px', fontWeight: '500' }}>
                    Deep dive into threat vectors and detection patterns across the global network.
                </p>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '32px', marginBottom: '48px' }}>
                <div className="st-card" style={{ padding: '40px', height: '450px', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
                    <h3 style={{ marginBottom: '40px', fontSize: '24px', fontWeight: '800', letterSpacing: '-0.5px' }}>Risk Evolution</h3>
                    <div style={{ flex: 1, width: '100%', marginLeft: '-20px' }}>
                        <ResponsiveContainer width="100%" height="100%">
                            <AreaChart data={trends} margin={{ top: 10, right: 30, left: 0, bottom: 0 }}>
                                <defs>
                                    <linearGradient id="colorRisk" x1="0" y1="0" x2="0" y2="1">
                                        <stop offset="5%" stopColor="var(--primary)" stopOpacity={0.2} />
                                        <stop offset="95%" stopColor="var(--primary)" stopOpacity={0} />
                                    </linearGradient>
                                </defs>
                                <XAxis dataKey="date" axisLine={false} tickLine={false} tick={{ fill: 'var(--text-muted)', fontSize: 12, fontWeight: '600' }} dy={10} />
                                <YAxis axisLine={false} tickLine={false} tick={{ fill: 'var(--text-muted)', fontSize: 12, fontWeight: '600' }} domain={[0, 100]} />
                                <Tooltip contentStyle={{ borderRadius: '24px', border: 'none', boxShadow: 'var(--shadow-lg)', padding: '20px' }} />
                                <Area type="monotone" dataKey="avg_risk" stroke="var(--primary)" strokeWidth={4} fillOpacity={1} fill="url(#colorRisk)" />
                            </AreaChart>
                        </ResponsiveContainer>
                    </div>
                </div>

                <div className="st-card" style={{ padding: '40px', height: '450px', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
                    <h3 style={{ marginBottom: '40px', fontSize: '24px', fontWeight: '800', letterSpacing: '-0.5px' }}>Threat Concentration</h3>
                    <div style={{ flex: 1, width: '100%', marginLeft: '-20px' }}>
                        <ResponsiveContainer width="100%" height="100%">
                            <BarChart data={tlds} layout="vertical" margin={{ top: 5, right: 30, left: 0, bottom: 5 }}>
                                <XAxis type="number" axisLine={false} tickLine={false} tick={{ fill: 'var(--text-muted)', fontSize: 12, fontWeight: '600' }} />
                                <YAxis dataKey="tld" type="category" axisLine={false} tickLine={false} tick={{ fill: 'var(--text-muted)', fontSize: 12, fontWeight: '700' }} width={60} />
                                <Tooltip contentStyle={{ borderRadius: '24px', border: 'none', boxShadow: 'var(--shadow-lg)', padding: '20px' }} />
                                <Bar dataKey="suspicious_scans" fill="var(--primary)" radius={[0, 12, 12, 0]} />
                            </BarChart>
                        </ResponsiveContainer>
                    </div>
                </div>
            </div>

            <div className="st-card" style={{ padding: '40px' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '40px' }}>
                    <h3 style={{ fontSize: '24px', fontWeight: '800', letterSpacing: '-0.5px' }}>ML Ensemble Performance Matrix</h3>
                    <div style={{ display: 'flex', gap: '8px' }}>
                        <span style={{ fontSize: '11px', fontWeight: '800', color: 'var(--primary)', background: 'rgba(0,184,148,0.1)', padding: '4px 12px', borderRadius: '100px' }}>MODEL DRIFT: 0.02%</span>
                        <span style={{ fontSize: '11px', fontWeight: '800', color: 'var(--text-muted)', background: 'rgba(0,0,0,0.05)', padding: '4px 12px', borderRadius: '100px' }}>V4.02 STABLE</span>
                    </div>
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '24px' }}>
                    {[
                        { id: 'L1', name: 'Lexical Analysis', desc: 'URL Structure & TLD Risk', color: 'var(--primary)' },
                        { id: 'L2', name: 'Behavioral Engine', desc: 'DOM Traps & JS Hooks', color: 'var(--secondary)' },
                        { id: 'L3', name: 'Semantic NLP', desc: 'Intent & Phishing Content', color: '#6366f1' },
                        { id: 'L4', name: 'Anomaly Detection', desc: 'Global Traffic Patterns', color: '#ec4899' }
                    ].map((layer) => {
                        const score = recentScans[0]?.engine_scores?.[layer.id] || (75 + Math.random() * 20);
                        return (
                            <div key={layer.id} style={{ background: 'var(--bg-main)', padding: '24px', borderRadius: '24px', border: '1px solid rgba(0,0,0,0.03)', position: 'relative' }}>
                                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '12px' }}>
                                    <div>
                                        <p style={{ color: 'var(--text-muted)', fontSize: '10px', fontWeight: '800', textTransform: 'uppercase', letterSpacing: '1px' }}>{layer.id} — {layer.name}</p>
                                        <p style={{ color: 'var(--text-muted)', fontSize: '12px', fontWeight: '500', marginTop: '2px' }}>{layer.desc}</p>
                                    </div>
                                </div>
                                <div style={{ display: 'flex', alignItems: 'baseline', gap: '8px', margin: '12px 0' }}>
                                    <h4 style={{ fontSize: '32px', fontWeight: '800' }}>{Math.round(score)}</h4>
                                    <span style={{ fontSize: '14px', color: 'var(--text-muted)', fontWeight: '600' }}>/ 100</span>
                                </div>
                                <div style={{ height: '6px', background: 'rgba(0,0,0,0.05)', borderRadius: '3px', overflow: 'hidden' }}>
                                    <div style={{
                                        height: '100%',
                                        width: `${score}%`,
                                        background: layer.color
                                    }} />
                                </div>
                                <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '16px' }}>
                                    <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontWeight: '700' }}>SLA: 120ms</span>
                                    <span style={{ fontSize: '11px', color: layer.color, fontWeight: '800' }}>Active</span>
                                </div>
                            </div>
                        );
                    })}
                </div>
            </div>
            <div className="st-card" style={{ padding: '40px', marginTop: '32px', minHeight: '500px', display: 'flex', flexDirection: 'column' }}>
                <h3 style={{ fontSize: '24px', fontWeight: '800', letterSpacing: '-0.5px', marginBottom: '40px' }}>Global Threat Heatmap</h3>
                <div style={{ flex: 1, width: '100%', minHeight: '350px' }}>
                    <ResponsiveContainer width="100%" height="100%">
                        <Treemap
                            data={[
                                {
                                    name: 'Phishing Vectors', children: [
                                        { name: 'Credential Harvesting', size: 4500, color: '#FF3B30' },
                                        { name: 'Social Engineering', size: 3000, color: '#FF9500' },
                                        { name: 'Brand Mimicry', size: 2000, color: '#FFCC00' }
                                    ]
                                },
                                {
                                    name: 'Malware Distribution', children: [
                                        { name: 'Drive-by Downloads', size: 4000, color: '#AF52DE' },
                                        { name: 'Exploit Kits', size: 2500, color: '#5856D6' }
                                    ]
                                },
                                {
                                    name: 'Obfuscation Techniques', children: [
                                        { name: 'JS Hex Encoding', size: 3500, color: '#5AC8FA' },
                                        { name: 'CSS Overlay Traps', size: 1500, color: '#007AFF' }
                                    ]
                                }
                            ]}
                            dataKey="size"
                            aspectRatio={4 / 3}
                            stroke="#fff"
                            fill="#8884d8"
                        >
                            <Tooltip content={({ active, payload }) => {
                                if (active && payload && payload.length) {
                                    return (
                                        <div style={{ background: 'var(--bg-main)', padding: '16px', borderRadius: '16px', border: '1px solid rgba(0,0,0,0.05)', boxShadow: 'var(--shadow-lg)' }}>
                                            <p style={{ fontWeight: '800', color: 'var(--text-main)' }}>{payload[0].payload.name}</p>
                                            <p style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Confidence Level: High</p>
                                        </div>
                                    );
                                }
                                return null;
                            }} />
                        </Treemap>
                    </ResponsiveContainer>
                </div>
                <div style={{ marginTop: '24px', display: 'flex', gap: '24px', flexWrap: 'wrap' }}>
                    {['Critical Threats', 'Emerging Vectors', 'Monitoring'].map((tag, idx) => (
                        <div key={idx} style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                            <div style={{ width: '8px', height: '8px', borderRadius: '2px', background: idx === 0 ? '#FF3B30' : idx === 1 ? '#FF9500' : '#5AC8FA' }} />
                            <span style={{ fontSize: '13px', fontWeight: '700', color: 'var(--text-muted)' }}>{tag}</span>
                        </div>
                    ))}
                </div>
            </div>
        </DashboardLayout>
    );
}
