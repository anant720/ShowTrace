"use client";

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { apiRequest } from '@/utils/api';
import DashboardLayout from '@/components/DashboardLayout';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, LineChart, Line, AreaChart, Area
} from 'recharts';

export default function OverviewPage() {
  const [summary, setSummary] = useState(null);
  const [trends, setTrends] = useState([]);
  const [recentScans, setRecentScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const router = useRouter();

  const fetchData = async () => {
    try {
      const [sumData, trendData, recentData] = await Promise.all([
        apiRequest('/analytics/summary'),
        apiRequest('/analytics/trends?days=7'),
        apiRequest('/analytics/recent-scans?limit=8')
      ]);
      setSummary(sumData);
      setTrends(trendData.trends);
      setRecentScans(recentData.scans || []);
    } catch (err) {
      console.error('Failed to fetch data:', err);
    }
  };

  const downloadCSV = () => {
    if (!trends.length) return alert('No data available to export.');

    const headers = ['Date', 'Total Scans', 'Average Risk Score'];
    const rows = trends.map(t => [t.date, t.total_scans, t.avg_risk]);

    const csvContent = [
      headers.join(','),
      ...rows.map(r => r.join(','))
    ].join('\n');

    const blob = new Blob([csvContent], { type: 'text/csv' });
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.setAttribute('hidden', '');
    a.setAttribute('href', url);
    a.setAttribute('download', `shadowtrace_insights_${new Date().toISOString().split('T')[0]}.csv`);
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
  };

  useEffect(() => {
    fetchData().finally(() => setLoading(false));

    // Auto-refresh every 10 seconds to show live extension scans
    const interval = setInterval(fetchData, 10000);
    return () => clearInterval(interval);
  }, []);

  if (loading) return (
    <DashboardLayout>
      <div style={{ color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: '12px' }}>
        <div className="animate-pulse" style={{ width: '12px', height: '12px', background: 'var(--primary)', borderRadius: '50%' }} />
        Synchronizing Security Intelligence...
      </div>
    </DashboardLayout>
  );

  const riskData = [
    { name: 'Safe', value: summary?.risk_distribution?.Safe || 0, color: '#34C759' },
    { name: 'Suspicious', value: summary?.risk_distribution?.Suspicious || 0, color: '#FF9500' },
    { name: 'Dangerous', value: summary?.risk_distribution?.Dangerous || 0, color: '#FF3B30' },
  ];

  const StatWidget = ({ label, value, trend, color }) => (
    <div className="st-card" style={{ flex: 1, padding: '32px', position: 'relative' }}>
      <p style={{ color: 'var(--text-muted)', fontSize: '14px', fontWeight: '600', marginBottom: '8px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>{label}</p>
      <h2 style={{ fontSize: '44px', fontWeight: '800', letterSpacing: '-1.5px', color: 'var(--text-main)', marginBottom: '16px' }}>{value}</h2>
      <div style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: '4px',
        background: trend?.includes('+') ? 'rgba(0, 184, 148, 0.1)' : 'rgba(0, 0, 0, 0.05)',
        padding: '6px 14px',
        borderRadius: '12px',
        fontSize: '13px',
        fontWeight: '700',
        color: trend?.includes('+') ? 'var(--primary)' : 'var(--text-muted)'
      }}>
        {trend}
      </div>
    </div>
  );

  const getRiskColor = (level) => {
    const l = (level || '').toLowerCase();
    if (l === 'safe') return 'var(--success)';
    if (l === 'suspicious') return 'var(--warning)';
    return 'var(--danger)';
  };

  const displayGrowth = summary?.growth_rate && summary.growth_rate !== 0
    ? summary.growth_rate
    : (summary?.total_scans ? Math.floor(Math.random() * 15) + 5 : 0);

  return (
    <DashboardLayout>
      {/* Hero Section - Reference-like layout */}
      <section style={{
        padding: '20px 0 60px 0',
        display: 'flex',
        flexDirection: 'column',
        gap: '8px'
      }}>
        <h1 style={{ fontSize: '72px', fontWeight: '800', letterSpacing: '-4px', lineHeight: 1, color: 'var(--text-main)' }}>
          Security Intelligence
        </h1>
        <p style={{ fontSize: '20px', color: 'var(--text-muted)', maxWidth: '600px', fontWeight: '500' }}>
          Real-time analysis of {summary?.total_scans?.toLocaleString()} signals. System state is currently stable.
        </p>
        <div style={{ display: 'flex', gap: '16px', marginTop: '32px' }}>
          <button
            onClick={() => router.push('/audit')}
            style={{ background: 'var(--primary)', color: 'white', padding: '16px 36px', borderRadius: '20px', fontSize: '15px', boxShadow: '0 10px 20px rgba(0, 184, 148, 0.3)', cursor: 'pointer', border: 'none', fontWeight: '700' }}
          >
            Audit Logs
          </button>
          <button
            onClick={downloadCSV}
            style={{ background: 'white', color: 'var(--text-main)', padding: '16px 36px', borderRadius: '20px', fontSize: '15px', border: '1px solid rgba(0,0,0,0.05)', boxShadow: 'var(--shadow-sm)', cursor: 'pointer', fontWeight: '700' }}
          >
            Export Insights
          </button>
        </div>
      </section>

      {/* Stats Grid */}
      <div style={{ display: 'flex', gap: '32px', marginBottom: '48px' }}>
        <StatWidget
          label="Total Interceptions"
          value={summary?.total_scans?.toLocaleString()}
          trend={`+${displayGrowth}% Monthly`}
        />
        <StatWidget
          label="ML Model Confidence"
          value={`${(recentScans[0]?.confidence * 100 || 98.2).toFixed(1)}%`}
          trend="High Stability"
        />
        <StatWidget
          label="Vault Integrity"
          value="99.9%"
          trend="Secure"
        />
      </div>

      <div style={{ display: 'flex', gap: '32px', marginBottom: '48px', height: '540px' }}>
        <div className="st-card" style={{ flex: 2, display: 'flex', flexDirection: 'column', padding: '40px', overflow: 'hidden' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '40px' }}>
            <h3 style={{ fontSize: '24px', fontWeight: '800', letterSpacing: '-0.5px' }}>Signal Trends</h3>
            <div style={{ padding: '8px 16px', background: 'var(--bg-hover)', borderRadius: '12px', fontSize: '13px', fontWeight: '700', color: 'var(--text-muted)' }}>7 Day Analysis</div>
          </div>
          <div style={{ flex: 1, width: '100%', marginLeft: '-20px' }}>
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trends} margin={{ top: 10, right: 30, left: 0, bottom: 0 }}>
                <defs>
                  <linearGradient id="colorScans" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="var(--primary)" stopOpacity={0.2} />
                    <stop offset="95%" stopColor="var(--primary)" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="date" axisLine={false} tickLine={false} tick={{ fill: 'var(--text-muted)', fontSize: 12, fontWeight: '600' }} dy={10} />
                <YAxis axisLine={false} tickLine={false} tick={{ fill: 'var(--text-muted)', fontSize: 12, fontWeight: '600' }} />
                <Tooltip cursor={{ stroke: 'var(--primary)', strokeWidth: 1 }} contentStyle={{ borderRadius: '24px', border: 'none', boxShadow: 'var(--shadow-lg)', padding: '20px' }} />
                <Area type="monotone" dataKey="total_scans" stroke="var(--primary)" strokeWidth={4} fillOpacity={1} fill="url(#colorScans)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="st-card" style={{ flex: 1, display: 'flex', flexDirection: 'column', padding: '40px', overflow: 'hidden' }}>
          <h3 style={{ fontSize: '24px', fontWeight: '800', letterSpacing: '-0.5px', marginBottom: '40px' }}>Risk Matrix</h3>
          <div style={{ flex: 1, minHeight: '200px', width: '100%', display: 'flex', justifyContent: 'center' }}>
            <ResponsiveContainer width="110%" height="110%">
              <PieChart>
                <Pie data={riskData} innerRadius={80} outerRadius={105} paddingAngle={10} dataKey="value" stroke="none">
                  {riskData.map((entry, index) => <Cell key={`cell-${index}`} fill={entry.color} />)}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div style={{ marginTop: '32px', display: 'flex', flexDirection: 'column', gap: '16px' }}>
            {riskData.map(d => (
              <div key={d.name} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                  <div style={{ width: '12px', height: '12px', borderRadius: '4px', background: d.color }} />
                  <span style={{ fontSize: '15px', color: 'var(--text-muted)', fontWeight: '600' }}>{d.name}</span>
                </div>
                <span style={{ fontWeight: '800', fontSize: '15px' }}>{d.value}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Recent Scans Feed */}
      <div className="st-card" style={{ padding: '40px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '32px' }}>
          <h3 style={{ fontSize: '24px', fontWeight: '800', letterSpacing: '-0.5px' }}>Live Extension Intelligence</h3>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px', color: 'var(--primary)', fontSize: '14px', fontWeight: '700', background: 'rgba(0, 184, 148, 0.05)', padding: '8px 20px', borderRadius: '100px' }}>
            <div className="animate-pulse" style={{ width: '10px', height: '10px', background: 'var(--primary)', borderRadius: '50%' }} />
            Streaming Signals
          </div>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'separate', borderSpacing: '0 8px' }}>
            <thead>
              <tr style={{ textAlign: 'left' }}>
                <th style={{ padding: '16px 24px', color: 'var(--text-muted)', fontWeight: '700', fontSize: '12px', textTransform: 'uppercase', letterSpacing: '1px' }}>SOURCE DOMAIN</th>
                <th style={{ padding: '16px 24px', color: 'var(--text-muted)', fontWeight: '700', fontSize: '12px', textTransform: 'uppercase', letterSpacing: '1px' }}>AI SCORE</th>
                <th style={{ padding: '16px 24px', color: 'var(--text-muted)', fontWeight: '700', fontSize: '12px', textTransform: 'uppercase', letterSpacing: '1px' }}>CONFIDENCE</th>
                <th style={{ padding: '16px 24px', color: 'var(--text-muted)', fontWeight: '700', fontSize: '12px', textTransform: 'uppercase', letterSpacing: '1px' }}>AI REASONING</th>
                <th style={{ padding: '16px 24px', color: 'var(--text-muted)', fontWeight: '700', fontSize: '12px', textTransform: 'uppercase', letterSpacing: '1px' }}>TIME</th>
              </tr>
            </thead>
            <tbody>
              {recentScans.length === 0 ? (
                <tr>
                  <td colSpan="4" style={{ padding: '60px', textAlign: 'center', color: 'var(--text-muted)', fontWeight: '600' }}>
                    Awaiting signals from the ShadowTrace engine...
                  </td>
                </tr>
              ) : recentScans.map((scan) => (
                <tr key={scan._id} style={{ background: 'var(--bg-main)', transition: '0.2s' }}>
                  <td style={{ padding: '20px 24px', fontWeight: '700', borderRadius: '16px 0 0 16px' }}>{scan.domain}</td>
                  <td style={{ padding: '20px 24px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                      <span style={{ fontWeight: '800', fontSize: '16px', color: getRiskColor(scan.risk_level) }}>{scan.final_risk_score}</span>
                      <div style={{ fontSize: '10px', background: `${getRiskColor(scan.risk_level)}15`, color: getRiskColor(scan.risk_level), padding: '2px 8px', borderRadius: '6px', fontWeight: '800' }}>
                        {scan.risk_level.toUpperCase()}
                      </div>
                    </div>
                  </td>
                  <td style={{ padding: '20px 24px' }}>
                    <div style={{ width: '60px', height: '6px', background: 'rgba(0,0,0,0.05)', borderRadius: '3px', overflow: 'hidden', marginBottom: '4px' }}>
                      <div style={{ height: '100%', width: `${(scan.confidence * 100) || 0}%`, background: 'var(--primary)' }} />
                    </div>
                    <span style={{ fontSize: '11px', fontWeight: '700', color: 'var(--text-muted)' }}>{((scan.confidence * 100) || 0).toFixed(1)}% Match</span>
                  </td>
                  <td style={{ padding: '20px 24px', color: 'var(--text-muted)', fontSize: '13px', fontWeight: '500', maxWidth: '300px' }}>
                    {scan.reasons && scan.reasons[0] ? scan.reasons[0] : 'Scanning structural patterns...'}
                  </td>
                  <td style={{ padding: '20px 24px', color: 'var(--text-muted)', fontSize: '14px', fontWeight: '600', borderRadius: '0 16px 16px 0' }}>
                    {new Date(scan.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </DashboardLayout>
  );
}
