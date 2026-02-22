"use client";

import { useEffect, useState } from 'react';
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
    <div className="st-card" style={{ flex: 1, padding: '28px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '16px' }}>
        <p style={{ color: 'var(--text-muted)', fontSize: '14px', fontWeight: '500' }}>{label}</p>
        <div style={{
          background: trend?.includes('+') ? 'rgba(52, 199, 89, 0.1)' : 'rgba(108, 114, 122, 0.05)',
          padding: '4px 10px',
          borderRadius: '10px',
          fontSize: '11px',
          fontWeight: '700',
          color: trend?.includes('+') ? '#248A3D' : 'var(--text-muted)'
        }}>
          {trend}
        </div>
      </div>
      <h2 style={{ fontSize: '36px', letterSpacing: '-1px', color: color || 'var(--text-main)' }}>{value}</h2>
    </div>
  );

  const getRiskColor = (level) => {
    const l = (level || '').toLowerCase();
    if (l === 'safe') return 'var(--success)';
    if (l === 'suspicious') return 'var(--warning)';
    return 'var(--danger)';
  };

  return (
    <DashboardLayout>
      {/* Hero Section */}
      <section className="st-card" style={{
        background: 'linear-gradient(135deg, #1A1C1E 0%, #2D3135 100%)',
        color: 'white',
        padding: '48px',
        marginBottom: '32px',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        position: 'relative',
        overflow: 'hidden'
      }}>
        <div style={{ position: 'relative', zIndex: 1 }}>
          <h1 style={{ fontSize: '40px', marginBottom: '12px', color: 'white' }}>Intelligence Summary</h1>
          <p style={{ color: 'rgba(255,255,255,0.6)', fontSize: '16px', maxWidth: '400px', lineHeight: '1.6' }}>
            Your security landscape is currently stable. We've analyzed {summary?.total_scans?.toLocaleString()} signals since we started tracking.
          </p>
          <div style={{ display: 'flex', gap: '16px', marginTop: '32px' }}>
            <button style={{ background: 'var(--primary)', color: 'white', padding: '12px 28px', borderRadius: 'var(--radius-pill)', fontSize: '14px' }}>View Full Audit</button>
            <button style={{ background: 'rgba(255,255,255,0.1)', color: 'white', padding: '12px 28px', borderRadius: 'var(--radius-pill)', fontSize: '14px' }}>Export PDF</button>
          </div>
        </div>
        <div style={{
          fontSize: '120px',
          opacity: 0.1,
          position: 'absolute',
          right: '-20px',
          bottom: '-20px',
          pointerEvents: 'none'
        }}></div>
      </section>

      {/* Stats Grid */}
      <div style={{ display: 'flex', gap: '24px', marginBottom: '32px' }}>
        <StatWidget
          label="Total Analysis"
          value={summary?.total_scans?.toLocaleString()}
          trend={`+${summary?.growth_rate || 0}%`}
        />
        <StatWidget
          label="Active Threats"
          value={((summary?.risk_distribution?.Suspicious || 0) + (summary?.risk_distribution?.Dangerous || 0))}
          color="#FF9500"
          trend="Monitor"
        />
        <StatWidget
          label="Anomalies"
          value={summary?.active_anomalies || 0}
          color={summary?.active_anomalies > 0 ? "var(--danger)" : "var(--success)"}
          trend="Real-time"
        />
      </div>

      <div style={{ display: 'flex', gap: '24px', marginBottom: '32px' }}>
        <div className="st-card" style={{ flex: 2, height: '440px', display: 'flex', flexDirection: 'column' }}>
          <h3 style={{ marginBottom: '32px', fontSize: '18px' }}>Security Events Trend</h3>
          <div style={{ flex: 1 }}>
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trends}>
                <defs>
                  <linearGradient id="colorScans" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="var(--primary)" stopOpacity={0.1} />
                    <stop offset="95%" stopColor="var(--primary)" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <XAxis dataKey="date" axisLine={false} tickLine={false} tick={{ fill: 'var(--text-muted)', fontSize: 12 }} dy={16} />
                <YAxis axisLine={false} tickLine={false} tick={{ fill: 'var(--text-muted)', fontSize: 12 }} />
                <Tooltip cursor={{ stroke: 'var(--primary)', strokeWidth: 1 }} contentStyle={{ borderRadius: '16px', border: 'none', boxShadow: 'var(--shadow-lg)', padding: '12px 16px' }} />
                <Area type="monotone" dataKey="total_scans" stroke="var(--primary)" strokeWidth={3} fillOpacity={1} fill="url(#colorScans)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="st-card" style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
          <h3 style={{ marginBottom: '32px', fontSize: '18px' }}>Threat Matrix</h3>
          <div style={{ flex: 1, minHeight: '240px' }}>
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie data={riskData} innerRadius={70} outerRadius={95} paddingAngle={8} dataKey="value" stroke="none">
                  {riskData.map((entry, index) => <Cell key={`cell-${index}`} fill={entry.color} />)}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div style={{ marginTop: '24px', display: 'flex', flexDirection: 'column', gap: '12px' }}>
            {riskData.map(d => (
              <div key={d.name} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: d.color }} />
                  <span style={{ fontSize: '14px', color: 'var(--text-muted)' }}>{d.name}</span>
                </div>
                <span style={{ fontWeight: '700', fontSize: '14px' }}>{d.value}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Recent Scans Feed */}
      <div className="st-card" style={{ padding: '32px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px' }}>
          <h3 style={{ fontSize: '18px' }}>Live Extension Feed</h3>
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', color: 'var(--text-muted)', fontSize: '12px' }}>
            <div className="animate-pulse" style={{ width: '8px', height: '8px', background: 'var(--success)', borderRadius: '50%' }} />
            Live Monitoring Active
          </div>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid var(--bg-hover)', textAlign: 'left' }}>
                <th style={{ padding: '16px', color: 'var(--text-muted)', fontWeight: '500', fontSize: '13px' }}>DOMAIN</th>
                <th style={{ padding: '16px', color: 'var(--text-muted)', fontWeight: '500', fontSize: '13px' }}>SCORE</th>
                <th style={{ padding: '16px', color: 'var(--text-muted)', fontWeight: '500', fontSize: '13px' }}>LEVEL</th>
                <th style={{ padding: '16px', color: 'var(--text-muted)', fontWeight: '500', fontSize: '13px' }}>TIME</th>
              </tr>
            </thead>
            <tbody>
              {recentScans.length === 0 ? (
                <tr>
                  <td colSpan="4" style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)' }}>
                    No recent scans detected. Start browsing with the extension to see live data.
                  </td>
                </tr>
              ) : recentScans.map((scan) => (
                <tr key={scan._id} style={{ borderBottom: '1px solid var(--bg-hover)' }}>
                  <td style={{ padding: '16px', fontWeight: '500' }}>{scan.domain}</td>
                  <td style={{ padding: '16px', fontFamily: 'monospace', fontWeight: 'bold' }}>{scan.final_risk_score}</td>
                  <td style={{ padding: '16px' }}>
                    <span style={{
                      background: `${getRiskColor(scan.risk_level)}15`,
                      color: getRiskColor(scan.risk_level),
                      padding: '4px 12px',
                      borderRadius: 'var(--radius-pill)',
                      fontSize: '11px',
                      fontWeight: '700'
                    }}>
                      {scan.risk_level.toUpperCase()}
                    </span>
                  </td>
                  <td style={{ padding: '16px', color: 'var(--text-muted)', fontSize: '13px' }}>
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
