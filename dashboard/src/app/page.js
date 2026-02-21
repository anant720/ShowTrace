"use client";

import { useEffect, useState } from 'react';
import { apiRequest } from '@/utils/api';
import DashboardLayout from '@/components/DashboardLayout';
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, LineChart, Line
} from 'recharts';

export default function OverviewPage() {
  const [summary, setSummary] = useState(null);
  const [trends, setTrends] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const [sumData, trendData] = await Promise.all([
          apiRequest('/analytics/summary'),
          apiRequest('/analytics/trends?days=7')
        ]);
        setSummary(sumData);
        setTrends(trendData.trends);
      } catch (err) {
        console.error('Failed to fetch summary:', err);
      } finally {
        setLoading(false);
      }
    };
    fetchData();
  }, []);

  if (loading) return (
    <DashboardLayout>
      <div style={{ color: 'var(--secondary)' }}>Initializing Security Intelligence...</div>
    </DashboardLayout>
  );

  const riskData = [
    { name: 'Safe', value: summary?.risk_distribution?.Safe || 0, color: 'var(--accent-green)' },
    { name: 'Suspicious', value: summary?.risk_distribution?.Suspicious || 0, color: 'var(--accent-amber)' },
    { name: 'Dangerous', value: summary?.risk_distribution?.Dangerous || 0, color: 'var(--accent-red)' },
  ];

  const StatCard = ({ label, value, sub, color }) => (
    <div className="glass" style={{ padding: '24px', borderRadius: '12px', flex: 1 }}>
      <p style={{ color: 'var(--secondary)', fontSize: '14px', marginBottom: '8px' }}>{label}</p>
      <h2 style={{ fontSize: '32px', color: color || 'white' }}>{value}</h2>
      {sub && <p style={{ fontSize: '12px', marginTop: '4px', color: sub.includes('+') ? 'var(--accent-green)' : 'var(--secondary)' }}>{sub}</p>}
    </div>
  );

  return (
    <DashboardLayout>
      <div style={{ marginBottom: '32px' }}>
        <h1 style={{ fontSize: '24px' }}>System Overview</h1>
        <p style={{ color: 'var(--secondary)' }}>Real-time threat landscape analysis</p>
      </div>

      <div style={{ display: 'flex', gap: '20px', marginBottom: '32px' }}>
        <StatCard
          label="Total Scans"
          value={summary?.total_scans?.toLocaleString()}
          sub={`${summary?.growth_rate > 0 ? '+' : ''}${summary?.growth_rate}% from yesterday`}
        />
        <StatCard
          label="Risk Flagged"
          value={(summary?.risk_distribution?.Suspicious + summary?.risk_distribution?.Dangerous) || 0}
          color="var(--accent-amber)"
        />
        <StatCard
          label="Anomalies"
          value={summary?.active_anomalies}
          color={summary?.active_anomalies > 0 ? "var(--accent-red)" : "var(--accent-green)"}
          sub="Requires attention"
        />
        <StatCard
          label="User Reports"
          value={summary?.total_reports}
          sub={`${summary?.reports_today} today`}
        />
      </div>

      <div style={{ display: 'flex', gap: '20px', height: '400px' }}>
        <div className="glass" style={{ flex: 2, padding: '24px', borderRadius: '12px' }}>
          <h3 style={{ marginBottom: '24px', fontSize: '16px' }}>Scan Activity (Last 7 Days)</h3>
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={trends}>
              <CartesianGrid strokeDasharray="3 3" stroke="#2a2a2e" />
              <XAxis dataKey="date" stroke="var(--secondary)" fontSize={12} />
              <YAxis stroke="var(--secondary)" fontSize={12} />
              <Tooltip
                contentStyle={{ background: '#131316', border: '1px solid #1f1f23' }}
                itemStyle={{ color: 'var(--primary)' }}
              />
              <Line type="monotone" dataKey="total_scans" stroke="var(--primary)" strokeWidth={2} dot={{ r: 4 }} />
            </LineChart>
          </ResponsiveContainer>
        </div>

        <div className="glass" style={{ flex: 1, padding: '24px', borderRadius: '12px' }}>
          <h3 style={{ marginBottom: '24px', fontSize: '16px' }}>Risk Distribution</h3>
          <ResponsiveContainer width="100%" height="80%">
            <PieChart>
              <Pie
                data={riskData}
                innerRadius={60}
                outerRadius={80}
                paddingAngle={5}
                dataKey="value"
              >
                {riskData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{ background: '#131316', border: '1px solid #1f1f23' }}
              />
            </PieChart>
          </ResponsiveContainer>
          <div style={{ display: 'flex', justifyContent: 'center', gap: '16px', marginTop: '16px' }}>
            {riskData.map(d => (
              <div key={d.name} style={{ textAlign: 'center' }}>
                <p style={{ fontSize: '12px', color: 'var(--secondary)' }}>{d.name}</p>
                <p style={{ fontWeight: '600' }}>{d.value}</p>
              </div>
            ))}
          </div>
        </div>
      </div>
    </DashboardLayout>
  );
}
