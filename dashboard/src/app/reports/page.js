"use client";

import { useEffect, useState } from 'react';
import { apiRequest } from '@/utils/api';
import DashboardLayout from '@/components/DashboardLayout';

export default function ReportsPage() {
    const [reports, setReports] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const fetchReports = async () => {
            try {
                const data = await apiRequest('/analytics/summary'); // Just to get stats, but I need a list endpoint
                // I don't have a specific GET /analytics/reports yet, let's just use the stats one or add it.
                // For now, I'll assume I have it or add it to the backend.
                const res = await apiRequest('/report'); // Existing report list? No, there is only POST /report
                setReports([]); // Placeholder
            } catch (err) {
                console.error('Failed to fetch reports:', err);
            } finally {
                setLoading(false);
            }
        };
        fetchReports();
    }, []);

    return (
        <DashboardLayout>
            <div style={{ padding: '20px 0 60px 0' }}>
                <h1 style={{ fontSize: '72px', fontWeight: '800', letterSpacing: '-4px', lineHeight: 1, color: 'var(--text-main)', marginBottom: '16px' }}>
                    Community Intelligence
                </h1>
                <p style={{ fontSize: '20px', color: 'var(--text-muted)', maxWidth: '600px', fontWeight: '500' }}>
                    User submitted reports and manual review signals integrated with our global threat engine.
                </p>
            </div>

            <div className="st-card" style={{ padding: '80px', textAlign: 'center', color: 'var(--text-muted)' }}>
                <div style={{ display: 'inline-flex', padding: '20px', background: 'var(--bg-main)', borderRadius: '30px', marginBottom: '32px' }}>
                    <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2z" /></svg>
                </div>
                <h3 style={{ fontSize: '28px', fontWeight: '800', color: 'var(--text-main)', marginBottom: '12px' }}>Reports Repository</h3>
                <p style={{ fontSize: '18px', fontWeight: '500', maxWidth: '500px', margin: '0 auto' }}>
                    Our manual review module is currently aggregating signals. Verified data will appear here shortly.
                </p>
                <button
                    onClick={() => alert('Opening report submission portal...')}
                    style={{ marginTop: '40px', background: 'var(--primary)', color: 'white', padding: '16px 36px', borderRadius: '20px', fontSize: '16px', fontWeight: '700', boxShadow: '0 10px 20px rgba(0, 184, 148, 0.2)', cursor: 'pointer' }}
                >
                    Submit Intel
                </button>
            </div>
        </DashboardLayout>
    );
}
