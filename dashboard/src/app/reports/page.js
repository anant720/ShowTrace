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
                const data = await apiRequest('/report');
                setReports(data.reports || []);
            } catch (err) {
                console.error('Failed to fetch reports:', err);
            } finally {
                setLoading(false);
            }
        };
        fetchReports();
    }, []);

    const [domain, setDomain] = useState('');
    const [reason, setReason] = useState('');
    const [submitting, setSubmitting] = useState(false);
    const [success, setSuccess] = useState(false);

    const handleSubmit = async (e) => {
        e.preventDefault();
        setSubmitting(true);
        try {
            await apiRequest('/report', 'POST', { domain, reason });
            setSuccess(true);
            setDomain('');
            setReason('');
            setTimeout(() => setSuccess(false), 5000);
        } catch (err) {
            alert('Failed to submit report: ' + err.message);
        } finally {
            setSubmitting(false);
        }
    };

    return (
        <DashboardLayout>
            <div style={{ padding: '20px 0 60px 0' }}>
                <h1 style={{ fontSize: 'var(--hero-font-size)', fontWeight: '800', letterSpacing: '-4px', lineHeight: 1, color: 'var(--text-main)', marginBottom: '16px', transition: 'font-size 0.3s ease' }}>
                    Community Intelligence
                </h1>
                <p style={{ fontSize: 'clamp(16px, 2vw, 20px)', color: 'var(--text-muted)', maxWidth: '600px', fontWeight: '500' }}>
                    User submitted reports and manual review signals integrated with our global threat engine.
                </p>
            </div>

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 'var(--grid-gap)', alignItems: 'start' }}>
                <div className="st-card" style={{ padding: '48px' }}>
                    <h3 style={{ fontSize: '28px', fontWeight: '800', color: 'var(--text-main)', marginBottom: '32px', letterSpacing: '-0.5px' }}>Submit Intel</h3>

                    <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '24px' }}>
                        <div style={{ textAlign: 'left' }}>
                            <label style={{ fontSize: '12px', fontWeight: '800', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '1px', marginLeft: '12px' }}>Suspect Domain</label>
                            <input
                                placeholder="example-phish.com"
                                value={domain}
                                onChange={e => setDomain(e.target.value)}
                                required
                                style={{
                                    width: '100%',
                                    background: 'var(--bg-main)',
                                    border: '1px solid rgba(0,0,0,0.05)',
                                    color: 'var(--text-main)',
                                    padding: '18px 24px',
                                    borderRadius: '20px',
                                    fontSize: '16px',
                                    marginTop: '8px',
                                    fontWeight: '600'
                                }}
                            />
                        </div>

                        <div style={{ textAlign: 'left' }}>
                            <label style={{ fontSize: '12px', fontWeight: '800', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '1px', marginLeft: '12px' }}>Detection Reasoning</label>
                            <textarea
                                placeholder="Describe the suspicious behavior observed..."
                                value={reason}
                                onChange={e => setReason(e.target.value)}
                                required
                                style={{
                                    width: '100%',
                                    background: 'var(--bg-main)',
                                    border: '1px solid rgba(0,0,0,0.05)',
                                    color: 'var(--text-main)',
                                    padding: '18px 24px',
                                    borderRadius: '20px',
                                    fontSize: '16px',
                                    marginTop: '8px',
                                    fontWeight: '600',
                                    minHeight: '120px',
                                    resize: 'none',
                                    fontFamily: 'inherit'
                                }}
                            />
                        </div>

                        <button
                            type="submit"
                            disabled={submitting}
                            style={{
                                padding: '18px',
                                background: success ? 'var(--success)' : 'var(--primary)',
                                color: 'white',
                                marginTop: '16px',
                                borderRadius: '20px',
                                fontWeight: '800',
                                fontSize: '16px',
                                transition: 'all 0.3s ease',
                                border: 'none',
                                boxShadow: success ? '0 10px 20px rgba(52, 199, 89, 0.2)' : '0 10px 20px rgba(0, 184, 148, 0.2)',
                                cursor: 'pointer'
                            }}
                        >
                            {submitting ? 'Authenticating Signal...' : (success ? 'Signal Successfully Logged' : 'Broadcast Intel')}
                        </button>
                    </form>
                </div>

                <div className="st-card" style={{ padding: '48px', background: 'var(--bg-main)', border: 'none' }}>
                    <div style={{ display: 'inline-flex', padding: '20px', background: 'white', borderRadius: '30px', marginBottom: '32px', boxShadow: 'var(--shadow-sm)' }}>
                        <svg width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><path d="M21 15a2 2 0 01-2 2H7l-4 4V5a2 2 0 012-2h14a2 2 0 012 2z" /></svg>
                    </div>
                    <h3 style={{ fontSize: '28px', fontWeight: '800', color: 'var(--text-main)', marginBottom: '12px' }}>Community Shield</h3>
                    <p style={{ fontSize: '16px', fontWeight: '500', color: 'var(--text-muted)', lineHeight: '1.6' }}>
                        Your manual reports directly feed our global neural threat engine. Domains with multiple reports are automatically promoted to high-criticality protection status for all users in the ShadowTrace network.
                    </p>
                    <div style={{ marginTop: '32px', padding: '24px', background: 'rgba(52, 199, 89, 0.1)', borderRadius: '20px', color: 'var(--success)', border: '1px solid rgba(52, 199, 89, 0.2)' }}>
                        <div style={{ display: 'flex', gap: '12px', alignItems: 'center' }}>
                            <div style={{ width: '8px', height: '8px', background: 'var(--success)', borderRadius: '50%' }} />
                            <span style={{ fontWeight: '800', fontSize: '13px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Live Integrity Tracking</span>
                        </div>
                    </div>
                </div>
            </div>
        </DashboardLayout>
    );
}
