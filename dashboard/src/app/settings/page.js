"use client";

import { useState, useEffect } from 'react';
import { apiRequest } from '@/utils/api';
import { useAuth } from '@/context/AuthContext';

const ROLE_COLORS = {
    admin: { bg: 'rgba(255,59,48,0.1)', color: '#FF3B30' },
    analyst: { bg: 'rgba(0,184,148,0.1)', color: '#00B894' },
    member: { bg: 'rgba(0,122,255,0.1)', color: '#007AFF' },
};

export default function SettingsPage() {
    const { user } = useAuth();
    const [members, setMembers] = useState([]);
    const [invitations, setInvitations] = useState([]);
    const [email, setEmail] = useState('');
    const [role, setRole] = useState('member');
    const [loading, setLoading] = useState(false);
    const [message, setMessage] = useState('');
    const [error, setError] = useState('');
    const [activeTab, setActiveTab] = useState('members');
    const [generatedKey, setGeneratedKey] = useState('');

    const fetchMembers = async () => {
        try {
            const data = await apiRequest('/organizations/members');
            setMembers(data);
        } catch (err) { console.error(err); }
    };

    const fetchInvitations = async () => {
        try {
            const data = await apiRequest('/organizations/invitations');
            setInvitations(data);
        } catch (err) { console.error(err); }
    };

    useEffect(() => {
        if (user?.org_id) {
            fetchMembers();
            fetchInvitations();
            // Auto-refresh every 30 seconds
            const interval = setInterval(() => {
                fetchMembers();
                fetchInvitations();
            }, 30000);
            return () => clearInterval(interval);
        }
    }, [user?.org_id]);

    const handleInvite = async (e) => {
        e.preventDefault();
        setLoading(true);
        setMessage('');
        setError('');
        setGeneratedKey('');
        try {
            const resp = await apiRequest('/organizations/invite', 'POST', { email, role });
            setMessage(`Invitation created for ${email}`);
            if (resp.member_key) setGeneratedKey(resp.member_key);
            setEmail('');
            fetchMembers();
            fetchInvitations();
        } catch (err) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    const isAdmin = user?.role === 'admin';

    return (
        <div style={{ minHeight: '100vh', padding: '48px var(--padding-page)', background: 'var(--bg-main)' }}>

            {/* ── Page Header ─────────────────────────────────────── */}
            <div style={{ marginBottom: '48px' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '16px', marginBottom: '8px' }}>
                    <div style={{
                        width: '48px', height: '48px', borderRadius: '16px',
                        background: 'linear-gradient(135deg, #00B894, #00CEC9)',
                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                        fontSize: '22px', boxShadow: '0 8px 24px rgba(0,184,148,0.3)'
                    }}>⚙️</div>
                    <div>
                        <h1 style={{ fontFamily: 'Outfit, sans-serif', fontSize: '36px', fontWeight: '800', letterSpacing: '-1.5px', lineHeight: 1 }}>
                            Organization Settings
                        </h1>
                        <p style={{ color: 'var(--text-muted)', fontSize: '15px', marginTop: '4px' }}>
                            Manage your team, roles, and security collaboration context
                        </p>
                    </div>
                </div>
            </div>

            {/* ── Stats Row ─────────────────────────────────────────── */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '20px', marginBottom: '36px' }}>
                {[
                    { label: 'Active Members', value: members.length, icon: '👥', color: '#007AFF' },
                    { label: 'Pending Invites', value: invitations.length, icon: '📨', color: '#FF9F0A' },
                    { label: 'Your Role', value: user?.role?.toUpperCase() || '—', icon: '🔑', color: '#00B894' },
                ].map((stat) => (
                    <div key={stat.label} className="st-card" style={{ padding: '28px 32px', display: 'flex', alignItems: 'center', gap: '20px' }}>
                        <div style={{
                            width: '52px', height: '52px', borderRadius: '16px', flexShrink: 0,
                            background: `${stat.color}18`,
                            display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '22px'
                        }}>{stat.icon}</div>
                        <div>
                            <p style={{ fontSize: '11px', fontWeight: '700', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>{stat.label}</p>
                            <p style={{ fontSize: '28px', fontWeight: '800', fontFamily: 'Outfit, sans-serif', color: stat.color, lineHeight: 1.1 }}>{stat.value}</p>
                        </div>
                    </div>
                ))}
            </div>

            {/* ── Main Grid ─────────────────────────────────────────── */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 380px', gap: '24px', alignItems: 'start' }}>

                {/* Left Column — Members / Invitations */}
                <div className="st-card" style={{ padding: '0', overflow: 'hidden' }}>
                    {/* Tab Bar */}
                    <div style={{ display: 'flex', borderBottom: '1px solid var(--bg-main)', padding: '0 32px' }}>
                        {['members', 'invitations'].map(tab => (
                            <button key={tab} onClick={() => setActiveTab(tab)} style={{
                                background: 'none', border: 'none', padding: '20px 0', marginRight: '32px',
                                fontSize: '14px', fontWeight: '700',
                                color: activeTab === tab ? 'var(--text-main)' : 'var(--text-muted)',
                                borderBottom: activeTab === tab ? '2px solid var(--primary)' : '2px solid transparent',
                                borderRadius: 0, cursor: 'pointer', textTransform: 'capitalize',
                                transition: 'all 0.2s', letterSpacing: '0.02em'
                            }}>
                                {tab === 'members' ? `Members (${members.length})` : `Invitations (${invitations.length})`}
                            </button>
                        ))}
                    </div>

                    <div style={{ padding: '28px 32px', display: 'flex', flexDirection: 'column', gap: '12px' }}>
                        {activeTab === 'members' && (
                            members.length === 0
                                ? <EmptyState icon="👥" text="No members found" />
                                : members.map(member => {
                                    const roleStyle = ROLE_COLORS[member.role] || ROLE_COLORS.member;
                                    const initial = (member.email || '?')[0].toUpperCase();
                                    return (
                                        <div key={member.user_id} style={{
                                            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                                            padding: '16px 20px', background: 'var(--bg-main)', borderRadius: '18px',
                                            transition: 'transform 0.2s'
                                        }}>
                                            <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
                                                <div style={{
                                                    width: '44px', height: '44px', borderRadius: '14px',
                                                    background: `linear-gradient(135deg, ${roleStyle.color}33, ${roleStyle.color}55)`,
                                                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                                                    fontWeight: '800', fontSize: '16px', color: roleStyle.color
                                                }}>{initial}</div>
                                                <div>
                                                    <p style={{ fontWeight: '700', fontSize: '14px' }}>{member.email}</p>
                                                    <p style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                                                        Joined {new Date(member.joined_at).toLocaleDateString('en-US', { day: 'numeric', month: 'short', year: 'numeric' })}
                                                    </p>
                                                </div>
                                            </div>
                                            <span style={{
                                                padding: '5px 14px', borderRadius: '10px', fontSize: '11px',
                                                fontWeight: '800', textTransform: 'uppercase', letterSpacing: '0.06em',
                                                background: roleStyle.bg, color: roleStyle.color
                                            }}>{member.role}</span>
                                        </div>
                                    );
                                })
                        )}

                        {activeTab === 'invitations' && (
                            invitations.length === 0
                                ? <EmptyState icon="📨" text="No pending invitations" />
                                : invitations.map((inv, idx) => (
                                    <div key={idx} style={{
                                        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                                        padding: '16px 20px', background: 'var(--bg-main)', borderRadius: '18px'
                                    }}>
                                        <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
                                            <div style={{
                                                width: '44px', height: '44px', borderRadius: '14px',
                                                background: 'rgba(255,159,10,0.1)',
                                                display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '20px'
                                            }}>📨</div>
                                            <div>
                                                <p style={{ fontWeight: '700', fontSize: '14px' }}>{inv.email}</p>
                                                <p style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
                                                    Expires {new Date(inv.expires_at).toLocaleDateString('en-US', { day: 'numeric', month: 'short' })}
                                                </p>
                                            </div>
                                        </div>
                                        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: '4px' }}>
                                            <span style={{
                                                padding: '5px 14px', borderRadius: '10px', fontSize: '11px', fontWeight: '800',
                                                textTransform: 'uppercase', letterSpacing: '0.06em',
                                                background: ['SENT', 'MANUAL'].includes(inv.email_status) ? 'rgba(0,184,148,0.1)' : 'rgba(255,59,48,0.1)',
                                                color: ['SENT', 'MANUAL'].includes(inv.email_status) ? '#00B894' : '#FF3B30'
                                            }}>{inv.email_status}</span>
                                            <span style={{ fontSize: '11px', color: 'var(--text-muted)', textTransform: 'capitalize' }}>{inv.role}</span>
                                        </div>
                                    </div>
                                ))
                        )}
                    </div>
                </div>

                {/* Right Column — Invite Panel */}
                <div className="st-card" style={{ padding: '32px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '28px' }}>
                        <div style={{
                            width: '40px', height: '40px', borderRadius: '12px',
                            background: 'linear-gradient(135deg, #007AFF22, #007AFF44)',
                            display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: '18px'
                        }}>✉️</div>
                        <div>
                            <h2 style={{ fontFamily: 'Outfit, sans-serif', fontSize: '18px', fontWeight: '800' }}>Invite Team Member</h2>
                            <p style={{ fontSize: '12px', color: 'var(--text-muted)' }}>Generate an org key for a new analyst</p>
                        </div>
                    </div>

                    <form onSubmit={handleInvite} style={{ display: 'flex', flexDirection: 'column', gap: '18px' }}>
                        <Field label="Email Address">
                            <input
                                type="email" value={email}
                                onChange={e => setEmail(e.target.value)}
                                placeholder="analyst@corp.com"
                                required disabled={!isAdmin}
                                style={{ width: '100%', fontSize: '14px', marginTop: '8px', color: 'var(--text-main)' }}
                            />
                        </Field>

                        <Field label="Access Role">
                            <select
                                value={role} onChange={e => setRole(e.target.value)}
                                disabled={!isAdmin}
                                style={{
                                    width: '100%', marginTop: '8px', padding: '14px 20px',
                                    background: 'var(--bg-hover)', border: '1px solid transparent',
                                    borderRadius: '20px', fontSize: '14px', fontFamily: 'Inter, sans-serif',
                                    fontWeight: '600', outline: 'none', cursor: isAdmin ? 'pointer' : 'not-allowed',
                                    color: 'var(--text-main)'
                                }}
                            >
                                <option value="member">Analyst (Member)</option>
                                <option value="admin">Administrator</option>
                            </select>
                        </Field>

                        {message && (
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                                <div style={{ padding: '12px 16px', borderRadius: '14px', background: 'rgba(0,184,148,0.1)', display: 'flex', alignItems: 'center', gap: '8px' }}>
                                    <span>✅</span>
                                    <p style={{ color: '#00B894', fontSize: '13px', fontWeight: '700' }}>{message}</p>
                                </div>
                                {generatedKey && (
                                    <div style={{ padding: '12px 16px', borderRadius: '14px', background: 'var(--bg-main)', border: '1px dashed rgba(0,184,148,0.4)' }}>
                                        <p style={{ fontSize: '11px', fontWeight: '800', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '6px' }}>
                                            🔑 Member Key — Share this manually
                                        </p>
                                        <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
                                            <code style={{ flex: 1, fontSize: '11px', fontFamily: 'monospace', color: '#00B894', wordBreak: 'break-all', lineHeight: 1.5 }}>
                                                {generatedKey}
                                            </code>
                                            <button
                                                type="button"
                                                onClick={() => navigator.clipboard.writeText(generatedKey)}
                                                style={{ padding: '6px 12px', borderRadius: '8px', background: 'rgba(0,184,148,0.15)', color: '#00B894', fontSize: '11px', fontWeight: '700', flexShrink: 0 }}
                                            >Copy</button>
                                        </div>
                                    </div>
                                )}
                            </div>
                        )}
                        {error && (
                            <div style={{ padding: '12px 16px', borderRadius: '14px', background: 'rgba(255,59,48,0.08)', display: 'flex', alignItems: 'center', gap: '8px' }}>
                                <span>⚠️</span>
                                <p style={{ color: '#FF3B30', fontSize: '13px', fontWeight: '700' }}>{error}</p>
                            </div>
                        )}

                        <button
                            type="submit"
                            disabled={loading || !isAdmin}
                            style={{
                                width: '100%', padding: '15px',
                                background: isAdmin ? 'linear-gradient(135deg, #00B894, #00CEC9)' : 'var(--bg-hover)',
                                color: isAdmin ? 'white' : 'var(--text-muted)',
                                borderRadius: '18px', fontWeight: '800', fontSize: '15px',
                                cursor: (!isAdmin || loading) ? 'not-allowed' : 'pointer',
                                opacity: loading ? 0.7 : 1,
                                boxShadow: isAdmin ? '0 8px 20px rgba(0,184,148,0.3)' : 'none',
                                transition: 'all 0.25s'
                            }}
                        >
                            {loading ? 'Sending…' : '🚀 Issue Invitation'}
                        </button>

                        {!isAdmin && (
                            <p style={{ fontSize: '12px', color: 'var(--text-muted)', textAlign: 'center' }}>
                                Only administrators can issue invitations.
                            </p>
                        )}
                    </form>

                    {/* Divider */}
                    <div style={{ height: '1px', background: 'var(--bg-main)', margin: '24px 0' }} />

                    <div style={{ padding: '16px', background: 'var(--bg-main)', borderRadius: '16px' }}>
                        <p style={{ fontSize: '11px', fontWeight: '800', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em', marginBottom: '8px' }}>How it works</p>
                        <ol style={{ paddingLeft: '18px', display: 'flex', flexDirection: 'column', gap: '6px' }}>
                            {['Invite a member by email', 'They receive an org key via email', 'They paste it in the ShadowTrace extension', 'All their scans are attributed to your org'].map((step, i) => (
                                <li key={i} style={{ fontSize: '12px', color: 'var(--text-muted)', fontWeight: '600' }}>{step}</li>
                            ))}
                        </ol>
                    </div>
                </div>
            </div>
        </div>
    );
}

function Field({ label, children }) {
    return (
        <div>
            <label style={{ fontSize: '11px', fontWeight: '800', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.08em' }}>
                {label}
            </label>
            {children}
        </div>
    );
}

function EmptyState({ icon, text }) {
    return (
        <div style={{ padding: '48px 0', textAlign: 'center' }}>
            <div style={{ fontSize: '40px', marginBottom: '12px' }}>{icon}</div>
            <p style={{ color: 'var(--text-muted)', fontWeight: '600', fontSize: '14px' }}>{text}</p>
        </div>
    );
}
