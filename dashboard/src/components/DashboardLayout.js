"use client";

import { useAuth } from '@/context/AuthContext';
import { useRouter, usePathname } from 'next/navigation';
import { useEffect } from 'react';
import Link from 'next/link';

export default function DashboardLayout({ children }) {
    const { user, loading, logout } = useAuth();
    const router = useRouter();
    const pathname = usePathname();

    useEffect(() => {
        if (!loading && !user && pathname !== '/login') {
            router.push('/login');
        }
    }, [user, loading, pathname, router]);

    if (loading || (!user && pathname !== '/login')) {
        return <div style={{ background: '#0a0a0c', height: '100vh' }} />;
    }

    if (pathname === '/login') return children;

    const NavItem = ({ href, label, icon }) => {
        const active = pathname === href;
        return (
            <Link href={href} style={{
                display: 'flex',
                alignItems: 'center',
                padding: '12px 20px',
                color: active ? 'var(--primary)' : 'var(--secondary)',
                background: active ? 'rgba(0, 212, 255, 0.1)' : 'transparent',
                borderRadius: '8px',
                marginBottom: '4px',
                fontWeight: active ? '600' : '400',
                transition: '0.2s'
            }}>
                <span style={{ marginRight: '12px' }}>{icon}</span>
                {label}
            </Link>
        );
    };

    return (
        <div style={{ display: 'flex', minHeight: '100vh' }}>
            {/* Sidebar */}
            <div className="glass" style={{
                width: 'var(--sidebar-width)',
                padding: '24px 16px',
                position: 'fixed',
                height: '100vh',
                zIndex: 100
            }}>
                <div style={{ padding: '0 12px 32px' }}>
                    <h2 style={{ color: 'var(--primary)', letterSpacing: '1px' }}>SHADOW TRACE</h2>
                    <p style={{ fontSize: '10px', color: 'var(--secondary)', fontWeight: 'bold' }}>v3.0.0 ENTERPRISE</p>
                </div>

                <nav>
                    <NavItem href="/" label="Overview" icon="📊" />
                    <NavItem href="/analytics" label="Analytics" icon="📈" />
                    <NavItem href="/domains" label="High Risk" icon="🛡️" />
                    <NavItem href="/anomalies" label="Anomalies" icon="⚠️" />
                    <NavItem href="/reports" label="User Reports" icon="📄" />
                </nav>

                <div style={{ position: 'absolute', bottom: '24px', left: '16px', right: '16px' }}>
                    <div className="glass" style={{ padding: '12px', borderRadius: '8px', marginBottom: '12px' }}>
                        <p style={{ fontSize: '12px', color: 'var(--secondary)' }}>Signed in as</p>
                        <p style={{ fontWeight: '600', fontSize: '14px' }}>{user?.username}</p>
                    </div>
                    <button onClick={logout} style={{
                        width: '100%',
                        padding: '10px',
                        background: 'transparent',
                        color: 'var(--accent-red)',
                        border: '1px solid #331a1a'
                    }}>
                        Log Out
                    </button>
                </div>
            </div>

            {/* Main Content */}
            <main style={{
                marginLeft: 'var(--sidebar-width)',
                flex: 1,
                padding: '32px'
            }}>
                {children}
            </main>
        </div>
    );
}
