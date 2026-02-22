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
        return <div style={{ background: 'var(--bg-main)', height: '100vh' }} />;
    }

    if (pathname === '/login') return children;

    const SideMenuItem = ({ href, svg, label }) => {
        const active = pathname === href;
        return (
            <Link href={href} style={{
                width: '60px',
                height: '60px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                borderRadius: '20px',
                background: active ? 'var(--bg-hover)' : 'transparent',
                color: active ? 'var(--primary)' : 'var(--text-muted)',
                marginBottom: '16px',
                transition: '0.3s cubic-bezier(0.4, 0, 0.2, 1)',
                border: active ? '1px solid rgba(0,0,0,0.05)' : '1px solid transparent'
            }} title={label}>
                {svg}
            </Link>
        );
    };

    const TabButton = ({ href, label }) => {
        const active = pathname === href;
        return (
            <Link href={href} style={{
                padding: '10px 24px',
                borderRadius: 'var(--radius-pill)',
                background: active ? 'white' : 'transparent',
                color: active ? 'var(--text-main)' : 'var(--text-muted)',
                fontSize: '14px',
                fontWeight: '600',
                transition: '0.2s',
                textDecoration: 'none',
                boxShadow: active ? 'var(--shadow-sm)' : 'none'
            }}>
                {label}
            </Link>
        );
    };

    return (
        <div style={{ display: 'flex', background: 'var(--bg-main)', minHeight: '100vh', padding: '24px' }}>
            {/* Minimal Side Menu */}
            <aside style={{
                width: 'var(--sidebar-width)',
                background: 'var(--bg-sidebar)',
                borderRadius: '30px',
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                padding: '32px 0',
                position: 'fixed',
                height: 'calc(100vh - 48px)',
                zIndex: 100,
                boxShadow: 'var(--shadow-md)'
            }}>
                <div style={{ marginBottom: '48px' }}>
                    <img src="/dashboard_logo.png" alt="Logo" style={{ width: '80px', height: '80px' }} />
                </div>
                <nav style={{ display: 'flex', flexDirection: 'column', flex: 1 }}>
                    <SideMenuItem href="/" svg={
                        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M3 9l9-7 9 7v11a2 2 0 01-2 2H5a2 2 0 01-2-2z" /><path d="M9 22V12h6v10" /></svg>
                    } label="Overview" />
                    <SideMenuItem href="/analytics" svg={
                        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M18 20V10M12 20V4M6 20v-6" /></svg>
                    } label="Analytics" />
                    <SideMenuItem href="/domains" svg={
                        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2" /><path d="M7 11V7a5 5 0 0110 0v4" /></svg>
                    } label="Domains" />
                    <SideMenuItem href="/audit" svg={
                        <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" /><path d="M12 8v4" /><path d="M12 16h.01" /></svg>
                    } label="Audit Log" />
                </nav>
                <button onClick={logout} style={{
                    width: '48px',
                    height: '48px',
                    borderRadius: '16px',
                    background: 'var(--bg-hover)',
                    color: 'var(--danger)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center'
                }} title="Logout">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4M16 17l5-5-5-5M21 12H9" /></svg>
                </button>
            </aside>

            {/* Main Wrapper */}
            <div style={{ marginLeft: 'calc(var(--sidebar-width) + 24px)', flex: 1, display: 'flex', flexDirection: 'column' }}>
                {/* Top Bar */}
                <header style={{
                    height: '80px',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    padding: '0 40px',
                    background: 'transparent',
                    marginBottom: '24px'
                }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
                        <h1 style={{ fontWeight: 800, fontSize: '32px', letterSpacing: '-1.5px', color: 'var(--text-main)' }}>ShadowTrace</h1>
                    </div>

                    <div style={{
                        background: '#D1D1D1',
                        padding: '6px',
                        borderRadius: 'var(--radius-pill)',
                        display: 'flex',
                        gap: '4px'
                    }}>
                        <TabButton href="/" label="Overview" />
                        <TabButton href="/analytics" label="Security" />
                        <TabButton href="/audit" label="Forensics" />
                        <TabButton href="/reports" label="Signals" />
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
                        <div style={{
                            display: 'flex',
                            alignItems: 'center',
                            gap: '10px',
                            background: 'white',
                            padding: '10px 20px',
                            borderRadius: '20px',
                            boxShadow: 'var(--shadow-sm)'
                        }}>
                            <div style={{ width: '10px', height: '10px', background: 'var(--success)', borderRadius: '50%' }} />
                            <span style={{ fontSize: '14px', fontWeight: '700' }}>Active Analysis</span>
                        </div>
                        <div style={{
                            width: '44px',
                            height: '44px',
                            borderRadius: '16px',
                            background: 'white',
                            color: 'var(--text-main)',
                            display: 'flex',
                            alignItems: 'center',
                            justifyContent: 'center',
                            fontWeight: 'bold',
                            boxShadow: 'var(--shadow-sm)',
                            border: '1px solid rgba(0,0,0,0.05)'
                        }}>
                            {user?.username?.[0].toUpperCase()}
                        </div>
                    </div>
                </header>

                <div style={{ display: 'flex', flex: 1 }}>
                    <main style={{ flex: 1, padding: '0 40px 40px 40px' }}>
                        {children}
                    </main>
                </div>
            </div>
        </div>
    );
}
