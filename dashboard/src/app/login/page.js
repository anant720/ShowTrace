"use client";

import { useState } from 'react';
import { useAuth } from '@/context/AuthContext';
import { apiRequest } from '@/utils/api';

export default function LoginPage() {
    const [username, setUsername] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');
    const [loading, setLoading] = useState(false);
    const { login } = useAuth();

    const handleSubmit = async (e) => {
        e.preventDefault();
        setError('');
        setLoading(true);

        try {
            const data = await apiRequest('/auth/login', 'POST', { username, password });
            login(data.access_token, data.role, data.username);
        } catch (err) {
            setError(err.message);
        } finally {
            setLoading(false);
        }
    };

    return (
        <div style={{
            height: '100vh',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            background: '#0A0A0B',
            color: 'white'
        }}>
            <div style={{
                padding: '48px',
                borderRadius: '24px',
                width: '100%',
                maxWidth: '420px',
                textAlign: 'center',
                background: 'rgba(255, 255, 255, 0.02)',
                border: '1px solid rgba(255, 255, 255, 0.05)',
                backdropFilter: 'blur(20px)',
                boxShadow: '0 20px 50px rgba(0,0,0,0.5)'
            }}>
                <img
                    src="/dashboard_logo.png"
                    alt="ShadowTrace Logo"
                    style={{ width: '80px', height: '80px', marginBottom: '24px' }}
                />
                <h1 style={{ fontSize: '32px', marginBottom: '8px', fontWeight: '700', letterSpacing: '-0.5px' }}>ShadowTrace</h1>
                <p style={{ color: 'rgba(255,255,255,0.5)', marginBottom: '32px', fontSize: '14px' }}>Secure Enterprise Gateway</p>

                <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '20px' }}>
                    <input
                        type="text"
                        placeholder="Identity Identifier"
                        value={username}
                        onChange={(e) => setUsername(e.target.value)}
                        required
                        style={{
                            background: 'rgba(255,255,255,0.05)',
                            border: '1px solid rgba(255,255,255,0.1)',
                            color: 'white',
                            padding: '16px',
                            borderRadius: '12px',
                            fontSize: '15px'
                        }}
                    />
                    <input
                        type="password"
                        placeholder="Security Key"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        required
                        style={{
                            background: 'rgba(255,255,255,0.05)',
                            border: '1px solid rgba(255,255,255,0.1)',
                            color: 'white',
                            padding: '16px',
                            borderRadius: '12px',
                            fontSize: '15px'
                        }}
                    />

                    {error && <p style={{ color: '#FF453A', fontSize: '13px', textAlign: 'left' }}>{error}</p>}

                    <button
                        type="submit"
                        disabled={loading}
                        style={{
                            padding: '16px',
                            background: 'white',
                            color: 'black',
                            marginTop: '12px',
                            borderRadius: '12px',
                            fontWeight: '700',
                            fontSize: '15px',
                            transition: 'all 0.3s'
                        }}
                        onMouseOver={(e) => e.target.style.opacity = '0.9'}
                        onMouseOut={(e) => e.target.style.opacity = '1'}
                    >
                        {loading ? 'Processing...' : 'Access Intelligence'}
                    </button>
                </form>
            </div>
        </div>
    );
}
