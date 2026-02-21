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
            background: 'radial-gradient(circle at center, #1a1a2e 0%, #0a0a0c 100%)'
        }}>
            <div className="glass" style={{
                padding: '40px',
                borderRadius: '16px',
                width: '100%',
                maxWidth: '400px',
                textAlign: 'center'
            }}>
                <h1 style={{ marginBottom: '8px', color: 'var(--primary)' }}>ShadowTrace</h1>
                <p style={{ color: 'var(--secondary)', marginBottom: '32px' }}>Enterprise Admin Access</p>

                <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
                    <input
                        type="text"
                        placeholder="Username"
                        value={username}
                        onChange={(e) => setUsername(e.target.value)}
                        required
                    />
                    <input
                        type="password"
                        placeholder="Password"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        required
                    />

                    {error && <p style={{ color: 'var(--accent-red)', fontSize: '14px' }}>{error}</p>}

                    <button
                        type="submit"
                        disabled={loading}
                        style={{
                            padding: '14px',
                            background: 'var(--primary)',
                            color: 'black',
                            marginTop: '16px'
                        }}
                    >
                        {loading ? 'Authenticating...' : 'Secure Login'}
                    </button>
                </form>
            </div>
        </div>
    );
}
