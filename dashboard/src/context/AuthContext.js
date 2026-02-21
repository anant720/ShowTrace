"use client";

import { createContext, useContext, useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';

const AuthContext = createContext();

export const AuthProvider = ({ children }) => {
    const [user, setUser] = useState(null);
    const [loading, setLoading] = useState(true);
    const router = useRouter();

    useEffect(() => {
        const token = localStorage.getItem('st_token');
        const role = localStorage.getItem('st_role');
        const username = localStorage.getItem('st_user');

        if (token && role && username) {
            setUser({ token, role, username });
        }
        setLoading(false);
    }, []);

    const login = (token, role, username) => {
        localStorage.setItem('st_token', token);
        localStorage.setItem('st_role', role);
        localStorage.setItem('st_user', username);
        setUser({ token, role, username });
        router.push('/');
    };

    const logout = () => {
        localStorage.removeItem('st_token');
        localStorage.removeItem('st_role');
        localStorage.removeItem('st_user');
        setUser(null);
        router.push('/login');
    };

    return (
        <AuthContext.Provider value={{ user, loading, login, logout }}>
            {children}
        </AuthContext.Provider>
    );
};

export const useAuth = () => useContext(AuthContext);
