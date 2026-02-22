const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:8000';

export const apiRequest = async (endpoint, method = 'GET', body = null) => {
    const token = typeof window !== 'undefined' ? localStorage.getItem('st_token') : null;

    const headers = {
        'Content-Type': 'application/json',
    };

    if (token) {
        headers['Authorization'] = `Bearer ${token}`;
    }

    const options = {
        method,
        headers,
    };

    if (body) {
        options.body = JSON.stringify(body);
    }

    const response = await fetch(`${API_BASE}${endpoint}`, options);

    if (response.status === 401) {
        if (typeof window !== 'undefined') {
            localStorage.removeItem('st_token');
            window.location.href = '/login';
        }
        throw new Error('Unauthorized');
    }

    if (!response.ok) {
        const error = await response.json();
        throw new Error(error.detail || 'API Request failed');
    }

    return response.json();
};
