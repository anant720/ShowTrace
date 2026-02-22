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

    const url = `${API_BASE}${endpoint}`;
    console.log(`[API Request] ${method} ${url}`);

    try {
        const response = await fetch(url, options);

        if (response.status === 401) {
            if (typeof window !== 'undefined') {
                localStorage.removeItem('st_token');
                window.location.href = '/login';
            }
            throw new Error('Unauthorized');
        }

        if (!response.ok) {
            const error = await response.json().catch(() => ({}));
            throw new Error(error.detail || `API Error: ${response.status}`);
        }

        return response.json();
    } catch (err) {
        console.error(`[API Fetch Error] ${url}:`, err);
        if (err.message === 'Failed to fetch' || err.name === 'TypeError') {
            throw new Error('Network error: Could not connect to backend. Please check CORS settings or if the backend is live.');
        }
        throw err;
    }
};
