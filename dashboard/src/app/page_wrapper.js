"use client";

import DashboardLayout from '@/components/DashboardLayout';

export default function App({ children }) {
    return children;
}

export function ProtectedPage({ children }) {
    return <DashboardLayout>{children}</DashboardLayout>;
}
