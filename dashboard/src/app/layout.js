import './globals.css';
import { AuthProvider } from '@/context/AuthContext';

export const metadata = {
  title: 'ShadowTrace Admin Dashboard',
  description: 'Enterprise Security Intelligence Panel',
};

export default function RootLayout({ children }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body>
        <AuthProvider>
          {children}
        </AuthProvider>
      </body>
    </html>
  );
}
