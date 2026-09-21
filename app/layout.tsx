import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "TraceGuard — AI Security Investigation",
  description:
    "Evidence-first AI security investigation agent. Don't just find the misconfiguration — trace what it can lead to.",
  icons: {
    icon: "/favicon.ico",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className="antialiased">{children}</body>
    </html>
  );
}
