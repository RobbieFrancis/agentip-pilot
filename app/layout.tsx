import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "Reciprocal Agent Trust — experimental AgentIP pilot",
  description: "Register an agent key, prove possession, recover or revoke it, and complete a mutual handshake. Open experimental pilot; no real-world identity verification.",
  icons: {
    icon: "/favicon.svg",
    shortcut: "/favicon.svg",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className="antialiased">{children}</body>
    </html>
  );
}
