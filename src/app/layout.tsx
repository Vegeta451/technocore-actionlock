import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "ActionLock for Technocore",
  description: "Enforced MCP capability gateway for agents consuming untrusted Technocore messages.",
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
