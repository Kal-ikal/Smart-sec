import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "SMART-SEC",
  description:
    "Sistem Evaluasi Keamanan Berbasis Risk Scoring CVSS v4.0 untuk Identifikasi Kerentanan Aplikasi Web secara Massal",
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="id">
      <body className="bg-neutral-950 text-neutral-100 antialiased">
        {children}
      </body>
    </html>
  );
}
