import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";
import Header from "@/components/Header";
import { Toaster } from "react-hot-toast";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "ScanZero | Scan Smarter. Compare Better. Understand Every Score.",
  description:
    "ScanZero analyzes websites across multiple dimensions, explains every score, compares competing websites, and turns complex results into an easy-to-understand report.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="scroll-smooth">
      <body className={`${inter.className} bg-gray-50 text-gray-900 min-h-screen flex flex-col selection:bg-teal-500 selection:text-white`}>
        <Header />
        <main className="flex-1 flex flex-col">
          {children}
        </main>
        <Toaster position="bottom-right" />
      </body>
    </html>
  );
}
