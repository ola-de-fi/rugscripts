import type { Metadata } from "next";
import "./globals.css";
export const metadata: Metadata = {
  title: { absolute: "Rugscripts" },
  description:
    "Reverse-engineer Web3 websites and investigate suspicious scripts, wallet interactions, and hidden frontend security risks with RUGSCRIPTS.",
  metadataBase: new URL("https://rugscript.vercel.app"),
  icons: {
    icon: [
      { url: "/branding/icon.svg", type: "image/svg+xml" },
      { url: "/favicon.ico", sizes: "any" },
      { url: "/favicon.png", type: "image/png", sizes: "64x64" },
    ],
    apple: [{ url: "/branding/apple-touch-icon.png", sizes: "180x180" }],
  },
  openGraph: {
    title: "RUGSCRIPTS | Web3 Reverse Engineering & Security Intelligence",
    description:
      "Reverse-engineer Web3 websites and investigate suspicious scripts, wallet interactions, and hidden frontend security risks with RUGSCRIPTS.",
    siteName: "RUGSCRIPTS",
    type: "website",
    images: [
      {
        url: "/branding/banner.png",
        width: 1500,
        height: 500,
        alt: "RUGSCRIPTS — Expose the scripts.",
      },
    ],
  },
  twitter: {
    card: "summary_large_image",
    title: "RUGSCRIPTS | Web3 Reverse Engineering & Security Intelligence",
    description:
      "Reverse-engineer Web3 websites and investigate suspicious scripts, wallet interactions, and hidden frontend security risks with RUGSCRIPTS.",
    site: "@rugscripts",
    creator: "@rugscripts",
    images: ["/branding/banner.png"],
  },
};
export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
