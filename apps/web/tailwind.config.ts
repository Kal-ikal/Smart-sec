import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./app/**/*.{ts,tsx}",
    "./components/**/*.{ts,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        risk: {
          critical: "#7f1d1d",
          high: "#dc2626",
          medium: "#d97706",
          low: "#65a30d",
          none: "#6b7280",
        },
      },
    },
  },
  plugins: [],
};

export default config;
