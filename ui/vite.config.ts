import { defineConfig } from "vite";

// Tauri 가 dev 서버를 띄운다. 외부 자원 없음 (CSP: self).
export default defineConfig({
  clearScreen: false,
  server: { port: 5173, strictPort: true },
  build: { target: "es2022", sourcemap: false },
});
