import { defineConfig } from "vite";
import scalaJSPlugin from "@scala-js/vite-plugin-scalajs";
import tailwindcss from "@tailwindcss/vite";
import rollupPluginSourcemaps from "rollup-plugin-sourcemaps";

export default defineConfig({
  plugins: [
    scalaJSPlugin({
      cwd: '..',
      projectID: 'admin'
    }),
    tailwindcss(),
  ],
  server: {
    watch: { usePolling: true },
    proxy: {
      '/api': {
        target: 'http://localhost:9100',
        changeOrigin: true,
      }
    }
  },
  build: {
    rollupOptions: {
      plugins: [rollupPluginSourcemaps()],
    },
    minify: "esbuild",
    sourcemap: true
  }
});
