import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    include: ["server/**/*.test.ts"],
    environment: "node",
  },
});
