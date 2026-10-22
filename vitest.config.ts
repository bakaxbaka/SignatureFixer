import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    globals: true,
    include: ["server/**/*.test.ts", "tests/keys/**/*.test.ts"],
    environment: "node",
  },
});
