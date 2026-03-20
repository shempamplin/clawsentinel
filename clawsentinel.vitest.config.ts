import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: [
      'tests/**/*.test.ts',
      'src/security/**/*.test.ts',
    ],
    exclude: [
      'src/security/audit.test.ts',
      'src/security/dm-policy-channel-smoke.test.ts',
      '**/node_modules/**',
    ],
    coverage: {
      provider: 'v8',
      include: ['src/security/**'],
      thresholds: { branches: 80 },
    },
  },
});
