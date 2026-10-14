import { defineConfig } from 'vitest/config'

// The live suites share the deployment's agent and relayer accounts, so test files run one at a time.
export default defineConfig({ test: { fileParallelism: false } })
