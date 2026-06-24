module.exports = {
  projects: [
    {
      displayName: 'core',
      preset: 'ts-jest',
      testEnvironment: 'node',
      testMatch: [
        '<rootDir>/src/core/**/__tests__/**/*.{ts,tsx}',
        '<rootDir>/src/core/**/*.{spec,test}.{ts,tsx}',
      ],
      moduleFileExtensions: ['ts', 'tsx', 'js', 'jsx', 'json', 'node'],
      collectCoverageFrom: [
        'src/core/**/*.{ts,tsx}',
        '!src/core/**/__tests__/**',
        '!src/core/**/*.d.ts',
        '!src/core/**/index.ts',
      ],
    },
    {
      displayName: 'react',
      preset: 'ts-jest',
      testEnvironment: 'jsdom',
      setupFilesAfterEnv: ['<rootDir>/src/adapters/react/__tests__/jest.setup.ts'],
      testMatch: [
        '<rootDir>/src/adapters/react/__tests__/**/*.{ts,tsx}',
        '<rootDir>/src/adapters/react/**/*.{spec,test}.{ts,tsx}',
      ],
      testPathIgnorePatterns: ['<rootDir>/src/adapters/react/__tests__/jest.setup.ts'],
      moduleFileExtensions: ['ts', 'tsx', 'js', 'jsx', 'json', 'node'],
      globals: {
        'ts-jest': {
          tsconfig: {
            jsx: 'react-jsx',
            esModuleInterop: true,
            strict: true,
            lib: ['ES2020', 'DOM', 'DOM.Iterable'],
          },
          diagnostics: false,
        },
      },
      collectCoverageFrom: [
        'src/adapters/react/**/*.{ts,tsx}',
        '!src/adapters/react/__tests__/**',
        '!src/adapters/react/**/*.d.ts',
        '!src/adapters/react/**/index.ts',
      ],
    },
  ],
  coverageThreshold: {
    global: {
      branches: 55,
      functions: 65,
      lines: 65,
      statements: 65,
    },
  },
};
