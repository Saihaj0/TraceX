export default {
  testEnvironment: 'node',
  transform: {
    '^.+\\.tsx?$': ['ts-jest', { tsconfig: { module: 'commonjs', target: 'es2020' } }],
  },
  testMatch: ['<rootDir>/src/**/*.{test,spec}.{ts,tsx}'],
};
