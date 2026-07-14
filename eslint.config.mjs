// Lint sobre : les recommandations typescript-eslint, rien « pour faire pro ».
// Les vraies gardes du dépôt sont les 3 gardes grep de la CI et les invariants
// Postgres — le lint attrape le reste (variables mortes, promesses ignorées).
import tseslint from 'typescript-eslint';

export default tseslint.config(
  { ignores: ['dist/', 'node_modules/', 'jest.config.js'] },
  ...tseslint.configs.recommended,
  {
    files: ['**/*.ts'],
    languageOptions: {
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      '@typescript-eslint/no-floating-promises': 'error',
      '@typescript-eslint/no-misused-promises': 'error',
    },
  },
);
