// Flat ESLint config for vibetesting-agent.
// Lints the TypeScript source, the test suite, and the .mjs scripts. Kept intentionally
// pragmatic: this is a black-box scanner that handles untyped remote responses and injects
// stringified probes into pages, so a few escape hatches (explicit `any`, console output) are
// expected. Enforced as part of the test suite (see tests/lint.test.ts).
import js from '@eslint/js';
import tseslint from 'typescript-eslint';
import globals from 'globals';

export default tseslint.config(
    {
        ignores: [
            'dist/**',
            'node_modules/**',
            'reports/**',
            'templates/**',
            'docs/**',
            'examples/**',
            'shipcheck/**',
            'plugins/examples/**',
            // Hosted product is its own package; build output must never fail the OSS lint gate
            'vibetesting-agent/**',
            '.open-next/**',
            '**/mcp/node_modules/**',
        ],
    },
    js.configs.recommended,
    ...tseslint.configs.recommended,
    {
        files: ['**/*.ts', '**/*.mjs', '**/*.js'],
        languageOptions: {
            globals: { ...globals.node },
        },
        rules: {
            // The scanner deliberately handles untyped remote data (HTTP bodies, page.evaluate
            // results); `any` is a legitimate escape hatch here, not a smell to chase.
            '@typescript-eslint/no-explicit-any': 'off',
            // A CLI tool: stdout/stderr is the product.
            'no-console': 'off',
            // Best-effort probes swallow failures by design (parse-or-skip); an empty catch is
            // an intentional "ignore and continue" here. Other empty blocks stay errors.
            'no-empty': ['error', { allowEmptyCatch: true }],
            // Off (matches eslint/typescript-eslint recommended, which don't enable it): it
            // false-positives on the idiomatic `let x = null; try { x = … } catch { x = null }`
            // defensive pattern this scanner uses throughout, where the initializer documents the
            // fallback value even when every path reassigns it.
            'no-useless-assignment': 'off',
            // Underscore-prefixed identifiers are intentional throwaways.
            '@typescript-eslint/no-unused-vars': [
                'error',
                {
                    argsIgnorePattern: '^_',
                    varsIgnorePattern: '^_',
                    caughtErrorsIgnorePattern: '^_',
                },
            ],
        },
    }
);
