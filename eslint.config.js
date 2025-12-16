const prettierConfig = require('eslint-config-prettier');

module.exports = [
    {
        ignores: ['node_modules/**', 'ee-dist/**', 'test/fixtures/**', 'examples/devel-*']
    },
    prettierConfig,
    {
        languageOptions: {
            ecmaVersion: 2020,
            sourceType: 'commonjs',
            globals: {
                BigInt: true,
                console: 'readonly',
                process: 'readonly',
                Buffer: 'readonly',
                __dirname: 'readonly',
                __filename: 'readonly',
                exports: 'writable',
                module: 'writable',
                require: 'readonly',
                setTimeout: 'readonly',
                setInterval: 'readonly',
                clearTimeout: 'readonly',
                clearInterval: 'readonly',
                setImmediate: 'readonly',
                clearImmediate: 'readonly'
            }
        },
        rules: {
            'no-await-in-loop': 0,
            'require-atomic-updates': 0,
            'no-unused-vars': [
                'error',
                {
                    argsIgnorePattern: '^_',
                    caughtErrors: 'none'
                }
            ],
            'no-console': 0
        }
    }
];
