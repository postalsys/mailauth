'use strict';

module.exports = {
    upgrade: true,
    target: name => {
        // commander 15 is ESM only. The CLI is bundled into a @yao-pkg/pkg binary, which
        // can only load a CommonJS module graph, so it stays on the 14.x line
        if (name === 'commander') {
            return 'minor';
        }
        // @types/node stays on the 22.x line so the compiler rejects APIs that do not
        // exist on Node 22, the oldest supported version
        if (name === '@types/node') {
            return 'minor';
        }
        // typescript-eslint declares a peer range that excludes TypeScript 7
        if (name === 'typescript') {
            return 'minor';
        }
        return 'latest';
    }
};
