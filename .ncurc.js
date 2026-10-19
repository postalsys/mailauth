module.exports = {
    upgrade: true,
    reject: [
        // only works as ESM
        'chai'
    ],
    target: name => {
        // commander 15 is ESM only. The CLI is bundled into a @yao-pkg/pkg binary, which
        // can only load a CommonJS module graph, so it stays on the 14.x line
        if (name === 'commander') {
            return 'minor';
        }
        return 'latest';
    }
};
