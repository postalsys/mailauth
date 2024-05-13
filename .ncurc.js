module.exports = {
    upgrade: true,
    reject: [
        'marked',
        'marked-man',
        // only works as ESM
        'chai',

        // Fails in Node 16
        'undici',

        // fix later
        'eslint'
    ]
};
