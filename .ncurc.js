module.exports = {
    upgrade: true,
    reject: [
        'marked',
        'marked-man',
        // only works as ESM
        'chai',
        'fast-xml-parser',

        // fix later
        'eslint',
        'eslint-config-prettier'
    ]
};
