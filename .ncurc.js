module.exports = {
    upgrade: true,
    reject: [
        // only works as ESM
        'chai',
        'fast-xml-parser',
        'yargs'
    ]
};
