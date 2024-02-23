'use strict';

const { spf } = require('../lib/spf');
const util = require('node:util');

const main = async () => {
    let tests = [
        { sender: 'andris@wildduck.email', ip: '127.0.0.1', helo: 'foo' },
        { sender: 'andris@wildduckzzzzzz.email', ip: '127.0.0.1', helo: 'foo' },
        { sender: 'andris@wildduck.email', ip: '217.146.76.20', helo: 'foo' }
    ];

    for (let opts of tests) {
        let result = await spf(opts);
        console.log(util.inspect(result, { depth: 22, colors: true }));
    }
};

main()
    .then(() => {
        console.log('done');
    })
    .catch(err => {
        console.error(err);
    });
