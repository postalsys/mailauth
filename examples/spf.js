'use strict';

const { spf } = require('../lib/spf');

const main = async () => {
    let result = await spf({ sender: 'andris@wildduck.email', ip: '127.0.0.1', helo: 'foo' });
    console.log(result);

    result = await spf({ sender: 'andris@wildduckzzzzzz.email', ip: '127.0.0.1', helo: 'foo' });
    console.log(result);

    result = await spf({ sender: 'andris@wildduck.email', ip: '217.146.76.20', helo: 'foo' });
    console.log(result);
};

main()
    .then(() => {
        console.log('done');
    })
    .catch(err => {
        console.error(err);
    });
