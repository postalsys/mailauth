'use strict';

const getDmarcRecord = require('../lib/dmarc/get-dmarc-record');

const domain = (process.argv[2] || '').trim();

if (!domain) {
    console.log('Provide domain name as an argument');
    console.log('$ node get-dmarc-record.js domain.tld');
    process.exit();
}

getDmarcRecord(domain).then(console.log);
