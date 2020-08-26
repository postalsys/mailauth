'use strict';

const dns = require('dns').promises;

const resolveSpf = async domain => {
    let responses = await dns.resolveTxt(domain);
    let spfRecord;

    for (let row of responses) {
        row = row.join('');
        let parts = row.trim().split(/\s+/);
        if (parts[0].toLowerCase() === 'v=spf1') {
            spfRecord = parts;
            break;
        }
    }
    if (!spfRecord) {
        return false;
    }
    console.log(spfRecord);
};

resolveSpf('outfunnel.com');
