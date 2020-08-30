'use strict';

const { spfVerify } = require('./spf-verify');
const os = require('os');

/**
 *
 * @param {Object} opts
 * @param {String} opts.sender Email address
 * @param {String} opts.ip Client IP address
 * @param {String} [opts.mta] Hostname of the MTA or MX server that processes the message
 * @param {String} opts.helo Client EHLO/HELO hostname
 */
const verify = async opts => {
    let { sender, ip, mta, helo, resolver } = opts || {};

    mta = mta || os.hostname();

    sender = sender || `postmaster@${helo}`;

    let domain = sender.split('@').pop().toLowerCase().trim();
    let result = await spfVerify(domain, { sender, ip, mta, helo, resolver });

    let response = {};

    result = result || {};
    switch (result.qualifier) {
        case '+':
            response.status = 'pass';
            response.info = `${mta}: domain of ${sender} designates ${ip} as permitted sender`;
            break;
        case '-':
            response.status = 'fail';
            response.info = `${mta}: domain of ${sender} does not designate ${ip} as permitted sender`;
            break;
    }
};

module.exportS = verify;
