'use strict';

const { Buffer } = require('node:buffer');

// Minimal RFC822 message for signing and sealing tests
const buildMessage = opts => {
    opts = opts || {};

    return Buffer.from(
        [
            `From: ${opts.from || 'sender@example.com'}`,
            `To: ${opts.to || 'rcpt@example.net'}`,
            'Subject: hello',
            'Date: Mon, 1 Jan 2024 00:00:00 +0000',
            `Message-ID: <1@${(opts.from || 'sender@example.com').split('@').pop()}>`,
            '',
            'body',
            ''
        ].join('\r\n')
    );
};

module.exports = { buildMessage };
