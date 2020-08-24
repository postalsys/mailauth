'use strict';

const { promisify } = require('util');
const MailComposer = require('nodemailer/lib/mail-composer');
const nodemailer = require('nodemailer');
const { dkimSign } = require('../lib/dkim/sign');
const fs = require('fs');

const transport = nodemailer.createTransport({
    host: 'gmail-smtp-in.l.google.com',
    port: 25,
    debug: true,
    logger: true
});

const from = 'Andris Reinman <andris@tahvel.info>';
const to = 'Andris Reinman <andris.reinman@gmail.com>';
const envelope = {
    from: 'andris@tahvel.info',
    to: ['andris.reinman@gmail.com']
};

const sendNext = async (subject, dkimOpts) => {
    const nr = Date.now();
    const mail = new MailComposer({
        from,
        to,

        subject: `    Signed message nr #${nr} 🚵 (${subject})    `,
        text: `    This is signed message nr #${nr} 🚵  ${' tere'.repeat(100)}  `,
        html: `    <p>This is signed message nr #${nr} 🚵  ${' <span>tere</span>'.repeat(100)}</p>    `
    });
    const compiled = mail.compile();
    const build = promisify(compiled.build.bind(compiled));
    const raw = await build();

    let signatures = await dkimSign(raw, dkimOpts);
    const signed = Buffer.concat([Buffer.from(signatures.join('\r\n') + '\r\n'), raw]);

    await transport.sendMail({
        envelope,
        raw: signed
    });
};

const matrix = [
    // signing algo
    ['rsa', 'ed25519'],
    // hashing algo
    ['sha1', 'sha256'],
    // header canonicalization
    ['simple', 'relaxed'],
    // body canonicalization
    ['simple', 'relaxed']
];

let testList = [];
for (let sa of matrix[0]) {
    for (let ha of matrix[1]) {
        for (let hc of matrix[2]) {
            for (let bc of matrix[3]) {
                testList.push([sa, ha, hc, bc]);
            }
        }
    }
}

const main = async () => {
    let count = 0;
    for (let test of testList) {
        let algo = `${test[0]}-${test[1]}`;
        let canon = `${test[2]}/${test[3]}`;
        await sendNext(`#${++count}: ${algo}, ${canon}, test.${test[0]}`, {
            algorithm: `${algo}`,
            canonicalization: `${canon}`,
            signatureData: [
                {
                    signingDomain: 'tahvel.info',
                    selector: `test.${test[0]}`,
                    privateKey: fs.readFileSync(`./test/fixtures/private-${test[0]}.pem`)
                }
            ]
        });
    }
};

main()
    .then(() => console.log('DONE'))
    .catch(err => console.error(err));
