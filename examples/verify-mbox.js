'use strict';

const { eachMessage } = require('mbox-reader');

const fs = require('fs');
const { dkimVerify } = require('../lib/dkim/verify');
const pathlib = require('path');

let file = process.argv[2];
let mbox = fs.createReadStream(file);

let dest = process.argv[3];

const main = async () => {
    console.log('fname,status,format,algo,selector,domain,message');

    let counter = 0;
    for await (let message of eachMessage(mbox)) {
        counter++;
        let msg = Buffer.concat([message.content, Buffer.from('\r\n')]);
        try {
            let result = await dkimVerify(msg);

            result.results.forEach(r => {
                if (['fail', 'neutral'].includes(r.status)) {
                    console.log(
                        `${r.status}/${counter}.eml,${r.status},${r.format},${r.algo},${r.selector},${r.signingDomain},"${
                            (r.message && r.message.replace(/"/g, '""')) || ''
                        }"`
                    );
                }
            });

            if (result.results.some(r => r.status === 'fail')) {
                if (dest) {
                    let out = Buffer.concat([Buffer.from('X-DGB: ' + JSON.stringify(result.results)), msg]);
                    await fs.promises.writeFile(pathlib.join(dest, 'fail', counter + '.eml'), out);
                }
            }

            if (result.results.some(r => r.status === 'neutral')) {
                if (dest) {
                    let out = Buffer.concat([Buffer.from('X-DGB: ' + JSON.stringify(result.results)), msg]);
                    await fs.promises.writeFile(pathlib.join(dest, 'neutral', counter + '.eml'), out);
                }
            }
        } catch (err) {
            console.error(err);
            if (dest) {
                console.log(`error/${counter}.eml,error,,,,,"${err.stack.replace(/\r?\n/g, ' ').replace(/\s+/g, ' ').trim().replace(/"/g, '""')}"`);
                let out = Buffer.concat([Buffer.from('X-DGB: ' + JSON.stringify(err.stack)), msg]);
                await fs.promises.writeFile(pathlib.join(dest, 'error', counter + '.eml'), out);
            }
            //process.exit(1);
        }
    }
};

main()
    .then(() => {
        console.log('DONE');
    })
    .catch(err => {
        console.error(err);
        process.exit(2);
    });
