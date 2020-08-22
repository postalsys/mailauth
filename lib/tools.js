'use strict';

const punycode = require('punycode');
const libmime = require('libmime');

const defaultFieldNames =
    'From:Sender:Reply-To:Subject:Date:Message-ID:To:' +
    'Cc:MIME-Version:Content-Type:Content-Transfer-Encoding:Content-ID:' +
    'Content-Description:Resent-Date:Resent-From:Resent-Sender:' +
    'Resent-To:Resent-Cc:Resent-Message-ID:In-Reply-To:References:' +
    'List-Id:List-Help:List-Unsubscribe:List-Subscribe:List-Post:' +
    'List-Owner:List-Archive';

const writeToStream = async (stream, input, chunkSize) => {
    chunkSize = chunkSize || 64 * 1024;

    if (typeof input === 'string') {
        input = Buffer.from(input);
    }

    return new Promise((resolve, reject) => {
        if (typeof input.on === 'function') {
            // pipe as stream
            input.pipe(stream);
            input.on('error', reject);
        } else {
            let pos = 0;
            let writeChunk = () => {
                if (pos >= input.length) {
                    return stream.end();
                }

                let chunk;
                if (pos + chunkSize >= input.length) {
                    chunk = input.slice(pos);
                } else {
                    chunk = input.slice(pos, pos + chunkSize);
                }
                pos += chunk.length;

                if (stream.write(chunk) === false) {
                    stream.once('drain', () => writeChunk);
                    return;
                }
                setImmediate(writeChunk);
            };
            setImmediate(writeChunk);
        }

        stream.on('end', resolve);
        stream.on('finish', resolve);
        stream.on('error', reject);
    });
};

const parseHeaders = buf => {
    let rows = buf
        .toString('binary')
        .replace(/[\r\n]+$/, '')
        .split(/\r?\n/)
        .map(row => [row]);
    for (let i = rows.length - 1; i >= 0; i--) {
        if (i > 0 && /^\s/.test(rows[i][0])) {
            rows[i - 1] = rows[i - 1].concat(rows[i]);
            rows.splice(i, 1);
        }
    }

    rows = rows.map(row => {
        row = row.join('\r\n');
        let key = row.match(/^[^:]+/);
        let casedKey;
        if (key) {
            casedKey = key[0].trim();
            key = casedKey.toLowerCase();
        }

        return { key, casedKey, line: Buffer.from(row, 'binary') };
    });

    return { parsed: rows, original: buf };
};

const getSignedHeaderLines = (parsedHeaders, fieldNames, verify) => {
    fieldNames = (fieldNames || defaultFieldNames)
        .split(':')
        .map(key => key.trim().toLowerCase())
        .filter(key => key);

    let signingList = [];

    if (verify) {
        let parsedList = [].concat(parsedHeaders).reverse();
        for (let fieldName of fieldNames) {
            for (let i = parsedList.length - 1; i >= 0; i--) {
                let header = parsedList[i];
                if (fieldName === header.key) {
                    signingList.push(header);
                    parsedList.splice(i, 1);
                    break;
                }
            }
        }
    } else {
        for (let i = parsedHeaders.length - 1; i >= 0; i--) {
            let header = parsedHeaders[i];
            if (fieldNames.includes(header.key)) {
                signingList.push(header);
            }
        }
    }

    return {
        keys: signingList.map(entry => entry.casedKey).join(': '),
        headers: signingList
    };
};

/**
 * Generates `DKIM-Signature: ...` header for selected values
 * @param {Object} values
 */
const formatDKIMHeaderLine = (values, folded) => {
    values = Object.assign({ v: 1, t: Math.round(Date.now() / 1000), q: 'dns/txt' }, values);
    let keyOrdering = ['v', 'a', 'c', 'd', 'h', 'i', 'l', 'q', 's', 't', 'x', 'z', 'bh', 'b'];

    let header =
        'DKIM-Signature: ' +
        Object.keys(values)
            .filter(key => values[key] !== false && typeof values[key] !== 'undefined' && values.key !== null)
            .sort((a, b) => keyOrdering.indexOf(a) - keyOrdering.indexOf(b))
            .map(key => {
                let val = values[key] || '';
                if (key === 'b' && folded && val) {
                    // fold signature value
                    return `${key}=${val}`.replace(/.{75}/g, '$& ').trim();
                }

                if (['d', 's'].includes(key)) {
                    try {
                        // convert to A-label if needed
                        val = punycode.toASCII(val);
                    } catch (err) {
                        // ignore
                    }
                }

                if (key === 'i') {
                    let atPos = val.indexOf('@');
                    if (atPos >= 0) {
                        let domainPart = val.substr(atPos + 1);
                        try {
                            // convert to A-label if needed
                            domainPart = punycode.toASCII(domainPart);
                        } catch (err) {
                            // ignore
                        }
                        val = val.substr(0, atPos + 1) + domainPart;
                    }
                }

                return `${key}=${val}`;
            })
            .join('; ');

    if (folded) {
        return libmime.foldLines(header);
    }

    return header;
};

module.exports = {
    writeToStream,
    parseHeaders,
    getSignedHeaderLines,
    formatDKIMHeaderLine
};
