'use strict';

const resolveStream = async (stream, buf, chunkSize) => {
    chunkSize = chunkSize || 64 * 1024;

    if (typeof buf === 'string') {
        buf = Buffer.from(buf);
    }

    return new Promise((resolve, reject) => {
        let pos = 0;
        let run = () => {
            if (pos >= buf.length) {
                return stream.end();
            }

            let chunk;
            if (pos + chunkSize >= buf.length) {
                chunk = buf.slice(pos);
            } else {
                chunk = buf.slice(pos, pos + chunkSize);
            }
            pos += chunk.length;

            if (stream.write(chunk) === false) {
                stream.once('drain', () => run);
                return;
            }
            setImmediate(run);
        };
        setImmediate(run);

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
        if (key) {
            key = key[0].trim().toLowerCase();
        }

        return { key, line: Buffer.from(row, 'binary') };
    });

    return { parsed: rows, original: buf };
};

module.exports = { resolveStream, parseHeaders };
