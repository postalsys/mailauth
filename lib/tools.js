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

module.exports = { resolveStream };
