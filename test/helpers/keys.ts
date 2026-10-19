import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const fixturePath = (file: string): string => __dirname + `/../fixtures/${file}`;

// Reads a PEM fixture and returns it as the base64 body of a DKIM/ARC public key record
const dkimTxtRecord = (file: string): string => `v=DKIM1; k=rsa; p=${fs.readFileSync(fixturePath(file), 'utf8').replace(/-----[^-]+-----|\s/g, '')}`;

const privateKey = (file: string): Buffer => fs.readFileSync(fixturePath(file));

export { dkimTxtRecord, privateKey };
