// The header fields DKIM2 signs (draft-ietf-dkim-dkim2-spec-09 sections 4 and 6.2)

const MI_KEY = 'message-instance';
const SIG_KEY = 'dkim2-signature';

// Section 4.1: header fields that are not signed, processed as if they were not present
const UNSIGNED_FIELDS = new Set([
    'apparently-to',
    'arc-authentication-results',
    'arc-message-signature',
    'arc-seal',
    'authentication-results',
    'delivered-to',
    'dkim-signature',
    'dl-expansion-history',
    'original-recipient',
    'received',
    'return-path',
    'sio-label-history',
    'x400-received',
    'x400-trace'
]);

const isUnsignedField = (key: string): boolean => UNSIGNED_FIELDS.has(key) || key.startsWith('received-') || key.startsWith('x-');

// Section 6.2: the header hash leaves out the unsigned fields and the DKIM2 fields themselves
const isHashedField = (key: string | null | undefined): key is string => !!key && key !== MI_KEY && key !== SIG_KEY && !isUnsignedField(key);

export { MI_KEY, SIG_KEY, isHashedField };
