'use strict';

// Grammar shared by the DKIM and ARC signers and verifiers. ARC reuses the DKIM tag syntax
// (RFC 8617 section 4.1), so both read these from here. This module requires nothing, so
// that lib/tools.js can use it as well.

// RFC 6376 section 3.5 sub-domain
const DOMAIN_LABEL = '[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?';
// domain-name = sub-domain 1*("." sub-domain)
const DOMAIN_NAME = new RegExp(`^${DOMAIN_LABEL}(?:\\.${DOMAIN_LABEL})+$`);
// selector = sub-domain *("." sub-domain)
const SELECTOR = new RegExp(`^${DOMAIN_LABEL}(?:\\.${DOMAIN_LABEL})*$`);
// sig-t-tag and sig-x-tag are 1*12DIGIT, sig-l-tag is 1*76DIGIT
const TIMESTAMP = /^[0-9]{1,12}$/;
const BODY_LENGTH = /^[0-9]{1,76}$/;
// the Local-part of an i= value (RFC 6376 section 3.5): RFC 5322 dot-atom-text with the UTF-8
// of RFC 6531, or a quoted-string
const LOCAL_PART = /^(?:(?:[A-Za-z0-9!#$%&'*+\-/=?^_`{|}~]|[^\x00-\x7f])+(?:\.(?:[A-Za-z0-9!#$%&'*+\-/=?^_`{|}~]|[^\x00-\x7f])+)*|"(?:[^"\\\r\n]|\\.)*")$/;

// The characters of a host name, after U-labels are converted to A-labels. A d= with anything
// else (such as "/", "?", "#", "@" or ":") can not name the zone of its key record, so a
// DKIM-Signature, ARC-Seal or ARC-Message-Signature with it is a syntax error in every mode
// (RFC 6376 section 3.5)
const HOST_NAME_CHARS = /^[A-Za-z0-9_.-]+$/;

// RFC 8617 section 4.2.1: instance values range from 1 to 50
const MAX_ARC_INSTANCE = 50;

// the header fields of an ARC set (RFC 8617 section 4.1)
const ARC_HEADER_KEYS = ['arc-seal', 'arc-message-signature', 'arc-authentication-results'];

module.exports = {
    DOMAIN_LABEL,
    DOMAIN_NAME,
    SELECTOR,
    LOCAL_PART,
    HOST_NAME_CHARS,
    TIMESTAMP,
    BODY_LENGTH,
    MAX_ARC_INSTANCE,
    ARC_HEADER_KEYS
};
