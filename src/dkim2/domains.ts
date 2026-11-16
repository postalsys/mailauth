// Domains in DKIM2: the addresses of SMTP paths, the relaxed domain match of
// draft-ietf-dkim-dkim2-spec-09 section 7, and the chain of custody between two hops (section 7.1 item 1)

import { isSameOrSubdomain, toALabel } from '../tools.js';

// Which tag of a hop does not continue the chain of custody: its mf= domain, or, without a
// non-null mf=, its d= domain
type CustodyProblem = 'mf' | 'd' | null;

/**
 * Splits an RFC 5321 path into its address, with the domain as a lower case A-label, which is
 * how sections 14.4 and 18 compare it. A source route in front of the mailbox is left out
 *
 * @param {String} path Path with or without the angle brackets
 * @returns {Object} { address, domain }, both empty for the null path
 */
const parsePath = (path: string | null | undefined): { address: string; domain: string } => {
    let address = (path || '').toString().trim().replace(/^<|>$/g, '');
    if (address.charAt(0) === '@' && address.indexOf(':') > 0) {
        address = address.substring(address.indexOf(':') + 1);
    }
    let atPos = address.lastIndexOf('@');
    if (atPos < 0) {
        return { address, domain: '' };
    }
    let domain = toALabel(address.substring(atPos + 1)).toLowerCase();
    return { address: `${address.substring(0, atPos)}@${domain}`, domain };
};

/**
 * Whether a value is an RFC 5321 path in angle brackets with nothing after it: sections 10.5 and
 * 10.6 record the reverse-path and the Forward-path without their SMTP parameters. It is the null
 * path, "<Postmaster>", or a mailbox with a local part and a domain, after an obsolete source
 * route. Whitespace, control characters and angle brackets can only be in a quoted local part
 *
 * @param {String} path Path with the angle brackets
 * @returns {Boolean}
 */
const isSmtpPath = (path: string): boolean => {
    if (path === '<>') {
        return true;
    }
    if (path.length < 3 || path.charAt(0) !== '<' || path.charAt(path.length - 1) !== '>') {
        return false;
    }
    let mailbox = path
        .slice(1, -1)
        .replace(/"(?:[^"\\\r\n]|\\[^\r\n])*"/g, '""')
        .replace(/^@[^:]*:/, '');
    if (/[\s\x00-\x1f\x7f<>]/.test(mailbox)) {
        return false;
    }
    return /^postmaster$/i.test(mailbox) || /^[^@]+@[^@]+$/.test(mailbox);
};

/**
 * The relaxed domain match of section 7.2: Parameter1 is Parameter2, or becomes it once labels
 * are removed from its left. A domain literal never matches
 *
 * @param {String} first Parameter1, a domain
 * @param {String} second Parameter2, a domain
 * @returns {Boolean}
 */
const relaxedMatch = (first: string | null | undefined, second: string | null | undefined): boolean =>
    !!first && !!second && first.charAt(0) !== '[' && second.charAt(0) !== '[' && isSameOrSubdomain(first, second);

/**
 * Section 7.1 item 1: whether a hop continues the chain of custody of the hop before it. A
 * non-null mf= domain (Parameter1) has to match a domain of the previous rt= (Parameter2). With
 * the null mf= or with nd=, a domain of the previous rt= (Parameter1) has to match the d=
 * domain (Parameter2). A hop after one with nd= is not checked here, its d= has to equal that
 * nd= instead
 *
 * @param {Object} previous Parsed previous DKIM2-Signature
 * @param {Object} current { mailFrom, signingDomain } of the hop
 * @returns {String|null} null when the chain continues, otherwise "mf" or "d", the tag that does
 *          not match
 */
const custodyProblem = (
    previous: { nextDomain?: string | undefined; rcptTo?: string[] | undefined } | undefined,
    current: { mailFrom?: string | undefined; signingDomain: string }
): CustodyProblem => {
    if (!previous || previous.nextDomain) {
        return null;
    }
    let recipients = (previous.rcptTo || []).map(path => parsePath(path).domain);
    if (current.mailFrom && current.mailFrom !== '<>') {
        let domain = parsePath(current.mailFrom).domain;
        return recipients.some(recipient => relaxedMatch(domain, recipient)) ? null : 'mf';
    }
    return recipients.some(recipient => relaxedMatch(recipient, current.signingDomain)) ? null : 'd';
};

export { parsePath, isSmtpPath, relaxedMatch, custodyProblem };
