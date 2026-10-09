'use strict';

const { XMLParser, XMLValidator } = require('fast-xml-parser');

// Validates a BIMI Indicator against the SVG Tiny Portable/Secure profile (draft-svg-tiny-ps-abrotman).
// Elements are checked against an allowlist with resolved namespaces. Script, interactivity, linking,
// multimedia and animation are not allowed (section 2.3), and every reference must point into the
// document itself. The checks also cover markup that an HTML parser would read differently than an
// XML parser, as some clients insert the SVG into an HTML document.

const SVG_NS = 'http://www.w3.org/2000/svg';
const XML_NS = 'http://www.w3.org/XML/1998/namespace';
const XMLNS_NS = 'http://www.w3.org/2000/xmlns/';
// elements in these namespaces are rendered or executed by browsers
const ACTIVE_NAMESPACES = new Set(['http://www.w3.org/1999/xhtml', 'http://www.w3.org/1998/Math/MathML']);

// The element set of the validation RNC schema (section 7)
const TINY_PS_ELEMENTS = new Set([
    'svg',
    'title',
    'desc',
    'metadata',
    'path',
    'rect',
    'circle',
    'line',
    'ellipse',
    'polyline',
    'polygon',
    'solidColor',
    'textArea',
    'linearGradient',
    'radialGradient',
    'stop',
    'text',
    'g',
    'defs',
    'use',
    'font',
    'glyph',
    'hkern'
]);

// Static rendering elements of SVG 1.1 that are not part of the profile, but are found in published
// logos. They do not run code or load anything, references are checked like everywhere else.
const STATIC_ELEMENTS = new Set([
    'style',
    'clipPath',
    'mask',
    'pattern',
    'symbol',
    'marker',
    'tspan',
    'tbreak',
    'textPath',
    'missing-glyph',
    'vkern',
    'font-face',
    'font-face-src',
    'font-face-name',
    'filter',
    'feBlend',
    'feColorMatrix',
    'feComponentTransfer',
    'feComposite',
    'feConvolveMatrix',
    'feDiffuseLighting',
    'feDisplacementMap',
    'feDistantLight',
    'feDropShadow',
    'feFlood',
    'feFuncA',
    'feFuncB',
    'feFuncG',
    'feFuncR',
    'feGaussianBlur',
    'feMerge',
    'feMergeNode',
    'feMorphology',
    'feOffset',
    'fePointLight',
    'feSpecularLighting',
    'feSpotLight',
    'feTile',
    'feTurbulence'
]);

const MAX_DEPTH = 256;

// Attributes that SHOULD NOT be present, and if present MUST have this value (sections 2.2 and 2.3)
const FIXED_ATTRIBUTE_VALUES = {
    zoomAndPan: 'disable',
    externalResourcesRequired: 'false',
    focusable: 'false',
    snapshotTime: 'none',
    playbackOrder: 'all',
    timelineBegin: 'onLoad',
    editable: 'none'
};

const PREDEFINED_ENTITIES = { lt: '<', gt: '>', amp: '&', quot: '"', apos: "'" };

const parser = new XMLParser({
    ignoreAttributes: false,
    attributeNamePrefix: '',
    preserveOrder: true,
    // entities are decoded by decodeEntities(), the parser would leave some character references as is
    processEntities: false,
    htmlEntities: false,
    parseTagValue: false,
    parseAttributeValue: false,
    trimValues: false,
    ignoreDeclaration: false,
    ignorePiTags: false,
    commentPropName: '#comment',
    cdataPropName: '#cdata',
    textNodeName: '#text'
});

const createError = (message, code, details) => {
    let error = new Error(message);
    error.code = code;
    if (details) {
        error.details = details;
    }
    return error;
};

const invalidXml = (message, details) => createError('Invalid SVG file', 'INVALID_XML_FILE', Object.assign({ message }, details || {}));

const isXmlChar = code =>
    code === 0x09 ||
    code === 0x0a ||
    code === 0x0d ||
    (code >= 0x20 && code <= 0xd7ff) ||
    (code >= 0xe000 && code <= 0xfffd) ||
    (code >= 0x10000 && code <= 0x10ffff);

// Decodes the predefined entities and character references. Other entities are only defined in a
// DTD, which is not allowed.
const decodeEntities = value =>
    value.replace(/&([^;&]*);?/g, (match, ref) => {
        if (match.charAt(match.length - 1) !== ';') {
            throw invalidXml('Unterminated entity reference');
        }
        if (Object.prototype.hasOwnProperty.call(PREDEFINED_ENTITIES, ref)) {
            return PREDEFINED_ENTITIES[ref];
        }
        let code = /^#x[0-9a-fA-F]+$/.test(ref) ? parseInt(ref.slice(2), 16) : /^#[0-9]+$/.test(ref) ? parseInt(ref.slice(1), 10) : NaN;
        if (!isXmlChar(code)) {
            throw invalidXml(`Invalid entity reference &${ref};`);
        }
        return String.fromCodePoint(code);
    });

// Returns the reason why a CSS value or a presentation attribute might load an external resource
const checkCss = value => {
    if (value.indexOf('\\') >= 0) {
        // escapes could hide function names and URLs from the checks below
        return 'CSS escape';
    }
    if (/@import/i.test(value)) {
        return 'CSS import';
    }
    if (/(?:src|image|image-set|cross-fade|element)\s*\(/i.test(value)) {
        return 'CSS image function';
    }
    let urlRe = /url\s*\(\s*(['"]?)\s*([^'")]*)/gi;
    let match;
    while ((match = urlRe.exec(value))) {
        if (match[2].charAt(0) !== '#') {
            return 'external url()';
        }
    }
    return false;
};

const splitName = name => {
    let pos = name.indexOf(':');
    return pos >= 0 ? { prefix: name.slice(0, pos), local: name.slice(pos + 1) } : { prefix: '', local: name };
};

/**
 * Validates an SVG Indicator against the SVG Tiny PS profile
 *
 * @param {Buffer|String} logo SVG document
 * @param {Object} [opts]
 * @param {Boolean} [opts.strict=false] Apply the profile exactly: the version attribute, a single title as
 *        the first child, only the elements of the validation schema and the required attribute values
 * @param {Array} [opts.warnings] Without strict, markers of the profile deviations that were accepted are added here
 * @returns {Boolean} true, throws if the document is not valid
 */
function validateSvg(logo, opts) {
    opts = opts || {};
    const strict = !!opts.strict;
    const warnings = Array.isArray(opts.warnings) ? opts.warnings : [];

    // a deviation from the profile that does not make the logo unsafe, an error only in strict mode
    const lax = (marker, error) => {
        if (strict) {
            throw error;
        }
        if (!warnings.includes(marker)) {
            warnings.push(marker);
        }
    };
    let source = Buffer.isBuffer(logo) ? logo.toString('utf-8') : String(logo || '');
    if (source.charCodeAt(0) === 0xfeff) {
        source = source.slice(1);
    }

    let logoObj;
    try {
        if (!source.trim()) {
            throw new Error('Empty file');
        }
        logoObj = parser.parse(source);
        if (!Array.isArray(logoObj)) {
            throw new Error('Empty file');
        }
    } catch (err) {
        let error = new Error('Invalid SVG file');
        error._err = err;
        error.code = 'INVALID_XML_FILE';
        throw error;
    }

    const nodeName = node => Object.keys(node).find(key => key !== ':@');

    let root = logoObj.find(node => /^[^#?]/.test(nodeName(node) || ''));
    if (!root || splitName(nodeName(root)).local !== 'svg') {
        let error = new Error('Invalid SVG file');
        error.code = 'INVALID_SVG_FILE';
        throw error;
    }

    // the parser accepts mismatched tags, repeated attributes and similar errors, the validator does not
    let validation = XMLValidator.validate(source);
    if (validation !== true) {
        throw invalidXml(validation?.err?.msg || 'Invalid XML');
    }

    const childText = node => (node[nodeName(node)] || []).map(entry => entry['#text'] || '').join('');

    const checkComment = (node, path) => {
        // "<!-->" and "--!>" end a comment in HTML
        let text = childText(node);
        if (/[<>]|--/.test(text) || /^-|-$/.test(text)) {
            throw createError('Unexpected content in comment', 'LOGO_INVALID_CONTENT', { path });
        }
    };

    // An internal DTD subset can declare entities and default attributes, the parser and a browser
    // would not see the same document. The DOCTYPE of SVG 1.1 is allowed, it is ignored by browsers.
    let doctypeRe = /<!doctype/gi;
    let doctypeMatch;
    while ((doctypeMatch = doctypeRe.exec(source))) {
        let tail = source.slice(doctypeMatch.index);
        if (!/^<!DOCTYPE\s+svg(?:\s+PUBLIC\s+"[^"<>[\]]*"\s+"[^"<>[\]]*"|\s+SYSTEM\s+"[^"<>[\]]*")?\s*>/.test(tail)) {
            throw invalidXml('Unsupported DOCTYPE declaration');
        }
    }
    if (/<!ENTITY/i.test(source)) {
        throw invalidXml('Entity declarations are not allowed');
    }

    let rootCount = 0;
    for (let [i, node] of logoObj.entries()) {
        let name = nodeName(node);
        if (name === '#text') {
            if ((node['#text'] || '').trim()) {
                throw invalidXml('Text outside of the root element');
            }
        } else if (name === '#comment') {
            checkComment(node, '');
        } else if (name === '?xml') {
            if (i !== 0) {
                throw invalidXml('Misplaced XML declaration');
            }
            let attrs = node[':@'] || {};
            for (let [key, value] of Object.entries(attrs)) {
                if (
                    !(key === 'version' && /^1\.[0-9]+$/.test(value)) &&
                    !(key === 'encoding' && /^[A-Za-z][A-Za-z0-9._-]*$/.test(value)) &&
                    !(key === 'standalone' && /^(?:yes|no)$/.test(value))
                ) {
                    throw invalidXml('Invalid XML declaration');
                }
            }
        } else if (name && name.charAt(0) === '?') {
            // for example xml-stylesheet, which loads an external style sheet
            throw createError('Processing instructions are not allowed', 'LOGO_INVALID_CONTENT', { instruction: name.slice(1) });
        } else if (name && ++rootCount > 1) {
            throw invalidXml('Multiple root elements');
        }
    }

    // returns the namespace of a prefix in the current scope
    const resolvePrefix = (scope, prefix, path) => {
        if (prefix === 'xml') {
            return XML_NS;
        }
        if (prefix === 'xmlns') {
            return XMLNS_NS;
        }
        if (!Object.prototype.hasOwnProperty.call(scope, prefix)) {
            if (!prefix) {
                return null;
            }
            throw invalidXml(`Undeclared namespace prefix "${prefix}"`, { path });
        }
        return scope[prefix];
    };

    let rootInfo = null;
    let titleCount = 0;
    let titleText = '';
    let firstChild = true;

    // checks the content of a text node or a CDATA section
    const checkText = (value, path) => {
        // Text of a CDATA section is not escaped. An HTML parser does not handle CDATA in title or
        // desc, and would read a tag from it.
        if (value.indexOf('<') >= 0) {
            throw createError('Unexpected markup in text content', 'LOGO_INVALID_CONTENT', { path });
        }
    };

    const walk = (node, scope, path, depth, inMetadata) => {
        if (depth > MAX_DEPTH) {
            throw createError('Document is nested too deeply', 'LOGO_INVALID_CONTENT', { path });
        }

        let qname = nodeName(node);
        let attrs = node[':@'] || {};

        // namespace declarations of this element
        let localScope = scope;
        for (let [key, value] of Object.entries(attrs)) {
            if (key === 'xmlns' || key.indexOf('xmlns:') === 0) {
                if (localScope === scope) {
                    localScope = Object.assign({}, scope);
                }
                let decoded = decodeEntities(value);
                localScope[key === 'xmlns' ? '' : key.slice(6)] = decoded || null;
            }
        }

        let { prefix, local } = splitName(qname);
        let namespace = resolvePrefix(localScope, prefix, path);
        let elementPath = `${path}.${qname}`;

        if (depth === 0 && namespace !== SVG_NS) {
            // 2.1: xmlns="http://www.w3.org/2000/svg", in any other namespace this is not an SVG document
            throw createError('Invalid SVG file', 'INVALID_SVG_FILE', { namespace });
        }
        let isSvg = namespace === SVG_NS;

        // attributes are checked first, so an external reference is reported as such
        for (let [key, rawValue] of Object.entries(attrs)) {
            if (key === 'xmlns' || key.indexOf('xmlns:') === 0) {
                continue;
            }
            let attr = splitName(key);
            // an unprefixed attribute has no namespace
            let attrNs = attr.prefix ? resolvePrefix(localScope, attr.prefix, elementPath) : null;
            if (rawValue.indexOf('<') >= 0) {
                throw invalidXml('Unescaped "<" in an attribute value', { path: elementPath, attribute: key });
            }
            let value = decodeEntities(rawValue);

            if (/^on/i.test(attr.local)) {
                throw createError('Event handler attribute found from file', 'LOGO_INVALID_ATTRIBUTE', {
                    element: qname,
                    attribute: key,
                    path: elementPath
                });
            }

            // href in the XLink namespace, without namespace (SVG 2), or with any prefix an HTML parser
            // could map to XLink. Only same-document references are allowed (section 2.3, Linking).
            if (attr.local.toLowerCase() === 'href' && value.trim().charAt(0) !== '#') {
                let error = new Error('External reference found from file');
                error.details = {
                    element: qname,
                    link: value,
                    path: elementPath
                };
                error.code = 'LOGO_INCLUDES_REFERENCE';
                throw error;
            }

            if (
                isSvg &&
                !attr.prefix &&
                Object.prototype.hasOwnProperty.call(FIXED_ATTRIBUTE_VALUES, attr.local) &&
                value.trim() !== FIXED_ATTRIBUTE_VALUES[attr.local]
            ) {
                lax(
                    'svg-attribute-value',
                    createError(`${attr.local} must be "${FIXED_ATTRIBUTE_VALUES[attr.local]}"`, 'LOGO_INVALID_ATTRIBUTE', {
                        element: qname,
                        attribute: key,
                        value,
                        path: elementPath
                    })
                );
            }

            if (attrNs === XML_NS && attr.local === 'base' && value.trim()) {
                // a base URI could turn a fragment reference into an external one
                throw createError('xml:base attribute found from file', 'LOGO_INVALID_ATTRIBUTE', { element: qname, attribute: key, path: elementPath });
            }

            // presentation attributes and the style attribute are parsed as CSS
            let cssError = checkCss(value);
            if (cssError) {
                let error = new Error('External reference found from file');
                error.details = {
                    element: qname,
                    attribute: key,
                    link: value,
                    reason: cssError,
                    path: elementPath
                };
                error.code = 'LOGO_INCLUDES_REFERENCE';
                throw error;
            }
        }

        const invalidElement = reason =>
            createError('Unallowed element found from file', 'LOGO_INVALID_ELEMENT', {
                element: qname,
                namespace,
                reason,
                path: elementPath
            });

        // An HTML parser ignores namespace declarations and treats an unprefixed element in SVG
        // content as an SVG element, so an unprefixed name must be allowed in any namespace.
        if ((isSvg || !prefix) && !TINY_PS_ELEMENTS.has(local) && !STATIC_ELEMENTS.has(local)) {
            throw invalidElement('not allowed in SVG Tiny PS');
        }
        if (namespace && ACTIVE_NAMESPACES.has(namespace)) {
            throw invalidElement('not allowed in SVG Tiny PS');
        }
        if (!prefix && local === 'font' && ['color', 'face', 'size'].some(key => key in attrs)) {
            // an HTML parser would end the SVG content here and continue in HTML
            throw invalidElement('font element with HTML attributes');
        }
        if (inMetadata && isSvg) {
            throw invalidElement('SVG element in metadata');
        }

        // the validation schema (section 7) does not allow these, they are not unsafe
        if (inMetadata) {
            // metadata only has text content in the schema
            lax('svg-metadata-content', invalidElement('element in metadata'));
        } else if (!isSvg) {
            lax('svg-foreign-element', invalidElement('element in another namespace'));
        } else if (STATIC_ELEMENTS.has(local)) {
            lax('svg-element', invalidElement('not part of the SVG Tiny PS profile'));
        }

        if (depth === 0) {
            rootInfo = { qname, local, namespace, isSvg, attrs };
        } else if (isSvg && local === 'title' && depth === 1) {
            // 2.1: one non-empty title, the schema has it as the first child of the root element
            titleCount++;
            if (titleCount === 1) {
                titleText = (node[qname] || [])
                    .map(child => (child['#text'] !== undefined ? decodeEntities(child['#text']) : child['#cdata'] ? childText(child) : ''))
                    .join('');
                if (!firstChild) {
                    lax(
                        'svg-title-position',
                        createError('The title element must be the first child of the svg element', 'LOGO_INVALID_ELEMENT', { path: elementPath })
                    );
                }
            } else {
                lax('svg-title-count', createError('Logo file has more than one title', 'LOGO_MULTIPLE_TITLES', { path: elementPath }));
            }
        } else if (isSvg && local === 'title') {
            lax('svg-title-position', createError('The title element must be a child of the svg element', 'LOGO_INVALID_ELEMENT', { path: elementPath }));
        } else if (isSvg && local === 'desc' && !childText(node).trim()) {
            // 2.1: if present, the contents of desc MUST NOT be empty
            lax('svg-empty-desc', createError('The desc element is empty', 'LOGO_INVALID_CONTENT', { path: elementPath }));
        }
        if (depth === 1) {
            firstChild = false;
        }

        let isStyle = isSvg && local === 'style';
        const checkStyle = text => {
            let cssError = isStyle && checkCss(text);
            if (cssError) {
                throw createError('External reference found from file', 'LOGO_INCLUDES_REFERENCE', {
                    element: qname,
                    link: text,
                    reason: cssError,
                    path: elementPath
                });
            }
        };
        let childMetadata = inMetadata || (isSvg && local === 'metadata');

        for (let child of node[qname] || []) {
            let childName = nodeName(child);
            if (childName === '#text') {
                checkText(child['#text'] || '', elementPath);
                checkStyle(decodeEntities(child['#text'] || ''));
            } else if (childName === '#cdata') {
                let text = childText(child);
                checkText(text, elementPath);
                checkStyle(text);
            } else if (childName === '#comment') {
                checkComment(child, elementPath);
            } else if (childName && childName.charAt(0) === '?') {
                throw createError('Processing instructions are not allowed', 'LOGO_INVALID_CONTENT', { instruction: childName.slice(1), path: elementPath });
            } else if (childName) {
                walk(child, localScope, elementPath, depth + 1, childMetadata);
            }
        }
    };

    walk(root, {}, '', 0, false);

    let rootAttrs = rootInfo.attrs;

    if (rootAttrs.baseProfile !== 'tiny-ps') {
        let error = new Error('Not a Tiny PS profile');
        error.code = 'INVALID_BASE_PROFILE';
        throw error;
    }

    if (!titleCount || !titleText.trim()) {
        let error = new Error('Logo file is missing title');
        error.code = 'LOGO_MISSING_TITLE';
        throw error;
    }

    if ('x' in rootAttrs || 'y' in rootAttrs) {
        let error = new Error('Logo root includes x/y attributes');
        error.code = 'LOGO_INVALID_ROOT_ATTRS';
        throw error;
    }

    if (rootAttrs.version !== '1.2') {
        // 2.1: version="1.2"
        lax('svg-version', createError('SVG version must be 1.2', 'INVALID_SVG_VERSION', { version: rootAttrs.version }));
    }

    // all validations passed
    return true;
}

module.exports = { validateSvg };
