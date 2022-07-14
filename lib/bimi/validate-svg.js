'use strict';

const { XMLParser } = require('fast-xml-parser');

function validateSvg(logo) {
    const parser = new XMLParser({
        ignoreAttributes: false,
        attributeNamePrefix: '@_'
    });

    let logoObj;
    try {
        logoObj = parser.parse(logo);
        if (!logoObj) {
            throw new Error('Emtpy file');
        }
    } catch (err) {
        let error = new Error('Invalid SVG file');
        error._err = err;
        error.code = 'INVALID_XML_FILE';
        throw error;
    }

    if (!logoObj.svg) {
        let error = new Error('Invalid SVG file');
        error.code = 'INVALID_SVG_FILE';
        throw error;
    }

    if (logoObj.svg['@_baseProfile'] !== 'tiny-ps') {
        let error = new Error('Not a Tiny PS profile');
        error.code = 'INVALID_BASE_PROFILE';
        throw error;
    }

    if (!logoObj.svg.title) {
        let error = new Error('Logo file is missing title');
        error.code = 'LOGO_MISSING_TITLE';
        throw error;
    }

    if ('@_x' in logoObj.svg || '@_y' in logoObj.svg) {
        let error = new Error('Logo root includes x/y attributes');
        error.code = 'LOGO_INVALID_ROOT_ATTRS';
        throw error;
    }

    let walkElm = (node, name, path) => {
        if (!node) {
            return;
        }
        if (Array.isArray(node)) {
            for (let entry of node) {
                walkElm(entry, name, path + '.' + name + '[]');
            }
        } else if (typeof node === 'object') {
            if (node['@_xlink:href'] && !/^#/.test(node['@_xlink:href'])) {
                let error = new Error('External reference found from file');
                error.details = {
                    element: name,
                    link: node['@_xlink:href'],
                    path
                };
                error.code = 'LOGO_INCLUDES_REFERENCE';
                throw error;
            }

            for (let key of Object.keys(node)) {
                if (['script', 'animate', 'animatemotion', 'animatetransform', 'discard', 'set'].includes(key.toLowerCase())) {
                    let error = new Error('Unallowed element found from file');
                    error.details = {
                        element: key,
                        path: path + '.' + key
                    };
                    error.code = 'LOGO_INVALID_ELEMENT';
                    throw error;
                }

                if (Array.isArray(node[key])) {
                    for (let entry of node[key]) {
                        walkElm(entry, key, path + '.' + key + '[]');
                    }
                } else if (node[key] && typeof node[key] === 'object') {
                    walkElm(node[key], key, path + '.' + key);
                }
            }
        }
    };

    walkElm(logoObj, 'root', '');

    // all validations passed
    return true;
}

module.exports = { validateSvg };
