/* eslint no-unused-expressions:0 */
'use strict';

const chai = require('chai');
const expect = chai.expect;

const { validateSvg } = require('../../lib/bimi/validate-svg');

chai.config.includeStack = true;

describe('BIMI SVG Validation Tests', () => {
    describe('Valid SVG acceptance', () => {
        it('Should accept valid tiny-ps profile SVG', () => {
            const validSvg = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" baseProfile="tiny-ps" version="1.2" viewBox="0 0 100 100">
    <title>Test Logo</title>
    <rect width="100" height="100" fill="blue"/>
</svg>`;

            const result = validateSvg(validSvg);
            expect(result).to.be.true;
        });

        it('Should accept SVG with internal references (#id)', () => {
            const validSvg = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" baseProfile="tiny-ps" version="1.2" viewBox="0 0 100 100">
    <title>Test Logo</title>
    <defs>
        <linearGradient id="grad1">
            <stop offset="0%" style="stop-color:rgb(255,255,0);stop-opacity:1" />
            <stop offset="100%" style="stop-color:rgb(255,0,0);stop-opacity:1" />
        </linearGradient>
    </defs>
    <rect width="100" height="100" fill="url(#grad1)"/>
    <use xlink:href="#grad1"/>
</svg>`;

            const result = validateSvg(validSvg);
            expect(result).to.be.true;
        });

        it('Should accept SVG with nested groups and paths', () => {
            const validSvg = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" baseProfile="tiny-ps" version="1.2" viewBox="0 0 100 100">
    <title>Complex Logo</title>
    <g>
        <g>
            <path d="M10 10 L90 10 L90 90 L10 90 Z" fill="red"/>
        </g>
        <circle cx="50" cy="50" r="30" fill="blue"/>
    </g>
</svg>`;

            const result = validateSvg(validSvg);
            expect(result).to.be.true;
        });

        it('Should accept SVG with various valid elements', () => {
            const validSvg = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" baseProfile="tiny-ps" version="1.2" viewBox="0 0 100 100">
    <title>Multi-element Logo</title>
    <rect x="10" y="10" width="30" height="30" fill="red"/>
    <circle cx="70" cy="30" r="15" fill="green"/>
    <ellipse cx="30" cy="70" rx="20" ry="10" fill="blue"/>
    <line x1="50" y1="50" x2="90" y2="90" stroke="black"/>
    <polygon points="60,70 70,90 80,70" fill="yellow"/>
    <polyline points="10,90 20,80 30,90" stroke="purple" fill="none"/>
</svg>`;

            const result = validateSvg(validSvg);
            expect(result).to.be.true;
        });
    });

    describe('XML parsing errors', () => {
        it('Should reject empty input', () => {
            try {
                validateSvg('');
                expect.fail('Should have thrown');
            } catch (err) {
                // Empty input may fail as XML or SVG
                expect(['INVALID_XML_FILE', 'INVALID_SVG_FILE']).to.include(err.code);
            }
        });

        it('Should reject non-XML content', () => {
            try {
                validateSvg('This is not XML content at all');
                expect.fail('Should have thrown');
            } catch (err) {
                expect(err.code).to.equal('INVALID_SVG_FILE');
            }
        });

        it('Should reject HTML instead of SVG', () => {
            const html = `<!DOCTYPE html>
<html>
<head><title>Not SVG</title></head>
<body>This is HTML</body>
</html>`;

            try {
                validateSvg(html);
                expect.fail('Should have thrown');
            } catch (err) {
                expect(err.code).to.equal('INVALID_SVG_FILE');
            }
        });
    });

    describe('Structure validation', () => {
        it('Should reject SVG without tiny-ps baseProfile', () => {
            const invalidProfile = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" baseProfile="full" version="1.2" viewBox="0 0 100 100">
    <title>Test Logo</title>
    <rect width="100" height="100" fill="blue"/>
</svg>`;

            try {
                validateSvg(invalidProfile);
                expect.fail('Should have thrown');
            } catch (err) {
                expect(err.code).to.equal('INVALID_BASE_PROFILE');
            }
        });

        it('Should reject SVG without baseProfile attribute', () => {
            const noProfile = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" version="1.2" viewBox="0 0 100 100">
    <title>Test Logo</title>
    <rect width="100" height="100" fill="blue"/>
</svg>`;

            try {
                validateSvg(noProfile);
                expect.fail('Should have thrown');
            } catch (err) {
                expect(err.code).to.equal('INVALID_BASE_PROFILE');
            }
        });

        it('Should reject SVG without title element', () => {
            const noTitle = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" baseProfile="tiny-ps" version="1.2" viewBox="0 0 100 100">
    <rect width="100" height="100" fill="blue"/>
</svg>`;

            try {
                validateSvg(noTitle);
                expect.fail('Should have thrown');
            } catch (err) {
                expect(err.code).to.equal('LOGO_MISSING_TITLE');
            }
        });

        it('Should reject SVG with x attribute on root', () => {
            const withX = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" baseProfile="tiny-ps" version="1.2" viewBox="0 0 100 100" x="10">
    <title>Test Logo</title>
    <rect width="100" height="100" fill="blue"/>
</svg>`;

            try {
                validateSvg(withX);
                expect.fail('Should have thrown');
            } catch (err) {
                expect(err.code).to.equal('LOGO_INVALID_ROOT_ATTRS');
            }
        });

        it('Should reject SVG with y attribute on root', () => {
            const withY = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" baseProfile="tiny-ps" version="1.2" viewBox="0 0 100 100" y="10">
    <title>Test Logo</title>
    <rect width="100" height="100" fill="blue"/>
</svg>`;

            try {
                validateSvg(withY);
                expect.fail('Should have thrown');
            } catch (err) {
                expect(err.code).to.equal('LOGO_INVALID_ROOT_ATTRS');
            }
        });
    });

    describe('Disallowed elements', () => {
        it('Should reject SVG with script element', () => {
            const withScript = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" baseProfile="tiny-ps" version="1.2" viewBox="0 0 100 100">
    <title>Test Logo</title>
    <script>alert('XSS')</script>
    <rect width="100" height="100" fill="blue"/>
</svg>`;

            try {
                validateSvg(withScript);
                expect.fail('Should have thrown');
            } catch (err) {
                expect(err.code).to.equal('LOGO_INVALID_ELEMENT');
                expect(err.details.element.toLowerCase()).to.equal('script');
            }
        });

        it('Should reject SVG with animate element', () => {
            const withAnimate = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" baseProfile="tiny-ps" version="1.2" viewBox="0 0 100 100">
    <title>Test Logo</title>
    <rect width="100" height="100" fill="blue">
        <animate attributeName="fill" values="blue;red;blue" dur="3s" repeatCount="indefinite"/>
    </rect>
</svg>`;

            try {
                validateSvg(withAnimate);
                expect.fail('Should have thrown');
            } catch (err) {
                expect(err.code).to.equal('LOGO_INVALID_ELEMENT');
                expect(err.details.element.toLowerCase()).to.equal('animate');
            }
        });

        it('Should reject SVG with animateMotion element', () => {
            const withAnimateMotion = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" baseProfile="tiny-ps" version="1.2" viewBox="0 0 100 100">
    <title>Test Logo</title>
    <circle cx="10" cy="50" r="5" fill="red">
        <animateMotion path="M 0 0 L 80 0" dur="2s" repeatCount="indefinite"/>
    </circle>
</svg>`;

            try {
                validateSvg(withAnimateMotion);
                expect.fail('Should have thrown');
            } catch (err) {
                expect(err.code).to.equal('LOGO_INVALID_ELEMENT');
                expect(err.details.element.toLowerCase()).to.equal('animatemotion');
            }
        });

        it('Should reject SVG with animateTransform element', () => {
            const withAnimateTransform = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" baseProfile="tiny-ps" version="1.2" viewBox="0 0 100 100">
    <title>Test Logo</title>
    <rect x="20" y="20" width="60" height="60" fill="green">
        <animateTransform attributeName="transform" type="rotate" from="0 50 50" to="360 50 50" dur="5s" repeatCount="indefinite"/>
    </rect>
</svg>`;

            try {
                validateSvg(withAnimateTransform);
                expect.fail('Should have thrown');
            } catch (err) {
                expect(err.code).to.equal('LOGO_INVALID_ELEMENT');
                expect(err.details.element.toLowerCase()).to.equal('animatetransform');
            }
        });

        it('Should reject SVG with set element', () => {
            const withSet = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" baseProfile="tiny-ps" version="1.2" viewBox="0 0 100 100">
    <title>Test Logo</title>
    <rect width="100" height="100" fill="blue">
        <set attributeName="fill" to="red" begin="1s"/>
    </rect>
</svg>`;

            try {
                validateSvg(withSet);
                expect.fail('Should have thrown');
            } catch (err) {
                expect(err.code).to.equal('LOGO_INVALID_ELEMENT');
                expect(err.details.element.toLowerCase()).to.equal('set');
            }
        });

        it('Should reject SVG with discard element', () => {
            const withDiscard = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" baseProfile="tiny-ps" version="1.2" viewBox="0 0 100 100">
    <title>Test Logo</title>
    <rect id="myRect" width="100" height="100" fill="blue">
        <discard begin="5s"/>
    </rect>
</svg>`;

            try {
                validateSvg(withDiscard);
                expect.fail('Should have thrown');
            } catch (err) {
                expect(err.code).to.equal('LOGO_INVALID_ELEMENT');
                expect(err.details.element.toLowerCase()).to.equal('discard');
            }
        });

        it('Should reject nested disallowed elements', () => {
            const nestedScript = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" baseProfile="tiny-ps" version="1.2" viewBox="0 0 100 100">
    <title>Test Logo</title>
    <g>
        <g>
            <g>
                <script>alert('deep')</script>
            </g>
        </g>
    </g>
</svg>`;

            try {
                validateSvg(nestedScript);
                expect.fail('Should have thrown');
            } catch (err) {
                expect(err.code).to.equal('LOGO_INVALID_ELEMENT');
            }
        });
    });

    describe('External references', () => {
        it('Should reject SVG with external http xlink:href', () => {
            const externalHttp = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" baseProfile="tiny-ps" version="1.2" viewBox="0 0 100 100">
    <title>Test Logo</title>
    <image xlink:href="http://evil.com/image.png" width="100" height="100"/>
</svg>`;

            try {
                validateSvg(externalHttp);
                expect.fail('Should have thrown');
            } catch (err) {
                expect(err.code).to.equal('LOGO_INCLUDES_REFERENCE');
            }
        });

        it('Should reject SVG with external https xlink:href', () => {
            const externalHttps = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" baseProfile="tiny-ps" version="1.2" viewBox="0 0 100 100">
    <title>Test Logo</title>
    <image xlink:href="https://external.com/image.png" width="100" height="100"/>
</svg>`;

            try {
                validateSvg(externalHttps);
                expect.fail('Should have thrown');
            } catch (err) {
                expect(err.code).to.equal('LOGO_INCLUDES_REFERENCE');
            }
        });

        it('Should reject SVG with external data URI', () => {
            const dataUri = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" baseProfile="tiny-ps" version="1.2" viewBox="0 0 100 100">
    <title>Test Logo</title>
    <image xlink:href="data:image/png;base64,iVBORw0KGgo=" width="100" height="100"/>
</svg>`;

            try {
                validateSvg(dataUri);
                expect.fail('Should have thrown');
            } catch (err) {
                expect(err.code).to.equal('LOGO_INCLUDES_REFERENCE');
            }
        });

        it('Should allow internal #id references', () => {
            const internalRef = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" baseProfile="tiny-ps" version="1.2" viewBox="0 0 100 100">
    <title>Test Logo</title>
    <defs>
        <rect id="myRect" width="50" height="50" fill="blue"/>
    </defs>
    <use xlink:href="#myRect" x="25" y="25"/>
</svg>`;

            const result = validateSvg(internalRef);
            expect(result).to.be.true;
        });

        it('Should reject external reference in nested element', () => {
            const nestedExternal = `<?xml version="1.0" encoding="UTF-8"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" baseProfile="tiny-ps" version="1.2" viewBox="0 0 100 100">
    <title>Test Logo</title>
    <g>
        <g>
            <use xlink:href="http://evil.com/element"/>
        </g>
    </g>
</svg>`;

            try {
                validateSvg(nestedExternal);
                expect.fail('Should have thrown');
            } catch (err) {
                expect(err.code).to.equal('LOGO_INCLUDES_REFERENCE');
                expect(err.details.link).to.equal('http://evil.com/element');
            }
        });
    });

    describe('Error codes', () => {
        it('Should return error for unparseable content', () => {
            try {
                validateSvg('<<<not valid xml>>>');
                expect.fail('Should have thrown');
            } catch (err) {
                // Parser may return XML or SVG error
                expect(['INVALID_XML_FILE', 'INVALID_SVG_FILE']).to.include(err.code);
            }
        });

        it('Should return INVALID_SVG_FILE for non-SVG XML', () => {
            const nonSvgXml = `<?xml version="1.0"?><root><child/></root>`;

            try {
                validateSvg(nonSvgXml);
                expect.fail('Should have thrown');
            } catch (err) {
                expect(err.code).to.equal('INVALID_SVG_FILE');
            }
        });

        it('Should return INVALID_BASE_PROFILE for wrong profile', () => {
            const wrongProfile = `<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg" baseProfile="basic">
    <title>Test</title>
</svg>`;

            try {
                validateSvg(wrongProfile);
                expect.fail('Should have thrown');
            } catch (err) {
                expect(err.code).to.equal('INVALID_BASE_PROFILE');
            }
        });

        it('Should return LOGO_MISSING_TITLE for missing title', () => {
            const noTitle = `<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg" baseProfile="tiny-ps">
    <rect width="100" height="100"/>
</svg>`;

            try {
                validateSvg(noTitle);
                expect.fail('Should have thrown');
            } catch (err) {
                expect(err.code).to.equal('LOGO_MISSING_TITLE');
            }
        });

        it('Should return LOGO_INVALID_ROOT_ATTRS for x/y on root', () => {
            const withRootXY = `<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg" baseProfile="tiny-ps" x="0" y="0">
    <title>Test</title>
</svg>`;

            try {
                validateSvg(withRootXY);
                expect.fail('Should have thrown');
            } catch (err) {
                expect(err.code).to.equal('LOGO_INVALID_ROOT_ATTRS');
            }
        });

        it('Should return LOGO_INVALID_ELEMENT with details for script', () => {
            const withScript = `<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg" baseProfile="tiny-ps">
    <title>Test</title>
    <script>bad</script>
</svg>`;

            try {
                validateSvg(withScript);
                expect.fail('Should have thrown');
            } catch (err) {
                expect(err.code).to.equal('LOGO_INVALID_ELEMENT');
                expect(err.details).to.be.an('object');
                expect(err.details.element.toLowerCase()).to.equal('script');
                expect(err.details.path).to.be.a('string');
            }
        });

        it('Should return LOGO_INCLUDES_REFERENCE with details for external ref', () => {
            const withRef = `<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" baseProfile="tiny-ps">
    <title>Test</title>
    <use xlink:href="http://bad.com/ref"/>
</svg>`;

            try {
                validateSvg(withRef);
                expect.fail('Should have thrown');
            } catch (err) {
                expect(err.code).to.equal('LOGO_INCLUDES_REFERENCE');
                expect(err.details).to.be.an('object');
                expect(err.details.link).to.equal('http://bad.com/ref');
                expect(err.details.element).to.equal('use');
            }
        });
    });

    describe('Edge cases', () => {
        it('Should handle SVG with arrays of elements', () => {
            const arrayElements = `<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg" baseProfile="tiny-ps">
    <title>Test</title>
    <rect width="10" height="10"/>
    <rect width="20" height="20"/>
    <rect width="30" height="30"/>
</svg>`;

            const result = validateSvg(arrayElements);
            expect(result).to.be.true;
        });

        it('Should handle deeply nested valid structure', () => {
            const deepNesting = `<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg" baseProfile="tiny-ps">
    <title>Test</title>
    <g><g><g><g><g><g><g><g><g><g>
        <rect width="10" height="10"/>
    </g></g></g></g></g></g></g></g></g></g>
</svg>`;

            const result = validateSvg(deepNesting);
            expect(result).to.be.true;
        });

        it('Should handle case variations in disallowed elements', () => {
            const upperScript = `<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg" baseProfile="tiny-ps">
    <title>Test</title>
    <SCRIPT>bad</SCRIPT>
</svg>`;

            try {
                validateSvg(upperScript);
                expect.fail('Should have thrown');
            } catch (err) {
                expect(err.code).to.equal('LOGO_INVALID_ELEMENT');
            }
        });

        it('Should handle SVG with text content', () => {
            const withText = `<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg" baseProfile="tiny-ps">
    <title>Test Logo</title>
    <text x="50" y="50">Hello World</text>
</svg>`;

            const result = validateSvg(withText);
            expect(result).to.be.true;
        });
    });
});
