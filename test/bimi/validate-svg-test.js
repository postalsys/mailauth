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

    describe('SVG Tiny PS allowlist', () => {
        const head = '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.2" baseProfile="tiny-ps"';

        const rejects = {
            'prefixed script element': [
                `${head} xmlns:s="http://www.w3.org/2000/svg"><title>t</title><s:script>alert(1)</s:script></svg>`,
                'LOGO_INVALID_ELEMENT'
            ],
            'onload attribute on root': [`${head} onload="alert(1)"><title>t</title></svg>`, 'LOGO_INVALID_ATTRIBUTE'],
            'onclick attribute on a child': [`${head}><title>t</title><rect width="1" height="1" onclick="alert(1)"/></svg>`, 'LOGO_INVALID_ATTRIBUTE'],
            'upper case event attribute': [`${head}><title>t</title><rect width="1" height="1" ONCLICK="alert(1)"/></svg>`, 'LOGO_INVALID_ATTRIBUTE'],
            'event attribute in another namespace': [
                `${head} xmlns:ev="http://www.w3.org/2001/xml-events"><title>t</title><rect ev:onclick="x"/></svg>`,
                'LOGO_INVALID_ATTRIBUTE'
            ],
            'handler element': [`${head}><title>t</title><handler type="application/ecmascript">alert(1)</handler></svg>`, 'LOGO_INVALID_ELEMENT'],
            foreignObject: [
                `${head}><title>t</title><foreignObject><div xmlns="http://www.w3.org/1999/xhtml"><iframe src="https://evil.test/"/></div></foreignObject></svg>`,
                'LOGO_INVALID_ELEMENT'
            ],
            'XHTML element': [`${head}><title>t</title><h:div xmlns:h="http://www.w3.org/1999/xhtml">x</h:div></svg>`, 'LOGO_INVALID_ELEMENT'],
            'image with SVG 2 href': [
                `${head}><title>t</title><image href="https://evil.test/track.png" width="1" height="1"/></svg>`,
                'LOGO_INCLUDES_REFERENCE'
            ],
            'image with a same-document href': [`${head}><title>t</title><image href="#a" width="1" height="1"/></svg>`, 'LOGO_INVALID_ELEMENT'],
            'use with xlink bound to another prefix': [
                '<svg xmlns="http://www.w3.org/2000/svg" xmlns:x="http://www.w3.org/1999/xlink" version="1.2" baseProfile="tiny-ps"><title>t</title><use x:href="https://evil.test/a.svg#x"/></svg>',
                'LOGO_INCLUDES_REFERENCE'
            ],
            'a with javascript: href': [
                `${head}><title>t</title><a href="javascript:alert(1)"><rect width="1" height="1"/></a></svg>`,
                'LOGO_INCLUDES_REFERENCE'
            ],
            'a with a same-document href': [`${head}><title>t</title><a href="#x"><rect width="1" height="1"/></a></svg>`, 'LOGO_INVALID_ELEMENT'],
            'external url() in style element': [
                `${head}><title>t</title><style>rect{fill:url(https://evil.test/x)}</style><rect width="1" height="1"/></svg>`,
                'LOGO_INCLUDES_REFERENCE'
            ],
            'external url() in CDATA style': [
                `${head}><title>t</title><style><![CDATA[rect{fill:url( 'https://evil.test/x' )}]]></style></svg>`,
                'LOGO_INCLUDES_REFERENCE'
            ],
            'CSS import': [`${head}><title>t</title><style>@import "https://evil.test/x.css";</style></svg>`, 'LOGO_INCLUDES_REFERENCE'],
            'CSS escape': [`${head}><title>t</title><style>rect{fill:\\75 rl(https://evil.test/x)}</style></svg>`, 'LOGO_INCLUDES_REFERENCE'],
            'CSS image-set': [`${head}><title>t</title><rect style="fill:image-set('https://evil.test/x' 1x)"/></svg>`, 'LOGO_INCLUDES_REFERENCE'],
            'external url() in presentation attribute': [`${head}><title>t</title><rect fill="url(https://evil.test/x)"/></svg>`, 'LOGO_INCLUDES_REFERENCE'],
            'character reference hiding url()': [`${head}><title>t</title><rect fill="&#x75;rl(https://evil.test/x)"/></svg>`, 'LOGO_INCLUDES_REFERENCE'],
            'audio and switch': [`${head}><title>t</title><switch><audio xlink:href="#a"/></switch></svg>`, 'LOGO_INVALID_ELEMENT'],
            'unknown SVG element': [`${head}><title>t</title><iframe/></svg>`, 'LOGO_INVALID_ELEMENT'],
            'feImage filter primitive': [`${head}><title>t</title><filter id="f"><feImage xlink:href="#a"/></filter></svg>`, 'LOGO_INVALID_ELEMENT'],
            'unprefixed script in a foreign namespace': [
                `${head}><title>t</title><g xmlns="urn:x"><script>alert(1)</script></g></svg>`,
                'LOGO_INVALID_ELEMENT'
            ],
            'SVG element in metadata': [`${head}><title>t</title><metadata><script>alert(1)</script></metadata></svg>`, 'LOGO_INVALID_ELEMENT'],
            'font element with HTML attributes': [`${head}><title>t</title><font color="red"/></svg>`, 'LOGO_INVALID_ELEMENT'],
            'xml:base': [`${head} xml:base="https://evil.test/"><title>t</title><use xlink:href="#a"/></svg>`, 'LOGO_INVALID_ATTRIBUTE'],
            'xml-stylesheet processing instruction': [
                `<?xml-stylesheet href="https://evil.test/x.css"?>${head}><title>t</title></svg>`,
                'LOGO_INVALID_CONTENT'
            ],
            'processing instruction in content': [`${head}><title>t</title><?foo bar?></svg>`, 'LOGO_INVALID_CONTENT'],
            'markup in CDATA': [`${head}><title><![CDATA[</title><img src=x onerror=alert(1)>]]></title></svg>`, 'LOGO_INVALID_CONTENT'],
            'comment that HTML ends early': [`${head}><title>t</title><!--><img src=x onerror=alert(1)>--></svg>`, 'LOGO_INVALID_CONTENT'],
            'DTD with entity declarations': [`<!DOCTYPE svg [<!ENTITY x "<script>alert(1)</script>">]>${head}><title>t</title>&x;</svg>`, 'INVALID_XML_FILE'],
            'undefined entity': [`${head}><title>&x;</title></svg>`, 'INVALID_XML_FILE'],
            'undeclared namespace prefix': [`${head}><title>t</title><x:rect/></svg>`, 'INVALID_XML_FILE'],
            'repeated attribute': [`${head}><title>t</title><rect fill="red" fill="blue"/></svg>`, 'INVALID_XML_FILE'],
            'mismatched tags': [`${head}><title>t</title><g></rect></svg>`, 'INVALID_XML_FILE'],
            'invalid XML declaration': [`<?xml version="1.0" encoding="x><img src=x onerror=alert(1)>"?>${head}><title>t</title></svg>`, 'INVALID_XML_FILE']
        };

        for (let [name, [svg, code]] of Object.entries(rejects)) {
            it(`Should reject ${name}`, () => {
                let error;
                try {
                    validateSvg(Buffer.from(svg));
                } catch (err) {
                    error = err;
                }
                expect(error, 'validation error').to.exist;
                expect(error.code).to.equal(code);
            });
        }

        it('Should accept same-document references and static elements', () => {
            const svg = `<?xml version="1.0" encoding="utf-8"?>
<!-- Generator: Adobe Illustrator 24.1.0, SVG Export Plug-In . SVG Version: 6.00 Build 0)  -->
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
<svg version="1.2" baseProfile="tiny-ps" id="Layer_1" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" viewBox="0 0 10 10" xml:space="preserve">
<title>AT&amp;T &#x2122;</title>
<style type="text/css"><![CDATA[ .st0{fill:url(#g1)} .st1{clip-path:url( "#c1" )} ]]></style>
<defs>
    <linearGradient id="g1"><stop offset="0" stop-color="#fff"/><stop offset="1" stop-color="#000"/></linearGradient>
    <linearGradient id="g2" xlink:href="#g1"/>
    <clipPath id="c1"><rect width="5" height="5"/></clipPath>
</defs>
<g class="st0" style="fill:url('#g2')"><rect width="10" height="10"/></g>
<use href=" #c1"/>
</svg>`;
            expect(validateSvg(Buffer.from(svg))).to.be.true;
        });

        it('Should accept metadata in other namespaces', () => {
            const svg = `${head} xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns:cc="http://creativecommons.org/ns#" xmlns:dc="http://purl.org/dc/elements/1.1/">
<title>t</title>
<metadata><rdf:RDF><cc:Work rdf:about=""><dc:format>image/svg+xml</dc:format><dc:type rdf:resource="http://purl.org/dc/dcmitype/StillImage"/></cc:Work></rdf:RDF></metadata>
<rect width="1" height="1"/>
</svg>`;
            expect(validateSvg(Buffer.from(svg))).to.be.true;
        });
    });

    describe('SVG Tiny PS document rules', () => {
        const svgNs = 'xmlns="http://www.w3.org/2000/svg"';

        const run = (svg, strict) => {
            let warnings = [];
            try {
                validateSvg(Buffer.from(svg), { strict, warnings });
            } catch (err) {
                return { error: err, warnings };
            }
            return { warnings };
        };

        it('Should reject a root element without the SVG namespace in both modes', () => {
            for (let svg of [
                '<svg xmlns="http://example.com/not-svg" version="1.2" baseProfile="tiny-ps"><title>t</title></svg>',
                '<svg version="1.2" baseProfile="tiny-ps"><title>t</title></svg>',
                '<x:svg xmlns:x="http://example.com/not-svg" version="1.2" baseProfile="tiny-ps"><title>t</title></x:svg>'
            ]) {
                for (let strict of [false, true]) {
                    expect(run(svg, strict).error?.code, svg).to.equal('INVALID_SVG_FILE');
                }
            }
        });

        it('Should accept a prefixed root element in the SVG namespace', () => {
            const svg = '<s:svg xmlns:s="http://www.w3.org/2000/svg" version="1.2" baseProfile="tiny-ps"><s:title>t</s:title></s:svg>';
            expect(run(svg, true).error).to.not.exist;
        });

        const laxCases = {
            'missing version': [`<svg ${svgNs} baseProfile="tiny-ps"><title>t</title></svg>`, 'INVALID_SVG_VERSION', 'svg-version'],
            'other version': [`<svg ${svgNs} version="1.1" baseProfile="tiny-ps"><title>t</title></svg>`, 'INVALID_SVG_VERSION', 'svg-version'],
            'two titles': [
                `<svg ${svgNs} version="1.2" baseProfile="tiny-ps"><title>t</title><title>u</title></svg>`,
                'LOGO_MULTIPLE_TITLES',
                'svg-title-count'
            ],
            'title that is not the first child': [
                `<svg ${svgNs} version="1.2" baseProfile="tiny-ps"><desc>d</desc><title>t</title></svg>`,
                'LOGO_INVALID_ELEMENT',
                'svg-title-position'
            ],
            'nested title': [
                `<svg ${svgNs} version="1.2" baseProfile="tiny-ps"><title>t</title><g><title>u</title></g></svg>`,
                'LOGO_INVALID_ELEMENT',
                'svg-title-position'
            ],
            'zoomAndPan="magnify"': [
                `<svg ${svgNs} version="1.2" baseProfile="tiny-ps" zoomAndPan="magnify"><title>t</title></svg>`,
                'LOGO_INVALID_ATTRIBUTE',
                'svg-attribute-value'
            ],
            'externalResourcesRequired="true"': [
                `<svg ${svgNs} version="1.2" baseProfile="tiny-ps" externalResourcesRequired="true"><title>t</title></svg>`,
                'LOGO_INVALID_ATTRIBUTE',
                'svg-attribute-value'
            ],
            'editable text': [
                `<svg ${svgNs} version="1.2" baseProfile="tiny-ps"><title>t</title><text editable="simple">x</text></svg>`,
                'LOGO_INVALID_ATTRIBUTE',
                'svg-attribute-value'
            ],
            'empty desc': [`<svg ${svgNs} version="1.2" baseProfile="tiny-ps"><title>t</title><desc> </desc></svg>`, 'LOGO_INVALID_CONTENT', 'svg-empty-desc'],
            'element outside the profile': [
                `<svg ${svgNs} version="1.2" baseProfile="tiny-ps"><title>t</title><clipPath id="c"><rect width="1" height="1"/></clipPath></svg>`,
                'LOGO_INVALID_ELEMENT',
                'svg-element'
            ],
            'element in another namespace': [
                `<svg ${svgNs} xmlns:i="http://www.inkscape.org/namespaces/inkscape" version="1.2" baseProfile="tiny-ps"><title>t</title><i:grid/></svg>`,
                'LOGO_INVALID_ELEMENT',
                'svg-foreign-element'
            ],
            'element in metadata': [
                `<svg ${svgNs} xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" version="1.2" baseProfile="tiny-ps"><title>t</title><metadata><rdf:RDF/></metadata></svg>`,
                'LOGO_INVALID_ELEMENT',
                'svg-metadata-content'
            ]
        };

        for (let [name, [svg, code, warning]] of Object.entries(laxCases)) {
            it(`Should accept ${name} with a warning, and reject it in strict mode`, () => {
                let lax = run(svg, false);
                expect(lax.error).to.not.exist;
                expect(lax.warnings).to.deep.equal([warning]);

                let strict = run(svg, true);
                expect(strict.error?.code).to.equal(code);
            });
        }

        it('Should accept zoomAndPan="disable" and the example document of the profile in strict mode', () => {
            const svg = `<?xml version="1.0"?>
<svg width="400px" height="400px" xmlns="http://www.w3.org/2000/svg"
    version="1.2" baseProfile="tiny-ps"
    zoomAndPan="disable" externalResourcesRequired="false">
  <title>Example, Inc.</title>
  <desc>Logo for Example, Inc.</desc>
  <rect x="1" y="1" width="399" height="399" fill="teal"
     stroke="gray" stroke-width="9"/>
  <circle cx="200" cy="200" r="125" fill="white"
     stroke="black" stroke-width="2"/>
  <polyline fill="gray" stroke="silver" stroke-width="9"
     points="40,30 25,40 100,330 310,270 290,250 120,300 40,26"/>
</svg>`;
            let result = run(svg, true);
            expect(result.error).to.not.exist;
            expect(result.warnings).to.deep.equal([]);
        });
    });
});
