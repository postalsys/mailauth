/* eslint no-unused-expressions:0 */
'use strict';

const { Buffer } = require('node:buffer');
const chai = require('chai');
const expect = chai.expect;

let { bimi, validateVMC } = require('../lib/bimi');

chai.config.includeStack = true;

// NB! these tests perform live DNS and HTTPS queries

const dnsReject = () => {
    let err = new Error('Error');
    err.code = 'ENOTFOUND';
    throw err;
};

describe('BIMI Tests', () => {
    it('Should resolve BIMI location', async () => {
        let res = await bimi({
            dmarc: {
                status: {
                    result: 'pass',
                    header: {
                        from: 'gmail.com'
                    }
                },
                domain: 'gmail.com',
                policy: 'reject'
            },
            resolver: async (name, rr) => {
                if (rr !== 'TXT') {
                    dnsReject();
                }
                switch (name) {
                    case 'default._bimi.gmail.com':
                        return [['v=BIMI1; l=https:', '//cldup.com/a6t0ORNG2z.svg']];
                    default: {
                        dnsReject();
                    }
                }
            }
        });

        expect(res?.status?.result).to.equal('pass');
        expect(res?.status?.header).to.deep.equal({ selector: 'default', d: 'gmail.com' });
        expect(res?.location).to.equal('https://cldup.com/a6t0ORNG2z.svg');
    });

    it('Should resolve author BIMI location', async () => {
        let res = await bimi({
            dmarc: {
                status: {
                    result: 'pass',
                    header: {
                        from: 'sub.gmail.com'
                    }
                },
                domain: 'gmail.com',
                policy: 'reject'
            },
            resolver: async (name, rr) => {
                if (rr !== 'TXT') {
                    dnsReject();
                }
                switch (name) {
                    case 'default._bimi.sub.gmail.com':
                        return [['v=BIMI1; l=https:', '//cldup.com/a6t0ORNG2y.svg']];
                    case 'default._bimi.gmail.com':
                        return [['v=BIMI1; l=https:', '//cldup.com/a6t0ORNG2z.svg']];
                    default: {
                        dnsReject();
                    }
                }
            }
        });

        expect(res?.status?.result).to.equal('pass');
        expect(res?.status?.header).to.deep.equal({ selector: 'default', d: 'sub.gmail.com' });
        expect(res?.location).to.equal('https://cldup.com/a6t0ORNG2y.svg');
    });

    it('Should resolve organization BIMI location', async () => {
        let res = await bimi({
            dmarc: {
                status: {
                    result: 'pass',
                    header: {
                        from: 'sub.gmail.com'
                    }
                },
                domain: 'gmail.com',
                policy: 'reject'
            },
            resolver: async (name, rr) => {
                if (rr !== 'TXT') {
                    dnsReject();
                }
                switch (name) {
                    case 'default._bimi.gmail.com':
                        return [['v=BIMI1; l=https:', '//cldup.com/a6t0ORNG2z.svg']];
                    default: {
                        dnsReject();
                    }
                }
            }
        });

        expect(res?.status?.result).to.equal('pass');
        expect(res?.status?.header).to.deep.equal({ selector: 'default', d: 'gmail.com' });
        expect(res?.location).to.equal('https://cldup.com/a6t0ORNG2z.svg');
    });

    it('Should resolve BIMI location with specific selector', async () => {
        let res = await bimi({
            dmarc: {
                status: {
                    result: 'pass',
                    header: {
                        from: 'gmail.com'
                    }
                },
                domain: 'gmail.com',
                policy: 'reject',
                alignment: {
                    spf: { result: 'gmail.com', strict: false },
                    dkim: { result: 'gmail.com', strict: false }
                }
            },

            headers: {
                parsed: [
                    {
                        key: 'bimi-selector',
                        line: 'v=BIMI1; s=test'
                    }
                ]
            },

            resolver: async (name, rr) => {
                if (rr !== 'TXT') {
                    dnsReject();
                }
                switch (name) {
                    case 'test._bimi.gmail.com':
                        return [['v=BIMI1; l=https:', '//cldup.com/a6t0ORNG2z.svg']];
                    default: {
                        dnsReject();
                    }
                }
            },

            bimiWithAlignedDkim: false
        });

        expect(res?.status?.result).to.equal('pass');
        expect(res?.status?.header).to.deep.equal({ selector: 'test', d: 'gmail.com' });
        expect(res?.location).to.equal('https://cldup.com/a6t0ORNG2z.svg');
    });

    it('Should resolve BIMI location with valid DKIM', async () => {
        let res = await bimi({
            dmarc: {
                status: {
                    result: 'pass',
                    header: {
                        from: 'gmail.com'
                    }
                },
                domain: 'gmail.com',
                policy: 'reject',
                alignment: {
                    spf: { result: false, strict: false },
                    dkim: { result: 'gmail.com', strict: false }
                }
            },

            resolver: async (name, rr) => {
                if (rr !== 'TXT') {
                    dnsReject();
                }
                switch (name) {
                    case 'default._bimi.gmail.com':
                        return [['v=BIMI1; l=https:', '//cldup.com/a6t0ORNG2z.svg']];
                    default: {
                        dnsReject();
                    }
                }
            },

            bimiWithAlignedDkim: true
        });

        expect(res?.status?.result).to.equal('pass');
        expect(res?.status?.header).to.deep.equal({ selector: 'default', d: 'gmail.com' });
        expect(res?.location).to.equal('https://cldup.com/a6t0ORNG2z.svg');
    });

    it('Should fail resolving BIMI location without valid DKIM', async () => {
        let res = await bimi({
            dmarc: {
                status: {
                    result: 'pass',
                    header: {
                        from: 'gmail.com'
                    }
                },
                domain: 'gmail.com',
                policy: 'reject',
                alignment: {
                    spf: { result: 'gmail.com', strict: false },
                    dkim: { result: false, strict: false }
                }
            },

            resolver: async (name, rr) => {
                if (rr !== 'TXT') {
                    dnsReject();
                }
                switch (name) {
                    case 'default._bimi.gmail.com':
                        return [['v=BIMI1; l=https:', '//cldup.com/a6t0ORNG2z.svg']];
                    default: {
                        dnsReject();
                    }
                }
            },

            bimiWithAlignedDkim: true
        });

        expect(res?.status?.result).to.equal('skipped');
    });

    it('Should not fail resolving BIMI location without valid DKIM', async () => {
        let res = await bimi({
            dmarc: {
                status: {
                    result: 'pass',
                    header: {
                        from: 'gmail.com'
                    }
                },
                domain: 'gmail.com',
                policy: 'reject',
                alignment: {
                    spf: { result: 'gmail.com', strict: false },
                    dkim: { result: false, strict: false }
                }
            },

            resolver: async (name, rr) => {
                if (rr !== 'TXT') {
                    dnsReject();
                }
                switch (name) {
                    case 'default._bimi.gmail.com':
                        return [['v=BIMI1; l=https:', '//cldup.com/a6t0ORNG2z.svg']];
                    default: {
                        dnsReject();
                    }
                }
            },

            bimiWithAlignedDkim: false
        });

        expect(res?.status?.result).to.equal('pass');
        expect(res?.status?.header).to.deep.equal({ selector: 'default', d: 'gmail.com' });
        expect(res?.location).to.equal('https://cldup.com/a6t0ORNG2z.svg');
    });

    it('Should fail BIMI location with undersized DKIM', async () => {
        let res = await bimi({
            dmarc: {
                status: {
                    result: 'pass',
                    header: {
                        from: 'gmail.com'
                    }
                },
                domain: 'gmail.com',
                policy: 'reject',
                alignment: {
                    spf: { result: false, strict: false },
                    dkim: { result: 'gmail.com', strict: false, underSized: 100 }
                }
            },

            resolver: async (name, rr) => {
                if (rr !== 'TXT') {
                    dnsReject();
                }
                switch (name) {
                    case 'default._bimi.gmail.com':
                        return [['v=BIMI1; l=https:', '//cldup.com/a6t0ORNG2z.svg']];
                    default: {
                        dnsReject();
                    }
                }
            }
        });

        expect(res?.status?.result).to.equal('skipped');
    });

    it('Should validate VMC', async () => {
        let bimiData = {
            location: 'https://amplify.valimail.com/bimi/time-warner/yV3KRIg4nJW-cnn.svg',
            locationPath: Buffer.from(
                `PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0idXRmLTgiPz4KPCEtLSBHZW5lcmF0b3I6IEFkb2JlIElsbHVzdHJhdG9yIDI0LjEuMCwgU1ZHIEV4cG9ydCBQbHVnLUluIC4gU1ZHIFZlcnNpb246IDYuMDAgQnVpbGQgMCkgIC0tPgo8c3ZnIHZlcnNpb249IjEuMiIgYmFzZVByb2ZpbGU9InRpbnktcHMiIGlkPSJMYXllcl8xIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hsaW5rIgp2aWV3Qm94PSIwIDAgOTY3LjUgOTY3LjUiIHhtbDpzcGFjZT0icHJlc2VydmUiPgo8dGl0bGU+Q05OPC90aXRsZT4KPHBhdGggZmlsbD0iI0NDMDAwMCIgZD0iTTc3OS41LDMyMy4ydjI2MS40YzAsMTAuNC02LjUsMTkuMS0xNi4yLDIxLjhjLTEuOSwwLjUtMy44LDAuOC01LjcsMC44Yy03LjQsMC0xNS44LTMuNy0yMi0xNC4xTDY3NCw0ODYuOQoJbC02MS4zLTEwNS44Yy0zLjQtNS44LTguMi04LjUtMTIuNy03LjNjLTMuOSwxLTYuNCw0LjYtNi40LDl2MjAxLjhjMCwxMC40LTYuNSwxOS4xLTE2LjIsMjEuOGMtOC4zLDIuMi0xOS45LTAuMS0yNy43LTEzLjMKCWwtNTYuMi05Ni45bC02Ni43LTExNWMtMy40LTUuOC04LjItOC41LTEyLjgtNy4zYy00LDEuMS02LjYsNC45LTYuNCw5djE5Ny4zYzAsMTMtMTEuNCwyNC40LTI0LjQsMjQuNEgyODMKCWMtNjYuOCwwLTEyMC45LTU0LjEtMTIwLjktMTIwLjhjMC02Ni44LDU0LjEtMTIwLjksMTIwLjgtMTIwLjloMC4xaDUydi0zOS42aC01MmMtODguNiwxLTE1OS43LDczLjctMTU4LjcsMTYyLjMKCWMxLDg3LjIsNzEuNSwxNTcuNywxNTguNywxNTguN2gxMDEuMmMzOC41LDAsNjMuMi0yMi41LDYzLjEtNjQuMXYtOTEuNWMwLDAsNjQuNSwxMTEuMiw2Ny41LDExNi4yYzQxLDY5LjYsMTE4LjQsNDAuOCwxMTguNC0xOS4xCgl2LTk3LjFjMCwwLDY0LjUsMTExLjIsNjcuNSwxMTYuMmM0MSw2OS42LDExOC40LDQwLjgsMTE4LjQtMTkuMVYzMjMuMkg3NzkuNXoiLz4KPHBhdGggZmlsbD0iI0NDMDAwMCIgZD0iTTE3NS4zLDQ4My43YzAuMSw1OS40LDQ4LjIsMTA3LjYsMTA3LjcsMTA3LjdoMTAwLjJjNi4zLDAsMTEuMi02LDExLjItMTEuMlYzODIuOQoJYzAtMTAuNCw2LjUtMTkuMSwxNi4yLTIxLjhjOC4zLTIuMiwxOS45LDAuMSwyNy43LDEzLjNjMC40LDAuNywzNC4xLDU4LjksNjYuOCwxMTUuMWMyOC43LDQ5LjQsNTUuNyw5Niw1Ni4yLDk2LjgKCWMzLjQsNS44LDguMiw4LjUsMTIuOCw3LjNjNC0xLjEsNi42LTQuOSw2LjQtOVYzODIuOWMwLTEwLjQsNi41LTE5LjEsMTYuMS0yMS44YzguMi0yLjIsMTkuOCwwLjEsMjcuNiwxMy4zCgljMC40LDAuNywzMCw1MS43LDYxLjQsMTA1LjhjMzAsNTEuNyw2MSwxMDUuMiw2MS42LDEwNi4xYzMuNCw1LjgsOC4yLDguNSwxMi44LDcuM2M0LTEuMSw2LjYtNC45LDYuNC05VjMyMy4yaC0zOS43djE1NS43CgljMCwwLTY0LjUtMTExLjItNjcuNS0xMTYuMmMtNDEtNjkuNi0xMTguNC00MC44LTExOC40LDE5LjF2OTcuMWMwLDAtNjQuNS0xMTEuMi02Ny41LTExNi4yYy00MS02OS42LTExOC40LTQwLjgtMTE4LjQsMTkuMXYxNTkuMQoJYzAuMSw1LjktNC41LDEwLjctMTAuMywxMC44Yy0wLjEsMC0wLjIsMC0wLjMsMGgtNjAuOGMtMzcuNiwwLTY4LTMwLjQtNjgtNjhzMzAuNC02OCw2OC02OEgzMzVWMzc2aC01MgoJQzIyMy42LDM3Ni4xLDE3NS40LDQyNC4zLDE3NS4zLDQ4My43eiIvPgo8L3N2Zz4K`,
                'base64'
            ),
            authority: 'https://amplify.valimail.com/bimi/time-warner/yV3KRIg4nJW-cnn.pem',
            authorityPath: Buffer.from(
                `LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tDQpNSUlNaURDQ0NuQ2dBd0lCQWdJUUNDRzQvZ3FjdkR1c0VOb0l3SWp1OURBTkJna3Foa2lHOXcwQkFRc0ZBREJmDQpNUXN3Q1FZRFZRUUdFd0pWVXpFWE1CVUdBMVVFQ2hNT1JHbG5hVU5sY25Rc0lFbHVZeTR4TnpBMUJnTlZCQU1UDQpMa1JwWjJsRFpYSjBJRlpsY21sbWFXVmtJRTFoY21zZ1VsTkJOREE1TmlCVFNFRXlOVFlnTWpBeU1TQkRRVEV3DQpIaGNOTWpFd09ERXlNREF3TURBd1doY05Nakl3T0RFeU1qTTFPVFU1V2pDQ0FTSXhIVEFiQmdOVkJBOFRGRkJ5DQphWFpoZEdVZ1QzSm5ZVzVwZW1GMGFXOXVNUk13RVFZTEt3WUJCQUdDTnp3Q0FRTVRBbFZUTVJrd0Z3WUxLd1lCDQpCQUdDTnp3Q0FRSVRDRVJsYkdGM1lYSmxNUkF3RGdZRFZRUUZFd2N5T1RjMk56TXdNUXN3Q1FZRFZRUUdFd0pWDQpVekVRTUE0R0ExVUVDQk1IUjJWdmNtZHBZVEVRTUE0R0ExVUVCeE1IUVhSc1lXNTBZVEViTUJrR0ExVUVDUk1TDQpNVGt3SUUxaGNtbGxkSFJoSUZOMElFNVhNU0V3SHdZRFZRUUtFeGhEWVdKc1pTQk9aWGR6SUU1bGRIZHZjbXNzDQpJRWx1WXk0eElUQWZCZ05WQkFNVEdFTmhZbXhsSUU1bGQzTWdUbVYwZDI5eWF5d2dTVzVqTGpFU01CQUdDaXNHDQpBUVFCZzU1ZkFRTVRBbFZUTVJjd0ZRWUtLd1lCQkFHRG5sOEJCQk1ITlRneE56a3pNRENDQVNJd0RRWUpLb1pJDQpodmNOQVFFQkJRQURnZ0VQQURDQ0FRb0NnZ0VCQUtyQ2RzZ2NacmNsc25MOGJhTi9qNUJvQUxEcStBRnl2L29CDQpVVVczR0g2RWJoOXErbE4wOEJ3b3NqVjdCQVAxSkR3RjI3T1JtaVpJTW5wYkZubW1xZU9OKzNjOHFLTkcwNk53DQpzRjNhdzQwZkdIT1lDczBGU2VmZWYwZHBxYzRtL0plNHMzS1JCS0xxcitmdG5TYlFmb2oxU0w5TUNhZlVQRFQwDQo2a2R6RDR5YlY2WU5tZzFJVm5Kbmp4Uzk3MU05ZVU0SVcrc3pIdHVDUlFIVnFWVU0vWkNWT0wwZnducDVjOWtHDQpjM1RNZ3NnNmxMVGFnd05CWUkxcm90NlcxTU1PUDB1ZDMrS3RzbHdLQ1Fqa2ltZEJwVDBXT3VCQ3FHanFvKzlwDQpvS1NnYndSVFZtUlZFN09MSHFlcVN2NTN5WUVlS0s5YUNqUXkwWUphM2RLcG84M3RtTVVDQXdFQUFhT0NCM2t3DQpnZ2QxTUI4R0ExVWRJd1FZTUJhQUZMNmZ2WTFYYlpXMXJXUERsMDZycUlSZE9nZjFNQjBHQTFVZERnUVdCQlFwDQo2RVM1aWVRL0FJeVE5eUdVYUpWV2xleTNDREFTQmdOVkhSRUVDekFKZ2dkamJtNHVZMjl0TUJNR0ExVWRKUVFNDQpNQW9HQ0NzR0FRVUZCd01mTUlHbEJnTlZIUjhFZ1owd2dab3dTNkJKb0VlR1JXaDBkSEE2THk5amNtd3pMbVJwDQpaMmxqWlhKMExtTnZiUzlFYVdkcFEyVnlkRlpsY21sbWFXVmtUV0Z5YTFKVFFUUXdPVFpUU0VFeU5UWXlNREl4DQpRMEV4TG1OeWJEQkxvRW1nUjRaRmFIUjBjRG92TDJOeWJEUXVaR2xuYVdObGNuUXVZMjl0TDBScFoybERaWEowDQpWbVZ5YVdacFpXUk5ZWEpyVWxOQk5EQTVObE5JUVRJMU5qSXdNakZEUVRFdVkzSnNNRkFHQTFVZElBUkpNRWN3DQpOd1lLWUlaSUFZYjliQUFDQlRBcE1DY0dDQ3NHQVFVRkJ3SUJGaHRvZEhSd09pOHZkM2QzTG1ScFoybGpaWEowDQpMbU52YlM5RFVGTXdEQVlLS3dZQkJBR0RubDhCQVRCa0JnZ3JCZ0VGQlFjQkFRUllNRll3VkFZSUt3WUJCUVVIDQpNQUtHU0doMGRIQTZMeTlqWVdObGNuUnpMbVJwWjJsalpYSjBMbU52YlM5RWFXZHBRMlZ5ZEZabGNtbG1hV1ZrDQpUV0Z5YTFKVFFUUXdPVFpUU0VFeU5UWXlNREl4UTBFeExtTnlkREFNQmdOVkhSTUJBZjhFQWpBQU1JSUZEQVlJDQpLd1lCQlFVSEFRd0VnZ1QrTUlJRStxS0NCUGFnZ2dUeU1JSUU3akNDQk9vd2dnVG1GZzFwYldGblpTOXpkbWNyDQplRzFzTUNNd0lUQUpCZ1VyRGdNQ0dnVUFCQlRxaklIYVl6eG1vV0ppRTBwNFYyemZCblk0NlRDQ0JLNFdnZ1NxDQpaR0YwWVRwcGJXRm5aUzl6ZG1jcmVHMXNPMkpoYzJVMk5DeElOSE5KUVVGQlFVRkJRVUZEY0RGVlZGY3ZZazlDDQpRVGw0Tnl0RGNUVTBTMnRFVTBoR1RDdE5UMFZWWWtaRk1rSmliRVpuUVZZNFdISnhURWQzYlhCMFVURmlhM1JNDQpPU3N6TVVGS01HdE9VVmxCYzJzMVNHbEhia2h1ZWpWc1IxaGllRGNyTjJOWVZVUnhablZ6UmpsWWNFVXdiREp1DQpNWHAxVHpNeVpDdDJjV1oyZVcxVmRsaHRZVzVJTldneFRHbFJOM1IyYUNzeE5FZEdZbWszWlROb1lYbHpLemwyDQpNemxoVTNkMVdWZDFUbmt4VERoMFptdG5NMm80WTBRNFRXOTJkbFF6WkN0eWFsaDFhbWt6VFhjeFZtbEtiMWs0DQpVemNyTmpZdlJtVmhNVVZGYjJndlYyMDJLM2h0UlhKalZGZzNZVzQ1VFdoNUsyUllNamR5YzFwMUx6RXdaRlExDQpXRzlpZEdaV2NDc3pNMlIyYVdKTFowaHJLemxQTmpKdk0ycGpZbFpqYm5NNWJtWllZalpOVG5kMGNsUkdiV2xhDQpVMUJTTVZsUVptSm1MelUyVjBSc1NFNWxiRzFwTVcxTWNqSXZUemQzYzBzMlRVMURTMGh4VURJNGJHbFRjakF6DQpTR0pCVFdoNFlVVXZkRTFNVlZaTlNTOWtNa3hrV0RFMU9DOVllVFZ1WXpOR05UTkpORGRCWTJvNWRXNXdNV1pSDQpNRlZaUWs5Skx6UjNlR0Y1SzJSa1pIQlBUbkJEZFVkNVVFbzJSbTlHZFVOc2NsVm9VekJzV2xvd1lXaFVjRXhKDQpNeko1ZFcxRlVGTnRka2tySzA1cGNuRlhVbkJIU0hvcmJXOXlSbFZGTUdvclJsZE5jelpDV2pCWVJqY3hRMk54DQpaa2xsUkRkMlZVbEJVRW95TTNnM2VGWmFNMGx5WVdOVFVreFJia1pqTVV0SWMyVmlTMGR4THpoRFZqbEtUMWR4DQpVME5RZVhWRWJVa3pTVkl3TkRkTWRYaDRWVWRYWjBGSllrRm1ka2wyU1d0bmVtZHNjVk5hWjFGQ1ExQkpha0Z6DQpiMk5CWjBvd1FVazBhMHBHVlhKWWIzQXhXWGhOUzA1YWR6bE5VVE5YTkV0TGRrZFhUWGhsVVZnclQyWTNjMnc0DQpWUzh5ZW5Wbk0yNXJOMHRhWkRFeVEyeDJNRlpSUTBKQ2VqRkhVM2hJY0hCV09HZHJia0pqYkRoT2VWSlVRbEZEDQpVVzE0UldWUGVraEdaV1IzVkU5aVQxQlJiV3BSZVZsTWIxbERiWGhaTmtFd1VVcHdWbmhGVXpCb1YyNU5SemxIDQpWV3h4ZDI5dFEwZDBjV3RwUlhwQmEyODRSRU5EWkZSVFlWcEdhR1UwU0hwWU9UZDJNVTVGWkhoT1JXUXJVR0YyDQphMHhtVmt3d1IwYzJaREJJT0VScWFWUlpXVVV5YUVad2JrazJWVE53YmtabU1HSkdRVFEwUkhkdFFsUm5jWHBDDQpjM1pITldOek5uaENhbGxDYmtwM1JFMUlSWE5zWjFaYVJWSldTMUZ6U2pnMVJqVnBVblJUWlRFME9IRjRkaTlJDQpRVEZSTUdsSmJERnNRMU5sUkVGTmRYTXhOQzlNT0VsSVMxRnlSR3B6VDNGSFpWbDZMMDlOYlZObFFtZDBUbk53DQpja0ZDU2twQ1dqWnliV1pIUVcxNmVVSm1aMnRvVUVWUE1GUjRVRkZGVFdOb1dqWk5PR2RxWmxORmJsWXJlbTVDDQpMMk56Tm5NMFRFMWxXVTk1VkN0dWQwSTFZbXAwVjJGYWVVa3lLMWMyTUVSNGNsRk9SazFsYVhkdFlUQkVWa1ZDDQpkRVZ2VDJKS01UQllkVkpSTDJNeEwxTnJiMDRyTjNwUkswUlRkSE5aUTFZMVdsVmhTR2hhTWt0blFVTnlaa3BaDQpORnB5VEdGek1FMVdUMmhTU25kNlFuTkxORE4wVmxCcGIwcG1ObVJJVlRWYVprNDROelZxV1hac1RWTTBkWEpwDQpNR0ZFZUVzdlpWSTNVVXBGVTBsd0t5OXJWQzl4WTJoamVHWTVOblpHWmpKNVZIVmlkVGxDWjBGQk1JR0xCZ29yDQpCZ0VFQWRaNUFnUUNCSDBFZXdCNUFIY0FWVmxUcmpDV0FJQnMwdXRTQ0tiSm5wTVlLS3dRVnJSQ0hGVTJGVXhmDQpkYXdBQUFGN083MUxCUUFBQkFNQVNEQkdBaUVBaUVJT0NVdTdFb0l1UmhKVTRLZmV6K3RoVWdtSkNGNVFzbEJMDQp2M1Bicm5nQ0lRQ3VGdng1UXI3ZVFmai9WcHlyZFVPb2ZxbFExZmlscTI5ZEtVV0VVUEN3aVRBTkJna3Foa2lHDQo5dzBCQVFzRkFBT0NBZ0VBWnZJdXViQWluQWFLT3BBT3YvcVp3S1NFYjQ4ZHZiZmJ4djN1L1NROHpld0ZadVhEDQpzSUhaRzNRNXh4T2ZVemYrWEZVdU5vbDk4YjgwdTVUTDFsOFZpa1NrcVRRL0k1L1ExZnJIbEVNUEJEL2hqVmNoDQpPMGVIS0VKaE1xYkFjVTQ0ZVF6dXBONzdLQy9SUGZjY1hKamtJYyt3Y1VrYWZianFQRHB4ZmE5cE42RVRySjZWDQpacjQyaEJSWDFYY1o3NVk1WW5HVjNCaTFFY2ZKWklUN0lxdnRpeTgrRnhUeU1jSy84WHdCbGRvMVdkYnQrQXQ4DQpCWW1DeCtibmFxaEduTzg2ZWQ0ZmNJK1hzQ3dhOStHNXVYWklBWDRIMURzd25lMkdjWFJIdGsyeGFUYm1rc0lLDQpWWVFCVWdLQTBZU1RNcFlEYno4SGc0M1BMYXlQRE9wMEJ0TzMwTFIvS0NGa0NyYXc2S3NYZUE0bDFSdnkyVTJBDQpLMllrVkNTRWZ5MVBsdjJqNXdSTmJFa2hkTFlNVzVOalhNV3Iyay93VkFNT3VvUHR4dWxLcWN4MEZrNWFUejRqDQpEMDJ4bGNxZmNlODQyeGhGaXVZUVY0ZXE4YWVrUHNRTEJSVFpXaVU0RWR4WUxSY1ZWWVRNa1daRkx0MWkvUFBSDQpZY0lWVERxeFAxMG5NaXhxY1hVdkd4Y2NhNWJQeXlNZ2dnM2J1cTE5SlJkY1BEYWdEV3MxdkFONVVUamZWa0ZkDQo0c1Q2aEpNTnBzUXp0VVZGcWltVFpGQURzTTV0M1JTek1QcWdXMHl2RkdCc21UOXUzNmhrR003TU8rckRidWhQDQprTVorMExNclFNQU1NVmxlNVd6TmR3WllPNXN2ZTZXeWJudFc1NzZjQ04wU1JSQ3NrcWtQbTdGclhJWT0NCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0NCi0tLS0tQkVHSU4gQ0VSVElGSUNBVEUtLS0tLQ0KTUlJSEN6Q0NCUE9nQXdJQkFnSVFERnR2ZnV1ejhjS3MzYUU2bUoyOWdqQU5CZ2txaGtpRzl3MEJBUXNGQURDQg0KaURFTE1Ba0dBMVVFQmhNQ1ZWTXhEVEFMQmdOVkJBZ1RCRlYwWVdneERUQUxCZ05WQkFjVEJFeGxhR2t4RnpBVg0KQmdOVkJBb1REa1JwWjJsRFpYSjBMQ0JKYm1NdU1Sa3dGd1lEVlFRTEV4QjNkM2N1WkdsbmFXTmxjblF1WTI5dA0KTVNjd0pRWURWUVFERXg1RWFXZHBRMlZ5ZENCV1pYSnBabWxsWkNCTllYSnJJRkp2YjNRZ1EwRXdIaGNOTWpFdw0KTnpBeE1EQXdNREF3V2hjTk16WXdOak13TWpNMU9UVTVXakJmTVFzd0NRWURWUVFHRXdKVlV6RVhNQlVHQTFVRQ0KQ2hNT1JHbG5hVU5sY25Rc0lFbHVZeTR4TnpBMUJnTlZCQU1UTGtScFoybERaWEowSUZabGNtbG1hV1ZrSUUxaA0KY21zZ1VsTkJOREE1TmlCVFNFRXlOVFlnTWpBeU1TQkRRVEV3Z2dJaU1BMEdDU3FHU0liM0RRRUJBUVVBQTRJQw0KRHdBd2dnSUtBb0lDQVFEY0wyUUpuREJhYi9wekVmM1lvaTZtQVhtS0QzNE1PZ3FNb3VHTFRUNEN2V1N1Z1RpLw0KeGpQUGJGVGYyekpHNFBneDM0WWFJR1l6dm5UU2dwc2NwTmYrc3N0aUFQRHJFUHd1V2svWlFtbzRFNDdjcm5PVg0KaEhUSGx0T2M4WFJpcDFVd0NQek9CMmh3bW5ad0ZUUFA2a1M2aHA4YW85UDVxYTQwVXAwM3NoMVFoaHh2aFZUWA0KZjZEc3hTak1WcEN6MkJJQ2E1Nm1XN2xQZUVmNUJncXFkYWVVb0V2WWR3NG13KzM3VjV2dWdVRjhwSDFsdXM4Sg0KZjk3RFlQQ0M4dWYxNFJ3dzhOWGhPZUxMeVV5bHFQOXQwV1M1bmx3UGppb2JKQW0vVmRoZ3JPemJBdVV5VTV1Sg0KMmJtVDRidHA2YUhOdm1PZXNIdmhFUzk2ZldkanN1MmpkVlFUYTllODdQSytWelVpU2RERE5Id3RZL21hVUcweQ0KOUFZVGhVOVBhS0VrR2lmbUYxKzg4ZHpOK0llVHN5NDY5aWtRNW5XRXM3bEVpVzhvbU8yYXFEY1kyQllSZmNVRA0KYVA0RVg1UmRWd0xsSWYzV2dzVlZlamdaMGFkbHFCK2ltaXAyREhGSEQ3eG5DQStha0RmUkFMZ2Rja050eEdpYw0KTXhXQ3V0dG11UUdzZjcrM09leE0wcXlNbzNGK3l2citIcjh6clY5RmpKbjhSMWNyQUJ2b3VYKzltMjRoajJRbA0KSTNPR0FYU2ozcnJMTVhaWm1GZUFiMWlUUHFwZmtEQUpiNXRwTVRxV1diRWFzMkw3NmFvenRGdDluNGtaUWZjMw0KRER4NEw0SHhVa0YrR0JzaS9wcXA1ME9wMnRhSW5xblRrbDZjWnQxSkZhWEp5SXYvelpyWGdUd04xUUlEQVFBQg0KbzRJQmx6Q0NBWk13SFFZRFZSME9CQllFRkw2ZnZZMVhiWlcxcldQRGwwNnJxSVJkT2dmMU1COEdBMVVkSXdRWQ0KTUJhQUZPeHZJcVN6Qk9MQlk0Zm1kMlBxUm1sTzd2enJNQTRHQTFVZER3RUIvd1FFQXdJQmhqQVRCZ05WSFNVRQ0KRERBS0JnZ3JCZ0VGQlFjREh6QVNCZ05WSFJNQkFmOEVDREFHQVFIL0FnRUFNSHdHQ0NzR0FRVUZCd0VCQkhBdw0KYmpBa0JnZ3JCZ0VGQlFjd0FZWVlhSFIwY0RvdkwyOWpjM0F1WkdsbmFXTmxjblF1WTI5dE1FWUdDQ3NHQVFVRg0KQnpBQ2hqcG9kSFJ3T2k4dlkyRmpaWEowY3k1a2FXZHBZMlZ5ZEM1amIyMHZSR2xuYVVObGNuUldaWEpwWm1sbA0KWkUxaGNtdFNiMjkwUTBFdVkzSjBNRWdHQTFVZEh3UkJNRDh3UGFBN29EbUdOMmgwZEhBNkx5OWpjbXd6TG1ScA0KWjJsalpYSjBMbU52YlM5RWFXZHBRMlZ5ZEZabGNtbG1hV1ZrVFdGeWExSnZiM1JEUVM1amNtd3dVQVlEVlIwZw0KQkVrd1J6QTNCZ3BnaGtnQmh2MXNBQUlGTUNrd0p3WUlLd1lCQlFVSEFnRVdHMmgwZEhBNkx5OTNkM2N1Wkdsbg0KYVdObGNuUXVZMjl0TDBOUVV6QU1CZ29yQmdFRUFZT2VYd0VCTUEwR0NTcUdTSWIzRFFFQkN3VUFBNElDQVFDcQ0KZytFQmVuQjYzNTVENG9OM1dVajc0MXU4YS9NY1ViQVdBaDJqdkJxOWJlVUJwZW9ydEkwemh3bzJqWFFMSURqdA0KbEpkdE53Y1pXbW1WNm91YzZjcDNacUduazBIUm5EMUhOQVNDUTMzaFR3NVVhcUcwdHVFVU9xOFZLTm5ObVZCaw0KWE5HYjY2UFZ3NlJGalFINC9XS0RCcWlnbGhpSTIzZjVjcERhbGZTWFg0UlZKWjNYTEdQVlNNbXEyVE9IbVFXRg0KK2gxTlI2cFZ5RGRYSm9vdVVLOFdPa0lrc1l5amx4TWF0VlgwUWFzWDh0ZXBIaXpXQk1aQzBITWczUTJncjBoNA0KSEtDZHVjdW1oYnV1Um5Td3BZaEcrT1UrUUFJVEtLMjlGaWN1R014MWkrQ2cxUHlRRUlkbXE0MUxnekxlbmRhUg0KdGV3aFV1RmZtNEZZRy9iM3NTa2xnK3Zlc3c4Q2JERTNnWFFSN1kvYjFNMWppWjZ2bmxuUC9xNzJaUlVCNUFwTg0Ka0EvaDlma29KTlI4K1I0MkJEZko3bzlRdTlFV25NZXNoTkIyNkVJVXBNMjBGZFlmT2h0V0k2SVFROWttbkx3aw0KNnl6RDJub2xod3VTRXAzMmhLOVg1cS9qUGZYc3RqT3NRQ2tVa1JvR2tHQmtTRVJVMnhqYVdoT1lZSmJybWc0Yw0KMVF0cWNyNjVtYzlGeXFZY2taMExkTE1qZDhTUFFuL2pRUExyUSs1UFljZkkvR0VaSVo0ZHFaNzNlbldSeE1LcQ0KMWQvdjg5MXlaQlFybXNhK2YvSDF1SEFIbUdmTXp3Y0E2V1dsWFpZbmpKRDBxUExwVXp5QndGb0dkOVlJeTAvSQ0Kc2FCRXp5STJBc1g5RWFsM3dyamZsWk95TXpFN3pZS1Y1WUV0UkREQldBPT0NCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0NCi0tLS0tQkVHSU4gQ0VSVElGSUNBVEUtLS0tLQ0KTUlJRjNqQ0NBOGFnQXdJQkFnSVFCc0Zueit2MGpUWFdKQkFZWGhIRjZ6QU5CZ2txaGtpRzl3MEJBUXNGQURDQg0KaURFTE1Ba0dBMVVFQmhNQ1ZWTXhEVEFMQmdOVkJBZ1RCRlYwWVdneERUQUxCZ05WQkFjVEJFeGxhR2t4RnpBVg0KQmdOVkJBb1REa1JwWjJsRFpYSjBMQ0JKYm1NdU1Sa3dGd1lEVlFRTEV4QjNkM2N1WkdsbmFXTmxjblF1WTI5dA0KTVNjd0pRWURWUVFERXg1RWFXZHBRMlZ5ZENCV1pYSnBabWxsWkNCTllYSnJJRkp2YjNRZ1EwRXdIaGNOTVRrdw0KT1RJek1USXhNakEyV2hjTk5Ea3dPVEl6TVRJeE1qQTJXakNCaURFTE1Ba0dBMVVFQmhNQ1ZWTXhEVEFMQmdOVg0KQkFnVEJGVjBZV2d4RFRBTEJnTlZCQWNUQkV4bGFHa3hGekFWQmdOVkJBb1REa1JwWjJsRFpYSjBMQ0JKYm1NdQ0KTVJrd0Z3WURWUVFMRXhCM2QzY3VaR2xuYVdObGNuUXVZMjl0TVNjd0pRWURWUVFERXg1RWFXZHBRMlZ5ZENCVw0KWlhKcFptbGxaQ0JOWVhKcklGSnZiM1FnUTBFd2dnSWlNQTBHQ1NxR1NJYjNEUUVCQVFVQUE0SUNEd0F3Z2dJSw0KQW9JQ0FRRGF3dnZJTzdjTDA0cHRaeGdMdy9Zd3FEdWx1aUZzTXZHc3IrdlpjZnE1YzNoS3VYMHVNcnNsemE5MQ0KT0ZCNlNQbWJrRzJoTEVyT2NhVkgwbk1uRzBSRTNBTTZkcGZodzdxVStuM2M2WFBTN0hsTzlaQzU3R0plYU9YeQ0KYjBjbWNLMkc5NldDL1ZSdUIxWmdqcVlvcTZQUDR5am4vREIvUGMrN2tqd0oyRURINUJGRW55d1ZxNHJIMWErUQ0KQWJWRHB4SmZDZlFaVjFWS1crSk50Ty9LS0tYK05sUHJ0SHJvU2dLaVJaMDE5b1dwdElteWZncGc3ajZGTk5BVA0KUjh1UHN2VTV6WUp5Q0RPeEt2NE1xbGxNSm1VVndHVUhGNjFXbmJpWmVKc3h6YjVINXdNcGlrWDRtZmRLYUltMA0KeW0yUXNIVlJhelNUMWJJVnZBWlRoY0tQZDJFbnlzUWk2WHBZcE1jcGlTUm81OEVOWFpXNDdNL09jdTdtQkNMUA0KVEpFUEVDOVlHMmFDZkh4RlN6L242eFpSKzFydk5QVXhjTForRk5Pd1pSbkhxY3FlNVRETlFld29DOC9BV1IwTw0KZEtxdTJXZ0JGNDBuY1htdG01UW5ZaGxUbUJjb1BVV2ZSNDBiQ0xKc200ZlYyQjRoa0M1WkNIVi85MWpwc3Y3ag0KaHNHa3BRcFk2bjlYV0JBQlc2WkdRV000alh4eWJiTm1iM3UyMXh4OHJFa2FJaDIyaXMwOGk0MXhlVjlpTFllYw0KUHVwNm5wWm5aYmlLU09FRlEzV0F3emkzVHRBQm1Sa25PTXliRkpLU2xKUVhNZkhxRU5md0twTnZNTVJWTzhQbA0KSitPaDZBTjhsNzV2WmFGRjI3Z3FCaGJtakoyWTlpb3FUSTdnK0RnNHFDbFVRcVhQQ1FJREFRQUJvMEl3UURBZA0KQmdOVkhRNEVGZ1FVN0c4aXBMTUU0c0ZqaCtaM1krcEdhVTd1L09zd0RnWURWUjBQQVFIL0JBUURBZ0dHTUE4Rw0KQTFVZEV3RUIvd1FGTUFNQkFmOHdEUVlKS29aSWh2Y05BUUVMQlFBRGdnSUJBQzgzMllMVmV2VldJTm5yM3ZXQw0KWE52TFB0bVBPUExLTzVjSHVwUXBrY3VnK0lPbGkyRkF4bkM4SkRsYk9UNmhpTUs3TVlhdXJhZzlRdkRJL0FzMA0KNGNOT2ErNHNxS0N4UVIzYUxFeXlxZUxBNFdkQTZVRklIZE1TSXpMSFp5bHpqdXdjaUk3MDZ4ODNJYjE3RE1LTw0KY3BPMlFWQjdCZXF2MjQwVFd4S3hIMjFwRlpzbDQ0T2dJK0hjQVBEYmZKZTNQRXp3RVpLTmNLUmtNV2EvRkZ1Mg0KY2tReHBUY2ZaQUJyYXJudVJMY1NJTmlvZFNXN1ZmeGN0emVnWFdNNFdtUWV1dFBCT2ljY2VWM0o0WlZraHRoQg0KbTc4NHZFUzFESXVEVHFUOS9pcVN0QkdOOGVPR3g5cUt2amFYVDhTZGNyUDU4RnBYcnRtL3hLZ3RJTHB0eGZWVA0KMDQyb29nUWZiMmNOYWhLUlN2czB4SDNqeWhPOTQ0dDB6TUgvYkVwUmRVMzZ3UjEvRm81NnpYeTJadjRjek13Zw0KM0hnN21iQWFsSnZjbkJ2SCtOSFBndWNRSTQzMlhYMTFLMjl2ejdIdU5DN1A5eUtoeG5zK01iT1FETURQT2h0Uw0KTFVwQm16Uk5HNCsyQlpKWnlLR3FZZCtTVEhpc0VHWWVZQ2kzTVZyd1NlMlVxY0RpOWYyVUFXVmJrREUvWUI2Lw0KZTcrQzdvNlVXa1hTVTdkelI3RndGc2ZCSGk2RXFnSWIyZTlwSU5BeGR2bGMvM0UxOUxkL0dKRXRsdzduU2R6cA0KNzFlTXA1WjQ4aVk1NGZWMmxNL3JYb2dTMVI0cjNwMm9QZTllZkcwWGFKTWQwdjFnb201RGEva2hKQTcrd2pSQg0KMHdiZXJkL3RnM04wZEpzU1N6blpqd1lCDQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tDQo=`,
                'base64'
            )
        };

        // has to use specific time or the cert will be expired
        const CUR_DATE_FIXED = '2022-07-09T08:30:14.715Z';

        let result = await validateVMC(bimiData, { now: new Date(CUR_DATE_FIXED) });

        expect(result).to.exist;
        expect(result.location.hashValue).to.equal('ea8c81da633c66a16262134a78576cdf067638e9');
    });
});
