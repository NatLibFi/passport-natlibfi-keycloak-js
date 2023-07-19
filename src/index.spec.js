/**
*
* @licstart  The following is the entire license notice for the JavaScript code in this file.
*
* Copyright 2023 University Of Helsinki (The National Library Of Finland)
*
* Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
*
* The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
*
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*
* @licend  The above is the entire license notice
* for the JavaScript code in this file.
*
*/

import {expect} from 'chai';

import {generatePassportMiddlewares} from '.';

describe('generatePassportMiddlewares', () => {
  it('Should initialize with local config from file', () => {
    const passportMiddlewares = generatePassportMiddlewares({
      localUsers: 'file://test-fixtures/testPassportLocalUsers.json'
    });

    expect(passportMiddlewares).to.be.an('object');
    expect(passportMiddlewares).to.have.property('credentials');
    expect(passportMiddlewares).to.have.property('token');
  });

  it('Should initialize with local config from stringified JSON', () => {
    const passportMiddlewares = generatePassportMiddlewares({
      localUsers: '[{"id": "foo","password": "foo"}]'
    });

    expect(passportMiddlewares).to.be.an('object');
    expect(passportMiddlewares).to.have.property('credentials');
    expect(passportMiddlewares).to.have.property('token');
  });

  it('Should initialize with Keycloak config', () => {
    const keycloakOpts = {
      jwksUrl: 'foo.bar.baz',
      algorithms: ['RS256'],
      audience: 'foo.audience',
      issuer: 'foo.issuer'
    };

    const passportMiddlewares = generatePassportMiddlewares({keycloakOpts});
    expect(passportMiddlewares).to.be.an('object');
    expect(passportMiddlewares).to.have.property('token');
  });

  it('Should throw error if initializing with invalid Keycloak config', () => {
    const keycloakOpts = {
      jwksUrl: 'foo.bar.baz',
      algorithms: ['RS256'],
      audience: 'foo.audience',
      issuer: 'foo.issuer'
    };

    Object.keys(keycloakOpts).forEach(key => {
      const optsCopy = {...keycloakOpts};
      delete optsCopy[key]; // eslint-disable-line functional/immutable-data
      expect(() => generatePassportMiddlewares({keycloakOpts: optsCopy})).to.throw();
    });

  });
});
