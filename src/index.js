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

import {readFileSync} from 'fs';
import {v4 as uuid} from 'uuid';

import passport from 'passport';
import {BasicStrategy} from 'passport-http';
import {Strategy as BearerStrategy} from 'passport-http-bearer';

import {createLogger} from '@natlibfi/melinda-backend-commons';
import {clone} from '@natlibfi/melinda-commons';
import {KeycloakStrategy} from '@natlibfi/passport-keycloak';

/**
 * Derived from passport-melinda-crowd-js src/index.js (https://github.com/NatLibFi/passport-melinda-crowd-js/blob/master/src/index.js)
 *   - Copyright (C) 2018-2020 University of Helsinki (The National Library of Finland)
 */
export function generatePassportMiddlewares({keycloakOpts, localUsers}) {
  const logger = createLogger();


  if (keycloakOpts && typeof keycloakOpts === 'object' && validateKeycloakOpts(keycloakOpts)) {
    return initKeycloakMiddleware(keycloakOpts);
  }

  if (typeof localUsers === 'string') {
    return initLocalMiddlewares(localUsers);
  }

  throw new Error('No configuration for passport strategies');

  function validateKeycloakOpts({algorithms = false, audience = false, issuer = false, jwksUrl = false}) {
    if (!algorithms || !audience || !issuer || !jwksUrl) {
      return false;
    }

    if (!Array.isArray(algorithms) || algorithms.length === 0) {
      return false;
    }

    return true;
  }

  function initKeycloakMiddleware(keycloakOpts) {
    passport.use(new KeycloakStrategy(keycloakOpts));

    logger.info('Enabling Keycloak passport strategy');

    return {
      token: passport.authenticate('keycloak-jwt-bearer', {session: false})
    };
  }

  function initLocalMiddlewares(localUsers) {
    const users = parseUsers();
    const localSessions = {};

    passport.use(new BasicStrategy(localBasicCallback));
    passport.use(new BearerStrategy(localBearerCallback));

    logger.info('Enabling local passport strategy');

    return {
      credentials: passport.authenticate('basic', {session: false}),
      token: passport.authenticate('bearer', {session: false})
    };

    function parseUsers() {
      if (localUsers.startsWith('file://')) {
        const str = readFileSync(localUsers.replace(/^file:\/\//u, ''), 'utf8');
        return parse(str);
      }

      return parse(localUsers);

      function parse(str) {
        try {
          return JSON.parse(str);
        } catch (err) {
          throw new Error('Could not parse local users');
        }
      }
    }

    /* istanbul ignore next */
    function localBasicCallback(reqUsername, reqPassword, done) {
      const user = users.find(({id, password}) => reqUsername === id && reqPassword === password);

      if (user) {
        const token = getToken();
        done(null, token);
        return;
      }

      done(null, false);

      function getToken() {
        const existingToken = Object.keys(localSessions).find(token => {
          const userInfo = localSessions[token];
          return userInfo.id === user.username;
        });

        if (existingToken) {
          return existingToken;
        }

        const newToken = uuid().replace(/-/gu, '');
        localSessions[newToken] = removePassword(user); // eslint-disable-line functional/immutable-data

        return newToken;

        function removePassword(userData) {
          return Object.keys(clone(userData)).filter(k => k !== 'password').reduce((acc, key) => ({...acc, [key]: userData[key]}), {});
        }
      }
    }

    function localBearerCallback(reqToken, done) {
      const entry = Object.entries(localSessions).find(([token]) => reqToken === token);

      if (entry) {
        done(null, entry[1]);
        return;
      }

      done(null, false);
    }
  }
}
