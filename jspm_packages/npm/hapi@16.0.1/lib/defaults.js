/* */ 
(function(process) {
  'use strict';
  const Os = require('os');
  const internals = {};
  exports.server = {
    debug: {
      request: ['implementation'],
      log: ['implementation']
    },
    load: {sampleInterval: 0},
    mime: null,
    useDomains: true
  };
  exports.connection = {
    compression: true,
    router: {
      isCaseSensitive: true,
      stripTrailingSlash: false
    },
    routes: {
      cache: {
        statuses: [200, 204],
        otherwise: 'no-cache'
      },
      compression: {},
      cors: false,
      files: {relativeTo: '.'},
      json: {
        replacer: null,
        space: null,
        suffix: null
      },
      log: false,
      payload: {
        failAction: 'error',
        maxBytes: 1024 * 1024,
        output: 'data',
        parse: true,
        timeout: 10 * 1000,
        uploads: Os.tmpdir(),
        defaultContentType: 'application/json',
        compression: {}
      },
      response: {
        ranges: true,
        emptyStatusCode: 200,
        options: {}
      },
      security: false,
      state: {
        parse: true,
        failAction: 'error'
      },
      timeout: {
        socket: undefined,
        server: false
      },
      validate: {options: {}}
    }
  };
  exports.security = {
    hsts: 15768000,
    xframe: 'deny',
    xss: true,
    noOpen: true,
    noSniff: true
  };
  exports.cors = {
    origin: ['*'],
    maxAge: 86400,
    headers: ['Accept', 'Authorization', 'Content-Type', 'If-None-Match'],
    additionalHeaders: [],
    exposedHeaders: ['WWW-Authenticate', 'Server-Authorization'],
    additionalExposedHeaders: [],
    credentials: false
  };
})(require('process'));
