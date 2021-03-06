/* */ 
'use strict';
const Hapi = require('hapi');
const Vision = require('../../lib/index');
const internals = {};
const rootHandler = function(request, reply) {
  reply.view('index', {
    title: 'examples/views/pug/index.js | Hapi ' + request.server.version,
    message: 'Index - Hello World!'
  });
};
const aboutHandler = function(request, reply) {
  reply.view('about', {
    title: 'examples/views/pug/index.js | Hapi ' + request.server.version,
    message: 'About - Hello World!'
  });
};
internals.main = function() {
  const server = new Hapi.Server();
  server.connection({port: 8000});
  server.register(Vision, (err) => {
    if (err) {
      throw err;
    }
    server.views({
      engines: {pug: require('pug')},
      path: __dirname + '/templates',
      compileOptions: {pretty: true}
    });
    server.route({
      method: 'GET',
      path: '/',
      handler: rootHandler
    });
    server.route({
      method: 'GET',
      path: '/about',
      handler: aboutHandler
    });
    server.start((err) => {
      if (err) {
        throw err;
      }
      console.log('Server is listening at ' + server.info.uri);
    });
  });
};
internals.main();
