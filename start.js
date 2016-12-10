'use-strict';
const System = require('jspm').Loader();

const reject = function reject(error) {
	console.log(error);
};

System.import('./server/src/index.js').then((server) => {
	server = server.default;
	server.start();
}, reject).catch(reject);