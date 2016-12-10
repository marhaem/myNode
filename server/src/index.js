import Hapi from 'hapi';
import vision from 'vision';
import handlebars from 'handlebars';

const log = function log(info) {
	console.log(info);
}

const PATH_APP = './app';

export default class{
	constructor() {
		//
	}

	start() {
		const hapiRoutes = [{
			method: 'GET',
			path: '/app',
			handler(request, reply) {
				reply.view('app.html');
			}
		}];

		const hapiPlugins = [{
			register: vision,
			options: {}
		}];

		const hapiViews = [{
			engines: {
				'htm': handlebars,
				'html': handlebars
			},
			relativeTo: PATH_APP,
			path: './'
		}];

		log('server starting...');
		const server = new Hapi.Server();
		
		server.connection({port: 3000});
		
		
		
		/*server.register(hapiPlugins, (err) => {
			if(err) throw err;
			else {
				server.views(hapiViews).then((err) => {
					if(err) throw err;
				});
				server.routes(hapiRoutes);
				server.start((err) => {
					if(err) throw err;
					else {
					log('server running at ' + server.info.uri);
					}
				});
			}
		});*/
		
		
	}
}