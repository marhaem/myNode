/* */ 
(function(Buffer, process) {
  'use strict';
  const Http = require('http');
  const Stream = require('stream');
  const internals = {};
  exports = module.exports = class Response extends Http.ServerResponse {
    constructor(req, onEnd) {
      super({
        method: req.method,
        httpVersionMajor: 1,
        httpVersionMinor: 1
      });
      this._shot = {
        trailers: {},
        payloadChunks: []
      };
      this.assignSocket(internals.nullSocket());
      this.once('finish', () => {
        const res = internals.payload(this);
        res.raw.req = req;
        process.nextTick(() => onEnd(res));
      });
    }
    writeHead() {
      const headers = ((arguments.length === 2 && typeof arguments[1] === 'object') ? arguments[1] : (arguments.length === 3 ? arguments[2] : {}));
      const result = super.writeHead.apply(this, arguments);
      this._headers = Object.assign({}, this._headers, headers);
      ['Date', 'Connection', 'Transfer-Encoding'].forEach((name) => {
        const regex = new RegExp('\\r\\n' + name + ': ([^\\r]*)\\r\\n');
        const field = this._header.match(regex);
        if (field) {
          this._headers[name.toLowerCase()] = field[1];
        }
      });
      return result;
    }
    write(data, encoding) {
      super.write(data, encoding);
      this._shot.payloadChunks.push(new Buffer(data, encoding));
      return true;
    }
    end(data, encoding) {
      super.end(data, encoding);
      this.emit('finish');
    }
    destroy() {}
    addTrailers(trailers) {
      for (const key in trailers) {
        this._shot.trailers[key.toLowerCase().trim()] = trailers[key].toString().trim();
      }
    }
  };
  internals.payload = function(response) {
    const res = {
      raw: {res: response},
      headers: response._headers,
      statusCode: response.statusCode,
      statusMessage: response.statusMessage,
      trailers: {}
    };
    const rawBuffer = Buffer.concat(response._shot.payloadChunks);
    res.rawPayload = rawBuffer;
    res.payload = rawBuffer.toString();
    res.trailers = response._shot.trailers;
    return res;
  };
  internals.nullSocket = function() {
    return new Stream.Writable({write(chunk, encoding, callback) {
        setImmediate(callback);
      }});
  };
})(require('buffer').Buffer, require('process'));
