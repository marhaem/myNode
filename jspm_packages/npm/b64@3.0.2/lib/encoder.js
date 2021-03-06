/* */ 
(function(Buffer) {
  'use strict';
  const Stream = require('stream');
  const internals = {};
  exports.encode = function(buffer) {
    return new Buffer(buffer.toString('base64'));
  };
  exports.Encoder = class Encoder extends Stream.Transform {
    constructor() {
      super();
      this._reminder = null;
    }
    _transform(chunk, encoding, callback) {
      let part = this._reminder ? Buffer.concat([this._reminder, chunk]) : chunk;
      const remaining = part.length % 3;
      if (remaining) {
        this._reminder = part.slice(part.length - remaining);
        part = part.slice(0, part.length - remaining);
      } else {
        this._reminder = null;
      }
      this.push(exports.encode(part));
      return callback();
    }
    _flush(callback) {
      if (this._reminder) {
        this.push(exports.encode(this._reminder));
      }
      return callback();
    }
  };
})(require('buffer').Buffer);
