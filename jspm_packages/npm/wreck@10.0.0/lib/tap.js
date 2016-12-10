/* */ 
'use strict';
const Hoek = require('hoek');
const Stream = require('stream');
const Payload = require('./payload');
const internals = {};
module.exports = internals.Tap = function() {
  Stream.Transform.call(this);
  this.buffers = [];
};
Hoek.inherits(internals.Tap, Stream.Transform);
internals.Tap.prototype._transform = function(chunk, encoding, next) {
  this.buffers.push(chunk);
  next(null, chunk);
};
internals.Tap.prototype.collect = function() {
  return new Payload(this.buffers);
};
