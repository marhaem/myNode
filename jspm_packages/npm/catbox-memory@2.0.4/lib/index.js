/* */ 
(function(Buffer) {
  'use strict';
  const Hoek = require('hoek');
  const internals = {};
  internals.defaults = {
    maxByteSize: 100 * 1024 * 1024,
    allowMixedContent: false
  };
  internals.MemoryCacheSegment = function MemoryCacheSegment() {};
  internals.MemoryCacheEntry = function MemoryCacheEntry(key, value, ttl, allowMixedContent) {
    let valueByteSize = 0;
    if (allowMixedContent && Buffer.isBuffer(value)) {
      this.item = new Buffer(value.length);
      value.copy(this.item);
      valueByteSize = this.item.length;
    } else {
      this.item = JSON.stringify(value);
      valueByteSize = Buffer.byteLength(this.item);
    }
    this.stored = Date.now();
    this.ttl = ttl;
    this.byteSize = 144 + valueByteSize + Buffer.byteLength(key.segment) + Buffer.byteLength(key.id);
    this.timeoutId = null;
  };
  exports = module.exports = internals.Connection = function MemoryCache(options) {
    Hoek.assert(this.constructor === internals.Connection, 'Memory cache client must be instantiated using new');
    Hoek.assert(!options || options.maxByteSize === undefined || options.maxByteSize >= 0, 'Invalid cache maxByteSize value');
    Hoek.assert(!options || options.allowMixedContent === undefined || typeof options.allowMixedContent === 'boolean', 'Invalid allowMixedContent value');
    this.settings = Hoek.applyToDefaults(internals.defaults, options || {});
    this.cache = null;
  };
  internals.Connection.prototype.start = function(callback) {
    callback = Hoek.nextTick(callback);
    if (!this.cache) {
      this.cache = {};
      this.byteSize = 0;
    }
    return callback();
  };
  internals.Connection.prototype.stop = function() {
    if (this.cache) {
      const segments = Object.keys(this.cache);
      for (let i = 0; i < segments.length; ++i) {
        const segment = segments[i];
        const keys = Object.keys(this.cache[segment]);
        for (let j = 0; j < keys.length; ++j) {
          const key = keys[j];
          clearTimeout(this.cache[segment][key].timeoutId);
        }
      }
    }
    this.cache = null;
    this.byteSize = 0;
    return;
  };
  internals.Connection.prototype.isReady = function() {
    return !!this.cache;
  };
  internals.Connection.prototype.validateSegmentName = function(name) {
    if (!name) {
      return new Error('Empty string');
    }
    if (name.indexOf('\u0000') !== -1) {
      return new Error('Includes null character');
    }
    return null;
  };
  internals.Connection.prototype.get = function(key, callback) {
    callback = Hoek.nextTick(callback);
    if (!this.cache) {
      return callback(new Error('Connection not started'));
    }
    const segment = this.cache[key.segment];
    if (!segment) {
      return callback(null, null);
    }
    const envelope = segment[key.id];
    if (!envelope) {
      return callback(null, null);
    }
    let value = null;
    if (Buffer.isBuffer(envelope.item)) {
      value = envelope.item;
    } else {
      value = internals.parseJSON(envelope.item);
      if (value instanceof Error) {
        return callback(new Error('Bad value content'));
      }
    }
    const result = {
      item: value,
      stored: envelope.stored,
      ttl: envelope.ttl
    };
    return callback(null, result);
  };
  internals.Connection.prototype.set = function(key, value, ttl, callback) {
    callback = Hoek.nextTick(callback);
    if (!this.cache) {
      return callback(new Error('Connection not started'));
    }
    if (ttl > 2147483647) {
      return callback(new Error('Invalid ttl (greater than 2147483647)'));
    }
    let envelope = null;
    try {
      envelope = new internals.MemoryCacheEntry(key, value, ttl, this.settings.allowMixedContent);
    } catch (err) {
      return callback(err);
    }
    this.cache[key.segment] = this.cache[key.segment] || new internals.MemoryCacheSegment();
    const segment = this.cache[key.segment];
    const cachedItem = segment[key.id];
    if (cachedItem && cachedItem.timeoutId) {
      clearTimeout(cachedItem.timeoutId);
      this.byteSize -= cachedItem.byteSize;
    }
    if (this.settings.maxByteSize) {
      if (this.byteSize + envelope.byteSize > this.settings.maxByteSize) {
        return callback(new Error('Cache size limit reached'));
      }
    }
    const timeoutId = setTimeout(() => {
      this.drop(key, () => {});
    }, ttl);
    envelope.timeoutId = timeoutId;
    segment[key.id] = envelope;
    this.byteSize += envelope.byteSize;
    return callback(null);
  };
  internals.Connection.prototype.drop = function(key, callback) {
    callback = Hoek.nextTick(callback);
    if (!this.cache) {
      return callback(new Error('Connection not started'));
    }
    const segment = this.cache[key.segment];
    if (segment) {
      const item = segment[key.id];
      if (item) {
        clearTimeout(item.timeoutId);
        this.byteSize -= item.byteSize;
      }
      delete segment[key.id];
    }
    return callback();
  };
  internals.parseJSON = function(json) {
    let obj = null;
    try {
      obj = JSON.parse(json);
    } catch (err) {
      obj = err;
    }
    return obj;
  };
})(require('buffer').Buffer);
