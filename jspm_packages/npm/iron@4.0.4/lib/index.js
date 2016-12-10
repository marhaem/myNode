/* */ 
(function(Buffer, process) {
  'use strict';
  const Crypto = require('crypto');
  const Boom = require('boom');
  const Hoek = require('hoek');
  const Cryptiles = require('cryptiles');
  const internals = {};
  exports.defaults = {
    encryption: {
      saltBits: 256,
      algorithm: 'aes-256-cbc',
      iterations: 1,
      minPasswordlength: 32
    },
    integrity: {
      saltBits: 256,
      algorithm: 'sha256',
      iterations: 1,
      minPasswordlength: 32
    },
    ttl: 0,
    timestampSkewSec: 60,
    localtimeOffsetMsec: 0
  };
  exports.algorithms = {
    'aes-128-ctr': {
      keyBits: 128,
      ivBits: 128
    },
    'aes-256-cbc': {
      keyBits: 256,
      ivBits: 128
    },
    'sha256': {keyBits: 256}
  };
  exports.macFormatVersion = '2';
  exports.macPrefix = 'Fe26.' + exports.macFormatVersion;
  exports.generateKey = function(password, options, callback) {
    const callbackTick = Hoek.nextTick(callback);
    if (!password) {
      return callbackTick(Boom.internal('Empty password'));
    }
    if (!options || typeof options !== 'object') {
      return callbackTick(Boom.internal('Bad options'));
    }
    const algorithm = exports.algorithms[options.algorithm];
    if (!algorithm) {
      return callbackTick(Boom.internal('Unknown algorithm: ' + options.algorithm));
    }
    const generate = () => {
      if (Buffer.isBuffer(password)) {
        if (password.length < algorithm.keyBits / 8) {
          return callbackTick(Boom.internal('Key buffer (password) too small'));
        }
        const result = {
          key: password,
          salt: ''
        };
        return generateIv(result);
      }
      if (password.length < options.minPasswordlength) {
        return callbackTick(Boom.internal('Password string too short (min ' + options.minPasswordlength + ' characters required)'));
      }
      if (options.salt) {
        return generateKey(options.salt);
      }
      if (options.saltBits) {
        return generateSalt();
      }
      return callbackTick(Boom.internal('Missing salt or saltBits options'));
    };
    const generateSalt = () => {
      const randomSalt = Cryptiles.randomBits(options.saltBits);
      if (randomSalt instanceof Error) {
        return callbackTick(Boom.wrap(randomSalt));
      }
      const salt = randomSalt.toString('hex');
      return generateKey(salt);
    };
    const generateKey = (salt) => {
      Crypto.pbkdf2(password, salt, options.iterations, algorithm.keyBits / 8, 'sha1', (err, derivedKey) => {
        if (err) {
          return callback(Boom.wrap(err));
        }
        const result = {
          key: derivedKey,
          salt
        };
        return generateIv(result);
      });
    };
    const generateIv = (result) => {
      if (algorithm.ivBits && !options.iv) {
        const randomIv = Cryptiles.randomBits(algorithm.ivBits);
        if (randomIv instanceof Error) {
          return callbackTick(Boom.wrap(randomIv));
        }
        result.iv = randomIv;
        return callbackTick(null, result);
      }
      if (options.iv) {
        result.iv = options.iv;
      }
      return callbackTick(null, result);
    };
    generate();
  };
  exports.encrypt = function(password, options, data, callback) {
    exports.generateKey(password, options, (err, key) => {
      if (err) {
        return callback(err);
      }
      const cipher = Crypto.createCipheriv(options.algorithm, key.key, key.iv);
      const enc = Buffer.concat([cipher.update(data, 'utf8'), cipher.final()]);
      callback(null, enc, key);
    });
  };
  exports.decrypt = function(password, options, data, callback) {
    exports.generateKey(password, options, (err, key) => {
      if (err) {
        return callback(err);
      }
      const decipher = Crypto.createDecipheriv(options.algorithm, key.key, key.iv);
      let dec = decipher.update(data, null, 'utf8');
      dec = dec + decipher.final('utf8');
      callback(null, dec);
    });
  };
  exports.hmacWithPassword = function(password, options, data, callback) {
    exports.generateKey(password, options, (err, key) => {
      if (err) {
        return callback(err);
      }
      const hmac = Crypto.createHmac(options.algorithm, key.key).update(data);
      const digest = hmac.digest('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/\=/g, '');
      const result = {
        digest,
        salt: key.salt
      };
      return callback(null, result);
    });
  };
  internals.normalizePassword = function(password) {
    const obj = {};
    if (password instanceof Object && !Buffer.isBuffer(password)) {
      obj.id = password.id;
      obj.encryption = password.secret || password.encryption;
      obj.integrity = password.secret || password.integrity;
    } else {
      obj.encryption = password;
      obj.integrity = password;
    }
    return obj;
  };
  exports.seal = function(object, password, options, callback) {
    const now = Date.now() + (options.localtimeOffsetMsec || 0);
    const callbackTick = Hoek.nextTick(callback);
    const objectString = internals.stringify(object);
    if (objectString instanceof Error) {
      return callbackTick(objectString);
    }
    let passwordId = '';
    password = internals.normalizePassword(password);
    if (password.id) {
      if (!/^\w+$/.test(password.id)) {
        return callbackTick(Boom.internal('Invalid password id'));
      }
      passwordId = password.id;
    }
    exports.encrypt(password.encryption, options.encryption, objectString, (err, encrypted, key) => {
      if (err) {
        return callback(err);
      }
      const encryptedB64 = Hoek.base64urlEncode(encrypted);
      const iv = Hoek.base64urlEncode(key.iv);
      const expiration = (options.ttl ? now + options.ttl : '');
      const macBaseString = exports.macPrefix + '*' + passwordId + '*' + key.salt + '*' + iv + '*' + encryptedB64 + '*' + expiration;
      exports.hmacWithPassword(password.integrity, options.integrity, macBaseString, (err, mac) => {
        if (err) {
          return callback(err);
        }
        const sealed = macBaseString + '*' + mac.salt + '*' + mac.digest;
        return callback(null, sealed);
      });
    });
  };
  exports.unseal = function(sealed, password, options, callback) {
    const now = Date.now() + (options.localtimeOffsetMsec || 0);
    const callbackTick = Hoek.nextTick(callback);
    const parts = sealed.split('*');
    if (parts.length !== 8) {
      return callbackTick(Boom.internal('Incorrect number of sealed components'));
    }
    const macPrefix = parts[0];
    const passwordId = parts[1];
    const encryptionSalt = parts[2];
    const encryptionIv = parts[3];
    const encryptedB64 = parts[4];
    const expiration = parts[5];
    const hmacSalt = parts[6];
    const hmac = parts[7];
    const macBaseString = macPrefix + '*' + passwordId + '*' + encryptionSalt + '*' + encryptionIv + '*' + encryptedB64 + '*' + expiration;
    if (macPrefix !== exports.macPrefix) {
      return callbackTick(Boom.internal('Wrong mac prefix'));
    }
    if (expiration) {
      if (!expiration.match(/^\d+$/)) {
        return callbackTick(Boom.internal('Invalid expiration'));
      }
      const exp = parseInt(expiration, 10);
      if (exp <= (now - (options.timestampSkewSec * 1000))) {
        return callbackTick(Boom.internal('Expired seal'));
      }
    }
    if (password instanceof Object && !(Buffer.isBuffer(password))) {
      password = password[passwordId || 'default'];
      if (!password) {
        return callbackTick(Boom.internal('Cannot find password: ' + passwordId));
      }
    }
    password = internals.normalizePassword(password);
    const macOptions = Hoek.clone(options.integrity);
    macOptions.salt = hmacSalt;
    exports.hmacWithPassword(password.integrity, macOptions, macBaseString, (err, mac) => {
      if (err) {
        return callback(err);
      }
      if (!Cryptiles.fixedTimeComparison(mac.digest, hmac)) {
        return callback(Boom.internal('Bad hmac value'));
      }
      const encrypted = Hoek.base64urlDecode(encryptedB64, 'buffer');
      if (encrypted instanceof Error) {
        return callback(Boom.wrap(encrypted));
      }
      const decryptOptions = Hoek.clone(options.encryption);
      decryptOptions.salt = encryptionSalt;
      decryptOptions.iv = Hoek.base64urlDecode(encryptionIv, 'buffer');
      if (decryptOptions.iv instanceof Error) {
        return callback(Boom.wrap(decryptOptions.iv));
      }
      exports.decrypt(password.encryption, decryptOptions, encrypted, (ignoreErr, decrypted) => {
        let object = null;
        try {
          object = JSON.parse(decrypted);
        } catch (err) {
          return callback(Boom.internal('Failed parsing sealed object JSON: ' + err.message));
        }
        return callback(null, object);
      });
    });
  };
  internals.stringify = function(object) {
    try {
      return JSON.stringify(object);
    } catch (err) {
      return Boom.internal('Failed to stringify object: ' + err.message);
    }
  };
})(require('buffer').Buffer, require('process'));
