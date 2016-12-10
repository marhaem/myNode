/* */ 
'use strict';
const RFC3986 = require('./rfc3986');
const internals = {Uri: {createUriRegex: function(optionalScheme, allowRelative, relativeOnly) {
      let scheme = RFC3986.scheme;
      let prefix;
      if (relativeOnly) {
        prefix = '(?:' + RFC3986.relativeRef + ')';
      } else {
        if (optionalScheme) {
          scheme = '(?:' + optionalScheme + ')';
        }
        const withScheme = '(?:' + scheme + ':' + RFC3986.hierPart + ')';
        prefix = allowRelative ? '(?:' + withScheme + '|' + RFC3986.relativeRef + ')' : withScheme;
      }
      return new RegExp('^' + prefix + '(?:\\?' + RFC3986.query + ')?' + '(?:#' + RFC3986.fragment + ')?$');
    }}};
module.exports = internals.Uri;
