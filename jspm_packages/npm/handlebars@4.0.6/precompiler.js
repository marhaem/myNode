/* */ 
"format cjs";
(function(process) {
  define(['exports', 'async', 'fs', './handlebars', 'path', 'source-map', 'uglify-js'], function(exports, _async, _fs, _handlebars, _path, _sourceMap, _uglifyJs) {
    'use strict';
    function _interopRequireDefault(obj) {
      return obj && obj.__esModule ? obj : {'default': obj};
    }
    var _Async = _interopRequireDefault(_async);
    var _fs2 = _interopRequireDefault(_fs);
    var _uglify = _interopRequireDefault(_uglifyJs);
    module.exports.loadTemplates = function(opts, callback) {
      loadStrings(opts, function(err, strings) {
        if (err) {
          callback(err);
        } else {
          loadFiles(opts, function(err, files) {
            if (err) {
              callback(err);
            } else {
              opts.templates = strings.concat(files);
              callback(undefined, opts);
            }
          });
        }
      });
    };
    function loadStrings(opts, callback) {
      var strings = arrayCast(opts.string),
          names = arrayCast(opts.name);
      if (names.length !== strings.length && strings.length > 1) {
        return callback(new _handlebars.Exception('Number of names did not match the number of string inputs'));
      }
      _Async['default'].map(strings, function(string, callback) {
        if (string !== '-') {
          callback(undefined, string);
        } else {
          (function() {
            var buffer = '';
            process.stdin.setEncoding('utf8');
            process.stdin.on('data', function(chunk) {
              buffer += chunk;
            });
            process.stdin.on('end', function() {
              callback(undefined, buffer);
            });
          })();
        }
      }, function(err, strings) {
        strings = strings.map(function(string, index) {
          return {
            name: names[index],
            path: names[index],
            source: string
          };
        });
        callback(err, strings);
      });
    }
    function loadFiles(opts, callback) {
      var extension = (opts.extension || 'handlebars').replace(/[\\^$*+?.():=!|{}\-\[\]]/g, function(arg) {
        return '\\' + arg;
      });
      extension = new RegExp('\\.' + extension + '$');
      var ret = [],
          queue = (opts.files || []).map(function(template) {
            return {
              template: template,
              root: opts.root
            };
          });
      _Async['default'].whilst(function() {
        return queue.length;
      }, function(callback) {
        var _queue$shift = queue.shift();
        var path = _queue$shift.template;
        var root = _queue$shift.root;
        _fs2['default'].stat(path, function(err, stat) {
          if (err) {
            return callback(new _handlebars.Exception('Unable to open template file "' + path + '"'));
          }
          if (stat.isDirectory()) {
            opts.hasDirectory = true;
            _fs2['default'].readdir(path, function(err, children) {
              if (err) {
                return callback(err);
              }
              children.forEach(function(file) {
                var childPath = path + '/' + file;
                if (extension.test(childPath) || _fs2['default'].statSync(childPath).isDirectory()) {
                  queue.push({
                    template: childPath,
                    root: root || path
                  });
                }
              });
              callback();
            });
          } else {
            _fs2['default'].readFile(path, 'utf8', function(err, data) {
              if (err) {
                return callback(err);
              }
              if (opts.bom && data.indexOf('﻿') === 0) {
                data = data.substring(1);
              }
              var name = path;
              if (!root) {
                name = _path.basename(name);
              } else if (name.indexOf(root) === 0) {
                name = name.substring(root.length + 1);
              }
              name = name.replace(extension, '');
              ret.push({
                path: path,
                name: name,
                source: data
              });
              callback();
            });
          }
        });
      }, function(err) {
        if (err) {
          callback(err);
        } else {
          callback(undefined, ret);
        }
      });
    }
    module.exports.cli = function(opts) {
      if (opts.version) {
        console.log(_handlebars.VERSION);
        return;
      }
      if (!opts.templates.length && !opts.hasDirectory) {
        throw new _handlebars.Exception('Must define at least one template or directory.');
      }
      if (opts.simple && opts.min) {
        throw new _handlebars.Exception('Unable to minimize simple output');
      }
      var multiple = opts.templates.length !== 1 || opts.hasDirectory;
      if (opts.simple && multiple) {
        throw new _handlebars.Exception('Unable to output multiple templates in simple mode');
      }
      if (!opts.amd && !opts.commonjs && opts.templates.length === 1 && !opts.templates[0].name) {
        opts.simple = true;
      }
      var known = {};
      if (opts.known && !Array.isArray(opts.known)) {
        opts.known = [opts.known];
      }
      if (opts.known) {
        for (var i = 0,
            len = opts.known.length; i < len; i++) {
          known[opts.known[i]] = true;
        }
      }
      var objectName = opts.partial ? 'Handlebars.partials' : 'templates';
      var output = new _sourceMap.SourceNode();
      if (!opts.simple) {
        if (opts.amd) {
          output.add('define([\'' + opts.handlebarPath + 'handlebars.runtime\'], function(Handlebars) {\n  Handlebars = Handlebars["default"];');
        } else if (opts.commonjs) {
          output.add('var Handlebars = require("' + opts.commonjs + '");');
        } else {
          output.add('(function() {\n');
        }
        output.add('  var template = Handlebars.template, templates = ');
        if (opts.namespace) {
          output.add(opts.namespace);
          output.add(' = ');
          output.add(opts.namespace);
          output.add(' || ');
        }
        output.add('{};\n');
      }
      opts.templates.forEach(function(template) {
        var options = {
          knownHelpers: known,
          knownHelpersOnly: opts.o
        };
        if (opts.map) {
          options.srcName = template.path;
        }
        if (opts.data) {
          options.data = true;
        }
        var precompiled = _handlebars.precompile(template.source, options);
        if (opts.map) {
          var consumer = new _sourceMap.SourceMapConsumer(precompiled.map);
          precompiled = _sourceMap.SourceNode.fromStringWithSourceMap(precompiled.code, consumer);
        }
        if (opts.simple) {
          output.add([precompiled, '\n']);
        } else {
          if (!template.name) {
            throw new _handlebars.Exception('Name missing for template');
          }
          if (opts.amd && !multiple) {
            output.add('return ');
          }
          output.add([objectName, '[\'', template.name, '\'] = template(', precompiled, ');\n']);
        }
      });
      if (!opts.simple) {
        if (opts.amd) {
          if (multiple) {
            output.add(['return ', objectName, ';\n']);
          }
          output.add('});');
        } else if (!opts.commonjs) {
          output.add('})();');
        }
      }
      if (opts.map) {
        output.add('\n//# sourceMappingURL=' + opts.map + '\n');
      }
      output = output.toStringWithSourceMap();
      output.map = output.map + '';
      if (opts.min) {
        output = _uglify['default'].minify(output.code, {
          fromString: true,
          outSourceMap: opts.map,
          inSourceMap: JSON.parse(output.map)
        });
        if (opts.map) {
          output.code += '\n//# sourceMappingURL=' + opts.map + '\n';
        }
      }
      if (opts.map) {
        _fs2['default'].writeFileSync(opts.map, output.map, 'utf8');
      }
      output = output.code;
      if (opts.output) {
        _fs2['default'].writeFileSync(opts.output, output, 'utf8');
      } else {
        console.log(output);
      }
    };
    function arrayCast(value) {
      value = value != null ? value : [];
      if (!Array.isArray(value)) {
        value = [value];
      }
      return value;
    }
  });
})(require('process'));
