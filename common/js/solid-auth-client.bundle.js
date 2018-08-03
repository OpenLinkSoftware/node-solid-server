(function webpackUniversalModuleDefinition(root, factory) {
	if(typeof exports === 'object' && typeof module === 'object')
		module.exports = factory(require("window"), require("crypto"), require("fetch"), require("TextEncoder"));
	else if(typeof define === 'function' && define.amd)
		define(["window", "crypto", "fetch", "TextEncoder"], factory);
	else if(typeof exports === 'object')
		exports["SolidAuthClient"] = factory(require("window"), require("crypto"), require("fetch"), require("TextEncoder"));
	else
		root["SolidAuthClient"] = factory(root["window"], root["crypto"], root["fetch"], root["TextEncoder"]);
})(typeof self !== 'undefined' ? self : this, function(__WEBPACK_EXTERNAL_MODULE_39__, __WEBPACK_EXTERNAL_MODULE_40__, __WEBPACK_EXTERNAL_MODULE_94__, __WEBPACK_EXTERNAL_MODULE_185__) {
return /******/ (function(modules) { // webpackBootstrap
/******/ 	// The module cache
/******/ 	var installedModules = {};
/******/
/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {
/******/
/******/ 		// Check if module is in cache
/******/ 		if(installedModules[moduleId]) {
/******/ 			return installedModules[moduleId].exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = installedModules[moduleId] = {
/******/ 			i: moduleId,
/******/ 			l: false,
/******/ 			exports: {}
/******/ 		};
/******/
/******/ 		// Execute the module function
/******/ 		modules[moduleId].call(module.exports, module, module.exports, __webpack_require__);
/******/
/******/ 		// Flag the module as loaded
/******/ 		module.l = true;
/******/
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/
/******/
/******/ 	// expose the modules object (__webpack_modules__)
/******/ 	__webpack_require__.m = modules;
/******/
/******/ 	// expose the module cache
/******/ 	__webpack_require__.c = installedModules;
/******/
/******/ 	// define getter function for harmony exports
/******/ 	__webpack_require__.d = function(exports, name, getter) {
/******/ 		if(!__webpack_require__.o(exports, name)) {
/******/ 			Object.defineProperty(exports, name, {
/******/ 				configurable: false,
/******/ 				enumerable: true,
/******/ 				get: getter
/******/ 			});
/******/ 		}
/******/ 	};
/******/
/******/ 	// getDefaultExport function for compatibility with non-harmony modules
/******/ 	__webpack_require__.n = function(module) {
/******/ 		var getter = module && module.__esModule ?
/******/ 			function getDefault() { return module['default']; } :
/******/ 			function getModuleExports() { return module; };
/******/ 		__webpack_require__.d(getter, 'a', getter);
/******/ 		return getter;
/******/ 	};
/******/
/******/ 	// Object.prototype.hasOwnProperty.call
/******/ 	__webpack_require__.o = function(object, property) { return Object.prototype.hasOwnProperty.call(object, property); };
/******/
/******/ 	// __webpack_public_path__
/******/ 	__webpack_require__.p = "";
/******/
/******/ 	// Load entry module and return exports
/******/ 	return __webpack_require__(__webpack_require__.s = 115);
/******/ })
/************************************************************************/
/******/ ([
/* 0 */
/***/ (function(module, exports) {

var core = module.exports = { version: '2.5.5' };
if (typeof __e == 'number') __e = core; // eslint-disable-line no-undef


/***/ }),
/* 1 */
/***/ (function(module, exports, __webpack_require__) {

var store = __webpack_require__(48)('wks');
var uid = __webpack_require__(32);
var Symbol = __webpack_require__(2).Symbol;
var USE_SYMBOL = typeof Symbol == 'function';

var $exports = module.exports = function (name) {
  return store[name] || (store[name] =
    USE_SYMBOL && Symbol[name] || (USE_SYMBOL ? Symbol : uid)('Symbol.' + name));
};

$exports.store = store;


/***/ }),
/* 2 */
/***/ (function(module, exports) {

// https://github.com/zloirock/core-js/issues/86#issuecomment-115759028
var global = module.exports = typeof window != 'undefined' && window.Math == Math
  ? window : typeof self != 'undefined' && self.Math == Math ? self
  // eslint-disable-next-line no-new-func
  : Function('return this')();
if (typeof __g == 'number') __g = global; // eslint-disable-line no-undef


/***/ }),
/* 3 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


module.exports = {
  Formats: __webpack_require__(95),
  Initializer: __webpack_require__(96),
  JSONDocument: __webpack_require__(174),
  JSONMapping: __webpack_require__(175),
  JSONPatch: __webpack_require__(97),
  JSONPointer: __webpack_require__(64),
  JSONSchema: __webpack_require__(176),
  Validator: __webpack_require__(98)
};

/***/ }),
/* 4 */
/***/ (function(module, exports, __webpack_require__) {

var global = __webpack_require__(2);
var core = __webpack_require__(0);
var ctx = __webpack_require__(15);
var hide = __webpack_require__(9);
var has = __webpack_require__(10);
var PROTOTYPE = 'prototype';

var $export = function (type, name, source) {
  var IS_FORCED = type & $export.F;
  var IS_GLOBAL = type & $export.G;
  var IS_STATIC = type & $export.S;
  var IS_PROTO = type & $export.P;
  var IS_BIND = type & $export.B;
  var IS_WRAP = type & $export.W;
  var exports = IS_GLOBAL ? core : core[name] || (core[name] = {});
  var expProto = exports[PROTOTYPE];
  var target = IS_GLOBAL ? global : IS_STATIC ? global[name] : (global[name] || {})[PROTOTYPE];
  var key, own, out;
  if (IS_GLOBAL) source = name;
  for (key in source) {
    // contains in native
    own = !IS_FORCED && target && target[key] !== undefined;
    if (own && has(exports, key)) continue;
    // export native or passed
    out = own ? target[key] : source[key];
    // prevent global pollution for namespaces
    exports[key] = IS_GLOBAL && typeof target[key] != 'function' ? source[key]
    // bind timers to global for call from export context
    : IS_BIND && own ? ctx(out, global)
    // wrap global constructors for prevent change them in library
    : IS_WRAP && target[key] == out ? (function (C) {
      var F = function (a, b, c) {
        if (this instanceof C) {
          switch (arguments.length) {
            case 0: return new C();
            case 1: return new C(a);
            case 2: return new C(a, b);
          } return new C(a, b, c);
        } return C.apply(this, arguments);
      };
      F[PROTOTYPE] = C[PROTOTYPE];
      return F;
    // make static versions for prototype methods
    })(out) : IS_PROTO && typeof out == 'function' ? ctx(Function.call, out) : out;
    // export proto methods to core.%CONSTRUCTOR%.methods.%NAME%
    if (IS_PROTO) {
      (exports.virtual || (exports.virtual = {}))[key] = out;
      // export proto methods to core.%CONSTRUCTOR%.prototype.%NAME%
      if (type & $export.R && expProto && !expProto[key]) hide(expProto, key, out);
    }
  }
};
// type bitmap
$export.F = 1;   // forced
$export.G = 2;   // global
$export.S = 4;   // static
$export.P = 8;   // proto
$export.B = 16;  // bind
$export.W = 32;  // wrap
$export.U = 64;  // safe
$export.R = 128; // real proto method for `library`
module.exports = $export;


/***/ }),
/* 5 */
/***/ (function(module, exports, __webpack_require__) {

var isObject = __webpack_require__(7);
module.exports = function (it) {
  if (!isObject(it)) throw TypeError(it + ' is not an object!');
  return it;
};


/***/ }),
/* 6 */
/***/ (function(module, exports, __webpack_require__) {

var anObject = __webpack_require__(5);
var IE8_DOM_DEFINE = __webpack_require__(67);
var toPrimitive = __webpack_require__(43);
var dP = Object.defineProperty;

exports.f = __webpack_require__(8) ? Object.defineProperty : function defineProperty(O, P, Attributes) {
  anObject(O);
  P = toPrimitive(P, true);
  anObject(Attributes);
  if (IE8_DOM_DEFINE) try {
    return dP(O, P, Attributes);
  } catch (e) { /* empty */ }
  if ('get' in Attributes || 'set' in Attributes) throw TypeError('Accessors not supported!');
  if ('value' in Attributes) O[P] = Attributes.value;
  return O;
};


/***/ }),
/* 7 */
/***/ (function(module, exports) {

module.exports = function (it) {
  return typeof it === 'object' ? it !== null : typeof it === 'function';
};


/***/ }),
/* 8 */
/***/ (function(module, exports, __webpack_require__) {

// Thank's IE8 for his funny defineProperty
module.exports = !__webpack_require__(16)(function () {
  return Object.defineProperty({}, 'a', { get: function () { return 7; } }).a != 7;
});


/***/ }),
/* 9 */
/***/ (function(module, exports, __webpack_require__) {

var dP = __webpack_require__(6);
var createDesc = __webpack_require__(23);
module.exports = __webpack_require__(8) ? function (object, key, value) {
  return dP.f(object, key, createDesc(1, value));
} : function (object, key, value) {
  object[key] = value;
  return object;
};


/***/ }),
/* 10 */
/***/ (function(module, exports) {

var hasOwnProperty = {}.hasOwnProperty;
module.exports = function (it, key) {
  return hasOwnProperty.call(it, key);
};


/***/ }),
/* 11 */
/***/ (function(module, exports, __webpack_require__) {

module.exports = __webpack_require__(122);


/***/ }),
/* 12 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


exports.__esModule = true;

var _promise = __webpack_require__(13);

var _promise2 = _interopRequireDefault(_promise);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

exports.default = function (fn) {
  return function () {
    var gen = fn.apply(this, arguments);
    return new _promise2.default(function (resolve, reject) {
      function step(key, arg) {
        try {
          var info = gen[key](arg);
          var value = info.value;
        } catch (error) {
          reject(error);
          return;
        }

        if (info.done) {
          resolve(value);
        } else {
          return _promise2.default.resolve(value).then(function (value) {
            step("next", value);
          }, function (err) {
            step("throw", err);
          });
        }
      }

      return step("next");
    });
  };
};

/***/ }),
/* 13 */
/***/ (function(module, exports, __webpack_require__) {

module.exports = { "default": __webpack_require__(124), __esModule: true };

/***/ }),
/* 14 */
/***/ (function(module, exports, __webpack_require__) {

module.exports = __webpack_require__(177).default;
module.exports.default = module.exports;


/***/ }),
/* 15 */
/***/ (function(module, exports, __webpack_require__) {

// optional / simple context binding
var aFunction = __webpack_require__(31);
module.exports = function (fn, that, length) {
  aFunction(fn);
  if (that === undefined) return fn;
  switch (length) {
    case 1: return function (a) {
      return fn.call(that, a);
    };
    case 2: return function (a, b) {
      return fn.call(that, a, b);
    };
    case 3: return function (a, b, c) {
      return fn.call(that, a, b, c);
    };
  }
  return function (/* ...args */) {
    return fn.apply(that, arguments);
  };
};


/***/ }),
/* 16 */
/***/ (function(module, exports) {

module.exports = function (exec) {
  try {
    return !!exec();
  } catch (e) {
    return true;
  }
};


/***/ }),
/* 17 */
/***/ (function(module, exports, __webpack_require__) {

// to indexed object, toObject with fallback for non-array-like ES3 strings
var IObject = __webpack_require__(69);
var defined = __webpack_require__(44);
module.exports = function (it) {
  return IObject(defined(it));
};


/***/ }),
/* 18 */
/***/ (function(module, exports) {

module.exports = {};


/***/ }),
/* 19 */
/***/ (function(module, exports) {

var g;

// This works in non-strict mode
g = (function() {
	return this;
})();

try {
	// This works if eval is allowed (see CSP)
	g = g || Function("return this")() || (1,eval)("this");
} catch(e) {
	// This works if the window reference is available
	if(typeof window === "object")
		g = window;
}

// g can still be undefined, but nothing to do about it...
// We return undefined, instead of nothing here, so it's
// easier to handle this case. if(!global) { ...}

module.exports = g;


/***/ }),
/* 20 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


exports.__esModule = true;

exports.default = function (instance, Constructor) {
  if (!(instance instanceof Constructor)) {
    throw new TypeError("Cannot call a class as a function");
  }
};

/***/ }),
/* 21 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


exports.__esModule = true;

var _defineProperty = __webpack_require__(56);

var _defineProperty2 = _interopRequireDefault(_defineProperty);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

exports.default = function () {
  function defineProperties(target, props) {
    for (var i = 0; i < props.length; i++) {
      var descriptor = props[i];
      descriptor.enumerable = descriptor.enumerable || false;
      descriptor.configurable = true;
      if ("value" in descriptor) descriptor.writable = true;
      (0, _defineProperty2.default)(target, descriptor.key, descriptor);
    }
  }

  return function (Constructor, protoProps, staticProps) {
    if (protoProps) defineProperties(Constructor.prototype, protoProps);
    if (staticProps) defineProperties(Constructor, staticProps);
    return Constructor;
  };
}();

/***/ }),
/* 22 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";
/* WEBPACK VAR INJECTION */(function(global) {/*!
 * The buffer module from node.js, for the browser.
 *
 * @author   Feross Aboukhadijeh <feross@feross.org> <http://feross.org>
 * @license  MIT
 */
/* eslint-disable no-proto */



var base64 = __webpack_require__(178)
var ieee754 = __webpack_require__(179)
var isArray = __webpack_require__(180)

exports.Buffer = Buffer
exports.SlowBuffer = SlowBuffer
exports.INSPECT_MAX_BYTES = 50

/**
 * If `Buffer.TYPED_ARRAY_SUPPORT`:
 *   === true    Use Uint8Array implementation (fastest)
 *   === false   Use Object implementation (most compatible, even IE6)
 *
 * Browsers that support typed arrays are IE 10+, Firefox 4+, Chrome 7+, Safari 5.1+,
 * Opera 11.6+, iOS 4.2+.
 *
 * Due to various browser bugs, sometimes the Object implementation will be used even
 * when the browser supports typed arrays.
 *
 * Note:
 *
 *   - Firefox 4-29 lacks support for adding new properties to `Uint8Array` instances,
 *     See: https://bugzilla.mozilla.org/show_bug.cgi?id=695438.
 *
 *   - Chrome 9-10 is missing the `TypedArray.prototype.subarray` function.
 *
 *   - IE10 has a broken `TypedArray.prototype.subarray` function which returns arrays of
 *     incorrect length in some situations.

 * We detect these buggy browsers and set `Buffer.TYPED_ARRAY_SUPPORT` to `false` so they
 * get the Object implementation, which is slower but behaves correctly.
 */
Buffer.TYPED_ARRAY_SUPPORT = global.TYPED_ARRAY_SUPPORT !== undefined
  ? global.TYPED_ARRAY_SUPPORT
  : typedArraySupport()

/*
 * Export kMaxLength after typed array support is determined.
 */
exports.kMaxLength = kMaxLength()

function typedArraySupport () {
  try {
    var arr = new Uint8Array(1)
    arr.__proto__ = {__proto__: Uint8Array.prototype, foo: function () { return 42 }}
    return arr.foo() === 42 && // typed array instances can be augmented
        typeof arr.subarray === 'function' && // chrome 9-10 lack `subarray`
        arr.subarray(1, 1).byteLength === 0 // ie10 has broken `subarray`
  } catch (e) {
    return false
  }
}

function kMaxLength () {
  return Buffer.TYPED_ARRAY_SUPPORT
    ? 0x7fffffff
    : 0x3fffffff
}

function createBuffer (that, length) {
  if (kMaxLength() < length) {
    throw new RangeError('Invalid typed array length')
  }
  if (Buffer.TYPED_ARRAY_SUPPORT) {
    // Return an augmented `Uint8Array` instance, for best performance
    that = new Uint8Array(length)
    that.__proto__ = Buffer.prototype
  } else {
    // Fallback: Return an object instance of the Buffer class
    if (that === null) {
      that = new Buffer(length)
    }
    that.length = length
  }

  return that
}

/**
 * The Buffer constructor returns instances of `Uint8Array` that have their
 * prototype changed to `Buffer.prototype`. Furthermore, `Buffer` is a subclass of
 * `Uint8Array`, so the returned instances will have all the node `Buffer` methods
 * and the `Uint8Array` methods. Square bracket notation works as expected -- it
 * returns a single octet.
 *
 * The `Uint8Array` prototype remains unmodified.
 */

function Buffer (arg, encodingOrOffset, length) {
  if (!Buffer.TYPED_ARRAY_SUPPORT && !(this instanceof Buffer)) {
    return new Buffer(arg, encodingOrOffset, length)
  }

  // Common case.
  if (typeof arg === 'number') {
    if (typeof encodingOrOffset === 'string') {
      throw new Error(
        'If encoding is specified then the first argument must be a string'
      )
    }
    return allocUnsafe(this, arg)
  }
  return from(this, arg, encodingOrOffset, length)
}

Buffer.poolSize = 8192 // not used by this implementation

// TODO: Legacy, not needed anymore. Remove in next major version.
Buffer._augment = function (arr) {
  arr.__proto__ = Buffer.prototype
  return arr
}

function from (that, value, encodingOrOffset, length) {
  if (typeof value === 'number') {
    throw new TypeError('"value" argument must not be a number')
  }

  if (typeof ArrayBuffer !== 'undefined' && value instanceof ArrayBuffer) {
    return fromArrayBuffer(that, value, encodingOrOffset, length)
  }

  if (typeof value === 'string') {
    return fromString(that, value, encodingOrOffset)
  }

  return fromObject(that, value)
}

/**
 * Functionally equivalent to Buffer(arg, encoding) but throws a TypeError
 * if value is a number.
 * Buffer.from(str[, encoding])
 * Buffer.from(array)
 * Buffer.from(buffer)
 * Buffer.from(arrayBuffer[, byteOffset[, length]])
 **/
Buffer.from = function (value, encodingOrOffset, length) {
  return from(null, value, encodingOrOffset, length)
}

if (Buffer.TYPED_ARRAY_SUPPORT) {
  Buffer.prototype.__proto__ = Uint8Array.prototype
  Buffer.__proto__ = Uint8Array
  if (typeof Symbol !== 'undefined' && Symbol.species &&
      Buffer[Symbol.species] === Buffer) {
    // Fix subarray() in ES2016. See: https://github.com/feross/buffer/pull/97
    Object.defineProperty(Buffer, Symbol.species, {
      value: null,
      configurable: true
    })
  }
}

function assertSize (size) {
  if (typeof size !== 'number') {
    throw new TypeError('"size" argument must be a number')
  } else if (size < 0) {
    throw new RangeError('"size" argument must not be negative')
  }
}

function alloc (that, size, fill, encoding) {
  assertSize(size)
  if (size <= 0) {
    return createBuffer(that, size)
  }
  if (fill !== undefined) {
    // Only pay attention to encoding if it's a string. This
    // prevents accidentally sending in a number that would
    // be interpretted as a start offset.
    return typeof encoding === 'string'
      ? createBuffer(that, size).fill(fill, encoding)
      : createBuffer(that, size).fill(fill)
  }
  return createBuffer(that, size)
}

/**
 * Creates a new filled Buffer instance.
 * alloc(size[, fill[, encoding]])
 **/
Buffer.alloc = function (size, fill, encoding) {
  return alloc(null, size, fill, encoding)
}

function allocUnsafe (that, size) {
  assertSize(size)
  that = createBuffer(that, size < 0 ? 0 : checked(size) | 0)
  if (!Buffer.TYPED_ARRAY_SUPPORT) {
    for (var i = 0; i < size; ++i) {
      that[i] = 0
    }
  }
  return that
}

/**
 * Equivalent to Buffer(num), by default creates a non-zero-filled Buffer instance.
 * */
Buffer.allocUnsafe = function (size) {
  return allocUnsafe(null, size)
}
/**
 * Equivalent to SlowBuffer(num), by default creates a non-zero-filled Buffer instance.
 */
Buffer.allocUnsafeSlow = function (size) {
  return allocUnsafe(null, size)
}

function fromString (that, string, encoding) {
  if (typeof encoding !== 'string' || encoding === '') {
    encoding = 'utf8'
  }

  if (!Buffer.isEncoding(encoding)) {
    throw new TypeError('"encoding" must be a valid string encoding')
  }

  var length = byteLength(string, encoding) | 0
  that = createBuffer(that, length)

  var actual = that.write(string, encoding)

  if (actual !== length) {
    // Writing a hex string, for example, that contains invalid characters will
    // cause everything after the first invalid character to be ignored. (e.g.
    // 'abxxcd' will be treated as 'ab')
    that = that.slice(0, actual)
  }

  return that
}

function fromArrayLike (that, array) {
  var length = array.length < 0 ? 0 : checked(array.length) | 0
  that = createBuffer(that, length)
  for (var i = 0; i < length; i += 1) {
    that[i] = array[i] & 255
  }
  return that
}

function fromArrayBuffer (that, array, byteOffset, length) {
  array.byteLength // this throws if `array` is not a valid ArrayBuffer

  if (byteOffset < 0 || array.byteLength < byteOffset) {
    throw new RangeError('\'offset\' is out of bounds')
  }

  if (array.byteLength < byteOffset + (length || 0)) {
    throw new RangeError('\'length\' is out of bounds')
  }

  if (byteOffset === undefined && length === undefined) {
    array = new Uint8Array(array)
  } else if (length === undefined) {
    array = new Uint8Array(array, byteOffset)
  } else {
    array = new Uint8Array(array, byteOffset, length)
  }

  if (Buffer.TYPED_ARRAY_SUPPORT) {
    // Return an augmented `Uint8Array` instance, for best performance
    that = array
    that.__proto__ = Buffer.prototype
  } else {
    // Fallback: Return an object instance of the Buffer class
    that = fromArrayLike(that, array)
  }
  return that
}

function fromObject (that, obj) {
  if (Buffer.isBuffer(obj)) {
    var len = checked(obj.length) | 0
    that = createBuffer(that, len)

    if (that.length === 0) {
      return that
    }

    obj.copy(that, 0, 0, len)
    return that
  }

  if (obj) {
    if ((typeof ArrayBuffer !== 'undefined' &&
        obj.buffer instanceof ArrayBuffer) || 'length' in obj) {
      if (typeof obj.length !== 'number' || isnan(obj.length)) {
        return createBuffer(that, 0)
      }
      return fromArrayLike(that, obj)
    }

    if (obj.type === 'Buffer' && isArray(obj.data)) {
      return fromArrayLike(that, obj.data)
    }
  }

  throw new TypeError('First argument must be a string, Buffer, ArrayBuffer, Array, or array-like object.')
}

function checked (length) {
  // Note: cannot use `length < kMaxLength()` here because that fails when
  // length is NaN (which is otherwise coerced to zero.)
  if (length >= kMaxLength()) {
    throw new RangeError('Attempt to allocate Buffer larger than maximum ' +
                         'size: 0x' + kMaxLength().toString(16) + ' bytes')
  }
  return length | 0
}

function SlowBuffer (length) {
  if (+length != length) { // eslint-disable-line eqeqeq
    length = 0
  }
  return Buffer.alloc(+length)
}

Buffer.isBuffer = function isBuffer (b) {
  return !!(b != null && b._isBuffer)
}

Buffer.compare = function compare (a, b) {
  if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b)) {
    throw new TypeError('Arguments must be Buffers')
  }

  if (a === b) return 0

  var x = a.length
  var y = b.length

  for (var i = 0, len = Math.min(x, y); i < len; ++i) {
    if (a[i] !== b[i]) {
      x = a[i]
      y = b[i]
      break
    }
  }

  if (x < y) return -1
  if (y < x) return 1
  return 0
}

Buffer.isEncoding = function isEncoding (encoding) {
  switch (String(encoding).toLowerCase()) {
    case 'hex':
    case 'utf8':
    case 'utf-8':
    case 'ascii':
    case 'latin1':
    case 'binary':
    case 'base64':
    case 'ucs2':
    case 'ucs-2':
    case 'utf16le':
    case 'utf-16le':
      return true
    default:
      return false
  }
}

Buffer.concat = function concat (list, length) {
  if (!isArray(list)) {
    throw new TypeError('"list" argument must be an Array of Buffers')
  }

  if (list.length === 0) {
    return Buffer.alloc(0)
  }

  var i
  if (length === undefined) {
    length = 0
    for (i = 0; i < list.length; ++i) {
      length += list[i].length
    }
  }

  var buffer = Buffer.allocUnsafe(length)
  var pos = 0
  for (i = 0; i < list.length; ++i) {
    var buf = list[i]
    if (!Buffer.isBuffer(buf)) {
      throw new TypeError('"list" argument must be an Array of Buffers')
    }
    buf.copy(buffer, pos)
    pos += buf.length
  }
  return buffer
}

function byteLength (string, encoding) {
  if (Buffer.isBuffer(string)) {
    return string.length
  }
  if (typeof ArrayBuffer !== 'undefined' && typeof ArrayBuffer.isView === 'function' &&
      (ArrayBuffer.isView(string) || string instanceof ArrayBuffer)) {
    return string.byteLength
  }
  if (typeof string !== 'string') {
    string = '' + string
  }

  var len = string.length
  if (len === 0) return 0

  // Use a for loop to avoid recursion
  var loweredCase = false
  for (;;) {
    switch (encoding) {
      case 'ascii':
      case 'latin1':
      case 'binary':
        return len
      case 'utf8':
      case 'utf-8':
      case undefined:
        return utf8ToBytes(string).length
      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return len * 2
      case 'hex':
        return len >>> 1
      case 'base64':
        return base64ToBytes(string).length
      default:
        if (loweredCase) return utf8ToBytes(string).length // assume utf8
        encoding = ('' + encoding).toLowerCase()
        loweredCase = true
    }
  }
}
Buffer.byteLength = byteLength

function slowToString (encoding, start, end) {
  var loweredCase = false

  // No need to verify that "this.length <= MAX_UINT32" since it's a read-only
  // property of a typed array.

  // This behaves neither like String nor Uint8Array in that we set start/end
  // to their upper/lower bounds if the value passed is out of range.
  // undefined is handled specially as per ECMA-262 6th Edition,
  // Section 13.3.3.7 Runtime Semantics: KeyedBindingInitialization.
  if (start === undefined || start < 0) {
    start = 0
  }
  // Return early if start > this.length. Done here to prevent potential uint32
  // coercion fail below.
  if (start > this.length) {
    return ''
  }

  if (end === undefined || end > this.length) {
    end = this.length
  }

  if (end <= 0) {
    return ''
  }

  // Force coersion to uint32. This will also coerce falsey/NaN values to 0.
  end >>>= 0
  start >>>= 0

  if (end <= start) {
    return ''
  }

  if (!encoding) encoding = 'utf8'

  while (true) {
    switch (encoding) {
      case 'hex':
        return hexSlice(this, start, end)

      case 'utf8':
      case 'utf-8':
        return utf8Slice(this, start, end)

      case 'ascii':
        return asciiSlice(this, start, end)

      case 'latin1':
      case 'binary':
        return latin1Slice(this, start, end)

      case 'base64':
        return base64Slice(this, start, end)

      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return utf16leSlice(this, start, end)

      default:
        if (loweredCase) throw new TypeError('Unknown encoding: ' + encoding)
        encoding = (encoding + '').toLowerCase()
        loweredCase = true
    }
  }
}

// The property is used by `Buffer.isBuffer` and `is-buffer` (in Safari 5-7) to detect
// Buffer instances.
Buffer.prototype._isBuffer = true

function swap (b, n, m) {
  var i = b[n]
  b[n] = b[m]
  b[m] = i
}

Buffer.prototype.swap16 = function swap16 () {
  var len = this.length
  if (len % 2 !== 0) {
    throw new RangeError('Buffer size must be a multiple of 16-bits')
  }
  for (var i = 0; i < len; i += 2) {
    swap(this, i, i + 1)
  }
  return this
}

Buffer.prototype.swap32 = function swap32 () {
  var len = this.length
  if (len % 4 !== 0) {
    throw new RangeError('Buffer size must be a multiple of 32-bits')
  }
  for (var i = 0; i < len; i += 4) {
    swap(this, i, i + 3)
    swap(this, i + 1, i + 2)
  }
  return this
}

Buffer.prototype.swap64 = function swap64 () {
  var len = this.length
  if (len % 8 !== 0) {
    throw new RangeError('Buffer size must be a multiple of 64-bits')
  }
  for (var i = 0; i < len; i += 8) {
    swap(this, i, i + 7)
    swap(this, i + 1, i + 6)
    swap(this, i + 2, i + 5)
    swap(this, i + 3, i + 4)
  }
  return this
}

Buffer.prototype.toString = function toString () {
  var length = this.length | 0
  if (length === 0) return ''
  if (arguments.length === 0) return utf8Slice(this, 0, length)
  return slowToString.apply(this, arguments)
}

Buffer.prototype.equals = function equals (b) {
  if (!Buffer.isBuffer(b)) throw new TypeError('Argument must be a Buffer')
  if (this === b) return true
  return Buffer.compare(this, b) === 0
}

Buffer.prototype.inspect = function inspect () {
  var str = ''
  var max = exports.INSPECT_MAX_BYTES
  if (this.length > 0) {
    str = this.toString('hex', 0, max).match(/.{2}/g).join(' ')
    if (this.length > max) str += ' ... '
  }
  return '<Buffer ' + str + '>'
}

Buffer.prototype.compare = function compare (target, start, end, thisStart, thisEnd) {
  if (!Buffer.isBuffer(target)) {
    throw new TypeError('Argument must be a Buffer')
  }

  if (start === undefined) {
    start = 0
  }
  if (end === undefined) {
    end = target ? target.length : 0
  }
  if (thisStart === undefined) {
    thisStart = 0
  }
  if (thisEnd === undefined) {
    thisEnd = this.length
  }

  if (start < 0 || end > target.length || thisStart < 0 || thisEnd > this.length) {
    throw new RangeError('out of range index')
  }

  if (thisStart >= thisEnd && start >= end) {
    return 0
  }
  if (thisStart >= thisEnd) {
    return -1
  }
  if (start >= end) {
    return 1
  }

  start >>>= 0
  end >>>= 0
  thisStart >>>= 0
  thisEnd >>>= 0

  if (this === target) return 0

  var x = thisEnd - thisStart
  var y = end - start
  var len = Math.min(x, y)

  var thisCopy = this.slice(thisStart, thisEnd)
  var targetCopy = target.slice(start, end)

  for (var i = 0; i < len; ++i) {
    if (thisCopy[i] !== targetCopy[i]) {
      x = thisCopy[i]
      y = targetCopy[i]
      break
    }
  }

  if (x < y) return -1
  if (y < x) return 1
  return 0
}

// Finds either the first index of `val` in `buffer` at offset >= `byteOffset`,
// OR the last index of `val` in `buffer` at offset <= `byteOffset`.
//
// Arguments:
// - buffer - a Buffer to search
// - val - a string, Buffer, or number
// - byteOffset - an index into `buffer`; will be clamped to an int32
// - encoding - an optional encoding, relevant is val is a string
// - dir - true for indexOf, false for lastIndexOf
function bidirectionalIndexOf (buffer, val, byteOffset, encoding, dir) {
  // Empty buffer means no match
  if (buffer.length === 0) return -1

  // Normalize byteOffset
  if (typeof byteOffset === 'string') {
    encoding = byteOffset
    byteOffset = 0
  } else if (byteOffset > 0x7fffffff) {
    byteOffset = 0x7fffffff
  } else if (byteOffset < -0x80000000) {
    byteOffset = -0x80000000
  }
  byteOffset = +byteOffset  // Coerce to Number.
  if (isNaN(byteOffset)) {
    // byteOffset: it it's undefined, null, NaN, "foo", etc, search whole buffer
    byteOffset = dir ? 0 : (buffer.length - 1)
  }

  // Normalize byteOffset: negative offsets start from the end of the buffer
  if (byteOffset < 0) byteOffset = buffer.length + byteOffset
  if (byteOffset >= buffer.length) {
    if (dir) return -1
    else byteOffset = buffer.length - 1
  } else if (byteOffset < 0) {
    if (dir) byteOffset = 0
    else return -1
  }

  // Normalize val
  if (typeof val === 'string') {
    val = Buffer.from(val, encoding)
  }

  // Finally, search either indexOf (if dir is true) or lastIndexOf
  if (Buffer.isBuffer(val)) {
    // Special case: looking for empty string/buffer always fails
    if (val.length === 0) {
      return -1
    }
    return arrayIndexOf(buffer, val, byteOffset, encoding, dir)
  } else if (typeof val === 'number') {
    val = val & 0xFF // Search for a byte value [0-255]
    if (Buffer.TYPED_ARRAY_SUPPORT &&
        typeof Uint8Array.prototype.indexOf === 'function') {
      if (dir) {
        return Uint8Array.prototype.indexOf.call(buffer, val, byteOffset)
      } else {
        return Uint8Array.prototype.lastIndexOf.call(buffer, val, byteOffset)
      }
    }
    return arrayIndexOf(buffer, [ val ], byteOffset, encoding, dir)
  }

  throw new TypeError('val must be string, number or Buffer')
}

function arrayIndexOf (arr, val, byteOffset, encoding, dir) {
  var indexSize = 1
  var arrLength = arr.length
  var valLength = val.length

  if (encoding !== undefined) {
    encoding = String(encoding).toLowerCase()
    if (encoding === 'ucs2' || encoding === 'ucs-2' ||
        encoding === 'utf16le' || encoding === 'utf-16le') {
      if (arr.length < 2 || val.length < 2) {
        return -1
      }
      indexSize = 2
      arrLength /= 2
      valLength /= 2
      byteOffset /= 2
    }
  }

  function read (buf, i) {
    if (indexSize === 1) {
      return buf[i]
    } else {
      return buf.readUInt16BE(i * indexSize)
    }
  }

  var i
  if (dir) {
    var foundIndex = -1
    for (i = byteOffset; i < arrLength; i++) {
      if (read(arr, i) === read(val, foundIndex === -1 ? 0 : i - foundIndex)) {
        if (foundIndex === -1) foundIndex = i
        if (i - foundIndex + 1 === valLength) return foundIndex * indexSize
      } else {
        if (foundIndex !== -1) i -= i - foundIndex
        foundIndex = -1
      }
    }
  } else {
    if (byteOffset + valLength > arrLength) byteOffset = arrLength - valLength
    for (i = byteOffset; i >= 0; i--) {
      var found = true
      for (var j = 0; j < valLength; j++) {
        if (read(arr, i + j) !== read(val, j)) {
          found = false
          break
        }
      }
      if (found) return i
    }
  }

  return -1
}

Buffer.prototype.includes = function includes (val, byteOffset, encoding) {
  return this.indexOf(val, byteOffset, encoding) !== -1
}

Buffer.prototype.indexOf = function indexOf (val, byteOffset, encoding) {
  return bidirectionalIndexOf(this, val, byteOffset, encoding, true)
}

Buffer.prototype.lastIndexOf = function lastIndexOf (val, byteOffset, encoding) {
  return bidirectionalIndexOf(this, val, byteOffset, encoding, false)
}

function hexWrite (buf, string, offset, length) {
  offset = Number(offset) || 0
  var remaining = buf.length - offset
  if (!length) {
    length = remaining
  } else {
    length = Number(length)
    if (length > remaining) {
      length = remaining
    }
  }

  // must be an even number of digits
  var strLen = string.length
  if (strLen % 2 !== 0) throw new TypeError('Invalid hex string')

  if (length > strLen / 2) {
    length = strLen / 2
  }
  for (var i = 0; i < length; ++i) {
    var parsed = parseInt(string.substr(i * 2, 2), 16)
    if (isNaN(parsed)) return i
    buf[offset + i] = parsed
  }
  return i
}

function utf8Write (buf, string, offset, length) {
  return blitBuffer(utf8ToBytes(string, buf.length - offset), buf, offset, length)
}

function asciiWrite (buf, string, offset, length) {
  return blitBuffer(asciiToBytes(string), buf, offset, length)
}

function latin1Write (buf, string, offset, length) {
  return asciiWrite(buf, string, offset, length)
}

function base64Write (buf, string, offset, length) {
  return blitBuffer(base64ToBytes(string), buf, offset, length)
}

function ucs2Write (buf, string, offset, length) {
  return blitBuffer(utf16leToBytes(string, buf.length - offset), buf, offset, length)
}

Buffer.prototype.write = function write (string, offset, length, encoding) {
  // Buffer#write(string)
  if (offset === undefined) {
    encoding = 'utf8'
    length = this.length
    offset = 0
  // Buffer#write(string, encoding)
  } else if (length === undefined && typeof offset === 'string') {
    encoding = offset
    length = this.length
    offset = 0
  // Buffer#write(string, offset[, length][, encoding])
  } else if (isFinite(offset)) {
    offset = offset | 0
    if (isFinite(length)) {
      length = length | 0
      if (encoding === undefined) encoding = 'utf8'
    } else {
      encoding = length
      length = undefined
    }
  // legacy write(string, encoding, offset, length) - remove in v0.13
  } else {
    throw new Error(
      'Buffer.write(string, encoding, offset[, length]) is no longer supported'
    )
  }

  var remaining = this.length - offset
  if (length === undefined || length > remaining) length = remaining

  if ((string.length > 0 && (length < 0 || offset < 0)) || offset > this.length) {
    throw new RangeError('Attempt to write outside buffer bounds')
  }

  if (!encoding) encoding = 'utf8'

  var loweredCase = false
  for (;;) {
    switch (encoding) {
      case 'hex':
        return hexWrite(this, string, offset, length)

      case 'utf8':
      case 'utf-8':
        return utf8Write(this, string, offset, length)

      case 'ascii':
        return asciiWrite(this, string, offset, length)

      case 'latin1':
      case 'binary':
        return latin1Write(this, string, offset, length)

      case 'base64':
        // Warning: maxLength not taken into account in base64Write
        return base64Write(this, string, offset, length)

      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return ucs2Write(this, string, offset, length)

      default:
        if (loweredCase) throw new TypeError('Unknown encoding: ' + encoding)
        encoding = ('' + encoding).toLowerCase()
        loweredCase = true
    }
  }
}

Buffer.prototype.toJSON = function toJSON () {
  return {
    type: 'Buffer',
    data: Array.prototype.slice.call(this._arr || this, 0)
  }
}

function base64Slice (buf, start, end) {
  if (start === 0 && end === buf.length) {
    return base64.fromByteArray(buf)
  } else {
    return base64.fromByteArray(buf.slice(start, end))
  }
}

function utf8Slice (buf, start, end) {
  end = Math.min(buf.length, end)
  var res = []

  var i = start
  while (i < end) {
    var firstByte = buf[i]
    var codePoint = null
    var bytesPerSequence = (firstByte > 0xEF) ? 4
      : (firstByte > 0xDF) ? 3
      : (firstByte > 0xBF) ? 2
      : 1

    if (i + bytesPerSequence <= end) {
      var secondByte, thirdByte, fourthByte, tempCodePoint

      switch (bytesPerSequence) {
        case 1:
          if (firstByte < 0x80) {
            codePoint = firstByte
          }
          break
        case 2:
          secondByte = buf[i + 1]
          if ((secondByte & 0xC0) === 0x80) {
            tempCodePoint = (firstByte & 0x1F) << 0x6 | (secondByte & 0x3F)
            if (tempCodePoint > 0x7F) {
              codePoint = tempCodePoint
            }
          }
          break
        case 3:
          secondByte = buf[i + 1]
          thirdByte = buf[i + 2]
          if ((secondByte & 0xC0) === 0x80 && (thirdByte & 0xC0) === 0x80) {
            tempCodePoint = (firstByte & 0xF) << 0xC | (secondByte & 0x3F) << 0x6 | (thirdByte & 0x3F)
            if (tempCodePoint > 0x7FF && (tempCodePoint < 0xD800 || tempCodePoint > 0xDFFF)) {
              codePoint = tempCodePoint
            }
          }
          break
        case 4:
          secondByte = buf[i + 1]
          thirdByte = buf[i + 2]
          fourthByte = buf[i + 3]
          if ((secondByte & 0xC0) === 0x80 && (thirdByte & 0xC0) === 0x80 && (fourthByte & 0xC0) === 0x80) {
            tempCodePoint = (firstByte & 0xF) << 0x12 | (secondByte & 0x3F) << 0xC | (thirdByte & 0x3F) << 0x6 | (fourthByte & 0x3F)
            if (tempCodePoint > 0xFFFF && tempCodePoint < 0x110000) {
              codePoint = tempCodePoint
            }
          }
      }
    }

    if (codePoint === null) {
      // we did not generate a valid codePoint so insert a
      // replacement char (U+FFFD) and advance only 1 byte
      codePoint = 0xFFFD
      bytesPerSequence = 1
    } else if (codePoint > 0xFFFF) {
      // encode to utf16 (surrogate pair dance)
      codePoint -= 0x10000
      res.push(codePoint >>> 10 & 0x3FF | 0xD800)
      codePoint = 0xDC00 | codePoint & 0x3FF
    }

    res.push(codePoint)
    i += bytesPerSequence
  }

  return decodeCodePointsArray(res)
}

// Based on http://stackoverflow.com/a/22747272/680742, the browser with
// the lowest limit is Chrome, with 0x10000 args.
// We go 1 magnitude less, for safety
var MAX_ARGUMENTS_LENGTH = 0x1000

function decodeCodePointsArray (codePoints) {
  var len = codePoints.length
  if (len <= MAX_ARGUMENTS_LENGTH) {
    return String.fromCharCode.apply(String, codePoints) // avoid extra slice()
  }

  // Decode in chunks to avoid "call stack size exceeded".
  var res = ''
  var i = 0
  while (i < len) {
    res += String.fromCharCode.apply(
      String,
      codePoints.slice(i, i += MAX_ARGUMENTS_LENGTH)
    )
  }
  return res
}

function asciiSlice (buf, start, end) {
  var ret = ''
  end = Math.min(buf.length, end)

  for (var i = start; i < end; ++i) {
    ret += String.fromCharCode(buf[i] & 0x7F)
  }
  return ret
}

function latin1Slice (buf, start, end) {
  var ret = ''
  end = Math.min(buf.length, end)

  for (var i = start; i < end; ++i) {
    ret += String.fromCharCode(buf[i])
  }
  return ret
}

function hexSlice (buf, start, end) {
  var len = buf.length

  if (!start || start < 0) start = 0
  if (!end || end < 0 || end > len) end = len

  var out = ''
  for (var i = start; i < end; ++i) {
    out += toHex(buf[i])
  }
  return out
}

function utf16leSlice (buf, start, end) {
  var bytes = buf.slice(start, end)
  var res = ''
  for (var i = 0; i < bytes.length; i += 2) {
    res += String.fromCharCode(bytes[i] + bytes[i + 1] * 256)
  }
  return res
}

Buffer.prototype.slice = function slice (start, end) {
  var len = this.length
  start = ~~start
  end = end === undefined ? len : ~~end

  if (start < 0) {
    start += len
    if (start < 0) start = 0
  } else if (start > len) {
    start = len
  }

  if (end < 0) {
    end += len
    if (end < 0) end = 0
  } else if (end > len) {
    end = len
  }

  if (end < start) end = start

  var newBuf
  if (Buffer.TYPED_ARRAY_SUPPORT) {
    newBuf = this.subarray(start, end)
    newBuf.__proto__ = Buffer.prototype
  } else {
    var sliceLen = end - start
    newBuf = new Buffer(sliceLen, undefined)
    for (var i = 0; i < sliceLen; ++i) {
      newBuf[i] = this[i + start]
    }
  }

  return newBuf
}

/*
 * Need to make sure that buffer isn't trying to write out of bounds.
 */
function checkOffset (offset, ext, length) {
  if ((offset % 1) !== 0 || offset < 0) throw new RangeError('offset is not uint')
  if (offset + ext > length) throw new RangeError('Trying to access beyond buffer length')
}

Buffer.prototype.readUIntLE = function readUIntLE (offset, byteLength, noAssert) {
  offset = offset | 0
  byteLength = byteLength | 0
  if (!noAssert) checkOffset(offset, byteLength, this.length)

  var val = this[offset]
  var mul = 1
  var i = 0
  while (++i < byteLength && (mul *= 0x100)) {
    val += this[offset + i] * mul
  }

  return val
}

Buffer.prototype.readUIntBE = function readUIntBE (offset, byteLength, noAssert) {
  offset = offset | 0
  byteLength = byteLength | 0
  if (!noAssert) {
    checkOffset(offset, byteLength, this.length)
  }

  var val = this[offset + --byteLength]
  var mul = 1
  while (byteLength > 0 && (mul *= 0x100)) {
    val += this[offset + --byteLength] * mul
  }

  return val
}

Buffer.prototype.readUInt8 = function readUInt8 (offset, noAssert) {
  if (!noAssert) checkOffset(offset, 1, this.length)
  return this[offset]
}

Buffer.prototype.readUInt16LE = function readUInt16LE (offset, noAssert) {
  if (!noAssert) checkOffset(offset, 2, this.length)
  return this[offset] | (this[offset + 1] << 8)
}

Buffer.prototype.readUInt16BE = function readUInt16BE (offset, noAssert) {
  if (!noAssert) checkOffset(offset, 2, this.length)
  return (this[offset] << 8) | this[offset + 1]
}

Buffer.prototype.readUInt32LE = function readUInt32LE (offset, noAssert) {
  if (!noAssert) checkOffset(offset, 4, this.length)

  return ((this[offset]) |
      (this[offset + 1] << 8) |
      (this[offset + 2] << 16)) +
      (this[offset + 3] * 0x1000000)
}

Buffer.prototype.readUInt32BE = function readUInt32BE (offset, noAssert) {
  if (!noAssert) checkOffset(offset, 4, this.length)

  return (this[offset] * 0x1000000) +
    ((this[offset + 1] << 16) |
    (this[offset + 2] << 8) |
    this[offset + 3])
}

Buffer.prototype.readIntLE = function readIntLE (offset, byteLength, noAssert) {
  offset = offset | 0
  byteLength = byteLength | 0
  if (!noAssert) checkOffset(offset, byteLength, this.length)

  var val = this[offset]
  var mul = 1
  var i = 0
  while (++i < byteLength && (mul *= 0x100)) {
    val += this[offset + i] * mul
  }
  mul *= 0x80

  if (val >= mul) val -= Math.pow(2, 8 * byteLength)

  return val
}

Buffer.prototype.readIntBE = function readIntBE (offset, byteLength, noAssert) {
  offset = offset | 0
  byteLength = byteLength | 0
  if (!noAssert) checkOffset(offset, byteLength, this.length)

  var i = byteLength
  var mul = 1
  var val = this[offset + --i]
  while (i > 0 && (mul *= 0x100)) {
    val += this[offset + --i] * mul
  }
  mul *= 0x80

  if (val >= mul) val -= Math.pow(2, 8 * byteLength)

  return val
}

Buffer.prototype.readInt8 = function readInt8 (offset, noAssert) {
  if (!noAssert) checkOffset(offset, 1, this.length)
  if (!(this[offset] & 0x80)) return (this[offset])
  return ((0xff - this[offset] + 1) * -1)
}

Buffer.prototype.readInt16LE = function readInt16LE (offset, noAssert) {
  if (!noAssert) checkOffset(offset, 2, this.length)
  var val = this[offset] | (this[offset + 1] << 8)
  return (val & 0x8000) ? val | 0xFFFF0000 : val
}

Buffer.prototype.readInt16BE = function readInt16BE (offset, noAssert) {
  if (!noAssert) checkOffset(offset, 2, this.length)
  var val = this[offset + 1] | (this[offset] << 8)
  return (val & 0x8000) ? val | 0xFFFF0000 : val
}

Buffer.prototype.readInt32LE = function readInt32LE (offset, noAssert) {
  if (!noAssert) checkOffset(offset, 4, this.length)

  return (this[offset]) |
    (this[offset + 1] << 8) |
    (this[offset + 2] << 16) |
    (this[offset + 3] << 24)
}

Buffer.prototype.readInt32BE = function readInt32BE (offset, noAssert) {
  if (!noAssert) checkOffset(offset, 4, this.length)

  return (this[offset] << 24) |
    (this[offset + 1] << 16) |
    (this[offset + 2] << 8) |
    (this[offset + 3])
}

Buffer.prototype.readFloatLE = function readFloatLE (offset, noAssert) {
  if (!noAssert) checkOffset(offset, 4, this.length)
  return ieee754.read(this, offset, true, 23, 4)
}

Buffer.prototype.readFloatBE = function readFloatBE (offset, noAssert) {
  if (!noAssert) checkOffset(offset, 4, this.length)
  return ieee754.read(this, offset, false, 23, 4)
}

Buffer.prototype.readDoubleLE = function readDoubleLE (offset, noAssert) {
  if (!noAssert) checkOffset(offset, 8, this.length)
  return ieee754.read(this, offset, true, 52, 8)
}

Buffer.prototype.readDoubleBE = function readDoubleBE (offset, noAssert) {
  if (!noAssert) checkOffset(offset, 8, this.length)
  return ieee754.read(this, offset, false, 52, 8)
}

function checkInt (buf, value, offset, ext, max, min) {
  if (!Buffer.isBuffer(buf)) throw new TypeError('"buffer" argument must be a Buffer instance')
  if (value > max || value < min) throw new RangeError('"value" argument is out of bounds')
  if (offset + ext > buf.length) throw new RangeError('Index out of range')
}

Buffer.prototype.writeUIntLE = function writeUIntLE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset | 0
  byteLength = byteLength | 0
  if (!noAssert) {
    var maxBytes = Math.pow(2, 8 * byteLength) - 1
    checkInt(this, value, offset, byteLength, maxBytes, 0)
  }

  var mul = 1
  var i = 0
  this[offset] = value & 0xFF
  while (++i < byteLength && (mul *= 0x100)) {
    this[offset + i] = (value / mul) & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeUIntBE = function writeUIntBE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset | 0
  byteLength = byteLength | 0
  if (!noAssert) {
    var maxBytes = Math.pow(2, 8 * byteLength) - 1
    checkInt(this, value, offset, byteLength, maxBytes, 0)
  }

  var i = byteLength - 1
  var mul = 1
  this[offset + i] = value & 0xFF
  while (--i >= 0 && (mul *= 0x100)) {
    this[offset + i] = (value / mul) & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeUInt8 = function writeUInt8 (value, offset, noAssert) {
  value = +value
  offset = offset | 0
  if (!noAssert) checkInt(this, value, offset, 1, 0xff, 0)
  if (!Buffer.TYPED_ARRAY_SUPPORT) value = Math.floor(value)
  this[offset] = (value & 0xff)
  return offset + 1
}

function objectWriteUInt16 (buf, value, offset, littleEndian) {
  if (value < 0) value = 0xffff + value + 1
  for (var i = 0, j = Math.min(buf.length - offset, 2); i < j; ++i) {
    buf[offset + i] = (value & (0xff << (8 * (littleEndian ? i : 1 - i)))) >>>
      (littleEndian ? i : 1 - i) * 8
  }
}

Buffer.prototype.writeUInt16LE = function writeUInt16LE (value, offset, noAssert) {
  value = +value
  offset = offset | 0
  if (!noAssert) checkInt(this, value, offset, 2, 0xffff, 0)
  if (Buffer.TYPED_ARRAY_SUPPORT) {
    this[offset] = (value & 0xff)
    this[offset + 1] = (value >>> 8)
  } else {
    objectWriteUInt16(this, value, offset, true)
  }
  return offset + 2
}

Buffer.prototype.writeUInt16BE = function writeUInt16BE (value, offset, noAssert) {
  value = +value
  offset = offset | 0
  if (!noAssert) checkInt(this, value, offset, 2, 0xffff, 0)
  if (Buffer.TYPED_ARRAY_SUPPORT) {
    this[offset] = (value >>> 8)
    this[offset + 1] = (value & 0xff)
  } else {
    objectWriteUInt16(this, value, offset, false)
  }
  return offset + 2
}

function objectWriteUInt32 (buf, value, offset, littleEndian) {
  if (value < 0) value = 0xffffffff + value + 1
  for (var i = 0, j = Math.min(buf.length - offset, 4); i < j; ++i) {
    buf[offset + i] = (value >>> (littleEndian ? i : 3 - i) * 8) & 0xff
  }
}

Buffer.prototype.writeUInt32LE = function writeUInt32LE (value, offset, noAssert) {
  value = +value
  offset = offset | 0
  if (!noAssert) checkInt(this, value, offset, 4, 0xffffffff, 0)
  if (Buffer.TYPED_ARRAY_SUPPORT) {
    this[offset + 3] = (value >>> 24)
    this[offset + 2] = (value >>> 16)
    this[offset + 1] = (value >>> 8)
    this[offset] = (value & 0xff)
  } else {
    objectWriteUInt32(this, value, offset, true)
  }
  return offset + 4
}

Buffer.prototype.writeUInt32BE = function writeUInt32BE (value, offset, noAssert) {
  value = +value
  offset = offset | 0
  if (!noAssert) checkInt(this, value, offset, 4, 0xffffffff, 0)
  if (Buffer.TYPED_ARRAY_SUPPORT) {
    this[offset] = (value >>> 24)
    this[offset + 1] = (value >>> 16)
    this[offset + 2] = (value >>> 8)
    this[offset + 3] = (value & 0xff)
  } else {
    objectWriteUInt32(this, value, offset, false)
  }
  return offset + 4
}

Buffer.prototype.writeIntLE = function writeIntLE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset | 0
  if (!noAssert) {
    var limit = Math.pow(2, 8 * byteLength - 1)

    checkInt(this, value, offset, byteLength, limit - 1, -limit)
  }

  var i = 0
  var mul = 1
  var sub = 0
  this[offset] = value & 0xFF
  while (++i < byteLength && (mul *= 0x100)) {
    if (value < 0 && sub === 0 && this[offset + i - 1] !== 0) {
      sub = 1
    }
    this[offset + i] = ((value / mul) >> 0) - sub & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeIntBE = function writeIntBE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset | 0
  if (!noAssert) {
    var limit = Math.pow(2, 8 * byteLength - 1)

    checkInt(this, value, offset, byteLength, limit - 1, -limit)
  }

  var i = byteLength - 1
  var mul = 1
  var sub = 0
  this[offset + i] = value & 0xFF
  while (--i >= 0 && (mul *= 0x100)) {
    if (value < 0 && sub === 0 && this[offset + i + 1] !== 0) {
      sub = 1
    }
    this[offset + i] = ((value / mul) >> 0) - sub & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeInt8 = function writeInt8 (value, offset, noAssert) {
  value = +value
  offset = offset | 0
  if (!noAssert) checkInt(this, value, offset, 1, 0x7f, -0x80)
  if (!Buffer.TYPED_ARRAY_SUPPORT) value = Math.floor(value)
  if (value < 0) value = 0xff + value + 1
  this[offset] = (value & 0xff)
  return offset + 1
}

Buffer.prototype.writeInt16LE = function writeInt16LE (value, offset, noAssert) {
  value = +value
  offset = offset | 0
  if (!noAssert) checkInt(this, value, offset, 2, 0x7fff, -0x8000)
  if (Buffer.TYPED_ARRAY_SUPPORT) {
    this[offset] = (value & 0xff)
    this[offset + 1] = (value >>> 8)
  } else {
    objectWriteUInt16(this, value, offset, true)
  }
  return offset + 2
}

Buffer.prototype.writeInt16BE = function writeInt16BE (value, offset, noAssert) {
  value = +value
  offset = offset | 0
  if (!noAssert) checkInt(this, value, offset, 2, 0x7fff, -0x8000)
  if (Buffer.TYPED_ARRAY_SUPPORT) {
    this[offset] = (value >>> 8)
    this[offset + 1] = (value & 0xff)
  } else {
    objectWriteUInt16(this, value, offset, false)
  }
  return offset + 2
}

Buffer.prototype.writeInt32LE = function writeInt32LE (value, offset, noAssert) {
  value = +value
  offset = offset | 0
  if (!noAssert) checkInt(this, value, offset, 4, 0x7fffffff, -0x80000000)
  if (Buffer.TYPED_ARRAY_SUPPORT) {
    this[offset] = (value & 0xff)
    this[offset + 1] = (value >>> 8)
    this[offset + 2] = (value >>> 16)
    this[offset + 3] = (value >>> 24)
  } else {
    objectWriteUInt32(this, value, offset, true)
  }
  return offset + 4
}

Buffer.prototype.writeInt32BE = function writeInt32BE (value, offset, noAssert) {
  value = +value
  offset = offset | 0
  if (!noAssert) checkInt(this, value, offset, 4, 0x7fffffff, -0x80000000)
  if (value < 0) value = 0xffffffff + value + 1
  if (Buffer.TYPED_ARRAY_SUPPORT) {
    this[offset] = (value >>> 24)
    this[offset + 1] = (value >>> 16)
    this[offset + 2] = (value >>> 8)
    this[offset + 3] = (value & 0xff)
  } else {
    objectWriteUInt32(this, value, offset, false)
  }
  return offset + 4
}

function checkIEEE754 (buf, value, offset, ext, max, min) {
  if (offset + ext > buf.length) throw new RangeError('Index out of range')
  if (offset < 0) throw new RangeError('Index out of range')
}

function writeFloat (buf, value, offset, littleEndian, noAssert) {
  if (!noAssert) {
    checkIEEE754(buf, value, offset, 4, 3.4028234663852886e+38, -3.4028234663852886e+38)
  }
  ieee754.write(buf, value, offset, littleEndian, 23, 4)
  return offset + 4
}

Buffer.prototype.writeFloatLE = function writeFloatLE (value, offset, noAssert) {
  return writeFloat(this, value, offset, true, noAssert)
}

Buffer.prototype.writeFloatBE = function writeFloatBE (value, offset, noAssert) {
  return writeFloat(this, value, offset, false, noAssert)
}

function writeDouble (buf, value, offset, littleEndian, noAssert) {
  if (!noAssert) {
    checkIEEE754(buf, value, offset, 8, 1.7976931348623157E+308, -1.7976931348623157E+308)
  }
  ieee754.write(buf, value, offset, littleEndian, 52, 8)
  return offset + 8
}

Buffer.prototype.writeDoubleLE = function writeDoubleLE (value, offset, noAssert) {
  return writeDouble(this, value, offset, true, noAssert)
}

Buffer.prototype.writeDoubleBE = function writeDoubleBE (value, offset, noAssert) {
  return writeDouble(this, value, offset, false, noAssert)
}

// copy(targetBuffer, targetStart=0, sourceStart=0, sourceEnd=buffer.length)
Buffer.prototype.copy = function copy (target, targetStart, start, end) {
  if (!start) start = 0
  if (!end && end !== 0) end = this.length
  if (targetStart >= target.length) targetStart = target.length
  if (!targetStart) targetStart = 0
  if (end > 0 && end < start) end = start

  // Copy 0 bytes; we're done
  if (end === start) return 0
  if (target.length === 0 || this.length === 0) return 0

  // Fatal error conditions
  if (targetStart < 0) {
    throw new RangeError('targetStart out of bounds')
  }
  if (start < 0 || start >= this.length) throw new RangeError('sourceStart out of bounds')
  if (end < 0) throw new RangeError('sourceEnd out of bounds')

  // Are we oob?
  if (end > this.length) end = this.length
  if (target.length - targetStart < end - start) {
    end = target.length - targetStart + start
  }

  var len = end - start
  var i

  if (this === target && start < targetStart && targetStart < end) {
    // descending copy from end
    for (i = len - 1; i >= 0; --i) {
      target[i + targetStart] = this[i + start]
    }
  } else if (len < 1000 || !Buffer.TYPED_ARRAY_SUPPORT) {
    // ascending copy from start
    for (i = 0; i < len; ++i) {
      target[i + targetStart] = this[i + start]
    }
  } else {
    Uint8Array.prototype.set.call(
      target,
      this.subarray(start, start + len),
      targetStart
    )
  }

  return len
}

// Usage:
//    buffer.fill(number[, offset[, end]])
//    buffer.fill(buffer[, offset[, end]])
//    buffer.fill(string[, offset[, end]][, encoding])
Buffer.prototype.fill = function fill (val, start, end, encoding) {
  // Handle string cases:
  if (typeof val === 'string') {
    if (typeof start === 'string') {
      encoding = start
      start = 0
      end = this.length
    } else if (typeof end === 'string') {
      encoding = end
      end = this.length
    }
    if (val.length === 1) {
      var code = val.charCodeAt(0)
      if (code < 256) {
        val = code
      }
    }
    if (encoding !== undefined && typeof encoding !== 'string') {
      throw new TypeError('encoding must be a string')
    }
    if (typeof encoding === 'string' && !Buffer.isEncoding(encoding)) {
      throw new TypeError('Unknown encoding: ' + encoding)
    }
  } else if (typeof val === 'number') {
    val = val & 255
  }

  // Invalid ranges are not set to a default, so can range check early.
  if (start < 0 || this.length < start || this.length < end) {
    throw new RangeError('Out of range index')
  }

  if (end <= start) {
    return this
  }

  start = start >>> 0
  end = end === undefined ? this.length : end >>> 0

  if (!val) val = 0

  var i
  if (typeof val === 'number') {
    for (i = start; i < end; ++i) {
      this[i] = val
    }
  } else {
    var bytes = Buffer.isBuffer(val)
      ? val
      : utf8ToBytes(new Buffer(val, encoding).toString())
    var len = bytes.length
    for (i = 0; i < end - start; ++i) {
      this[i + start] = bytes[i % len]
    }
  }

  return this
}

// HELPER FUNCTIONS
// ================

var INVALID_BASE64_RE = /[^+\/0-9A-Za-z-_]/g

function base64clean (str) {
  // Node strips out invalid characters like \n and \t from the string, base64-js does not
  str = stringtrim(str).replace(INVALID_BASE64_RE, '')
  // Node converts strings with length < 2 to ''
  if (str.length < 2) return ''
  // Node allows for non-padded base64 strings (missing trailing ===), base64-js does not
  while (str.length % 4 !== 0) {
    str = str + '='
  }
  return str
}

function stringtrim (str) {
  if (str.trim) return str.trim()
  return str.replace(/^\s+|\s+$/g, '')
}

function toHex (n) {
  if (n < 16) return '0' + n.toString(16)
  return n.toString(16)
}

function utf8ToBytes (string, units) {
  units = units || Infinity
  var codePoint
  var length = string.length
  var leadSurrogate = null
  var bytes = []

  for (var i = 0; i < length; ++i) {
    codePoint = string.charCodeAt(i)

    // is surrogate component
    if (codePoint > 0xD7FF && codePoint < 0xE000) {
      // last char was a lead
      if (!leadSurrogate) {
        // no lead yet
        if (codePoint > 0xDBFF) {
          // unexpected trail
          if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
          continue
        } else if (i + 1 === length) {
          // unpaired lead
          if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
          continue
        }

        // valid lead
        leadSurrogate = codePoint

        continue
      }

      // 2 leads in a row
      if (codePoint < 0xDC00) {
        if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
        leadSurrogate = codePoint
        continue
      }

      // valid surrogate pair
      codePoint = (leadSurrogate - 0xD800 << 10 | codePoint - 0xDC00) + 0x10000
    } else if (leadSurrogate) {
      // valid bmp char, but last char was a lead
      if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
    }

    leadSurrogate = null

    // encode utf8
    if (codePoint < 0x80) {
      if ((units -= 1) < 0) break
      bytes.push(codePoint)
    } else if (codePoint < 0x800) {
      if ((units -= 2) < 0) break
      bytes.push(
        codePoint >> 0x6 | 0xC0,
        codePoint & 0x3F | 0x80
      )
    } else if (codePoint < 0x10000) {
      if ((units -= 3) < 0) break
      bytes.push(
        codePoint >> 0xC | 0xE0,
        codePoint >> 0x6 & 0x3F | 0x80,
        codePoint & 0x3F | 0x80
      )
    } else if (codePoint < 0x110000) {
      if ((units -= 4) < 0) break
      bytes.push(
        codePoint >> 0x12 | 0xF0,
        codePoint >> 0xC & 0x3F | 0x80,
        codePoint >> 0x6 & 0x3F | 0x80,
        codePoint & 0x3F | 0x80
      )
    } else {
      throw new Error('Invalid code point')
    }
  }

  return bytes
}

function asciiToBytes (str) {
  var byteArray = []
  for (var i = 0; i < str.length; ++i) {
    // Node's code seems to be doing this and not & 0x7F..
    byteArray.push(str.charCodeAt(i) & 0xFF)
  }
  return byteArray
}

function utf16leToBytes (str, units) {
  var c, hi, lo
  var byteArray = []
  for (var i = 0; i < str.length; ++i) {
    if ((units -= 2) < 0) break

    c = str.charCodeAt(i)
    hi = c >> 8
    lo = c % 256
    byteArray.push(lo)
    byteArray.push(hi)
  }

  return byteArray
}

function base64ToBytes (str) {
  return base64.toByteArray(base64clean(str))
}

function blitBuffer (src, dst, offset, length) {
  for (var i = 0; i < length; ++i) {
    if ((i + offset >= dst.length) || (i >= src.length)) break
    dst[i + offset] = src[i]
  }
  return i
}

function isnan (val) {
  return val !== val // eslint-disable-line no-self-compare
}

/* WEBPACK VAR INJECTION */}.call(exports, __webpack_require__(19)))

/***/ }),
/* 23 */
/***/ (function(module, exports) {

module.exports = function (bitmap, value) {
  return {
    enumerable: !(bitmap & 1),
    configurable: !(bitmap & 2),
    writable: !(bitmap & 4),
    value: value
  };
};


/***/ }),
/* 24 */
/***/ (function(module, exports, __webpack_require__) {

// 19.1.2.14 / 15.2.3.14 Object.keys(O)
var $keys = __webpack_require__(68);
var enumBugKeys = __webpack_require__(49);

module.exports = Object.keys || function keys(O) {
  return $keys(O, enumBugKeys);
};


/***/ }),
/* 25 */
/***/ (function(module, exports) {

var toString = {}.toString;

module.exports = function (it) {
  return toString.call(it).slice(8, -1);
};


/***/ }),
/* 26 */
/***/ (function(module, exports, __webpack_require__) {

// 7.1.13 ToObject(argument)
var defined = __webpack_require__(44);
module.exports = function (it) {
  return Object(defined(it));
};


/***/ }),
/* 27 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";

var $at = __webpack_require__(125)(true);

// 21.1.3.27 String.prototype[@@iterator]()
__webpack_require__(71)(String, 'String', function (iterated) {
  this._t = String(iterated); // target
  this._i = 0;                // next index
// 21.1.5.2.1 %StringIteratorPrototype%.next()
}, function () {
  var O = this._t;
  var index = this._i;
  var point;
  if (index >= O.length) return { value: undefined, done: true };
  point = $at(O, index);
  this._i += point.length;
  return { value: point, done: false };
});


/***/ }),
/* 28 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


/**
 * @module JSON Object Signing and Encryption (JOSE)
 */
var JWA = __webpack_require__(65);
var JWK = __webpack_require__(103);
var JWKSet = __webpack_require__(189);
var JWT = __webpack_require__(190);
var JWS = __webpack_require__(109);
var Base64URLSchema = __webpack_require__(106);
var JOSEHeaderSchema = __webpack_require__(108);
var JWKSchema = __webpack_require__(41);
var JWKSetSchema = __webpack_require__(104);
var JWTClaimsSetSchema = __webpack_require__(107);
var JWTSchema = __webpack_require__(105

/**
 * Export
 */
);module.exports = {
  JWA: JWA,
  JWK: JWK,
  JWKSet: JWKSet,
  JWT: JWT,
  JWS: JWS,
  Base64URLSchema: Base64URLSchema,
  JOSEHeaderSchema: JOSEHeaderSchema,
  JWKSchema: JWKSchema,
  JWKSetSchema: JWKSetSchema,
  JWTClaimsSetSchema: JWTClaimsSetSchema,
  JWTSchema: JWTSchema
};

/***/ }),
/* 29 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


exports.__esModule = true;

var _assign = __webpack_require__(30);

var _assign2 = _interopRequireDefault(_assign);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

exports.default = _assign2.default || function (target) {
  for (var i = 1; i < arguments.length; i++) {
    var source = arguments[i];

    for (var key in source) {
      if (Object.prototype.hasOwnProperty.call(source, key)) {
        target[key] = source[key];
      }
    }
  }

  return target;
};

/***/ }),
/* 30 */
/***/ (function(module, exports, __webpack_require__) {

module.exports = { "default": __webpack_require__(117), __esModule: true };

/***/ }),
/* 31 */
/***/ (function(module, exports) {

module.exports = function (it) {
  if (typeof it != 'function') throw TypeError(it + ' is not a function!');
  return it;
};


/***/ }),
/* 32 */
/***/ (function(module, exports) {

var id = 0;
var px = Math.random();
module.exports = function (key) {
  return 'Symbol('.concat(key === undefined ? '' : key, ')_', (++id + px).toString(36));
};


/***/ }),
/* 33 */
/***/ (function(module, exports) {

exports.f = {}.propertyIsEnumerable;


/***/ }),
/* 34 */
/***/ (function(module, exports) {

module.exports = true;


/***/ }),
/* 35 */
/***/ (function(module, exports, __webpack_require__) {

var def = __webpack_require__(6).f;
var has = __webpack_require__(10);
var TAG = __webpack_require__(1)('toStringTag');

module.exports = function (it, tag, stat) {
  if (it && !has(it = stat ? it : it.prototype, TAG)) def(it, TAG, { configurable: true, value: tag });
};


/***/ }),
/* 36 */
/***/ (function(module, exports, __webpack_require__) {

__webpack_require__(128);
var global = __webpack_require__(2);
var hide = __webpack_require__(9);
var Iterators = __webpack_require__(18);
var TO_STRING_TAG = __webpack_require__(1)('toStringTag');

var DOMIterables = ('CSSRuleList,CSSStyleDeclaration,CSSValueList,ClientRectList,DOMRectList,DOMStringList,' +
  'DOMTokenList,DataTransferItemList,FileList,HTMLAllCollection,HTMLCollection,HTMLFormElement,HTMLSelectElement,' +
  'MediaList,MimeTypeArray,NamedNodeMap,NodeList,PaintRequestList,Plugin,PluginArray,SVGLengthList,SVGNumberList,' +
  'SVGPathSegList,SVGPointList,SVGStringList,SVGTransformList,SourceBufferList,StyleSheetList,TextTrackCueList,' +
  'TextTrackList,TouchList').split(',');

for (var i = 0; i < DOMIterables.length; i++) {
  var NAME = DOMIterables[i];
  var Collection = global[NAME];
  var proto = Collection && Collection.prototype;
  if (proto && !proto[TO_STRING_TAG]) hide(proto, TO_STRING_TAG, NAME);
  Iterators[NAME] = Iterators.Array;
}


/***/ }),
/* 37 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.postMessageStorage = exports.memStorage = exports.updateStorage = exports.getData = exports.defaultStorage = exports.NAMESPACE = undefined;

var _promise = __webpack_require__(13);

var _promise2 = _interopRequireDefault(_promise);

var _stringify = __webpack_require__(58);

var _stringify2 = _interopRequireDefault(_stringify);

var _regenerator = __webpack_require__(11);

var _regenerator2 = _interopRequireDefault(_regenerator);

var _asyncToGenerator2 = __webpack_require__(12);

var _asyncToGenerator3 = _interopRequireDefault(_asyncToGenerator2);

/**
 * Gets the deserialized stored data
 */
var getData = exports.getData = function () {
  var _ref = (0, _asyncToGenerator3.default)( /*#__PURE__*/_regenerator2.default.mark(function _callee(store) {
    var serialized, data;
    return _regenerator2.default.wrap(function _callee$(_context) {
      while (1) {
        switch (_context.prev = _context.next) {
          case 0:
            serialized = void 0;
            data = void 0;
            _context.prev = 2;
            _context.next = 5;
            return store.getItem(NAMESPACE);

          case 5:
            serialized = _context.sent;

            data = JSON.parse(serialized || '{}');
            _context.next = 14;
            break;

          case 9:
            _context.prev = 9;
            _context.t0 = _context['catch'](2);

            console.warn('Could not deserialize data:', serialized);
            console.error(_context.t0);
            data = {};

          case 14:
            return _context.abrupt('return', data);

          case 15:
          case 'end':
            return _context.stop();
        }
      }
    }, _callee, this, [[2, 9]]);
  }));

  return function getData(_x) {
    return _ref.apply(this, arguments);
  };
}();

/**
 * Updates a Storage object without mutating its intermediate representation.
 */


var updateStorage = exports.updateStorage = function () {
  var _ref2 = (0, _asyncToGenerator3.default)( /*#__PURE__*/_regenerator2.default.mark(function _callee2(store, update) {
    var currentData, newData;
    return _regenerator2.default.wrap(function _callee2$(_context2) {
      while (1) {
        switch (_context2.prev = _context2.next) {
          case 0:
            _context2.next = 2;
            return getData(store);

          case 2:
            currentData = _context2.sent;
            newData = update(currentData);
            _context2.next = 6;
            return store.setItem(NAMESPACE, (0, _stringify2.default)(newData));

          case 6:
            return _context2.abrupt('return', newData);

          case 7:
          case 'end':
            return _context2.stop();
        }
      }
    }, _callee2, this);
  }));

  return function updateStorage(_x2, _x3) {
    return _ref2.apply(this, arguments);
  };
}();

/**
 * Takes a synchronous storage interface and wraps it with an async interface.
 */


exports.asyncStorage = asyncStorage;

var _ipc = __webpack_require__(83);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

var NAMESPACE = exports.NAMESPACE = 'solid-auth-client';
var defaultStorage = exports.defaultStorage = function defaultStorage() {
  try {
    if (window && window.localStorage) {
      return asyncStorage(window.localStorage);
    }
  } catch (e) {
    if (!(e instanceof ReferenceError)) {
      throw e;
    }
  }
  console.warn('\'window.localStorage\' unavailable.  ' + 'Creating a (not very useful) in-memory storage object as the default storage interface.');
  return asyncStorage(memStorage());
};function asyncStorage(storage) {
  return {
    getItem: function getItem(key) {
      return _promise2.default.resolve(storage.getItem(key));
    },

    setItem: function setItem(key, val) {
      return _promise2.default.resolve(storage.setItem(key, val));
    },

    removeItem: function removeItem(key) {
      return _promise2.default.resolve(storage.removeItem(key));
    }
  };
}

var memStorage = exports.memStorage = function memStorage() {
  var store = {};
  return {
    getItem: function getItem(key) {
      if (typeof store[key] === 'undefined') return null;
      return store[key];
    },
    setItem: function setItem(key, val) {
      store[key] = val;
    },
    removeItem: function removeItem(key) {
      delete store[key];
    }
  };
};

var postMessageStorage = exports.postMessageStorage = function postMessageStorage(storageWindow, storageOrigin) {
  var request = (0, _ipc.client)(storageWindow, storageOrigin);
  return {
    getItem: function () {
      var _ref3 = (0, _asyncToGenerator3.default)( /*#__PURE__*/_regenerator2.default.mark(function _callee3(key) {
        var ret;
        return _regenerator2.default.wrap(function _callee3$(_context3) {
          while (1) {
            switch (_context3.prev = _context3.next) {
              case 0:
                _context3.next = 2;
                return request({ method: 'storage/getItem', args: [key] });

              case 2:
                ret = _context3.sent;

                if (!(typeof ret !== 'string')) {
                  _context3.next = 5;
                  break;
                }

                throw new Error('expected postMessage call for \'storage/getItem\' to return a string, but got value ' + ret);

              case 5:
                return _context3.abrupt('return', ret);

              case 6:
              case 'end':
                return _context3.stop();
            }
          }
        }, _callee3, undefined);
      }));

      function getItem(_x4) {
        return _ref3.apply(this, arguments);
      }

      return getItem;
    }(),

    setItem: function setItem(key, val) {
      return request({ method: 'storage/setItem', args: [key, val] });
    },

    removeItem: function removeItem(key) {
      return request({ method: 'storage/removeItem', args: [key] });
    }
  };
};

/***/ }),
/* 38 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


exports.__esModule = true;

var _iterator = __webpack_require__(146);

var _iterator2 = _interopRequireDefault(_iterator);

var _symbol = __webpack_require__(148);

var _symbol2 = _interopRequireDefault(_symbol);

var _typeof = typeof _symbol2.default === "function" && typeof _iterator2.default === "symbol" ? function (obj) { return typeof obj; } : function (obj) { return obj && typeof _symbol2.default === "function" && obj.constructor === _symbol2.default && obj !== _symbol2.default.prototype ? "symbol" : typeof obj; };

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

exports.default = typeof _symbol2.default === "function" && _typeof(_iterator2.default) === "symbol" ? function (obj) {
  return typeof obj === "undefined" ? "undefined" : _typeof(obj);
} : function (obj) {
  return obj && typeof _symbol2.default === "function" && obj.constructor === _symbol2.default && obj !== _symbol2.default.prototype ? "symbol" : typeof obj === "undefined" ? "undefined" : _typeof(obj);
};

/***/ }),
/* 39 */
/***/ (function(module, exports) {

module.exports = __WEBPACK_EXTERNAL_MODULE_39__;

/***/ }),
/* 40 */
/***/ (function(module, exports) {

module.exports = __WEBPACK_EXTERNAL_MODULE_40__;

/***/ }),
/* 41 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


/**
 * Dependencies
 * @ignore
 */

var _require = __webpack_require__(3),
    JSONSchema = _require.JSONSchema;

var _require2 = __webpack_require__(188

/**
 * JWK Schema
 */
),
    BASE64_REGEXP = _require2.BASE64_REGEXP;

var JWKSchema = new JSONSchema({
  type: 'object',
  properties: {

    kty: {
      type: 'string',
      //format: 'case-sensitive',
      enum: ['RSA', 'EC', 'oct'] // other values MAY be used
    },

    use: {
      type: 'string',
      //format: 'case-sensitive',
      enum: ['sig', 'enc'] // other values MAY be used
    },

    key_ops: {
      type: 'array',
      //format: 'case-sensitive',
      items: {
        enum: ['sign', 'verify', 'encrypt', 'decrypt', 'wrapKey', 'unwrapKey', 'deriveKey', 'deriveBits'] // other values MAY be used
      }
    },

    alg: {
      type: 'string',
      //format: 'case-sensitive',
      enum: ['HS256', 'HS384', 'HS512', 'RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512', 'none'] // other values MAY be used
    },

    kid: {
      type: 'string'
    },

    x5u: {
      type: 'string'
      //format: 'url'
    },

    x5c: {
      type: 'array'
      //format: BASE64_REGEXP
    },

    x5t: {
      type: 'string'
      //format: BASE64_REGEXP
    }

    //'x5t#S256': {
    //  type: 'string',
    //  //format: BASE64_REGEXP
    //}
  }
});

/**
 * Export
 */
module.exports = JWKSchema;

/***/ }),
/* 42 */
/***/ (function(module, exports, __webpack_require__) {

var isObject = __webpack_require__(7);
var document = __webpack_require__(2).document;
// typeof document.createElement is 'object' in old IE
var is = isObject(document) && isObject(document.createElement);
module.exports = function (it) {
  return is ? document.createElement(it) : {};
};


/***/ }),
/* 43 */
/***/ (function(module, exports, __webpack_require__) {

// 7.1.1 ToPrimitive(input [, PreferredType])
var isObject = __webpack_require__(7);
// instead of the ES6 spec version, we didn't implement @@toPrimitive case
// and the second argument - flag - preferred type is a string
module.exports = function (it, S) {
  if (!isObject(it)) return it;
  var fn, val;
  if (S && typeof (fn = it.toString) == 'function' && !isObject(val = fn.call(it))) return val;
  if (typeof (fn = it.valueOf) == 'function' && !isObject(val = fn.call(it))) return val;
  if (!S && typeof (fn = it.toString) == 'function' && !isObject(val = fn.call(it))) return val;
  throw TypeError("Can't convert object to primitive value");
};


/***/ }),
/* 44 */
/***/ (function(module, exports) {

// 7.2.1 RequireObjectCoercible(argument)
module.exports = function (it) {
  if (it == undefined) throw TypeError("Can't call method on  " + it);
  return it;
};


/***/ }),
/* 45 */
/***/ (function(module, exports, __webpack_require__) {

// 7.1.15 ToLength
var toInteger = __webpack_require__(46);
var min = Math.min;
module.exports = function (it) {
  return it > 0 ? min(toInteger(it), 0x1fffffffffffff) : 0; // pow(2, 53) - 1 == 9007199254740991
};


/***/ }),
/* 46 */
/***/ (function(module, exports) {

// 7.1.4 ToInteger
var ceil = Math.ceil;
var floor = Math.floor;
module.exports = function (it) {
  return isNaN(it = +it) ? 0 : (it > 0 ? floor : ceil)(it);
};


/***/ }),
/* 47 */
/***/ (function(module, exports, __webpack_require__) {

var shared = __webpack_require__(48)('keys');
var uid = __webpack_require__(32);
module.exports = function (key) {
  return shared[key] || (shared[key] = uid(key));
};


/***/ }),
/* 48 */
/***/ (function(module, exports, __webpack_require__) {

var global = __webpack_require__(2);
var SHARED = '__core-js_shared__';
var store = global[SHARED] || (global[SHARED] = {});
module.exports = function (key) {
  return store[key] || (store[key] = {});
};


/***/ }),
/* 49 */
/***/ (function(module, exports) {

// IE 8- don't enum bug keys
module.exports = (
  'constructor,hasOwnProperty,isPrototypeOf,propertyIsEnumerable,toLocaleString,toString,valueOf'
).split(',');


/***/ }),
/* 50 */
/***/ (function(module, exports) {

exports.f = Object.getOwnPropertySymbols;


/***/ }),
/* 51 */
/***/ (function(module, exports, __webpack_require__) {

// 19.1.2.2 / 15.2.3.5 Object.create(O [, Properties])
var anObject = __webpack_require__(5);
var dPs = __webpack_require__(127);
var enumBugKeys = __webpack_require__(49);
var IE_PROTO = __webpack_require__(47)('IE_PROTO');
var Empty = function () { /* empty */ };
var PROTOTYPE = 'prototype';

// Create object with fake `null` prototype: use iframe Object with cleared prototype
var createDict = function () {
  // Thrash, waste and sodomy: IE GC bug
  var iframe = __webpack_require__(42)('iframe');
  var i = enumBugKeys.length;
  var lt = '<';
  var gt = '>';
  var iframeDocument;
  iframe.style.display = 'none';
  __webpack_require__(73).appendChild(iframe);
  iframe.src = 'javascript:'; // eslint-disable-line no-script-url
  // createDict = iframe.contentWindow.Object;
  // html.removeChild(iframe);
  iframeDocument = iframe.contentWindow.document;
  iframeDocument.open();
  iframeDocument.write(lt + 'script' + gt + 'document.F=Object' + lt + '/script' + gt);
  iframeDocument.close();
  createDict = iframeDocument.F;
  while (i--) delete createDict[PROTOTYPE][enumBugKeys[i]];
  return createDict();
};

module.exports = Object.create || function create(O, Properties) {
  var result;
  if (O !== null) {
    Empty[PROTOTYPE] = anObject(O);
    result = new Empty();
    Empty[PROTOTYPE] = null;
    // add "__proto__" for Object.getPrototypeOf polyfill
    result[IE_PROTO] = O;
  } else result = createDict();
  return Properties === undefined ? result : dPs(result, Properties);
};


/***/ }),
/* 52 */
/***/ (function(module, exports, __webpack_require__) {

// getting tag from 19.1.3.6 Object.prototype.toString()
var cof = __webpack_require__(25);
var TAG = __webpack_require__(1)('toStringTag');
// ES3 wrong here
var ARG = cof(function () { return arguments; }()) == 'Arguments';

// fallback for IE11 Script Access Denied error
var tryGet = function (it, key) {
  try {
    return it[key];
  } catch (e) { /* empty */ }
};

module.exports = function (it) {
  var O, T, B;
  return it === undefined ? 'Undefined' : it === null ? 'Null'
    // @@toStringTag case
    : typeof (T = tryGet(O = Object(it), TAG)) == 'string' ? T
    // builtinTag case
    : ARG ? cof(O)
    // ES3 arguments fallback
    : (B = cof(O)) == 'Object' && typeof O.callee == 'function' ? 'Arguments' : B;
};


/***/ }),
/* 53 */
/***/ (function(module, exports, __webpack_require__) {

var classof = __webpack_require__(52);
var ITERATOR = __webpack_require__(1)('iterator');
var Iterators = __webpack_require__(18);
module.exports = __webpack_require__(0).getIteratorMethod = function (it) {
  if (it != undefined) return it[ITERATOR]
    || it['@@iterator']
    || Iterators[classof(it)];
};


/***/ }),
/* 54 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";

// 25.4.1.5 NewPromiseCapability(C)
var aFunction = __webpack_require__(31);

function PromiseCapability(C) {
  var resolve, reject;
  this.promise = new C(function ($$resolve, $$reject) {
    if (resolve !== undefined || reject !== undefined) throw TypeError('Bad Promise constructor');
    resolve = $$resolve;
    reject = $$reject;
  });
  this.resolve = aFunction(resolve);
  this.reject = aFunction(reject);
}

module.exports.f = function (C) {
  return new PromiseCapability(C);
};


/***/ }),
/* 55 */
/***/ (function(module, exports, __webpack_require__) {

// the whatwg-fetch polyfill installs the fetch() function
// on the global object (window or self)
//
// Return that as the export for use in Webpack, Browserify etc.
__webpack_require__(141);
module.exports = self.fetch.bind(self);


/***/ }),
/* 56 */
/***/ (function(module, exports, __webpack_require__) {

module.exports = { "default": __webpack_require__(143), __esModule: true };

/***/ }),
/* 57 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.clearSession = exports.getSession = undefined;

var _extends2 = __webpack_require__(29);

var _extends3 = _interopRequireDefault(_extends2);

var _regenerator = __webpack_require__(11);

var _regenerator2 = _interopRequireDefault(_regenerator);

var _asyncToGenerator2 = __webpack_require__(12);

var _asyncToGenerator3 = _interopRequireDefault(_asyncToGenerator2);

var getSession = exports.getSession = function () {
  var _ref = (0, _asyncToGenerator3.default)( /*#__PURE__*/_regenerator2.default.mark(function _callee(storage) {
    var data;
    return _regenerator2.default.wrap(function _callee$(_context) {
      while (1) {
        switch (_context.prev = _context.next) {
          case 0:
            _context.next = 2;
            return (0, _storage.getData)(storage);

          case 2:
            data = _context.sent;
            return _context.abrupt('return', data.session || null);

          case 4:
          case 'end':
            return _context.stop();
        }
      }
    }, _callee, this);
  }));

  return function getSession(_x) {
    return _ref.apply(this, arguments);
  };
}();

var clearSession = exports.clearSession = function () {
  var _ref3 = (0, _asyncToGenerator3.default)( /*#__PURE__*/_regenerator2.default.mark(function _callee3(storage) {
    return _regenerator2.default.wrap(function _callee3$(_context3) {
      while (1) {
        switch (_context3.prev = _context3.next) {
          case 0:
            _context3.next = 2;
            return (0, _storage.updateStorage)(storage, function (data) {
              return (0, _extends3.default)({}, data, { session: null });
            });

          case 2:
          case 'end':
            return _context3.stop();
        }
      }
    }, _callee3, this);
  }));

  return function clearSession(_x3) {
    return _ref3.apply(this, arguments);
  };
}();

exports.saveSession = saveSession;

var _storage = __webpack_require__(37);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function saveSession(storage) {
  var _this = this;

  return function () {
    var _ref2 = (0, _asyncToGenerator3.default)( /*#__PURE__*/_regenerator2.default.mark(function _callee2(session) {
      var data;
      return _regenerator2.default.wrap(function _callee2$(_context2) {
        while (1) {
          switch (_context2.prev = _context2.next) {
            case 0:
              _context2.next = 2;
              return (0, _storage.updateStorage)(storage, function (data) {
                return (0, _extends3.default)({}, data, { session: session });
              });

            case 2:
              data = _context2.sent;
              return _context2.abrupt('return', data.session);

            case 4:
            case 'end':
              return _context2.stop();
          }
        }
      }, _callee2, _this);
    }));

    return function (_x2) {
      return _ref2.apply(this, arguments);
    };
  }();
}

/***/ }),
/* 58 */
/***/ (function(module, exports, __webpack_require__) {

module.exports = { "default": __webpack_require__(145), __esModule: true };

/***/ }),
/* 59 */
/***/ (function(module, exports, __webpack_require__) {

exports.f = __webpack_require__(1);


/***/ }),
/* 60 */
/***/ (function(module, exports, __webpack_require__) {

var global = __webpack_require__(2);
var core = __webpack_require__(0);
var LIBRARY = __webpack_require__(34);
var wksExt = __webpack_require__(59);
var defineProperty = __webpack_require__(6).f;
module.exports = function (name) {
  var $Symbol = core.Symbol || (core.Symbol = LIBRARY ? {} : global.Symbol || {});
  if (name.charAt(0) != '_' && !(name in $Symbol)) defineProperty($Symbol, name, { value: wksExt.f(name) });
};


/***/ }),
/* 61 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.fetchWithCredentials = exports.requiresAuth = exports.getRegisteredRp = exports.logout = exports.currentSession = exports.login = undefined;

var _extends2 = __webpack_require__(29);

var _extends3 = _interopRequireDefault(_extends2);

var _regenerator = __webpack_require__(11);

var _regenerator2 = _interopRequireDefault(_regenerator);

var _asyncToGenerator2 = __webpack_require__(12);

var _asyncToGenerator3 = _interopRequireDefault(_asyncToGenerator2);

var getStoredRp = function () {
  var _ref3 = (0, _asyncToGenerator3.default)( /*#__PURE__*/_regenerator2.default.mark(function _callee3(storage) {
    var data, rpConfig;
    return _regenerator2.default.wrap(function _callee3$(_context3) {
      while (1) {
        switch (_context3.prev = _context3.next) {
          case 0:
            _context3.next = 2;
            return (0, _storage.getData)(storage);

          case 2:
            data = _context3.sent;
            rpConfig = data.rpConfig;

            if (!rpConfig) {
              _context3.next = 9;
              break;
            }

            rpConfig.store = storage;
            return _context3.abrupt('return', _oidcRp2.default.from(rpConfig));

          case 9:
            return _context3.abrupt('return', null);

          case 10:
          case 'end':
            return _context3.stop();
        }
      }
    }, _callee3, this);
  }));

  return function getStoredRp(_x4) {
    return _ref3.apply(this, arguments);
  };
}();

var storeRp = function () {
  var _ref4 = (0, _asyncToGenerator3.default)( /*#__PURE__*/_regenerator2.default.mark(function _callee4(storage, idp, rp) {
    return _regenerator2.default.wrap(function _callee4$(_context4) {
      while (1) {
        switch (_context4.prev = _context4.next) {
          case 0:
            _context4.next = 2;
            return (0, _storage.updateStorage)(storage, function (data) {
              return (0, _extends3.default)({}, data, {
                rpConfig: rp
              });
            });

          case 2:
            return _context4.abrupt('return', rp);

          case 3:
          case 'end':
            return _context4.stop();
        }
      }
    }, _callee4, this);
  }));

  return function storeRp(_x5, _x6, _x7) {
    return _ref4.apply(this, arguments);
  };
}();

__webpack_require__(55);

var _authHeader = __webpack_require__(86);

var authorization = _interopRequireWildcard(_authHeader);

var _oidcRp = __webpack_require__(162);

var _oidcRp2 = _interopRequireDefault(_oidcRp);

var _PoPToken = __webpack_require__(209);

var _PoPToken2 = _interopRequireDefault(_PoPToken);

var _urlUtil = __webpack_require__(66);

var _storage = __webpack_require__(37);

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/* global fetch, RequestInfo, Response */
var login = exports.login = function () {
  var _ref = (0, _asyncToGenerator3.default)( /*#__PURE__*/_regenerator2.default.mark(function _callee(idp, options) {
    var rp;
    return _regenerator2.default.wrap(function _callee$(_context) {
      while (1) {
        switch (_context.prev = _context.next) {
          case 0:
            _context.prev = 0;
            _context.next = 3;
            return getRegisteredRp(idp, options);

          case 3:
            rp = _context.sent;
            _context.next = 6;
            return saveAppHashFragment(options.storage);

          case 6:
            return _context.abrupt('return', function () {
              return sendAuthRequest(rp, options);
            });

          case 9:
            _context.prev = 9;
            _context.t0 = _context['catch'](0);

            console.warn('Error logging in with WebID-OIDC');
            console.error(_context.t0);
            return _context.abrupt('return', null);

          case 14:
          case 'end':
            return _context.stop();
        }
      }
    }, _callee, undefined, [[0, 9]]);
  }));

  return function login(_x, _x2) {
    return _ref.apply(this, arguments);
  };
}();

var currentSession = exports.currentSession = function () {
  var _ref2 = (0, _asyncToGenerator3.default)( /*#__PURE__*/_regenerator2.default.mark(function _callee2() {
    var storage = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : (0, _storage.defaultStorage)();
    var rp, url, storeData, resp, idp, idToken, accessToken, clientId, sessionKey;
    return _regenerator2.default.wrap(function _callee2$(_context2) {
      while (1) {
        switch (_context2.prev = _context2.next) {
          case 0:
            _context2.prev = 0;
            _context2.next = 3;
            return getStoredRp(storage);

          case 3:
            rp = _context2.sent;

            if (rp) {
              _context2.next = 6;
              break;
            }

            return _context2.abrupt('return', null);

          case 6:
            url = (0, _urlUtil.currentUrl)();

            if (!(!url || !url.includes('#'))) {
              _context2.next = 9;
              break;
            }

            return _context2.abrupt('return', null);

          case 9:
            _context2.next = 11;
            return (0, _storage.getData)(storage);

          case 11:
            storeData = _context2.sent;
            _context2.next = 14;
            return rp.validateResponse(url, storeData);

          case 14:
            resp = _context2.sent;

            if (resp) {
              _context2.next = 17;
              break;
            }

            return _context2.abrupt('return', null);

          case 17:
            _context2.next = 19;
            return restoreAppHashFragment(storage);

          case 19:
            idp = resp.idp, idToken = resp.idToken, accessToken = resp.accessToken, clientId = resp.clientId, sessionKey = resp.sessionKey;
            return _context2.abrupt('return', {
              authType: 'WebID-OIDC',
              webId: resp.decoded.payload.sub,
              idp: idp,
              idToken: idToken,
              accessToken: accessToken,
              clientId: clientId,
              sessionKey: sessionKey
            });

          case 23:
            _context2.prev = 23;
            _context2.t0 = _context2['catch'](0);

            console.warn('Error finding a WebID-OIDC session');
            console.error(_context2.t0);
            return _context2.abrupt('return', null);

          case 28:
          case 'end':
            return _context2.stop();
        }
      }
    }, _callee2, undefined, [[0, 23]]);
  }));

  return function currentSession() {
    return _ref2.apply(this, arguments);
  };
}();

var logout = exports.logout = function logout(storage, idp) {
  return getStoredRp(storage).then(function (rp) {
    return rp ? rp.logout() : undefined;
  }).catch(function (err) {
    console.warn('Error logging out of the WebID-OIDC session');
    console.error(err);
  }).then(function (x) {
    fetch(idp + '/logout', { method: 'GET', credentials: 'include' });
  }).catch(function (err) {
    console.warn('Error logging out of the WebID-OIDC session');
    console.error(err);
  });
};

var getRegisteredRp = exports.getRegisteredRp = function getRegisteredRp(idp, options) {
  return getStoredRp(options.storage).then(function (rp) {
    if (rp && rp.provider.url === idp) {
      return rp;
    }
    return registerRp(idp, options).then(function (rp) {
      return storeRp(options.storage, idp, rp);
    });
  });
};

var registerRp = function registerRp(idp, _ref5) {
  var storage = _ref5.storage,
      callbackUri = _ref5.callbackUri;

  var responseType = 'id_token token';
  var registration = {
    issuer: idp,
    grant_types: ['implicit'],
    redirect_uris: [callbackUri],
    response_types: [responseType],
    scope: 'openid profile'
  };
  var options = {
    defaults: {
      authenticate: {
        redirect_uri: callbackUri,
        response_type: responseType
      }
    },
    store: storage
  };
  return _oidcRp2.default.register(idp, registration, options);
};

var sendAuthRequest = function () {
  var _ref7 = (0, _asyncToGenerator3.default)( /*#__PURE__*/_regenerator2.default.mark(function _callee5(rp, _ref6) {
    var callbackUri = _ref6.callbackUri,
        storage = _ref6.storage;
    var data, url;
    return _regenerator2.default.wrap(function _callee5$(_context5) {
      while (1) {
        switch (_context5.prev = _context5.next) {
          case 0:
            _context5.next = 2;
            return (0, _storage.getData)(storage);

          case 2:
            data = _context5.sent;
            _context5.next = 5;
            return rp.createRequest({ redirect_uri: callbackUri }, data);

          case 5:
            url = _context5.sent;
            _context5.next = 8;
            return (0, _storage.updateStorage)(storage, function () {
              return data;
            });

          case 8:
            return _context5.abrupt('return', (0, _urlUtil.navigateTo)(url));

          case 9:
          case 'end':
            return _context5.stop();
        }
      }
    }, _callee5, undefined);
  }));

  return function sendAuthRequest(_x8, _x9) {
    return _ref7.apply(this, arguments);
  };
}();

var saveAppHashFragment = function saveAppHashFragment(store) {
  return (0, _storage.updateStorage)(store, function (data) {
    return (0, _extends3.default)({}, data, {
      appHashFragment: window.location.hash
    });
  });
};

var restoreAppHashFragment = function restoreAppHashFragment(store) {
  return (0, _storage.updateStorage)(store, function (data) {
    window.location.hash = data.appHashFragment;
    delete data.appHashFragment;
    return data;
  });
};

/**
 * Answers whether a HTTP response requires WebID-OIDC authentication.
 */
var requiresAuth = exports.requiresAuth = function requiresAuth(resp) {
  if (resp.status !== 401) {
    return false;
  }
  var wwwAuthHeader = resp.headers.get('www-authenticate');
  if (!wwwAuthHeader) {
    return false;
  }
  var auth = authorization.parse(wwwAuthHeader);
  return auth.scheme === 'Bearer' && auth.params && auth.params.scope === 'openid webid';
};

/**
 * Fetches a resource, providing the WebID-OIDC ID Token as authentication.
 * Assumes that the resource has requested those tokens in a previous response.
 */
var fetchWithCredentials = exports.fetchWithCredentials = function fetchWithCredentials(session) {
  return function () {
    var _ref8 = (0, _asyncToGenerator3.default)( /*#__PURE__*/_regenerator2.default.mark(function _callee6(url, options) {
      var popToken, authenticatedOptions;
      return _regenerator2.default.wrap(function _callee6$(_context6) {
        while (1) {
          switch (_context6.prev = _context6.next) {
            case 0:
              _context6.next = 2;
              return _PoPToken2.default.issueFor(url, session);

            case 2:
              popToken = _context6.sent;
              authenticatedOptions = (0, _extends3.default)({}, options, {
                headers: (0, _extends3.default)({}, options && options.headers ? options.headers : {}, {
                  authorization: 'Bearer ' + popToken
                })
              });
              return _context6.abrupt('return', fetch(url, authenticatedOptions));

            case 5:
            case 'end':
              return _context6.stop();
          }
        }
      }, _callee6, undefined);
    }));

    return function (_x10, _x11) {
      return _ref8.apply(this, arguments);
    };
  }();
};

/***/ }),
/* 62 */
/***/ (function(module, exports, __webpack_require__) {

module.exports = { "default": __webpack_require__(163), __esModule: true };

/***/ }),
/* 63 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";
/* WEBPACK VAR INJECTION */(function(global) {

// compare and isBuffer taken from https://github.com/feross/buffer/blob/680e9e5e488f22aac27599a57dc844a6315928dd/index.js
// original notice:

/*!
 * The buffer module from node.js, for the browser.
 *
 * @author   Feross Aboukhadijeh <feross@feross.org> <http://feross.org>
 * @license  MIT
 */
function compare(a, b) {
  if (a === b) {
    return 0;
  }

  var x = a.length;
  var y = b.length;

  for (var i = 0, len = Math.min(x, y); i < len; ++i) {
    if (a[i] !== b[i]) {
      x = a[i];
      y = b[i];
      break;
    }
  }

  if (x < y) {
    return -1;
  }
  if (y < x) {
    return 1;
  }
  return 0;
}
function isBuffer(b) {
  if (global.Buffer && typeof global.Buffer.isBuffer === 'function') {
    return global.Buffer.isBuffer(b);
  }
  return !!(b != null && b._isBuffer);
}

// based on node assert, original notice:

// http://wiki.commonjs.org/wiki/Unit_Testing/1.0
//
// THIS IS NOT TESTED NOR LIKELY TO WORK OUTSIDE V8!
//
// Originally from narwhal.js (http://narwhaljs.org)
// Copyright (c) 2009 Thomas Robinson <280north.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the 'Software'), to
// deal in the Software without restriction, including without limitation the
// rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
// sell copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED 'AS IS', WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
// ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
// WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

var util = __webpack_require__(170);
var hasOwn = Object.prototype.hasOwnProperty;
var pSlice = Array.prototype.slice;
var functionsHaveNames = (function () {
  return function foo() {}.name === 'foo';
}());
function pToString (obj) {
  return Object.prototype.toString.call(obj);
}
function isView(arrbuf) {
  if (isBuffer(arrbuf)) {
    return false;
  }
  if (typeof global.ArrayBuffer !== 'function') {
    return false;
  }
  if (typeof ArrayBuffer.isView === 'function') {
    return ArrayBuffer.isView(arrbuf);
  }
  if (!arrbuf) {
    return false;
  }
  if (arrbuf instanceof DataView) {
    return true;
  }
  if (arrbuf.buffer && arrbuf.buffer instanceof ArrayBuffer) {
    return true;
  }
  return false;
}
// 1. The assert module provides functions that throw
// AssertionError's when particular conditions are not met. The
// assert module must conform to the following interface.

var assert = module.exports = ok;

// 2. The AssertionError is defined in assert.
// new assert.AssertionError({ message: message,
//                             actual: actual,
//                             expected: expected })

var regex = /\s*function\s+([^\(\s]*)\s*/;
// based on https://github.com/ljharb/function.prototype.name/blob/adeeeec8bfcc6068b187d7d9fb3d5bb1d3a30899/implementation.js
function getName(func) {
  if (!util.isFunction(func)) {
    return;
  }
  if (functionsHaveNames) {
    return func.name;
  }
  var str = func.toString();
  var match = str.match(regex);
  return match && match[1];
}
assert.AssertionError = function AssertionError(options) {
  this.name = 'AssertionError';
  this.actual = options.actual;
  this.expected = options.expected;
  this.operator = options.operator;
  if (options.message) {
    this.message = options.message;
    this.generatedMessage = false;
  } else {
    this.message = getMessage(this);
    this.generatedMessage = true;
  }
  var stackStartFunction = options.stackStartFunction || fail;
  if (Error.captureStackTrace) {
    Error.captureStackTrace(this, stackStartFunction);
  } else {
    // non v8 browsers so we can have a stacktrace
    var err = new Error();
    if (err.stack) {
      var out = err.stack;

      // try to strip useless frames
      var fn_name = getName(stackStartFunction);
      var idx = out.indexOf('\n' + fn_name);
      if (idx >= 0) {
        // once we have located the function frame
        // we need to strip out everything before it (and its line)
        var next_line = out.indexOf('\n', idx + 1);
        out = out.substring(next_line + 1);
      }

      this.stack = out;
    }
  }
};

// assert.AssertionError instanceof Error
util.inherits(assert.AssertionError, Error);

function truncate(s, n) {
  if (typeof s === 'string') {
    return s.length < n ? s : s.slice(0, n);
  } else {
    return s;
  }
}
function inspect(something) {
  if (functionsHaveNames || !util.isFunction(something)) {
    return util.inspect(something);
  }
  var rawname = getName(something);
  var name = rawname ? ': ' + rawname : '';
  return '[Function' +  name + ']';
}
function getMessage(self) {
  return truncate(inspect(self.actual), 128) + ' ' +
         self.operator + ' ' +
         truncate(inspect(self.expected), 128);
}

// At present only the three keys mentioned above are used and
// understood by the spec. Implementations or sub modules can pass
// other keys to the AssertionError's constructor - they will be
// ignored.

// 3. All of the following functions must throw an AssertionError
// when a corresponding condition is not met, with a message that
// may be undefined if not provided.  All assertion methods provide
// both the actual and expected values to the assertion error for
// display purposes.

function fail(actual, expected, message, operator, stackStartFunction) {
  throw new assert.AssertionError({
    message: message,
    actual: actual,
    expected: expected,
    operator: operator,
    stackStartFunction: stackStartFunction
  });
}

// EXTENSION! allows for well behaved errors defined elsewhere.
assert.fail = fail;

// 4. Pure assertion tests whether a value is truthy, as determined
// by !!guard.
// assert.ok(guard, message_opt);
// This statement is equivalent to assert.equal(true, !!guard,
// message_opt);. To test strictly for the value true, use
// assert.strictEqual(true, guard, message_opt);.

function ok(value, message) {
  if (!value) fail(value, true, message, '==', assert.ok);
}
assert.ok = ok;

// 5. The equality assertion tests shallow, coercive equality with
// ==.
// assert.equal(actual, expected, message_opt);

assert.equal = function equal(actual, expected, message) {
  if (actual != expected) fail(actual, expected, message, '==', assert.equal);
};

// 6. The non-equality assertion tests for whether two objects are not equal
// with != assert.notEqual(actual, expected, message_opt);

assert.notEqual = function notEqual(actual, expected, message) {
  if (actual == expected) {
    fail(actual, expected, message, '!=', assert.notEqual);
  }
};

// 7. The equivalence assertion tests a deep equality relation.
// assert.deepEqual(actual, expected, message_opt);

assert.deepEqual = function deepEqual(actual, expected, message) {
  if (!_deepEqual(actual, expected, false)) {
    fail(actual, expected, message, 'deepEqual', assert.deepEqual);
  }
};

assert.deepStrictEqual = function deepStrictEqual(actual, expected, message) {
  if (!_deepEqual(actual, expected, true)) {
    fail(actual, expected, message, 'deepStrictEqual', assert.deepStrictEqual);
  }
};

function _deepEqual(actual, expected, strict, memos) {
  // 7.1. All identical values are equivalent, as determined by ===.
  if (actual === expected) {
    return true;
  } else if (isBuffer(actual) && isBuffer(expected)) {
    return compare(actual, expected) === 0;

  // 7.2. If the expected value is a Date object, the actual value is
  // equivalent if it is also a Date object that refers to the same time.
  } else if (util.isDate(actual) && util.isDate(expected)) {
    return actual.getTime() === expected.getTime();

  // 7.3 If the expected value is a RegExp object, the actual value is
  // equivalent if it is also a RegExp object with the same source and
  // properties (`global`, `multiline`, `lastIndex`, `ignoreCase`).
  } else if (util.isRegExp(actual) && util.isRegExp(expected)) {
    return actual.source === expected.source &&
           actual.global === expected.global &&
           actual.multiline === expected.multiline &&
           actual.lastIndex === expected.lastIndex &&
           actual.ignoreCase === expected.ignoreCase;

  // 7.4. Other pairs that do not both pass typeof value == 'object',
  // equivalence is determined by ==.
  } else if ((actual === null || typeof actual !== 'object') &&
             (expected === null || typeof expected !== 'object')) {
    return strict ? actual === expected : actual == expected;

  // If both values are instances of typed arrays, wrap their underlying
  // ArrayBuffers in a Buffer each to increase performance
  // This optimization requires the arrays to have the same type as checked by
  // Object.prototype.toString (aka pToString). Never perform binary
  // comparisons for Float*Arrays, though, since e.g. +0 === -0 but their
  // bit patterns are not identical.
  } else if (isView(actual) && isView(expected) &&
             pToString(actual) === pToString(expected) &&
             !(actual instanceof Float32Array ||
               actual instanceof Float64Array)) {
    return compare(new Uint8Array(actual.buffer),
                   new Uint8Array(expected.buffer)) === 0;

  // 7.5 For all other Object pairs, including Array objects, equivalence is
  // determined by having the same number of owned properties (as verified
  // with Object.prototype.hasOwnProperty.call), the same set of keys
  // (although not necessarily the same order), equivalent values for every
  // corresponding key, and an identical 'prototype' property. Note: this
  // accounts for both named and indexed properties on Arrays.
  } else if (isBuffer(actual) !== isBuffer(expected)) {
    return false;
  } else {
    memos = memos || {actual: [], expected: []};

    var actualIndex = memos.actual.indexOf(actual);
    if (actualIndex !== -1) {
      if (actualIndex === memos.expected.indexOf(expected)) {
        return true;
      }
    }

    memos.actual.push(actual);
    memos.expected.push(expected);

    return objEquiv(actual, expected, strict, memos);
  }
}

function isArguments(object) {
  return Object.prototype.toString.call(object) == '[object Arguments]';
}

function objEquiv(a, b, strict, actualVisitedObjects) {
  if (a === null || a === undefined || b === null || b === undefined)
    return false;
  // if one is a primitive, the other must be same
  if (util.isPrimitive(a) || util.isPrimitive(b))
    return a === b;
  if (strict && Object.getPrototypeOf(a) !== Object.getPrototypeOf(b))
    return false;
  var aIsArgs = isArguments(a);
  var bIsArgs = isArguments(b);
  if ((aIsArgs && !bIsArgs) || (!aIsArgs && bIsArgs))
    return false;
  if (aIsArgs) {
    a = pSlice.call(a);
    b = pSlice.call(b);
    return _deepEqual(a, b, strict);
  }
  var ka = objectKeys(a);
  var kb = objectKeys(b);
  var key, i;
  // having the same number of owned properties (keys incorporates
  // hasOwnProperty)
  if (ka.length !== kb.length)
    return false;
  //the same set of keys (although not necessarily the same order),
  ka.sort();
  kb.sort();
  //~~~cheap key test
  for (i = ka.length - 1; i >= 0; i--) {
    if (ka[i] !== kb[i])
      return false;
  }
  //equivalent values for every corresponding key, and
  //~~~possibly expensive deep test
  for (i = ka.length - 1; i >= 0; i--) {
    key = ka[i];
    if (!_deepEqual(a[key], b[key], strict, actualVisitedObjects))
      return false;
  }
  return true;
}

// 8. The non-equivalence assertion tests for any deep inequality.
// assert.notDeepEqual(actual, expected, message_opt);

assert.notDeepEqual = function notDeepEqual(actual, expected, message) {
  if (_deepEqual(actual, expected, false)) {
    fail(actual, expected, message, 'notDeepEqual', assert.notDeepEqual);
  }
};

assert.notDeepStrictEqual = notDeepStrictEqual;
function notDeepStrictEqual(actual, expected, message) {
  if (_deepEqual(actual, expected, true)) {
    fail(actual, expected, message, 'notDeepStrictEqual', notDeepStrictEqual);
  }
}


// 9. The strict equality assertion tests strict equality, as determined by ===.
// assert.strictEqual(actual, expected, message_opt);

assert.strictEqual = function strictEqual(actual, expected, message) {
  if (actual !== expected) {
    fail(actual, expected, message, '===', assert.strictEqual);
  }
};

// 10. The strict non-equality assertion tests for strict inequality, as
// determined by !==.  assert.notStrictEqual(actual, expected, message_opt);

assert.notStrictEqual = function notStrictEqual(actual, expected, message) {
  if (actual === expected) {
    fail(actual, expected, message, '!==', assert.notStrictEqual);
  }
};

function expectedException(actual, expected) {
  if (!actual || !expected) {
    return false;
  }

  if (Object.prototype.toString.call(expected) == '[object RegExp]') {
    return expected.test(actual);
  }

  try {
    if (actual instanceof expected) {
      return true;
    }
  } catch (e) {
    // Ignore.  The instanceof check doesn't work for arrow functions.
  }

  if (Error.isPrototypeOf(expected)) {
    return false;
  }

  return expected.call({}, actual) === true;
}

function _tryBlock(block) {
  var error;
  try {
    block();
  } catch (e) {
    error = e;
  }
  return error;
}

function _throws(shouldThrow, block, expected, message) {
  var actual;

  if (typeof block !== 'function') {
    throw new TypeError('"block" argument must be a function');
  }

  if (typeof expected === 'string') {
    message = expected;
    expected = null;
  }

  actual = _tryBlock(block);

  message = (expected && expected.name ? ' (' + expected.name + ').' : '.') +
            (message ? ' ' + message : '.');

  if (shouldThrow && !actual) {
    fail(actual, expected, 'Missing expected exception' + message);
  }

  var userProvidedMessage = typeof message === 'string';
  var isUnwantedException = !shouldThrow && util.isError(actual);
  var isUnexpectedException = !shouldThrow && actual && !expected;

  if ((isUnwantedException &&
      userProvidedMessage &&
      expectedException(actual, expected)) ||
      isUnexpectedException) {
    fail(actual, expected, 'Got unwanted exception' + message);
  }

  if ((shouldThrow && actual && expected &&
      !expectedException(actual, expected)) || (!shouldThrow && actual)) {
    throw actual;
  }
}

// 11. Expected to throw an error:
// assert.throws(block, Error_opt, message_opt);

assert.throws = function(block, /*optional*/error, /*optional*/message) {
  _throws(true, block, error, message);
};

// EXTENSION! This is annoying to write outside this module.
assert.doesNotThrow = function(block, /*optional*/error, /*optional*/message) {
  _throws(false, block, error, message);
};

assert.ifError = function(err) { if (err) throw err; };

var objectKeys = Object.keys || function (obj) {
  var keys = [];
  for (var key in obj) {
    if (hasOwn.call(obj, key)) keys.push(key);
  }
  return keys;
};

/* WEBPACK VAR INJECTION */}.call(exports, __webpack_require__(19)))

/***/ }),
/* 64 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


/**
 * Mode enumeration
 */

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

var THROW = 0;
var RECOVER = 1;
var SILENT = 2;

/**
 * JSONPointer
 *
 * @class
 * Implements RFC 6901: JavaScript Object Notation (JSON) Pointer
 * https://tools.ietf.org/html/rfc6901
 */

var JSONPointer = function () {

  /**
   * Constructor
   */
  function JSONPointer(expr, mode) {
    _classCallCheck(this, JSONPointer);

    this.expr = expr;
    this.mode = mode || THROW;
    this.tokens = expr && expr.charAt(0) === '#' ? this.parseURIFragmentIdentifier(expr) : this.parseJSONString(expr);
  }

  /**
   * Escape
   */


  _createClass(JSONPointer, [{
    key: 'escape',
    value: function escape(expr) {
      return expr.replace(/~/g, '~0').replace(/\//g, '~1');
    }

    /**
     * Unescape
     */

  }, {
    key: 'unescape',
    value: function unescape(expr) {
      return expr.replace(/~1/g, '/').replace(/~0/g, '~');
    }

    /**
     * Parse
     */

  }, {
    key: 'parseJSONString',


    /**
     * Parse JSON String
     *
     * @description Parse an expression into a list of tokens
     * @param {string} expr
     * @returns {Array}
     */
    value: function parseJSONString(expr) {
      if (typeof expr !== 'string') {
        throw new Error('JSON Pointer must be a string');
      }

      if (expr === '') {
        return [];
      }

      if (expr.charAt(0) !== '/') {
        throw new Error('Invalid JSON Pointer');
      }

      if (expr === '/') {
        return [''];
      }

      return expr.substr(1).split('/').map(this.unescape);
    }

    /**
     * To JSON String
     *
     * @description Render a JSON string representation of a pointer
     * @returns {string}
     */

  }, {
    key: 'toJSONString',
    value: function toJSONString() {
      return '/' + this.tokens.map(this.escape).join('/');
    }

    /**
     * Parse URI Fragment Identifer
     */

  }, {
    key: 'parseURIFragmentIdentifier',
    value: function parseURIFragmentIdentifier(expr) {
      if (typeof expr !== 'string') {
        throw new Error('JSON Pointer must be a string');
      }

      if (expr.charAt(0) !== '#') {
        throw new Error('Invalid JSON Pointer URI Fragment Identifier');
      }

      return this.parseJSONString(decodeURIComponent(expr.substr(1)));
    }

    /**
     * To URI Fragment Identifier
     *
     * @description Render a URI Fragment Identifier representation of a pointer
     * @returns {string}
     */

  }, {
    key: 'toURIFragmentIdentifier',
    value: function toURIFragmentIdentifier() {
      var _this = this;

      var value = this.tokens.map(function (token) {
        return encodeURIComponent(_this.escape(token));
      }).join('/');

      return '#/' + value;
    }

    /**
     * Get
     *
     * @description Get a value from the source object referenced by the pointer
     * @param {Object} source
     * @returns {*}
     */

  }, {
    key: 'get',
    value: function get(source) {
      var current = source;
      var tokens = this.tokens;

      for (var i = 0; i < tokens.length; i++) {
        if (!current || current[tokens[i]] === undefined) {
          if (this.mode !== THROW) {
            return undefined;
          } else {
            throw new Error('Invalid JSON Pointer reference');
          }
        }

        current = current[tokens[i]];
      }

      return current;
    }

    /**
     * Add
     *
     * @description Set a value on a target object referenced by the pointer. Put
     * will insert an array element. To change an existing array elemnent, use
     * `pointer.set()`
     * @param {Object} target
     * @param {*} value
     */

  }, {
    key: 'add',
    value: function add(target, value) {
      var tokens = this.tokens;
      var current = target;

      // iterate through the tokens
      for (var i = 0; i < tokens.length; i++) {
        var token = tokens[i];

        // set the property on the target location
        if (i === tokens.length - 1) {
          if (token === '-') {
            current.push(value);
          } else if (Array.isArray(current)) {
            current.splice(token, 0, value);
          } else if (value !== undefined) {
            current[token] = value;
          }

          // handle missing target location based on "mode"
        } else if (!current[token]) {
          switch (this.mode) {
            case THROW:
              throw new Error('Invalid JSON Pointer reference');

            case RECOVER:
              current = current[token] = parseInt(token) ? [] : {};
              break;

            case SILENT:
              return;

            default:
              throw new Error('Invalid pointer mode');
          }

          // reference the next object in the path
        } else {
          current = current[token];
        }
      }
    }

    /**
     * Replace
     *
     * @description Set a value on a target object referenced by the pointer. Set will
     * overwrite an existing array element at the target location.
     * @param {Object} target
     * @param {*} value
     */

  }, {
    key: 'replace',
    value: function replace(target, value) {
      var tokens = this.tokens;
      var current = target;

      for (var i = 0; i < tokens.length; i++) {
        var token = tokens[i];

        if (i === tokens.length - 1) {
          current[token] = value;
        } else if (!current[token]) {
          current = current[token] = parseInt(token) ? [] : {};
        } else {
          current = current[token];
        }
      }
    }

    /**
     * Del
     *
     * - if this is an array it should splice the value out
     */

  }, {
    key: 'remove',
    value: function remove(target) {
      var tokens = this.tokens;
      var current = target;

      for (var i = 0; i < tokens.length; i++) {
        var token = tokens[i];

        if (current === undefined || current[token] === undefined) {
          return undefined;
        } else if (Array.isArray(current)) {
          current.splice(token, 1);
          return undefined;
        } else if (i === tokens.length - 1) {
          delete current[token];
        }

        current = current[token];
      }

      // delete from the target
    }
  }], [{
    key: 'parse',
    value: function parse(expr) {
      return new JSONPointer(expr);
    }
  }]);

  return JSONPointer;
}();

/**
 * Exports
 */


module.exports = JSONPointer;

/***/ }),
/* 65 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

/**
 * Dependencies
 *
 * TODO
 * - switch between Node.js webcrypto package and browser implementation
 */
var base64url = __webpack_require__(14);
var supportedAlgorithms = __webpack_require__(182);

var _require = __webpack_require__(101

/**
 * JWA
 * https://tools.ietf.org/html/rfc7518
 */
),
    NotSupportedError = _require.NotSupportedError;

var JWA = function () {
  function JWA() {
    _classCallCheck(this, JWA);
  }

  _createClass(JWA, null, [{
    key: 'sign',


    /**
     * Sign
     *
     * @description
     * Create a digital signature.
     *
     * @param {string} alg
     * @param {CryptoKey} key
     * @param {string|Buffer} data
     *
     * @return {Promise}
     */
    value: function sign(alg, key, data) {
      // normalize the algorithm
      var normalizedAlgorithm = supportedAlgorithms.normalize('sign', alg

      // validate algorithm is supported
      );if (normalizedAlgorithm instanceof Error) {
        return Promise.reject(new NotSupportedError(alg));
      }

      // validate type of key
      // TODO
      //  - is the key suitable for the algorithm?
      //  - does that get validated in webcrypto?
      //if (key instanceof CryptoKey) {
      //  return Promise.reject(new InvalidKeyError())
      //}

      // sign the data
      return normalizedAlgorithm.sign(key, data);
    }

    /**
     * Verify
     *
     * @description
     * Verify a digital signature.
     *
     * @param {string} alg
     * @param {CryptoKey} privateKey
     * @param {string|Buffer} signature
     * @param {string|Buffer} data
     *
     * @return {Promise}
     */

  }, {
    key: 'verify',
    value: function verify(alg, key, signature, data) {
      var normalizedAlgorithm = supportedAlgorithms.normalize('verify', alg);

      if (normalizedAlgorithm instanceof Error) {
        return Promise.reject(new NotSupportedError(alg));
      }

      // TODO
      // validate publicKey

      // verify the signature
      return normalizedAlgorithm.verify(key, signature, data);
    }

    /**
     * Encrypt
     */

    /**
     * Decrypt
     */

    /**
     * Import
     */

  }, {
    key: 'importKey',
    value: function importKey(key) {
      var normalizedAlgorithm = supportedAlgorithms.normalize('importKey', key.alg);
      return normalizedAlgorithm.importKey(key);
    }
  }]);

  return JWA;
}();

/**
 * Export
 */


module.exports = JWA;

/***/ }),
/* 66 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


Object.defineProperty(exports, "__esModule", {
  value: true
});

/* eslint-env browser */

var currentUrl = exports.currentUrl = function currentUrl() {
  return window.location.href;
};

var currentUrlNoParams = exports.currentUrlNoParams = function currentUrlNoParams() {
  return window.location.origin + window.location.pathname;
};

var navigateTo = exports.navigateTo = function navigateTo(url) {
  window.location.href = url;
};

var originOf = exports.originOf = function originOf(url) {
  return new URL(url).origin;
};

/***/ }),
/* 67 */
/***/ (function(module, exports, __webpack_require__) {

module.exports = !__webpack_require__(8) && !__webpack_require__(16)(function () {
  return Object.defineProperty(__webpack_require__(42)('div'), 'a', { get: function () { return 7; } }).a != 7;
});


/***/ }),
/* 68 */
/***/ (function(module, exports, __webpack_require__) {

var has = __webpack_require__(10);
var toIObject = __webpack_require__(17);
var arrayIndexOf = __webpack_require__(120)(false);
var IE_PROTO = __webpack_require__(47)('IE_PROTO');

module.exports = function (object, names) {
  var O = toIObject(object);
  var i = 0;
  var result = [];
  var key;
  for (key in O) if (key != IE_PROTO) has(O, key) && result.push(key);
  // Don't enum bug & hidden keys
  while (names.length > i) if (has(O, key = names[i++])) {
    ~arrayIndexOf(result, key) || result.push(key);
  }
  return result;
};


/***/ }),
/* 69 */
/***/ (function(module, exports, __webpack_require__) {

// fallback for non-array-like ES3 and non-enumerable old V8 strings
var cof = __webpack_require__(25);
// eslint-disable-next-line no-prototype-builtins
module.exports = Object('z').propertyIsEnumerable(0) ? Object : function (it) {
  return cof(it) == 'String' ? it.split('') : Object(it);
};


/***/ }),
/* 70 */
/***/ (function(module, exports) {



/***/ }),
/* 71 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";

var LIBRARY = __webpack_require__(34);
var $export = __webpack_require__(4);
var redefine = __webpack_require__(72);
var hide = __webpack_require__(9);
var Iterators = __webpack_require__(18);
var $iterCreate = __webpack_require__(126);
var setToStringTag = __webpack_require__(35);
var getPrototypeOf = __webpack_require__(74);
var ITERATOR = __webpack_require__(1)('iterator');
var BUGGY = !([].keys && 'next' in [].keys()); // Safari has buggy iterators w/o `next`
var FF_ITERATOR = '@@iterator';
var KEYS = 'keys';
var VALUES = 'values';

var returnThis = function () { return this; };

module.exports = function (Base, NAME, Constructor, next, DEFAULT, IS_SET, FORCED) {
  $iterCreate(Constructor, NAME, next);
  var getMethod = function (kind) {
    if (!BUGGY && kind in proto) return proto[kind];
    switch (kind) {
      case KEYS: return function keys() { return new Constructor(this, kind); };
      case VALUES: return function values() { return new Constructor(this, kind); };
    } return function entries() { return new Constructor(this, kind); };
  };
  var TAG = NAME + ' Iterator';
  var DEF_VALUES = DEFAULT == VALUES;
  var VALUES_BUG = false;
  var proto = Base.prototype;
  var $native = proto[ITERATOR] || proto[FF_ITERATOR] || DEFAULT && proto[DEFAULT];
  var $default = $native || getMethod(DEFAULT);
  var $entries = DEFAULT ? !DEF_VALUES ? $default : getMethod('entries') : undefined;
  var $anyNative = NAME == 'Array' ? proto.entries || $native : $native;
  var methods, key, IteratorPrototype;
  // Fix native
  if ($anyNative) {
    IteratorPrototype = getPrototypeOf($anyNative.call(new Base()));
    if (IteratorPrototype !== Object.prototype && IteratorPrototype.next) {
      // Set @@toStringTag to native iterators
      setToStringTag(IteratorPrototype, TAG, true);
      // fix for some old engines
      if (!LIBRARY && typeof IteratorPrototype[ITERATOR] != 'function') hide(IteratorPrototype, ITERATOR, returnThis);
    }
  }
  // fix Array#{values, @@iterator}.name in V8 / FF
  if (DEF_VALUES && $native && $native.name !== VALUES) {
    VALUES_BUG = true;
    $default = function values() { return $native.call(this); };
  }
  // Define iterator
  if ((!LIBRARY || FORCED) && (BUGGY || VALUES_BUG || !proto[ITERATOR])) {
    hide(proto, ITERATOR, $default);
  }
  // Plug for library
  Iterators[NAME] = $default;
  Iterators[TAG] = returnThis;
  if (DEFAULT) {
    methods = {
      values: DEF_VALUES ? $default : getMethod(VALUES),
      keys: IS_SET ? $default : getMethod(KEYS),
      entries: $entries
    };
    if (FORCED) for (key in methods) {
      if (!(key in proto)) redefine(proto, key, methods[key]);
    } else $export($export.P + $export.F * (BUGGY || VALUES_BUG), NAME, methods);
  }
  return methods;
};


/***/ }),
/* 72 */
/***/ (function(module, exports, __webpack_require__) {

module.exports = __webpack_require__(9);


/***/ }),
/* 73 */
/***/ (function(module, exports, __webpack_require__) {

var document = __webpack_require__(2).document;
module.exports = document && document.documentElement;


/***/ }),
/* 74 */
/***/ (function(module, exports, __webpack_require__) {

// 19.1.2.9 / 15.2.3.2 Object.getPrototypeOf(O)
var has = __webpack_require__(10);
var toObject = __webpack_require__(26);
var IE_PROTO = __webpack_require__(47)('IE_PROTO');
var ObjectProto = Object.prototype;

module.exports = Object.getPrototypeOf || function (O) {
  O = toObject(O);
  if (has(O, IE_PROTO)) return O[IE_PROTO];
  if (typeof O.constructor == 'function' && O instanceof O.constructor) {
    return O.constructor.prototype;
  } return O instanceof Object ? ObjectProto : null;
};


/***/ }),
/* 75 */
/***/ (function(module, exports, __webpack_require__) {

// call something on iterator step with safe closing on error
var anObject = __webpack_require__(5);
module.exports = function (iterator, fn, value, entries) {
  try {
    return entries ? fn(anObject(value)[0], value[1]) : fn(value);
  // 7.4.6 IteratorClose(iterator, completion)
  } catch (e) {
    var ret = iterator['return'];
    if (ret !== undefined) anObject(ret.call(iterator));
    throw e;
  }
};


/***/ }),
/* 76 */
/***/ (function(module, exports, __webpack_require__) {

// check on default Array iterator
var Iterators = __webpack_require__(18);
var ITERATOR = __webpack_require__(1)('iterator');
var ArrayProto = Array.prototype;

module.exports = function (it) {
  return it !== undefined && (Iterators.Array === it || ArrayProto[ITERATOR] === it);
};


/***/ }),
/* 77 */
/***/ (function(module, exports, __webpack_require__) {

// 7.3.20 SpeciesConstructor(O, defaultConstructor)
var anObject = __webpack_require__(5);
var aFunction = __webpack_require__(31);
var SPECIES = __webpack_require__(1)('species');
module.exports = function (O, D) {
  var C = anObject(O).constructor;
  var S;
  return C === undefined || (S = anObject(C)[SPECIES]) == undefined ? D : aFunction(S);
};


/***/ }),
/* 78 */
/***/ (function(module, exports, __webpack_require__) {

var ctx = __webpack_require__(15);
var invoke = __webpack_require__(134);
var html = __webpack_require__(73);
var cel = __webpack_require__(42);
var global = __webpack_require__(2);
var process = global.process;
var setTask = global.setImmediate;
var clearTask = global.clearImmediate;
var MessageChannel = global.MessageChannel;
var Dispatch = global.Dispatch;
var counter = 0;
var queue = {};
var ONREADYSTATECHANGE = 'onreadystatechange';
var defer, channel, port;
var run = function () {
  var id = +this;
  // eslint-disable-next-line no-prototype-builtins
  if (queue.hasOwnProperty(id)) {
    var fn = queue[id];
    delete queue[id];
    fn();
  }
};
var listener = function (event) {
  run.call(event.data);
};
// Node.js 0.9+ & IE10+ has setImmediate, otherwise:
if (!setTask || !clearTask) {
  setTask = function setImmediate(fn) {
    var args = [];
    var i = 1;
    while (arguments.length > i) args.push(arguments[i++]);
    queue[++counter] = function () {
      // eslint-disable-next-line no-new-func
      invoke(typeof fn == 'function' ? fn : Function(fn), args);
    };
    defer(counter);
    return counter;
  };
  clearTask = function clearImmediate(id) {
    delete queue[id];
  };
  // Node.js 0.8-
  if (__webpack_require__(25)(process) == 'process') {
    defer = function (id) {
      process.nextTick(ctx(run, id, 1));
    };
  // Sphere (JS game engine) Dispatch API
  } else if (Dispatch && Dispatch.now) {
    defer = function (id) {
      Dispatch.now(ctx(run, id, 1));
    };
  // Browsers with MessageChannel, includes WebWorkers
  } else if (MessageChannel) {
    channel = new MessageChannel();
    port = channel.port2;
    channel.port1.onmessage = listener;
    defer = ctx(port.postMessage, port, 1);
  // Browsers with postMessage, skip WebWorkers
  // IE8 has postMessage, but it's sync & typeof its postMessage is 'object'
  } else if (global.addEventListener && typeof postMessage == 'function' && !global.importScripts) {
    defer = function (id) {
      global.postMessage(id + '', '*');
    };
    global.addEventListener('message', listener, false);
  // IE8-
  } else if (ONREADYSTATECHANGE in cel('script')) {
    defer = function (id) {
      html.appendChild(cel('script'))[ONREADYSTATECHANGE] = function () {
        html.removeChild(this);
        run.call(id);
      };
    };
  // Rest old browsers
  } else {
    defer = function (id) {
      setTimeout(ctx(run, id, 1), 0);
    };
  }
}
module.exports = {
  set: setTask,
  clear: clearTask
};


/***/ }),
/* 79 */
/***/ (function(module, exports) {

module.exports = function (exec) {
  try {
    return { e: false, v: exec() };
  } catch (e) {
    return { e: true, v: e };
  }
};


/***/ }),
/* 80 */
/***/ (function(module, exports, __webpack_require__) {

var anObject = __webpack_require__(5);
var isObject = __webpack_require__(7);
var newPromiseCapability = __webpack_require__(54);

module.exports = function (C, x) {
  anObject(C);
  if (isObject(x) && x.constructor === C) return x;
  var promiseCapability = newPromiseCapability.f(C);
  var resolve = promiseCapability.resolve;
  resolve(x);
  return promiseCapability.promise;
};


/***/ }),
/* 81 */
/***/ (function(module, exports, __webpack_require__) {

var ITERATOR = __webpack_require__(1)('iterator');
var SAFE_CLOSING = false;

try {
  var riter = [7][ITERATOR]();
  riter['return'] = function () { SAFE_CLOSING = true; };
  // eslint-disable-next-line no-throw-literal
  Array.from(riter, function () { throw 2; });
} catch (e) { /* empty */ }

module.exports = function (exec, skipClosing) {
  if (!skipClosing && !SAFE_CLOSING) return false;
  var safe = false;
  try {
    var arr = [7];
    var iter = arr[ITERATOR]();
    iter.next = function () { return { done: safe = true }; };
    arr[ITERATOR] = function () { return iter; };
    exec(arr);
  } catch (e) { /* empty */ }
  return safe;
};


/***/ }),
/* 82 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


exports.__esModule = true;

var _defineProperty = __webpack_require__(56);

var _defineProperty2 = _interopRequireDefault(_defineProperty);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

exports.default = function (obj, key, value) {
  if (key in obj) {
    (0, _defineProperty2.default)(obj, key, {
      value: value,
      enumerable: true,
      configurable: true,
      writable: true
    });
  } else {
    obj[key] = value;
  }

  return obj;
};

/***/ }),
/* 83 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.combineHandlers = exports.server = exports.client = undefined;

var _regenerator = __webpack_require__(11);

var _regenerator2 = _interopRequireDefault(_regenerator);

var _asyncToGenerator2 = __webpack_require__(12);

var _asyncToGenerator3 = _interopRequireDefault(_asyncToGenerator2);

var _promise = __webpack_require__(13);

var _promise2 = _interopRequireDefault(_promise);

var _typeof2 = __webpack_require__(38);

var _typeof3 = _interopRequireDefault(_typeof2);

var _defineProperty2 = __webpack_require__(82);

var _defineProperty3 = _interopRequireDefault(_defineProperty2);

var _v = __webpack_require__(157);

var _v2 = _interopRequireDefault(_v);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/*
  This module describes a simple IPC interface for communicating between browser windows.
  Window.postMessage() is the transport interface, and a request/response interface
  is defined on top of it as follows:

  const request = {
    'solid-auth-client': {
      id: 'abcd-efgh-ijkl',
      method: 'doSomethingPlease',
      args: [ 'one', 'two', 'three' ]
    }
  }

  const response = {
    'solid-auth-client': {
      id: 'abcd-efgh-ijkl',
      ret: 'the_value'
    }
  }
*/

var NAMESPACE = 'solid-auth-client';


var namespace = function namespace(data) {
  return (0, _defineProperty3.default)({}, NAMESPACE, data);
};

var getNamespacedPayload = function getNamespacedPayload(eventData) {
  if (!eventData || (typeof eventData === 'undefined' ? 'undefined' : (0, _typeof3.default)(eventData)) !== 'object') {
    return null;
  }
  var payload = eventData[NAMESPACE];
  if (!payload || (typeof payload === 'undefined' ? 'undefined' : (0, _typeof3.default)(payload)) !== 'object') {
    return null;
  }
  return payload;
};

var getResponse = function getResponse(eventData) {
  var resp = getNamespacedPayload(eventData);
  if (!resp) {
    return null;
  }
  var id = resp.id,
      ret = resp.ret;

  return id != null && typeof id === 'string' && resp.hasOwnProperty('ret') ? { id: id, ret: ret } : null;
};

var getRequest = function getRequest(eventData) {
  var req = getNamespacedPayload(eventData);
  if (!req) {
    return null;
  }
  var id = req.id,
      method = req.method,
      args = req.args;

  return id != null && typeof id === 'string' && typeof method === 'string' && Array.isArray(args) ? { id: id, method: method, args: args } : null;
};

var client = exports.client = function client(serverWindow, serverOrigin) {
  return function (request) {
    return new _promise2.default(function (resolve, reject) {
      var reqId = (0, _v2.default)();
      var responseListener = function responseListener(event) {
        var data = event.data,
            origin = event.origin;

        var resp = getResponse(data);
        if (serverOrigin !== '*' && origin !== serverOrigin || !resp) {
          return;
        }
        if (resp.id !== reqId) {
          return;
        }
        resolve(resp.ret);
        window.removeEventListener('message', responseListener);
      };
      window.addEventListener('message', responseListener);
      serverWindow.postMessage({
        'solid-auth-client': {
          id: reqId,
          method: request.method,
          args: request.args
        }
      }, serverOrigin);
    });
  };
};

var server = exports.server = function server(clientWindow, clientOrigin) {
  return function (handle) {
    var messageListener = function () {
      var _ref2 = (0, _asyncToGenerator3.default)( /*#__PURE__*/_regenerator2.default.mark(function _callee(event) {
        var data, origin, req, resp;
        return _regenerator2.default.wrap(function _callee$(_context) {
          while (1) {
            switch (_context.prev = _context.next) {
              case 0:
                data = event.data, origin = event.origin;
                req = getRequest(data);

                if (req) {
                  _context.next = 4;
                  break;
                }

                return _context.abrupt('return');

              case 4:
                if (!(origin !== clientOrigin)) {
                  _context.next = 7;
                  break;
                }

                console.warn('SECURITY WARNING: solid-auth-client is listening for messages from ' + clientOrigin + ', ' + ('but received a message from ' + origin + '.  Ignoring the message.'));
                return _context.abrupt('return');

              case 7:
                _context.next = 9;
                return handle(req);

              case 9:
                resp = _context.sent;

                if (resp) {
                  clientWindow.postMessage(namespace(resp), clientOrigin);
                }

              case 11:
              case 'end':
                return _context.stop();
            }
          }
        }, _callee, undefined);
      }));

      return function messageListener(_x) {
        return _ref2.apply(this, arguments);
      };
    }();

    var _server = {
      start: function start() {
        window.addEventListener('message', messageListener);
        return _server;
      },
      stop: function stop() {
        window.removeEventListener('message', messageListener);
        return _server;
      }
    };
    return _server;
  };
};

var combineHandlers = exports.combineHandlers = function combineHandlers() {
  for (var _len = arguments.length, handlers = Array(_len), _key = 0; _key < _len; _key++) {
    handlers[_key] = arguments[_key];
  }

  return function (req) {
    return handlers.map(function (handler) {
      return handler(req);
    }).find(function (promise) {
      return promise !== null;
    });
  };
};

/***/ }),
/* 84 */
/***/ (function(module, exports, __webpack_require__) {

// 19.1.2.7 / 15.2.3.4 Object.getOwnPropertyNames(O)
var $keys = __webpack_require__(68);
var hiddenKeys = __webpack_require__(49).concat('length', 'prototype');

exports.f = Object.getOwnPropertyNames || function getOwnPropertyNames(O) {
  return $keys(O, hiddenKeys);
};


/***/ }),
/* 85 */
/***/ (function(module, exports, __webpack_require__) {

var pIE = __webpack_require__(33);
var createDesc = __webpack_require__(23);
var toIObject = __webpack_require__(17);
var toPrimitive = __webpack_require__(43);
var has = __webpack_require__(10);
var IE8_DOM_DEFINE = __webpack_require__(67);
var gOPD = Object.getOwnPropertyDescriptor;

exports.f = __webpack_require__(8) ? gOPD : function getOwnPropertyDescriptor(O, P) {
  O = toIObject(O);
  P = toPrimitive(P, true);
  if (IE8_DOM_DEFINE) try {
    return gOPD(O, P);
  } catch (e) { /* empty */ }
  if (has(O, P)) return createDesc(!pIE.f.call(O, P), O[P]);
};


/***/ }),
/* 86 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.parse = exports.format = undefined;

var _format = __webpack_require__(160);

var _format2 = _interopRequireDefault(_format);

var _parse = __webpack_require__(161);

var _parse2 = _interopRequireDefault(_parse);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

exports.format = _format2.default;
exports.parse = _parse2.default;
//# sourceMappingURL=index.js.map

/***/ }),
/* 87 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


Object.defineProperty(exports, "__esModule", {
  value: true
});
var token = /^[^\u0000-\u001F\u007F()<>@,;:\\"/?={}\[\]\u0020\u0009]+$/;

var isToken = exports.isToken = function isToken(str) {
  return typeof str === 'string' && token.test(str);
};
var isScheme = exports.isScheme = isToken;
var quote = exports.quote = function quote(str) {
  return '"' + str.replace(/"/g, '\\"') + '"';
};
var unquote = exports.unquote = function unquote(str) {
  return str.substr(1, str.length - 2).replace(/\\"/g, '"');
};
//# sourceMappingURL=util.js.map

/***/ }),
/* 88 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";
/* WEBPACK VAR INJECTION */(function(global) {

var _assign = __webpack_require__(30);

var _assign2 = _interopRequireDefault(_assign);

var _stringify = __webpack_require__(58);

var _stringify2 = _interopRequireDefault(_stringify);

var _promise = __webpack_require__(13);

var _promise2 = _interopRequireDefault(_promise);

var _getPrototypeOf = __webpack_require__(62);

var _getPrototypeOf2 = _interopRequireDefault(_getPrototypeOf);

var _classCallCheck2 = __webpack_require__(20);

var _classCallCheck3 = _interopRequireDefault(_classCallCheck2);

var _createClass2 = __webpack_require__(21);

var _createClass3 = _interopRequireDefault(_createClass2);

var _possibleConstructorReturn2 = __webpack_require__(90);

var _possibleConstructorReturn3 = _interopRequireDefault(_possibleConstructorReturn2);

var _inherits2 = __webpack_require__(91);

var _inherits3 = _interopRequireDefault(_inherits2);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/**
 * Dependencies
 */
var assert = __webpack_require__(63);
var fetch = __webpack_require__(94);

var _require = __webpack_require__(39),
    URL = _require.URL;

var Headers = fetch.Headers ? fetch.Headers : global.Headers;

var _require2 = __webpack_require__(3),
    JSONDocument = _require2.JSONDocument;

var _require3 = __webpack_require__(28),
    JWKSet = _require3.JWKSet;

var AuthenticationRequest = __webpack_require__(191);
var AuthenticationResponse = __webpack_require__(204);
var RelyingPartySchema = __webpack_require__(208);
var onHttpError = __webpack_require__(113);

/**
 * RelyingParty
 *
 * @class
 * Client interface for OpenID Connect Relying Party.
 *
 * @example
 *  let client = RelyingParty({
 *    provider: {
 *      name: 'Anvil Research, Inc.',
 *      url: 'https://forge.anvil.io'
 *      // configuration
 *      // jwks
 *    },
 *    authenticate: {
 *      response_type: 'code',
 *      display: 'popup',
 *      scope: 'openid profile email'
 *    },
 *    register: {
 *      client_name: 'Example',
 *      client_uri: 'https://example.com',
 *      logo_uri: 'https://example.com/assets/logo.png',
 *      redirect_uris: ['https://app.example.com/callback'],
 *      response_types: ['code', 'code id_token token'],
 *      grant_types: ['authorization_code'],
 *      default_max_age: 7200,
 *      post_logout_redirect_uris: ['https://app.example.com']
 *    },
 *    registration: {
 *      // if you have it saved somewhere
 *    },
 *    store: localStorage || req.session,
 *    popup: { width: 400, height: 300 }
 *  })
 *
 *  client.discover() => Promise
 *  client.jwks() => Promise
 *  client.authenticate()
 *  client.authenticateUri()
 *  client.validateResponse(uri) => Promise
 *  client.userinfo() => Promise
 *  client.logout()
 */

var RelyingParty = function (_JSONDocument) {
  (0, _inherits3.default)(RelyingParty, _JSONDocument);

  function RelyingParty() {
    (0, _classCallCheck3.default)(this, RelyingParty);
    return (0, _possibleConstructorReturn3.default)(this, (RelyingParty.__proto__ || (0, _getPrototypeOf2.default)(RelyingParty)).apply(this, arguments));
  }

  (0, _createClass3.default)(RelyingParty, [{
    key: 'discover',


    /**
     * Discover
     *
     * @description Fetches the issuer's OpenID Configuration.
     * @returns {Promise<Object>} Resolves with the provider configuration response
     */
    value: function discover() {
      var _this2 = this;

      try {
        var issuer = this.provider.url;

        assert(issuer, 'RelyingParty provider must define "url"');

        var url = new URL(issuer);
        url.pathname = '.well-known/openid-configuration';

        return fetch(url.toString()).then(onHttpError('Error fetching openid configuration')).then(function (response) {
          return response.json().then(function (json) {
            return _this2.provider.configuration = json;
          });
        });
      } catch (error) {
        return _promise2.default.reject(error);
      }
    }

    /**
     * Register
     *
     * @description Register's a client with provider as a Relying Party
     *
     * @param options {Object}
     * @returns {Promise<Object>} Resolves with the registration response object
     */

  }, {
    key: 'register',
    value: function register(options) {
      var _this3 = this;

      try {
        var configuration = this.provider.configuration;

        assert(configuration, 'OpenID Configuration is not initialized.');
        assert(configuration.registration_endpoint, 'OpenID Configuration is missing registration_endpoint.');

        var uri = configuration.registration_endpoint;
        var method = 'post';
        var headers = new Headers({ 'Content-Type': 'application/json' });
        var params = this.defaults.register;
        var body = (0, _stringify2.default)((0, _assign2.default)({}, params, options));

        return fetch(uri, { method: method, headers: headers, body: body }).then(onHttpError('Error registering client')).then(function (response) {
          return response.json().then(function (json) {
            return _this3.registration = json;
          });
        });
      } catch (error) {
        return _promise2.default.reject(error);
      }
    }
  }, {
    key: 'serialize',
    value: function serialize() {
      return (0, _stringify2.default)(this);
    }

    /**
     * jwks
     *
     * @description Promises the issuer's JWK Set.
     * @returns {Promise}
     */

  }, {
    key: 'jwks',
    value: function jwks() {
      var _this4 = this;

      try {
        var configuration = this.provider.configuration;

        assert(configuration, 'OpenID Configuration is not initialized.');
        assert(configuration.jwks_uri, 'OpenID Configuration is missing jwks_uri.');

        var uri = configuration.jwks_uri;

        return fetch(uri).then(onHttpError('Error resolving provider keys')).then(function (response) {
          return response.json().then(function (json) {
            return JWKSet.importKeys(json);
          }).then(function (jwks) {
            return _this4.provider.jwks = jwks;
          });
        });
      } catch (error) {
        return _promise2.default.reject(error);
      }
    }

    /**
     * createRequest
     *
     * @param options {Object} Authn request options hashmap
     * @param options.redirect_uri {string}
     * @param options.response_type {string} e.g. 'code' or 'id_token token'
     * @param session {Session|Storage} req.session or localStorage
     * @returns {Promise<string>} Authn request URL
     */

  }, {
    key: 'createRequest',
    value: function createRequest(options, session) {
      return AuthenticationRequest.create(this, options, session || this.store);
    }

    /**
     * Validate Response
     *
     * @param response {string} req.query or req.body.text
     * @param session {Session|Storage} req.session or localStorage or similar
     * @returns {Promise<Object>} Custom response object, with `params` and
     *   `mode` properties
     */

  }, {
    key: 'validateResponse',
    value: function validateResponse(response, session) {
      session = session || this.store;

      if (response.match(/^http(s?):\/\//)) {
        response = { rp: this, redirect: response, session: session };
      } else {
        response = { rp: this, body: response, session: session };
      }

      return AuthenticationResponse.validateResponse(response);
    }

    /**
     * userinfo
     *
     * @description Promises the authenticated user's claims.
     * @returns {Promise}
     */

  }, {
    key: 'userinfo',
    value: function userinfo() {
      try {
        var configuration = this.provider.configuration;

        assert(configuration, 'OpenID Configuration is not initialized.');
        assert(configuration.userinfo_endpoint, 'OpenID Configuration is missing userinfo_endpoint.');

        var uri = configuration.userinfo_endpoint;
        var access_token = this.store.access_token;

        assert(access_token, 'Missing access token.');

        var headers = new Headers({
          'Content-Type': 'application/json',
          'Authorization': 'Bearer ' + access_token
        });

        return fetch(uri, { headers: headers }).then(onHttpError('Error fetching userinfo')).then(function (response) {
          return response.json();
        });
      } catch (error) {
        return _promise2.default.reject(error);
      }
    }

    /**
     * Logout
     *
     * @returns {Promise}
     */

  }, {
    key: 'logout',
    value: function logout() {
      var configuration = void 0;
      try {
        assert(this.provider, 'OpenID Configuration is not initialized.');
        configuration = this.provider.configuration;
        assert(configuration, 'OpenID Configuration is not initialized.');
        assert(configuration.end_session_endpoint, 'OpenID Configuration is missing end_session_endpoint.');
      } catch (error) {
        return _promise2.default.reject(error);
      }

      this.clearSession();

      return _promise2.default.resolve(configuration.end_session_endpoint);

      // TODO: Validate `frontchannel_logout_uri` if necessary
      /**
       * frontchannel_logout_uri - OPTIONAL. RP URL that will cause the RP to log
       * itself out when rendered in an iframe by the OP.
       *
       * An `iss` (issuer) query parameter and a `sid`
       * (session ID) query parameter MAY be included by the OP to enable the RP
       * to validate the request and to determine which of the potentially
       * multiple sessions is to be logged out. If a sid (session ID) query
       * parameter is included, an iss (issuer) query parameter MUST also be
       * included.
       * @see https://openid.net/specs/openid-connect-frontchannel-1_0.html#RPLogout
       */
    }
  }, {
    key: 'clearSession',
    value: function clearSession() {
      var session = this.store;

      if (!session) {
        return;
      }

      delete session[SESSION_PRIVATE_KEY];
    }

    /**
     * @param uri {string} Target Resource Server URI
     * @param idToken {IDToken} ID Token to be embedded in the PoP token
     *
     * @returns {Promise<PoPToken>}
     */

  }, {
    key: 'popTokenFor',
    value: function popTokenFor(uri, idToken) {
      return PoPToken.issueFor(uri, idToken, this);
    }
  }], [{
    key: 'from',


    /**
     * from
     *
     * @description
     * Create a RelyingParty instance from a previously registered client.
     *
     * @param {Object} data
     * @returns {Promise<RelyingParty>}
     */
    value: function from(data) {
      var rp = new RelyingParty(data);
      var validation = rp.validate();

      // schema validation
      if (!validation.valid) {
        return _promise2.default.reject(new Error((0, _stringify2.default)(validation)));
      }

      var jwks = rp.provider.jwks;

      // request the JWK Set if missing
      if (!jwks) {
        return rp.jwks().then(function () {
          return rp;
        });
      }

      // otherwise import the JWK Set to webcrypto
      return JWKSet.importKeys(jwks).then(function (jwks) {
        rp.provider.jwks = jwks;
        return rp;
      });
    }

    /**
     * register
     *
     * @param issuer {string} Provider URL
     * @param registration {Object} Client dynamic registration options
     * @param options {Object}
     * @param options.defaults
     * @param [options.store] {Session|Storage}
     * @returns {Promise<RelyingParty>} RelyingParty instance, registered.
     */

  }, {
    key: 'register',
    value: function register(issuer, registration, options) {
      var rp = new RelyingParty({
        provider: { url: issuer },
        defaults: (0, _assign2.default)({}, options.defaults),
        store: options.store
      });

      return _promise2.default.resolve().then(function () {
        return rp.discover();
      }).then(function () {
        return rp.jwks();
      }).then(function () {
        return rp.register(registration);
      }).then(function () {
        return rp;
      });
    }
  }, {
    key: 'schema',


    /**
     * Schema
     */
    get: function get() {
      return RelyingPartySchema;
    }
  }]);
  return RelyingParty;
}(JSONDocument);

var SESSION_PRIVATE_KEY = 'oidc.session.privateKey';

RelyingParty.SESSION_PRIVATE_KEY = SESSION_PRIVATE_KEY;

module.exports = RelyingParty;
/* WEBPACK VAR INJECTION */}.call(exports, __webpack_require__(19)))

/***/ }),
/* 89 */
/***/ (function(module, exports, __webpack_require__) {

// most Object methods by ES6 should accept primitives
var $export = __webpack_require__(4);
var core = __webpack_require__(0);
var fails = __webpack_require__(16);
module.exports = function (KEY, exec) {
  var fn = (core.Object || {})[KEY] || Object[KEY];
  var exp = {};
  exp[KEY] = exec(fn);
  $export($export.S + $export.F * fails(function () { fn(1); }), 'Object', exp);
};


/***/ }),
/* 90 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


exports.__esModule = true;

var _typeof2 = __webpack_require__(38);

var _typeof3 = _interopRequireDefault(_typeof2);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

exports.default = function (self, call) {
  if (!self) {
    throw new ReferenceError("this hasn't been initialised - super() hasn't been called");
  }

  return call && ((typeof call === "undefined" ? "undefined" : (0, _typeof3.default)(call)) === "object" || typeof call === "function") ? call : self;
};

/***/ }),
/* 91 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


exports.__esModule = true;

var _setPrototypeOf = __webpack_require__(92);

var _setPrototypeOf2 = _interopRequireDefault(_setPrototypeOf);

var _create = __webpack_require__(93);

var _create2 = _interopRequireDefault(_create);

var _typeof2 = __webpack_require__(38);

var _typeof3 = _interopRequireDefault(_typeof2);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

exports.default = function (subClass, superClass) {
  if (typeof superClass !== "function" && superClass !== null) {
    throw new TypeError("Super expression must either be null or a function, not " + (typeof superClass === "undefined" ? "undefined" : (0, _typeof3.default)(superClass)));
  }

  subClass.prototype = (0, _create2.default)(superClass && superClass.prototype, {
    constructor: {
      value: subClass,
      enumerable: false,
      writable: true,
      configurable: true
    }
  });
  if (superClass) _setPrototypeOf2.default ? (0, _setPrototypeOf2.default)(subClass, superClass) : subClass.__proto__ = superClass;
};

/***/ }),
/* 92 */
/***/ (function(module, exports, __webpack_require__) {

module.exports = { "default": __webpack_require__(165), __esModule: true };

/***/ }),
/* 93 */
/***/ (function(module, exports, __webpack_require__) {

module.exports = { "default": __webpack_require__(168), __esModule: true };

/***/ }),
/* 94 */
/***/ (function(module, exports) {

module.exports = __WEBPACK_EXTERNAL_MODULE_94__;

/***/ }),
/* 95 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


/**
 * JSON Schema Formats
 *
 * TODO
 * Is there a good way to express these over multiple lines with comments
 * for easier debugging and auditing?
 */

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

var DATETIME_REGEXP = /^\d\d\d\d-[0-1]\d-[0-3]\d[t\s][0-2]\d:[0-5]\d:[0-5]\d(?:\.\d+)?(?:z|[+-]\d\d:\d\d)$/i;
var URI_REGEXP = /^(?:[a-z][a-z0-9+-.]*)?(?:\:|\/)\/?[^\s]*$/i;
var EMAIL_REGEXP = /^[a-z0-9.!#$%&'*+\/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/i;
var IPV4_REGEXP = /^(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)$/;
var IPV6_REGEXP = /^\s*(?:(?:(?:[0-9a-f]{1,4}:){7}(?:[0-9a-f]{1,4}|:))|(?:(?:[0-9a-f]{1,4}:){6}(?::[0-9a-f]{1,4}|(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(?:(?:[0-9a-f]{1,4}:){5}(?:(?:(?::[0-9a-f]{1,4}){1,2})|:(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(?:(?:[0-9a-f]{1,4}:){4}(?:(?:(?::[0-9a-f]{1,4}){1,3})|(?:(?::[0-9a-f]{1,4})?:(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(?:(?:[0-9a-f]{1,4}:){3}(?:(?:(?::[0-9a-f]{1,4}){1,4})|(?:(?::[0-9a-f]{1,4}){0,2}:(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(?:(?:[0-9a-f]{1,4}:){2}(?:(?:(?::[0-9a-f]{1,4}){1,5})|(?:(?::[0-9a-f]{1,4}){0,3}:(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(?:(?:[0-9a-f]{1,4}:){1}(?:(?:(?::[0-9a-f]{1,4}){1,6})|(?:(?::[0-9a-f]{1,4}){0,4}:(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(?::(?:(?:(?::[0-9a-f]{1,4}){1,7})|(?:(?::[0-9a-f]{1,4}){0,5}:(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(?:%.+)?\s*$/i;
var HOSTNAME_REGEXP = /^[a-z](?:(?:[-0-9a-z]{0,61})?[0-9a-z])?(\.[a-z](?:(?:[-0-9a-z]{0,61})?[0-9a-z])?)*$/i;

/**
 * Formats
 */

var Formats = function () {
  function Formats() {
    _classCallCheck(this, Formats);
  }

  _createClass(Formats, [{
    key: 'register',


    /**
     * Register
     *
     * @description
     * Register a new mapping from named format to RegExp instance
     *
     * TODO
     * We can do some extra validation of the RegExp to
     * ensure it's the acceptable subset of RegExps allowed
     * by JSON Schema.
     *
     * @param {string} name
     * @param {RegExp} pattern
     * @returns {RegExp}
     */
    value: function register(name, pattern) {
      // verify name is a string
      if (typeof name !== 'string') {
        throw new Error('Format name must be a string');
      }

      // cast a string to RegExp
      if (typeof pattern === 'string') {
        pattern = new RegExp(pattern);
      }

      return this[name] = pattern;
    }

    /**
     * Resolve
     *
     * @description
     * Given a format name, return the corresponding registered validation. In the
     * event a format is not registered, throw an error.
     *
     * @param {string} name
     * @returns {RegExp}
     */

  }, {
    key: 'resolve',
    value: function resolve(name) {
      var format = this[name];

      if (!format) {
        throw new Error('Unknown JSON Schema format.');
      }

      return format;
    }

    /**
     * Test
     *
     * @description
     * Test that a value conforms to a format.
     *
     * @param {string} name
     * @param {string} value
     * @returns {Boolean}
     */

  }, {
    key: 'test',
    value: function test(name, value) {
      var format = this.resolve(name);
      return format.test(value);
    }
  }], [{
    key: 'initialize',


    /**
     * Initialize
     *
     * @description
     * Create a new Formats instance and register default formats
     *
     * @returns {Formats}
     */
    value: function initialize() {
      var formats = new Formats();
      formats.register('date-time', DATETIME_REGEXP);
      formats.register('uri', URI_REGEXP);
      formats.register('email', EMAIL_REGEXP);
      formats.register('ipv4', IPV4_REGEXP);
      formats.register('ipv6', IPV6_REGEXP);
      formats.register('hostname', HOSTNAME_REGEXP);
      return formats;
    }
  }]);

  return Formats;
}();

/**
 * Export
 */


module.exports = Formats.initialize();

/***/ }),
/* 96 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


/**
 * Initializer
 */

var _typeof = typeof Symbol === "function" && typeof Symbol.iterator === "symbol" ? function (obj) { return typeof obj; } : function (obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj; };

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

var Initializer = function () {

  /**
   * constructor
   */
  function Initializer(schema, options) {
    _classCallCheck(this, Initializer);

    Object.assign(this, options || {});
    this.root = this.root || this;

    this.root.depth = this.root.depth || 1;

    if (this.level > this.root.depth) {
      this.root.depth = this.level;
    }

    this.level = this.level || 0;
    this.schema = schema;
  }

  /**
   * compile (static)
   */


  _createClass(Initializer, [{
    key: 'compile',


    /**
     * compile
     */
    value: function compile() {
      var root = this.root,
          depth = this.depth,
          level = this.level;

      var declarations = '';
      var body = '';

      // traverse the schema and generate code
      body += this.default();
      body += this.properties();
      //body += this.additionalProperties()
      body += this.items();
      //body += this.additionalItems()


      // value
      body += this.member();
      body += this.item();

      // after traversing the schema
      // generate the variable declarations
      if (root === this) {
        for (var i = 1; i <= this.root.depth; i++) {
          declarations += this.declaration(i);
        }

        return '\n        options = options || {}\n\n        if (options.filter === false) {\n          Object.assign(target, JSON.parse(JSON.stringify(source)))\n        }\n\n        ' + declarations + '\n        ' + body + '\n      ';
      }

      return body;
    }

    /**
     * declaration
     */

  }, {
    key: 'declaration',
    value: function declaration(level) {
      return '\n      var target' + level + '\n      var source' + level + '\n      var count' + level + '\n    ';
    }

    /**
     * default
     */

  }, {
    key: 'default',
    value: function _default() {
      var schema = this.schema,
          level = this.level,
          key = this.key,
          index = this.index;
      var value = schema.default; // rename default to value because it's a keyword and syntax highlighter breaks

      var block = '';

      if (schema.hasOwnProperty('default')) {

        if (key) {
          block += '\n          target' + level + '[\'' + key + '\'] = ' + JSON.stringify(value) + '\n        ';
        }

        if (index) {
          block += '\n          target' + level + '[' + index + '] = ' + JSON.stringify(value) + '\n        ';
        }

        if (level > 1) {
          block += '\n          count' + level + '++\n        ';
        }

        block = '\n        if (options.defaults !== false) {\n          ' + block + '\n        }\n      ';
      }

      return block;
    }

    /**
     * member
     */

  }, {
    key: 'member',
    value: function member() {
      var schema = this.schema,
          root = this.root,
          level = this.level,
          key = this.key;
      var properties = schema.properties,
          additionalProperties = schema.additionalProperties,
          items = schema.items,
          additionalItems = schema.additionalItems;

      var block = '';

      // `key` tells us to treat this subschema as an object member vs an array item
      // and the absence of the other values here indicates we are dealing with a
      // primitive value
      if (key && !properties && !additionalProperties && !items && !additionalItems) {

        // first generate the assignment statement
        block += '\n        target' + level + '[\'' + key + '\'] = source' + level + '[\'' + key + '\']\n      ';

        // for nested container objects, add the counter incrementing statement
        if (level > 1) {
          block += '\n          count' + level + '++\n        ';
        }

        // wrap the foregoing in a check for presence on the source
        block = '\n        if (source' + level + '.hasOwnProperty(\'' + key + '\')) {\n          ' + block + '\n        }\n      ';
      }

      return block;
    }

    /**
     * item
     */

  }, {
    key: 'item',
    value: function item() {
      var schema = this.schema,
          root = this.root,
          level = this.level,
          index = this.index;
      var properties = schema.properties,
          additionalProperties = schema.additionalProperties,
          items = schema.items,
          additionalItems = schema.additionalItems;

      var block = '';

      if (index && !properties && !additionalProperties && !items && !additionalItems) {

        block += '\n        target' + level + '[' + index + '] = source' + level + '[' + index + ']\n      ';

        if (level > 1) {
          block += '\n          count' + level + '++\n        ';
        }

        block = '\n        if (' + index + ' < len) {\n          ' + block + '\n        }\n      ';
      }

      return block;
    }

    /**
     * properties
     */

  }, {
    key: 'properties',
    value: function properties() {
      var schema = this.schema,
          root = this.root,
          level = this.level,
          key = this.key,
          index = this.index;
      var properties = schema.properties;

      var block = '';

      if (properties) {
        Object.keys(properties).forEach(function (key) {
          var subschema = properties[key];
          var initializer = new Initializer(subschema, { key: key, root: root, level: level + 1 });

          block += initializer.compile();
        });

        // root-level properties boilerplate
        if (root === this) {
          block = '\n          if (typeof source === \'object\' && source !== null && !Array.isArray(source)) {\n            if (typeof target !== \'object\') {\n              throw new Error(\'?\')\n            }\n\n            source1 = source\n            target1 = target\n            count1 = 0\n\n            ' + block + '\n          }\n        ';

          // nested properties boilerplate
        } else {

          if (index) {
            block = '\n            if (' + index + ' < source' + level + '.length || typeof source' + level + '[' + index + '] === \'object\') {\n\n              source' + (level + 1) + ' = source' + level + '[' + index + '] || {}\n              count' + (level + 1) + ' = 0\n\n              if (' + index + ' < target' + level + '.length || typeof target' + level + '[' + index + '] !== \'object\') {\n                target' + (level + 1) + ' = {}\n                if (' + index + ' < source' + level + '.length) {\n                  count' + (level + 1) + '++\n                }\n              } else {\n                target' + (level + 1) + ' = target' + level + '[' + index + ']\n              }\n\n              ' + block + '\n\n              if (count' + (level + 1) + ' > 0) {\n                target' + level + '[' + index + '] = target' + (level + 1) + '\n                count' + level + '++\n              }\n\n            } else {\n              target' + level + '[' + index + '] = source' + level + '[' + index + ']\n              count' + level + '++\n            }\n          ';
          }

          if (key) {
            block = '\n            if ((typeof source' + level + '[\'' + key + '\'] === \'object\'\n                  && source' + level + '[\'' + key + '\'] !== null\n                  && !Array.isArray(source' + level + '[\'' + key + '\']))\n                || !source' + level + '.hasOwnProperty(\'' + key + '\')) {\n\n              source' + (level + 1) + ' = source' + level + '[\'' + key + '\'] || {}\n              count' + (level + 1) + ' = 0\n\n              if (!target' + level + '.hasOwnProperty(\'' + key + '\')\n                  || typeof target' + level + '[\'' + key + '\'] !== \'object\'\n                  || target' + level + '[\'' + key + '\'] === null\n                  || Array.isArray(target' + level + '[\'' + key + '\'])) {\n                target' + (level + 1) + ' = {}\n                if (source' + level + '.hasOwnProperty(\'' + key + '\')) {\n                  count' + (level + 1) + '++\n                }\n              } else {\n                target' + (level + 1) + ' = target' + level + '[\'' + key + '\']\n                count' + (level + 1) + '++\n              }\n\n              ' + block + '\n\n              if (count' + (level + 1) + ' > 0) {\n                target' + level + '[\'' + key + '\'] = target' + (level + 1) + '\n                count' + level + '++\n              }\n\n            } else {\n              target' + level + '[\'' + key + '\'] = source' + level + '[\'' + key + '\']\n              count' + level + '++\n            }\n          ';
          }
        }
      }

      return block;
    }

    /**
     *
     */

  }, {
    key: 'additionalProperties',
    value: function additionalProperties() {}

    /**
     * items
     */

  }, {
    key: 'items',
    value: function items() {
      var schema = this.schema,
          root = this.root,
          level = this.level,
          key = this.key,
          index = this.index;
      var items = schema.items;

      var block = '';

      if (items) {

        if (Array.isArray(items)) {
          // TODO
          //
          //
          //
          //
          //
          // ...

        } else if ((typeof items === 'undefined' ? 'undefined' : _typeof(items)) === 'object' && items !== null) {
          var _index = 'i' + (level + 1);
          var initializer = new Initializer(items, { index: _index, root: root, level: level + 1 });

          block += '\n          var sLen = source' + (level + 1) + '.length || 0\n          var tLen = target' + (level + 1) + '.length || 0\n          var len = 0\n\n          if (sLen > len) { len = sLen }\n          // THIS IS WRONG, CAUSED SIMPLE ARRAY INIT TO FAIL (OVERWRITE\n          // EXISTING TARGET VALUES WITH UNDEFINED WHEN SOURCE IS SHORTER THAN\n          // TARGET). LEAVING HERE UNTIL WE FINISH TESTING AND SEE WHY IT MIGHT\n          // HAVE BEEN HERE IN THE FIRST PLACE.\n          //\n          // if (tLen > len) { len = tLen }\n\n          for (var ' + _index + ' = 0; ' + _index + ' < len; ' + _index + '++) {\n            ' + initializer.compile() + '\n          }\n        ';
        }

        // root-level properties boilerplate
        if (root === this) {
          block = '\n          if (Array.isArray(source)) {\n            if (!Array.isArray(target)) {\n              throw new Error(\'?\')\n            }\n\n            source1 = source\n            target1 = target\n\n            ' + block + '\n          }\n        ';

          // nested properties boilerplate
        } else {
          block = '\n          if (Array.isArray(source' + level + '[\'' + key + '\']) || !source' + level + '.hasOwnProperty(\'' + key + '\')) {\n\n            source' + (level + 1) + ' = source' + level + '[\'' + key + '\'] || []\n            count' + (level + 1) + ' = 0\n\n            if (!target' + level + '.hasOwnProperty(\'' + key + '\') || !Array.isArray(target' + level + '[\'' + key + '\'])) {\n              target' + (level + 1) + ' = []\n                if (source' + level + '.hasOwnProperty(\'' + key + '\')) {\n                  count' + (level + 1) + '++\n                }\n\n            } else {\n              target' + (level + 1) + ' = target' + level + '[\'' + key + '\']\n              count' + (level + 1) + '++\n            }\n\n            ' + block + '\n\n            if (count' + (level + 1) + ' > 0) {\n              target' + level + '[\'' + key + '\'] = target' + (level + 1) + '\n              count' + level + '++\n            }\n\n          } else {\n            target' + level + '[\'' + key + '\'] = source' + level + '[\'' + key + '\']\n            count' + level + '++\n          }\n        ';
        }
      }

      return block;
    }

    /**
     *
     */

  }, {
    key: 'additionalItems',
    value: function additionalItems() {}
  }], [{
    key: 'compile',
    value: function compile(schema) {
      var initializer = new Initializer(schema);
      var block = initializer.compile();

      //console.log(beautify(block))
      try {
        return new Function('target', 'source', 'options', block);
      } catch (e) {
        console.log(e, e.stack);
      }
    }
  }]);

  return Initializer;
}();

module.exports = Initializer;

/***/ }),
/* 97 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


/**
 * Module dependencies
 * @ignore
 */

var _typeof = typeof Symbol === "function" && typeof Symbol.iterator === "symbol" ? function (obj) { return typeof obj; } : function (obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj; };

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

var JSONPointer = __webpack_require__(64);

/**
 * Modes
 */
var THROW = 0;
var RECOVER = 1;
var SILENT = 2;

/**
 * Operations list
 */
var OPERATIONS = ['add', 'remove', 'replace', 'move', 'copy', 'test'];

/**
 * Patch
 *
 * @class
 * Implements RFC 6902: JavaScript Object Notation (JSON) Patch
 * https://tools.ietf.org/html/rfc6902
 */

var JSONPatch = function () {

  /**
   * Constructor
   *
   * @param {Array} ops
   */
  function JSONPatch(ops) {
    _classCallCheck(this, JSONPatch);

    this.ops = ops || [];
  }

  /**
   * Apply
   *
   * @todo handle errors/roll back
   * @todo protect properties that are private in the schema
   * @todo map JSON Pointers real property names
   *
   * @param {Object} target
   */


  _createClass(JSONPatch, [{
    key: 'apply',
    value: function apply(target) {
      var _this = this;

      this.ops.forEach(function (operation) {
        var op = operation.op;

        if (!op) {
          throw new Error('Missing "op" in JSON Patch operation');
        }

        if (OPERATIONS.indexOf(op) === -1) {
          throw new Error('Invalid "op" in JSON Patch operation');
        }

        if (!operation.path) {
          throw new Error('Missing "path" in JSON Patch operation');
        }

        _this[op](operation, target);
      });
    }

    /**
     * Add
     *
     * @param {Object} op
     * @param {Object} target
     */

  }, {
    key: 'add',
    value: function add(op, target) {
      if (op.value === undefined) {
        throw new Error('Missing "value" in JSON Patch add operation');
      }

      var pointer = new JSONPointer(op.path, SILENT);
      pointer.add(target, op.value);
    }

    /**
     * Remove
     *
     * @param {Object} op
     * @param {Object} target
     */

  }, {
    key: 'remove',
    value: function remove(op, target) {
      var pointer = new JSONPointer(op.path);
      pointer.remove(target);
    }

    /**
     * Replace
     *
     * @param {Object} op
     * @param {Object} target
     */

  }, {
    key: 'replace',
    value: function replace(op, target) {
      if (op.value === undefined) {
        throw new Error('Missing "value" in JSON Patch replace operation');
      }

      var pointer = new JSONPointer(op.path);
      pointer.replace(target, op.value);
    }

    /**
     * Move
     *
     * @param {Object} op
     * @param {Object} target
     */

  }, {
    key: 'move',
    value: function move(op, target) {
      if (op.from === undefined) {
        throw new Error('Missing "from" in JSON Patch move operation');
      }

      if (op.path.match(new RegExp('^' + op.from))) {
        throw new Error('Invalid "from" in JSON Patch move operation');
      }

      var pointer = new JSONPointer(op.path);
      var from = new JSONPointer(op.from);
      var value = from.get(target);

      from.remove(target);
      pointer.add(target, value);
    }

    /**
     * Copy
     *
     * @param {Object} op
     * @param {Object} target
     */

  }, {
    key: 'copy',
    value: function copy(op, target) {
      if (op.from === undefined) {
        throw new Error('Missing "from" in JSON Patch copy operation');
      }

      var pointer = new JSONPointer(op.path);
      var from = new JSONPointer(op.from);
      var value = from.get(target);

      pointer.add(target, value);
    }

    /**
     * Test
     *
     * @param {Object} op
     * @param {Object} target
     */

  }, {
    key: 'test',
    value: function test(op, target) {
      if (op.value === undefined) {
        throw new Error('Missing "value" in JSON Patch test operation');
      }

      var pointer = new JSONPointer(op.path);
      var value = pointer.get(target);

      switch (_typeof(op.value)) {
        //case 'string':
        //case 'number':
        //case 'boolean':
        //  if (value !== op.value) {
        //    throw new Error('Mismatching JSON Patch test value')
        //  }
        default:
          if (value !== op.value) {
            throw new Error('Mismatching JSON Patch test value');
          }
      }
    }
  }]);

  return JSONPatch;
}();

/**
 * Exports
 */


module.exports = JSONPatch;

/***/ }),
/* 98 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


/**
 * Module dependencies
 * @ignore
 */

var _typeof = typeof Symbol === "function" && typeof Symbol.iterator === "symbol" ? function (obj) { return typeof obj; } : function (obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj; };

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

var formats = __webpack_require__(95);

/**
 * For variable iterator counter
 *
 * @type {number}
 */
var indexCount = 0;

/**
 * Validator
 *
 * Compile an object describing a JSON Schema into a validation function.
 */

var Validator = function () {
  _createClass(Validator, null, [{
    key: 'compile',


    /**
     * Compile (static)
     *
     * @description
     * Compile an object describing a JSON Schema into a validation function.
     *
     * @param {Object} schema
     * @returns {Function}
     */
    value: function compile(schema) {
      var validator = new Validator(schema);

      var body = '\n      // "cursor"\n      let value = data\n      let container\n      let stack = []\n      let top = -1\n\n      // error state\n      let valid = true\n      let errors = []\n\n      // complex schema state\n      let initialValidity\n      let anyValid\n      let notValid\n      let countOfValid\n      let initialErrorCount\n      let accumulatedErrorCount\n\n      // validation code\n      ' + validator.compile() + '\n\n      // validation result\n      return {\n        valid,\n        errors\n      }\n    ';

      return new Function('data', body);
    }

    /**
     * Return current iterator index counter and increase value
     *
     * @returns {number}
     */

  }, {
    key: 'counter',
    get: function get() {
      return indexCount++;
    }

    /**
     * Constructor
     *
     * @param {Object} schema - object representation of a schema
     * @param {string} options - compilation options
     */

  }]);

  function Validator(schema) {
    var options = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : {};

    _classCallCheck(this, Validator);

    // assign schema to this
    this.schema = schema;

    // assign all options to this
    Object.assign(this, options);

    // ensure address is defined
    if (!this.address) {
      this.address = '';
    }

    // ensure require is boolean
    if (this.require !== true) {
      this.require = false;
    }
  }

  /**
   * Compile
   *
   * @description
   * The instance compile method is "dumb". It only sequences invocation of
   * more specific compilation methods. It generates code to
   *
   *  - read a value from input
   *  - validate type(s) of input
   *  - validate constraints described by various schema keywords
   *
   * Conditional logic related to code generation is pushed downsteam to
   * type-specific methods.
   */


  _createClass(Validator, [{
    key: 'compile',
    value: function compile() {
      var block = '';

      if (this.require) {
        block += this.required();
      }

      // type validation
      block += this.type();

      // type specific validation generators
      // null and boolean are covered by this.type()
      // integer should be covered by number and this.type()
      block += this.array();
      block += this.number();
      block += this.object();
      block += this.string();

      // non-type-specific validation generators
      block += this.enum();
      block += this.anyOf();
      block += this.allOf();
      block += this.not();
      block += this.oneOf();

      return block;
    }

    /**
     * push
     */

  }, {
    key: 'push',
    value: function push() {
      return '\n      stack.push(value)\n      container = value\n      top++\n    ';
    }

    /**
     * pop
     */

  }, {
    key: 'pop',
    value: function pop() {
      return '\n      if (stack.length > 1) {\n        top--\n        stack.pop()\n      }\n\n      value = container = stack[top]\n    ';
    }

    /**
     * type
     *
     * @description
     * > An instance matches successfully if its primitive type is one of the
     * > types defined by keyword. Recall: "number" includes "integer".
     * > JSON Schema Validation Section 5.5.2
     *
     * @returns {string}
     */

  }, {
    key: 'type',
    value: function type() {
      var type = this.schema.type,
          address = this.address;

      var block = '';

      if (type) {
        var types = Array.isArray(type) ? type : [type];
        var conditions = types.map(function (type) {
          // TODO: can we make a mapping object for this to clean it up?
          if (type === 'array') return '!Array.isArray(value)';
          if (type === 'boolean') return 'typeof value !== \'boolean\'';
          if (type === 'integer') return '!Number.isInteger(value)';
          if (type === 'null') return 'value !== null';
          if (type === 'number') return 'typeof value !== \'number\'';
          if (type === 'object') return '(typeof value !== \'object\' || Array.isArray(value) || value === null)';
          if (type === 'string') return 'typeof value !== \'string\'';
        }).join(' && ');

        block += '\n      // ' + address + ' type checking\n      if (value !== undefined && ' + conditions + ') {\n        valid = false\n        errors.push({\n          keyword: \'type\',\n          message: \'invalid type\'\n        })\n      }\n      ';
      }

      return block;
    }

    /**
     * Type-specific validations
     *
     * Type checking is optional in JSON Schema, and a schema can allow
     * multiple types. Generated code needs to apply type-specific validations
     * only to appropriate values, and ignore everything else. Type validation
     * itself is handled separately from other validation keywords.
     *
     * The methods `array`, `number`, `object`, `string` generate type-specific
     * validation code blocks, wrapped in a conditional such that they will
     * only be applied to values of that type.
     *
     * For example, the `number` method, given the schema
     *
     *     { minimum: 3 }
     *
     * will generate
     *
     *     if (typeof value === 'number') {
     *       if (value < 3) {
     *         valid = false
     *         errors.push({ message: '...' })
     *       }
     *     }
     *
     * Integer values are also numbers, and are validated the same as numbers
     * other than the type validation itself. Therefore no `integer` method is
     * needed.
     */

    /**
     * array
     *
     * @description
     * Invoke methods for array-specific keywords and wrap resulting code in
     * type-checking conditional so that any resulting validations are only
     * applied to array values.
     *
     * @returns {string}
     */

  }, {
    key: 'array',
    value: function array() {
      var keywords = ['additionalItems', 'items', 'minItems', 'maxItems', 'uniqueItems'];
      var validations = this.validations(keywords);
      var block = '';

      if (validations.length > 0) {
        block += '\n      /**\n       * Array validations\n       */\n      if (Array.isArray(value)) {\n      ' + validations + '\n      }\n      ';
      }

      return block;
    }

    /**
     * number
     *
     * @description
     * Invoke methods for number-specific keywords and wrap resulting code in
     * type-checking conditional so that any resulting validations are only
     * applied to number values.
     *
     * @returns {string}
     */

  }, {
    key: 'number',
    value: function number() {
      var keywords = ['minimum', 'maximum', 'multipleOf'];
      var validations = this.validations(keywords);
      var block = '';

      if (validations.length > 0) {
        block += '\n      /**\n       * Number validations\n       */\n      if (typeof value === \'number\') {\n      ' + validations + '\n      }\n      ';
      }

      return block;
    }

    /**
     * object
     *
     * @description
     * Invoke methods for object-specific keywords and wrap resulting code in
     * type-checking conditional so that any resulting validations are only
     * applied to object values.
     *
     * @returns {string}
     */

  }, {
    key: 'object',
    value: function object() {
      var keywords = ['maxProperties', 'minProperties', 'additionalProperties', 'properties', 'patternProperties', 'dependencies', 'schemaDependencies', 'propertyDependencies'];
      var validations = this.validations(keywords);
      var block = '';

      if (validations.length > 0) {
        block += '\n      /**\n       * Object validations\n       */\n      if (typeof value === \'object\' && value !== null && !Array.isArray(value)) {\n      ' + validations + '\n      }\n      ';
      }

      return block;
    }

    /**
     * string
     *
     * @description
     * Invoke methods for string-specific keywords and wrap resulting code in
     * type-checking conditional so that any resulting validations are only
     * applied to string values.
     *
     * @returns {string}
     */

  }, {
    key: 'string',
    value: function string() {
      var keywords = ['maxLength', 'minLength', 'pattern', 'format'];
      var validations = this.validations(keywords);
      var block = '';

      if (validations.length > 0) {
        block += '\n      /**\n       * String validations\n       */\n      if (typeof value === \'string\') {\n      ' + validations + '\n      }\n      ';
      }

      return block;
    }

    /**
     * validations
     *
     * @description
     * Iterate over an array of keywords and invoke code generator methods
     * for each. Concatenate the results together and return. Used by "type"
     * methods such as this.array() and this.string()
     *
     * @param {Array} keywords
     * @returns {string}
     */

  }, {
    key: 'validations',
    value: function validations(keywords) {
      var _this = this;

      var schema = this.schema;

      var block = '';

      var constraints = Object.keys(schema).filter(function (key) {
        return keywords.indexOf(key) !== -1;
      });

      constraints.forEach(function (keyword) {
        block += _this[keyword]();
      });

      return block;
    }

    /**
     * enum
     *
     * @description
     * > An instance validates successfully against this keyword if its value
     * > is equal to one of the elements in this keyword's array value.
     * > JSON Schema Validation Section 5.5.1
     *
     * @returns {string}
     */

  }, {
    key: 'enum',
    value: function _enum() {
      var enumerated = this.schema.enum,
          address = this.address;

      var conditions = ['value !== undefined'];
      var block = '';

      if (enumerated) {
        enumerated.forEach(function (value) {
          switch (typeof value === 'undefined' ? 'undefined' : _typeof(value)) {
            case 'boolean':
              conditions.push('value !== ' + value);
              break;

            case 'number':
              conditions.push('value !== ' + value);
              break;

            case 'string':
              conditions.push('value !== "' + value + '"');
              break;

            case 'object':
              if (value === null) {
                conditions.push('value !== null');
              } else {
                conditions.push('\'' + JSON.stringify(value) + '\' !== JSON.stringify(value)');
              }
              break;

            default:
              throw new Error('Things are not well in the land of enum');

          }
        });

        block += '\n      /**\n       * Validate "' + address + '" enum\n       */\n      if (' + conditions.join(' && ') + ') {\n        valid = false\n        errors.push({\n          keyword: \'enum\',\n          message: JSON.stringify(value) + \' is not an enumerated value\'\n        })\n      }\n      ';
      }

      return block;
    }

    /**
     * anyOf
     *
     * @description
     * > An instance validates successfully against this keyword if it
     * > validates successfully against at least one schema defined by this
     * > keyword's value.
     * > JSON Schema Validation Section 5.5.4
     *
     * @returns {string}
     */

  }, {
    key: 'anyOf',
    value: function anyOf() {
      var anyOf = this.schema.anyOf,
          address = this.address;

      var block = '';

      if (Array.isArray(anyOf)) {
        block += '\n        initialValidity = valid\n        initialErrorCount = errors.length\n        anyValid = false\n      ';

        anyOf.forEach(function (subschema) {
          var validator = new Validator(subschema, { address: address });
          block += '\n        accumulatedErrorCount = errors.length\n        ' + validator.compile() + '\n        if (accumulatedErrorCount === errors.length) {\n          anyValid = true\n        }\n        ';
        });

        block += '\n          if (anyValid === true) {\n            valid = initialValidity\n            errors = errors.slice(0, initialErrorCount)\n          }\n      ';
      }

      return block;
    }

    /**
     * allOf
     *
     * @description
     * > An instance validates successfully against this keyword if it
     * > validates successfully against all schemas defined by this keyword's
     * > value.
     * > JSON Schema Validation Section 5.5.3
     *
     * @returns {string}
     */

  }, {
    key: 'allOf',
    value: function allOf() {
      var allOf = this.schema.allOf,
          address = this.address;

      var block = '';

      if (Array.isArray(allOf)) {
        allOf.forEach(function (subschema) {
          var validator = new Validator(subschema, { address: address });
          block += '\n        ' + validator.compile() + '\n        ';
        });
      }

      return block;
    }

    /**
     * oneOf
     *
     * @description
     * > An instance validates successfully against this keyword if it
     * > validates successfully against exactly one schema defined by this
     * > keyword's value.
     * > JSON Schema Validation Section 5.5.5
     *
     * @returns {string}
     */

  }, {
    key: 'oneOf',
    value: function oneOf() {
      var oneOf = this.schema.oneOf,
          address = this.address;

      var block = '';

      if (Array.isArray(oneOf)) {
        block += '\n        /**\n         * Validate ' + address + ' oneOf\n         */\n        initialValidity = valid\n        initialErrorCount = errors.length\n        countOfValid = 0\n      ';

        oneOf.forEach(function (subschema) {
          var validator = new Validator(subschema, { address: address });
          block += '\n        accumulatedErrorCount = errors.length\n        ' + validator.compile() + '\n        if (accumulatedErrorCount === errors.length) {\n          countOfValid += 1\n        }\n        ';
        });

        block += '\n          if (countOfValid === 1) {\n            valid = initialValidity\n            errors = errors.slice(0, initialErrorCount)\n          } else {\n            valid = false\n            errors.push({\n              keyword: \'oneOf\',\n              message: \'what is a reasonable error message for this case?\'\n            })\n          }\n      ';
      }

      return block;
    }

    /**
     * not
     *
     * @description
     * > An instance is valid against this keyword if it fails to validate
     * > successfully against the schema defined by this keyword.
     * > JSON Schema Validation Section 5.5.6
     *
     * @returns {string}
     */

  }, {
    key: 'not',
    value: function not() {
      var not = this.schema.not,
          address = this.address;

      var block = '';

      if ((typeof not === 'undefined' ? 'undefined' : _typeof(not)) === 'object' && not !== null && !Array.isArray(not)) {
        var subschema = not;
        var validator = new Validator(subschema, { address: address });

        block += '\n        /**\n         * NOT\n         */\n        if (value !== undefined) {\n          initialValidity = valid\n          initialErrorCount = errors.length\n          notValid = true\n\n          accumulatedErrorCount = errors.length\n\n          ' + validator.compile() + '\n\n          if (accumulatedErrorCount === errors.length) {\n            notValid = false\n          }\n\n          if (notValid === true) {\n            valid = initialValidity\n            errors = errors.slice(0, initialErrorCount)\n          } else {\n            valid = false\n            errors = errors.slice(0, initialErrorCount)\n            errors.push({\n              keyword: \'not\',\n              message: \'hmm...\'\n            })\n          }\n        }\n      ';
      }

      return block;
    }

    /**
     * properties
     *
     * @description
     * Iterate over the `properties` schema property if it is an object. For each
     * key, initialize a new Validator for the subschema represented by the property
     * value and invoke compile. Append the result of compiling each subschema to
     * the block of code being generated.
     *
     * @returns {string}
     */

  }, {
    key: 'properties',
    value: function properties() {
      var schema = this.schema,
          address = this.address;
      var properties = schema.properties,
          required = schema.required;

      var block = this.push();

      // ensure the value of "required" schema property is an array
      required = Array.isArray(required) ? required : [];

      if ((typeof properties === 'undefined' ? 'undefined' : _typeof(properties)) === 'object') {
        Object.keys(properties).forEach(function (key) {
          var subschema = properties[key];
          var isRequired = required.indexOf(key) !== -1;
          // TODO
          // how should we be calculating these things? should be json pointer?
          // needs a separate function
          var pointer = [address, key].filter(function (segment) {
            return !!segment;
          }).join('.');
          var validation = new Validator(subschema, { address: pointer, require: isRequired });

          // read the value
          block += '\n        value = container[\'' + key + '\']\n        ';

          block += validation.compile();
        });
      }

      block += this.pop();

      return block;
    }

    /**
     * Other Properties
     *
     * @description
     * This method is not for a keyword. It wraps validations for
     * patternProperties and additionalProperties in a single iteration over
     * an object-type value's properties.
     *
     * It should only be invoked once for a given subschema.
     *
     * @returns {string}
     */

  }, {
    key: 'otherProperties',
    value: function otherProperties() {
      return '\n      /**\n       * Validate Other Properties\n       */\n      ' + this.push() + '\n\n      for (let key in container) {\n        value = container[key]\n        matched = false\n\n        ' + this.patternValidations() + '\n        ' + this.additionalValidations() + '\n      }\n\n      ' + this.pop() + '\n    ';
    }

    /**
     * Pattern Validations
     *
     * @description
     * Generate validation code from a subschema for properties matching a
     * regular expression.
     *
     * @returns {string}
     */

  }, {
    key: 'patternValidations',
    value: function patternValidations() {
      var patternProperties = this.schema.patternProperties;

      var block = '';

      if ((typeof patternProperties === 'undefined' ? 'undefined' : _typeof(patternProperties)) === 'object') {
        Object.keys(patternProperties).forEach(function (pattern) {
          var subschema = patternProperties[pattern];
          var validator = new Validator(subschema);
          block += '\n          if (key.match(\'' + pattern + '\')) {\n            matched = true\n            ' + validator.compile() + '\n          }\n        ';
        });
      }

      return block;
    }

    /**
     * Additional Validations
     *
     * @description
     * Generate validation code, either from a subschema for properties not
     * defined in the schema, or to disallow properties not defined in the
     * schema.
     *
     * @returns {string}
     */

  }, {
    key: 'additionalValidations',
    value: function additionalValidations() {
      var _schema = this.schema,
          properties = _schema.properties,
          additionalProperties = _schema.additionalProperties,
          address = this.address;

      var validations = '';
      var block = '';

      // catch additional unmatched properties
      var conditions = ['matched !== true'];

      // ignore defined properties
      Object.keys(properties || {}).forEach(function (key) {
        conditions.push('key !== \'' + key + '\'');
      });

      // validate additional properties
      if ((typeof additionalProperties === 'undefined' ? 'undefined' : _typeof(additionalProperties)) === 'object') {
        var subschema = additionalProperties;
        var validator = new Validator(subschema, { address: address + '[APKey]' });
        block += '\n        // validate additional properties\n        if (' + conditions.join(' && ') + ') {\n          ' + validator.compile() + '\n        }\n      ';
      }

      // error for additional properties
      if (additionalProperties === false) {
        block += '\n        // validate non-presence of additional properties\n        if (' + conditions.join(' && ') + ') {\n          valid = false\n          errors.push({\n            keyword: \'additionalProperties\',\n            message: key + \' is not a defined property\'\n          })\n        }\n      ';
      }

      return block;
    }

    /**
     * patternProperties
     *
     * @description
     * Generate validation code for properties matching a pattern
     * defined by the property name (key), which must be a string
     * representing a valid regular expression.
     *
     * @returns {string}
     */

  }, {
    key: 'patternProperties',
    value: function patternProperties() {
      var block = '';

      if (!this.otherPropertiesCalled) {
        this.otherPropertiesCalled = true;
        block += this.otherProperties();
      }

      return block;
    }

    /**
     * additionalProperties
     *
     * @description
     * Generate validation code for additional properties not defined
     * in the schema, or disallow additional properties if the value of
     * `additionalProperties` in the schema is `false`.
     *
     * @returns {string}
     */

  }, {
    key: 'additionalProperties',
    value: function additionalProperties() {
      var block = '';

      if (!this.otherPropertiesCalled) {
        this.otherPropertiesCalled = true;
        block += this.otherProperties();
      }

      return block;
    }

    /**
     * minProperties
     *
     * @description
     * > An object instance is valid against "minProperties" if its number of
     * > properties is greater than, or equal to, the value of this keyword.
     * > JSON Schema Validation Section 5.4.2
     *
     * @returns {string}
     */

  }, {
    key: 'minProperties',
    value: function minProperties() {
      var minProperties = this.schema.minProperties,
          address = this.address;


      return '\n        // ' + address + ' min properties\n        if (Object.keys(value).length < ' + minProperties + ') {\n          valid = false\n          errors.push({\n            keyword: \'minProperties\',\n            message: \'too few properties\'\n          })\n        }\n    ';
    }

    /**
     * maxProperties
     *
     * @description
     * > An object instance is valid against "maxProperties" if its number of
     * > properties is less than, or equal to, the value of this keyword.
     * > JSON Schema Validation Section 5.4.1
     *
     * @returns {string}
     */

  }, {
    key: 'maxProperties',
    value: function maxProperties() {
      var maxProperties = this.schema.maxProperties,
          address = this.address;


      return '\n        // ' + address + ' max properties\n        if (Object.keys(value).length > ' + maxProperties + ') {\n          valid = false\n          errors.push({\n            keyword: \'maxProperties\',\n            message: \'too many properties\'\n          })\n        }\n    ';
    }

    /**
     * Dependencies
     *
     * @description
     * > For all (name, schema) pair of schema dependencies, if the instance has
     * > a property by this name, then it must also validate successfully against
     * > the schema.
     * >
     * > Note that this is the instance itself which must validate successfully,
     * > not the value associated with the property name.
     * >
     * > For each (name, propertyset) pair of property dependencies, if the
     * > instance has a property by this name, then it must also have properties
     * > with the same names as propertyset.
     * > JSON Schema Validation Section 5.4.5.2
     *
     * @returns {string}
     */

  }, {
    key: 'dependencies',
    value: function dependencies() {
      var dependencies = this.schema.dependencies,
          address = this.address;


      var block = this.push();

      if ((typeof dependencies === 'undefined' ? 'undefined' : _typeof(dependencies)) === 'object') {
        Object.keys(dependencies).forEach(function (key) {
          var dependency = dependencies[key];
          var conditions = [];

          if (Array.isArray(dependency)) {
            dependency.forEach(function (item) {
              conditions.push('container[\'' + item + '\'] === undefined');
            });

            block += '\n            if (container[\'' + key + '\'] !== undefined && (' + conditions.join(' || ') + ')) {\n              valid = false\n              errors.push({\n                keyword: \'dependencies\',\n                message: \'unmet dependencies\'\n              })\n            }\n          ';
          } else if ((typeof dependency === 'undefined' ? 'undefined' : _typeof(dependency)) === 'object') {
            var subschema = dependency;
            var validator = new Validator(subschema, { address: address });

            block += '\n            if (container[\'' + key + '\'] !== undefined) {\n              ' + validator.compile() + '\n            }\n          ';
          }
        });
      }

      block += this.pop();

      return block;
    }

    /**
     * Required
     *
     * @description
     * > An object instance is valid against this keyword if its property set
     * > contains all elements in this keyword's array value.
     * > JSON Schema Validation Section 5.4.3
     *
     * @returns {string}
     */

  }, {
    key: 'required',
    value: function required() {
      var properties = this.schema.properties,
          address = this.address;

      var block = '';

      block += '\n      // validate ' + address + ' presence\n      if (value === undefined) {\n        valid = false\n        errors.push({\n          keyword: \'required\',\n          message: \'is required\'\n        })\n      }\n    ';

      return block;
    }

    /**
     * additionalItems
     *
     * @description
     * > Successful validation of an array instance with regards to these two
     * > keywords is determined as follows: if "items" is not present, or its
     * > value is an object, validation of the instance always succeeds,
     * > regardless of the value of "additionalItems"; if the value of
     * > "additionalItems" is boolean value true or an object, validation of
     * > the instance always succeeds; if the value of "additionalItems" is
     * > boolean value false and the value of "items" is an array, the
     * > instance is valid if its size is less than, or equal to, the size
     * > of "items".
     * > JSON Schema Validation Section 5.3.1
     *
     * @returns {string}
     */

  }, {
    key: 'additionalItems',
    value: function additionalItems() {
      var _schema2 = this.schema,
          items = _schema2.items,
          additionalItems = _schema2.additionalItems,
          address = this.address;

      var block = '';

      if (additionalItems === false && Array.isArray(items)) {
        block += '\n        // don\'t allow additional items\n        if (value.length > ' + items.length + ') {\n          valid = false\n          errors.push({\n            keyword: \'additionalItems\',\n            message: \'additional items not allowed\'\n          })\n        }\n      ';
      }

      if ((typeof additionalItems === 'undefined' ? 'undefined' : _typeof(additionalItems)) === 'object' && additionalItems !== null && Array.isArray(items)) {
        var subschema = additionalItems;
        var validator = new Validator(subschema);
        var counter = Validator.counter;

        block += '\n        // additional items\n        ' + this.push() + '\n\n        for (var i' + counter + ' = ' + items.length + '; i' + counter + ' <= container.length; i' + counter + '++) {\n          value = container[i' + counter + ']\n          ' + validator.compile() + '\n        }\n\n        ' + this.pop() + '\n      ';
      }

      return block;
    }

    /**
     * Items
     *
     * @description
     * > Successful validation of an array instance with regards to these two
     * > keywords is determined as follows: if "items" is not present, or its
     * > value is an object, validation of the instance always succeeds,
     * > regardless of the value of "additionalItems"; if the value of
     * > "additionalItems" is boolean value true or an object, validation of
     * > the instance always succeeds; if the value of "additionalItems" is
     * > boolean value false and the value of "items" is an array, the
     * > instance is valid if its size is less than, or equal to, the size
     * > of "items".
     * > JSON Schema Validation Section 5.3.1
     *
     * Code to generate
     *
     *     // this outer conditional is generated by this.array()
     *     if (Array.isArray(value) {
     *       let parent = value
     *       for (let i = 0; i < parent.length; i++) {
     *         value = parent[i]
     *         // other validation code depending on value here
     *       }
     *       value = parent
     *     }
     *
     *
     * @returns {string}
     */

  }, {
    key: 'items',
    value: function items() {
      var items = this.schema.items,
          address = this.address;

      var block = '';

      // if items is an array
      if (Array.isArray(items)) {
        block += this.push();

        items.forEach(function (item, index) {
          var subschema = item;
          var validator = new Validator(subschema, { address: address + '[' + index + ']' });

          block += '\n          // item #' + index + '\n          value = container[' + index + ']\n          ' + validator.compile() + '\n        ';
        });

        block += this.pop();

        // if items is an object
      } else if ((typeof items === 'undefined' ? 'undefined' : _typeof(items)) === 'object' && items !== null) {
        var subschema = items;
        var validator = new Validator(subschema);
        var counter = Validator.counter;

        block += '\n        // items\n        ' + this.push() + '\n\n        for (var i' + counter + ' = 0; i' + counter + ' < container.length; i' + counter + '++) {\n          // read array element\n          value = container[i' + counter + ']\n          ' + validator.compile() + '\n        }\n\n        ' + this.pop() + '\n      ';
      }

      return block;
    }

    /**
     * minItems
     *
     * @description
     * > An array instance is valid against "minItems" if its size is greater
     * > than, or equal to, the value of this keyword.
     * > JSON Schema Validation Section 5.3.3
     *
     * @returns {string}
     */

  }, {
    key: 'minItems',
    value: function minItems() {
      var minItems = this.schema.minItems,
          address = this.address;


      return '\n        // ' + address + ' min items\n        if (value.length < ' + minItems + ') {\n          valid = false\n          errors.push({\n            keyword: \'minItems\',\n            message: \'too few properties\'\n          })\n        }\n    ';
    }

    /**
     * maxItems
     *
     * @description
     * > An array instance is valid against "maxItems" if its size is less
     * > than, or equal to, the value of this keyword.
     * > JSON Schema Validation Section 5.3.2
     *
     * @returns {string}
     */

  }, {
    key: 'maxItems',
    value: function maxItems() {
      var maxItems = this.schema.maxItems,
          address = this.address;


      return '\n        // ' + address + ' max items\n        if (value.length > ' + maxItems + ') {\n          valid = false\n          errors.push({\n            keyword: \'maxItems\',\n            message: \'too many properties\'\n          })\n        }\n    ';
    }

    /**
     * uniqueItems
     *
     * @description
     * > If this keyword has boolean value false, the instance validates
     * > successfully. If it has boolean value true, the instance validates
     * > successfully if all of its elements are unique.
     * > JSON Schema Validation Section 5.3.4
     *
     * TODO
     * optimize
     *
     * @returns {string}
     */

  }, {
    key: 'uniqueItems',
    value: function uniqueItems() {
      var uniqueItems = this.schema.uniqueItems,
          address = this.address;

      var block = '';

      if (uniqueItems === true) {
        block += '\n        // validate ' + address + ' unique items\n        let values = value.map(v => JSON.stringify(v)) // TODO: optimize\n        let set = new Set(values)\n        if (values.length !== set.size) {\n          valid = false\n          errors.push({\n            keyword: \'uniqueItems\',\n            message: \'items must be unique\'\n          })\n        }\n      ';
      }

      return block;
    }

    /**
     * minLength
     *
     * @description
     * > A string instance is valid against this keyword if its length is
     * > greater than, or equal to, the value of this keyword. The length of
     * > a string instance is defined as the number of its characters as
     * > defined by RFC 4627 [RFC4627].
     * > JSON Schema Validation Section 5.2.2
     *
     * @returns {string}
     */

  }, {
    key: 'minLength',
    value: function minLength() {
      var minLength = this.schema.minLength,
          address = this.address;


      return '\n        // ' + address + ' validate minLength\n        if (Array.from(value).length < ' + minLength + ') {\n          valid = false\n          errors.push({\n            keyword: \'minLength\',\n            message: \'too short\'\n          })\n        }\n    ';
    }

    /**
     * maxLength
     *
     * @description
     * > A string instance is valid against this keyword if its length is less
     * > than, or equal to, the value of this keyword. The length of a string
     * > instance is defined as the number of its characters as defined by
     * > RFC 4627 [RFC4627].
     * > JSON Schema Validation Section 5.2.1
     *
     * @returns {string}
     */

  }, {
    key: 'maxLength',
    value: function maxLength() {
      var maxLength = this.schema.maxLength,
          address = this.address;


      return '\n        // ' + address + ' validate maxLength\n        if (Array.from(value).length > ' + maxLength + ') {\n          valid = false\n          errors.push({\n            keyword: \'maxLength\',\n            message: \'too long\'\n          })\n        }\n    ';
    }

    /**
     * Pattern
     *
     * @description
     * > A string instance is considered valid if the regular expression
     * > matches the instance successfully.
     * > JSON Schema Validation Section 5.2.3
     *
     * @returns {string}
     */

  }, {
    key: 'pattern',
    value: function pattern() {
      var pattern = this.schema.pattern,
          address = this.address;


      if (pattern) {
        return '\n          // ' + address + ' validate pattern\n          if (!value.match(new RegExp(\'' + pattern + '\'))) {\n            valid = false\n            errors.push({\n              keyword: \'pattern\',\n              message: \'does not match the required pattern\'\n            })\n          }\n      ';
      }
    }

    /**
     * Format
     *
     * @description
     * > Structural validation alone may be insufficient to validate that
     * > an instance meets all the requirements of an application. The
     * > "format" keyword is defined to allow interoperable semantic
     * > validation for a fixed subset of values which are accurately
     * > described by authoritative resources, be they RFCs or other
     * > external specifications.
     * > JSON Schema Validation Section 7.1
     *
     * @returns {string}
     */

  }, {
    key: 'format',
    value: function format() {
      var format = this.schema.format,
          address = this.address;

      var matcher = formats.resolve(format);

      if (matcher) {
        return '\n      // ' + address + ' validate format\n      if (!value.match(' + matcher + ')) {\n        valid = false\n        errors.push({\n          keyword: \'format\',\n          message: \'is not "' + format + '" format\'\n        })\n      }\n      ';
      }
    }

    /**
     * Minimum
     *
     * @description
     * > Successful validation depends on the presence and value of
     * > "exclusiveMinimum": if "exclusiveMinimum" is not present, or has
     * > boolean value false, then the instance is valid if it is greater
     * > than, or equal to, the value of "minimum"; if "exclusiveMinimum" is
     * > present and has boolean value true, the instance is valid if it is
     * > strictly greater than the value of "minimum".
     * > JSON Schema Validation Section 5.1.3
     *
     * @returns {string}
     */

  }, {
    key: 'minimum',
    value: function minimum() {
      var _schema3 = this.schema,
          minimum = _schema3.minimum,
          exclusiveMinimum = _schema3.exclusiveMinimum,
          address = this.address;

      var operator = exclusiveMinimum === true ? '<=' : '<';

      return '\n        // ' + address + ' validate minimum\n        if (value ' + operator + ' ' + minimum + ') {\n          valid = false\n          errors.push({\n            keyword: \'minimum\',\n            message: \'too small\'\n          })\n        }\n    ';
    }

    /**
     * Maximum
     *
     * @description
     * > Successful validation depends on the presence and value of
     * > "exclusiveMaximum": if "exclusiveMaximum" is not present, or has
     * > boolean value false, then the instance is valid if it is lower than,
     * > or equal to, the value of "maximum"; if "exclusiveMaximum" has
     * > boolean value true, the instance is valid if it is strictly lower
     * > than the value of "maximum".
     * > JSON Schema Validation Section 5.1.2
     *
     * @returns {string}
     */

  }, {
    key: 'maximum',
    value: function maximum() {
      var _schema4 = this.schema,
          maximum = _schema4.maximum,
          exclusiveMaximum = _schema4.exclusiveMaximum,
          address = this.address;

      var operator = exclusiveMaximum === true ? '>=' : '>';

      return '\n        // ' + address + ' validate maximum\n        if (value ' + operator + ' ' + maximum + ') {\n          valid = false\n          errors.push({\n            keyword: \'maximum\',\n            message: \'too large\'\n          })\n        }\n    ';
    }

    /**
     * multipleOf
     *
     * @description
     * > A numeric instance is valid against "multipleOf" if the result of
     * > the division of the instance by this keyword's value is an integer.
     * > JSON Schema Validation Section 5.1.1
     *
     * @returns {string}
     */

  }, {
    key: 'multipleOf',
    value: function multipleOf() {
      var multipleOf = this.schema.multipleOf;

      var block = '';

      if (typeof multipleOf === 'number') {
        var length = multipleOf.toString().length;
        var decimals = length - multipleOf.toFixed(0).length - 1;
        var pow = decimals > 0 ? Math.pow(10, decimals) : 1;
        var condition = void 0;

        if (decimals > 0) {
          condition = '(value * ' + pow + ') % ' + multipleOf * pow + ' !== 0';
        } else {
          condition = 'value % ' + multipleOf + ' !== 0';
        }

        block += '\n        if (' + condition + ') {\n          valid = false\n          errors.push({\n            keyword: \'multipleOf\',\n            message: \'must be a multiple of ' + multipleOf + '\'\n          })\n        }\n      ';
      }

      return block;
    }
  }]);

  return Validator;
}();

/**
 * Export
 */


module.exports = Validator;

/***/ }),
/* 99 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";
/* WEBPACK VAR INJECTION */(function(global) {

var TextEncoder = global.TextEncoder ? global.TextEncoder // browser
: __webpack_require__(185).TextEncoder; // node shim
module.exports = TextEncoder;
/* WEBPACK VAR INJECTION */}.call(exports, __webpack_require__(19)))

/***/ }),
/* 100 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _possibleConstructorReturn(self, call) { if (!self) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return call && (typeof call === "object" || typeof call === "function") ? call : self; }

function _inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }

/**
 * NotSupportedError
 */
var NotSupportedError = function (_Error) {
  _inherits(NotSupportedError, _Error);

  function NotSupportedError(alg) {
    _classCallCheck(this, NotSupportedError);

    var _this = _possibleConstructorReturn(this, (NotSupportedError.__proto__ || Object.getPrototypeOf(NotSupportedError)).call(this));

    _this.message = alg + " is not a supported algorithm";
    return _this;
  }

  return NotSupportedError;
}(Error);

/**
 * Export
 */


module.exports = NotSupportedError;

/***/ }),
/* 101 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


module.exports = {
  DataError: __webpack_require__(102),
  NotSupportedError: __webpack_require__(100)
};

/***/ }),
/* 102 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _possibleConstructorReturn(self, call) { if (!self) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return call && (typeof call === "object" || typeof call === "function") ? call : self; }

function _inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }

/**
 * DataError
 */
var DataError = function (_Error) {
  _inherits(DataError, _Error);

  function DataError(message) {
    _classCallCheck(this, DataError);

    return _possibleConstructorReturn(this, (DataError.__proto__ || Object.getPrototypeOf(DataError)).call(this, message));
  }

  return DataError;
}(Error);

/**
 * Export
 */


module.exports = DataError;

/***/ }),
/* 103 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


/**
 * Dependencies
 * @ignore
 */

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _possibleConstructorReturn(self, call) { if (!self) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return call && (typeof call === "object" || typeof call === "function") ? call : self; }

function _inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }

var _require = __webpack_require__(3),
    JSONDocument = _require.JSONDocument;

var JWKSchema = __webpack_require__(41);
var JWA = __webpack_require__(65

/**
 * JWK Class
 */
);
var JWK = function (_JSONDocument) {
  _inherits(JWK, _JSONDocument);

  function JWK() {
    _classCallCheck(this, JWK);

    return _possibleConstructorReturn(this, (JWK.__proto__ || Object.getPrototypeOf(JWK)).apply(this, arguments));
  }

  _createClass(JWK, null, [{
    key: 'importKey',


    /**
     * importKey
     *
     * TODO:
     * - should this be on JWA?
     */
    value: function importKey(jwk) {
      return JWA.importKey(jwk);
    }
  }, {
    key: 'schema',


    /**
     * Schema
     */
    get: function get() {
      return JWKSchema;
    }
  }]);

  return JWK;
}(JSONDocument);

/**
 * Export
 */


module.exports = JWK;

/***/ }),
/* 104 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


/**
 * Dependencies
 */

var _require = __webpack_require__(3),
    JSONSchema = _require.JSONSchema;

var JWKSchema = __webpack_require__(41

/**
 * JWKSetSchema
 */
);var JWKSetSchema = new JSONSchema({
  type: 'object',
  properties: {
    keys: {
      type: 'array',
      items: JWKSchema
    }
  }
});

/**
 * Export
 */
module.exports = JWKSetSchema;

/***/ }),
/* 105 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


/**
 * Dependencies
 */
var Base64URLSchema = __webpack_require__(106);
var JWTClaimsSetSchema = __webpack_require__(107);
var JOSEHeaderSchema = __webpack_require__(108);

var _require = __webpack_require__(3

/**
 * JWTSchema
 *
 * @description
 * This schema represents all the things a deserialized JWT can be, i.e.,
 * either a JWS or JWE, and any serialization of them. Validation of well-
 * formedness for a given serialization is accomplished at the time of
 * encoding.
 */
),
    JSONSchema = _require.JSONSchema;

var JWTSchema = new JSONSchema({
  type: 'object',
  properties: {

    /**
     * type
     */
    type: {
      type: 'string',
      enum: ['JWS', 'JWE']
    },

    /**
     * segments
     */
    segments: {
      type: 'array'
    },

    /**
     * header
     */
    header: JOSEHeaderSchema,

    /**
     * protected
     */
    protected: JOSEHeaderSchema,

    /**
     * unprotected
     */
    unprotected: JOSEHeaderSchema,

    /**
     * iv
     */
    iv: Base64URLSchema,

    /**
     * aad
     */
    aad: Base64URLSchema,

    /**
     * ciphertext
     */
    ciphertext: Base64URLSchema,

    /**
     * tag
     */
    tag: Base64URLSchema,

    /**
     * recipients
     */
    recipients: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          header: JOSEHeaderSchema,
          encrypted_key: Base64URLSchema
        }
      }
    },

    /**
     * payload
     */
    payload: JWTClaimsSetSchema,

    /**
     * signatures
     */
    signatures: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          protected: JOSEHeaderSchema,
          header: JOSEHeaderSchema,
          signature: Base64URLSchema,
          key: { type: 'object' }
        }
      }
    },

    /**
     * signature
     */
    signature: Base64URLSchema,

    /**
     * verified
     */
    verified: {
      type: 'boolean',
      default: false
    },

    /**
     * key
     */
    key: {
      type: 'object'
    },

    /**
     * serialization
     */
    serialization: {
      type: 'string',
      enum: ['compact', 'json', 'flattened'],
      default: 'compact'
    }
  }
});

/**
 * Export
 */
module.exports = JWTSchema;

/***/ }),
/* 106 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


/**
 * Dependencies
 */
var _require = __webpack_require__(3

/**
 * Base64URLSchema
 */
),
    JSONSchema = _require.JSONSchema;

var Base64URLSchema = new JSONSchema({
  type: 'string',
  format: 'base64url'
});

/**
 * Export
 */
module.exports = Base64URLSchema;

/***/ }),
/* 107 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


/**
 * Dependencies
 */
var _require = __webpack_require__(3

/**
 * JWTClaimsSetSchema
 *
 * JSON Web Token (JWT)
 * https://tools.ietf.org/html/rfc7519#section-4
 *
 * 4.  JWT Claims
 *
 *   The JWT Claims Set represents a JSON object whose members are the
 *   claims conveyed by the JWT.  The Claim Names within a JWT Claims Set
 *   MUST be unique; JWT parsers MUST either reject JWTs with duplicate
 *   Claim Names or use a JSON parser that returns only the lexically last
 *   duplicate member name, as specified in Section 15.12 ("The JSON
 *   Object") of ECMAScript 5.1 [ECMAScript].
 *
 *   The set of claims that a JWT must contain to be considered valid is
 *   context dependent and is outside the scope of this specification.
 *   Specific applications of JWTs will require implementations to
 *   understand and process some claims in particular ways.  However, in
 *   the absence of such requirements, all claims that are not understood
 *   by implementations MUST be ignored.
 *
 *   There are three classes of JWT Claim Names: Registered Claim Names,
 *   Public Claim Names, and Private Claim Names.
 */
),
    JSONSchema = _require.JSONSchema;

var JWTClaimsSetSchema = new JSONSchema({
  properties: {

    /**
     * JSON Web Token (JWT)
     * https://tools.ietf.org/html/rfc7519#section-4.1
     *
     * 4.1.  Registered Claim Names
     *
     *   The following Claim Names are registered in the IANA "JSON Web Token
     *   Claims" registry established by Section 10.1.  None of the claims
     *   defined below are intended to be mandatory to use or implement in all
     *   cases, but rather they provide a starting point for a set of useful,
     *   interoperable claims.  Applications using JWTs should define which
     *   specific claims they use and when they are required or optional.  All
     *   the names are short because a core goal of JWTs is for the
     *   representation to be compact.
     */

    /**
     * iss
     *
     * JSON Web Token (JWT)
     * https://tools.ietf.org/html/rfc7519#section-4.1.1
     *
     * 4.1.1.  "iss" (Issuer) Claim
     *
     *   The "iss" (issuer) claim identifies the principal that issued the
     *   JWT.  The processing of this claim is generally application specific.
     *   The "iss" value is a case-sensitive string containing a StringOrURI
     *   value.  Use of this claim is OPTIONAL.
     */
    iss: {
      type: 'string',
      format: 'StringOrURI'
    },

    /**
     * sub
     *
     * JSON Web Token (JWT)
     * https://tools.ietf.org/html/rfc7519#section-4.1.2
     *
     * 4.1.2.  "sub" (Subject) Claim
     *
     *   The "sub" (subject) claim identifies the principal that is the
     *   subject of the JWT.  The claims in a JWT are normally statements
     *   about the subject.  The subject value MUST either be scoped to be
     *   locally unique in the context of the issuer or be globally unique.
     *   The processing of this claim is generally application specific.  The
     *   "sub" value is a case-sensitive string containing a StringOrURI
     *   value.  Use of this claim is OPTIONAL.
     */
    sub: {
      type: 'string',
      format: 'StringOrURI'
    },

    /**
     * aud
     *
     * JSON Web Token (JWT)
     * https://tools.ietf.org/html/rfc7519#section-4.1.3
     *
     * 4.1.3.  "aud" (Audience) Claim
     *
     *   The "aud" (audience) claim identifies the recipients that the JWT is
     *   intended for.  Each principal intended to process the JWT MUST
     *   identify itself with a value in the audience claim.  If the principal
     *   processing the claim does not identify itself with a value in the
     *   "aud" claim when this claim is present, then the JWT MUST be
     *   rejected.  In the general case, the "aud" value is an array of case-
     *   sensitive strings, each containing a StringOrURI value.  In the
     *   special case when the JWT has one audience, the "aud" value MAY be a
     *   single case-sensitive string containing a StringOrURI value.  The
     *   interpretation of audience values is generally application specific.
     *   Use of this claim is OPTIONAL.
     */
    aud: {
      type: ['array', 'string'],
      format: 'StringOrURI',
      items: {
        format: 'StringOrURI'
      }
    },

    /**
     * exp
     *
     * JSON Web Token (JWT)
     * https://tools.ietf.org/html/rfc7519#section-4.1.4
     *
     * 4.1.4.  "exp" (Expiration Time) Claim
     *
     *   The "exp" (expiration time) claim identifies the expiration time on
     *   or after which the JWT MUST NOT be accepted for processing.  The
     *   processing of the "exp" claim requires that the current date/time
     *   MUST be before the expiration date/time listed in the "exp" claim.
     *
     *   Implementers MAY provide for some small leeway, usually no more than
     *   a few minutes, to account for clock skew.  Its value MUST be a number
     *   containing a NumericDate value.  Use of this claim is OPTIONAL.
     *
     */
    exp: {
      type: 'number',
      format: 'NumericDate'
    },

    /**
     * nbf
     *
     * JSON Web Token (JWT)
     * https://tools.ietf.org/html/rfc7519#section-4.1.5
     *
     * 4.1.5.  "nbf" (Not Before) Claim
     *
     *   The "nbf" (not before) claim identifies the time before which the JWT
     *   MUST NOT be accepted for processing.  The processing of the "nbf"
     *   claim requires that the current date/time MUST be after or equal to
     *   the not-before date/time listed in the "nbf" claim.  Implementers MAY
     *   provide for some small leeway, usually no more than a few minutes, to
     *   account for clock skew.  Its value MUST be a number containing a
     *   NumericDate value.  Use of this claim is OPTIONAL.
     */
    nbf: {
      type: 'number',
      format: 'NumericDate'
    },

    /**
     * iat
     *
     * JSON Web Token (JWT)
     * https://tools.ietf.org/html/rfc7519#section-4.1.6
     *
     * 4.1.6.  "iat" (Issued At) Claim
     *
     *   The "iat" (issued at) claim identifies the time at which the JWT was
     *   issued.  This claim can be used to determine the age of the JWT.  Its
     *   value MUST be a number containing a NumericDate value.  Use of this
     *   claim is OPTIONAL.
     */
    iat: {
      type: 'number',
      format: 'NumericDate'
    },

    /**
     * jti
     *
     * JSON Web Token (JWT)
     * https://tools.ietf.org/html/rfc7519#section-4.1.7
     *
     * 4.1.7.  "jti" (JWT ID) Claim
     *
     *   The "jti" (JWT ID) claim provides a unique identifier for the JWT.
     *   The identifier value MUST be assigned in a manner that ensures that
     *   there is a negligible probability that the same value will be
     *   accidentally assigned to a different data object; if the application
     *   uses multiple issuers, collisions MUST be prevented among values
     *   produced by different issuers as well.  The "jti" claim can be used
     *   to prevent the JWT from being replayed.  The "jti" value is a case-
     *   sensitive string.  Use of this claim is OPTIONAL.
     */
    jti: {
      type: 'string'
    }
  }
});

/**
 * Export
 */
module.exports = JWTClaimsSetSchema;

/***/ }),
/* 108 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


/**
 * Dependencies
 */
var JWKSchema = __webpack_require__(41);

var _require = __webpack_require__(3

/**
 * JOSEHeaderSchema
 *
 * JSON Web Token (JWT)
 * https://tools.ietf.org/html/rfc7519#section-5
 *
 * 5.  JOSE Header
 *
 *   For a JWT object, the members of the JSON object represented by the
 *   JOSE Header describe the cryptographic operations applied to the JWT
 *   and optionally, additional properties of the JWT.  Depending upon
 *   whether the JWT is a JWS or JWE, the corresponding rules for the JOSE
 *   Header values apply.
 */
),
    JSONSchema = _require.JSONSchema;

var JOSEHeaderSchema = new JSONSchema({
  type: 'object',
  properties: {

    /**
     * typ
     *
     * JSON Web Token (JWT)
     * https://tools.ietf.org/html/rfc7519#section-5.1
     *
     * 5.1.  "typ" (Type) Header Parameter
     *
     *   The "typ" (type) Header Parameter defined by [JWS] and [JWE] is used
     *   by JWT applications to declare the media type [IANA.MediaTypes] of
     *   this complete JWT.  This is intended for use by the JWT application
     *   when values that are not JWTs could also be present in an application
     *   data structure that can contain a JWT object; the application can use
     *   this value to disambiguate among the different kinds of objects that
     *   might be present.  It will typically not be used by applications when
     *   it is already known that the object is a JWT.  This parameter is
     *   ignored by JWT implementations; any processing of this parameter is
     *   performed by the JWT application.  If present, it is RECOMMENDED that
     *   its value be "JWT" to indicate that this object is a JWT.  While
     *   media type names are not case sensitive, it is RECOMMENDED that "JWT"
     *   always be spelled using uppercase characters for compatibility with
     *   legacy implementations.  Use of this Header Parameter is OPTIONAL.
     *
     * JSON Web Signature (JWS)
     * https://tools.ietf.org/html/rfc7515#section-4.1.9
     *
     * 4.1.9.  "typ" (Type) Header Parameter
     *
     *   The "typ" (type) Header Parameter is used by JWS applications to
     *   declare the media type [IANA.MediaTypes] of this complete JWS.  This
     *   is intended for use by the application when more than one kind of
     *   object could be present in an application data structure that can
     *   contain a JWS; the application can use this value to disambiguate
     *   among the different kinds of objects that might be present.  It will
     *   typically not be used by applications when the kind of object is
     *   already known.  This parameter is ignored by JWS implementations; any
     *   processing of this parameter is performed by the JWS application.
     *   Use of this Header Parameter is OPTIONAL.
     *
     *   Per RFC 2045 [RFC2045], all media type values, subtype values, and
     *   parameter names are case insensitive.  However, parameter values are
     *   case sensitive unless otherwise specified for the specific parameter.
     *
     *   To keep messages compact in common situations, it is RECOMMENDED that
     *   producers omit an "application/" prefix of a media type value in a
     *   "typ" Header Parameter when no other '/' appears in the media type
     *   value.  A recipient using the media type value MUST treat it as if
     *   "application/" were prepended to any "typ" value not containing a
     *   '/'.  For instance, a "typ" value of "example" SHOULD be used to
     *   represent the "application/example" media type, whereas the media
     *   type "application/example;part="1/2"" cannot be shortened to
     *   "example;part="1/2"".
     *
     *   The "typ" value "JOSE" can be used by applications to indicate that
     *   this object is a JWS or JWE using the JWS Compact Serialization or
     *   the JWE Compact Serialization.  The "typ" value "JOSE+JSON" can be
     *   used by applications to indicate that this object is a JWS or JWE
     *   using the JWS JSON Serialization or the JWE JSON Serialization.
     *   Other type values can also be used by applications.
     *
     * JSON Web Encryption (JWE)
     * https://tools.ietf.org/html/rfc7516#section-4.1.11
     *
     * 4.1.11.  "typ" (Type) Header Parameter
     *
     *   This parameter has the same meaning, syntax, and processing rules as
     *   the "typ" Header Parameter defined in Section 4.1.9 of [JWS], except
     *   that the type is that of this complete JWE.
     */
    typ: {
      type: 'string'
    },

    /**
     * cty
     *
     * JSON Web Token (JWT)
     * https://tools.ietf.org/html/rfc7519#section-5.2
     *
     * 5.2.  "cty" (Content Type) Header Parameter
     *
     *   The "cty" (content type) Header Parameter defined by [JWS] and [JWE]
     *   is used by this specification to convey structural information about
     *   the JWT.
     *
     *   In the normal case in which nested signing or encryption operations
     *   are not employed, the use of this Header Parameter is NOT
     *   RECOMMENDED.  In the case that nested signing or encryption is
     *   employed, this Header Parameter MUST be present; in this case, the
     *   value MUST be "JWT", to indicate that a Nested JWT is carried in this
     *   JWT.  While media type names are not case sensitive, it is
     *   RECOMMENDED that "JWT" always be spelled using uppercase characters
     *   for compatibility with legacy implementations.  See Appendix A.2 for
     *   an example of a Nested JWT.
     *
     *
     * JSON Web Signature (JWS)
     * https://tools.ietf.org/html/rfc7515#section-4.1.10
     *
     * 4.1.10.  "cty" (Content Type) Header Parameter
     *
     *   The "cty" (content type) Header Parameter is used by JWS applications
     *   to declare the media type [IANA.MediaTypes] of the secured content
     *   (the payload).  This is intended for use by the application when more
     *   than one kind of object could be present in the JWS Payload; the
     *   application can use this value to disambiguate among the different
     *   kinds of objects that might be present.  It will typically not be
     *   used by applications when the kind of object is already known.  This
     *   parameter is ignored by JWS implementations; any processing of this
     *   parameter is performed by the JWS application.  Use of this Header
     *   Parameter is OPTIONAL.
     *
     *   Per RFC 2045 [RFC2045], all media type values, subtype values, and
     *   parameter names are case insensitive.  However, parameter values are
     *   case sensitive unless otherwise specified for the specific parameter.
     *
     *   To keep messages compact in common situations, it is RECOMMENDED that
     *   producers omit an "application/" prefix of a media type value in a
     *   "cty" Header Parameter when no other '/' appears in the media type
     *   value.  A recipient using the media type value MUST treat it as if
     *   "application/" were prepended to any "cty" value not containing a
     *   '/'.  For instance, a "cty" value of "example" SHOULD be used to
     *   represent the "application/example" media type, whereas the media
     *   type "application/example;part="1/2"" cannot be shortened to
     *   "example;part="1/2"".
     *
     * JSON Web Encryption (JWE)
     * https://tools.ietf.org/html/rfc7516#section-4.1.12
     *
     * 4.1.12.  "cty" (Content Type) Header Parameter
     *
     *   This parameter has the same meaning, syntax, and processing rules as
     *   the "cty" Header Parameter defined in Section 4.1.10 of [JWS], except
     *   that the type is that of the secured content (the plaintext).
     */
    cty: {
      type: 'string',
      enum: ['JWT']
    },

    /**
     * alg
     *
     * JSON Web Signature (JWS)
     * https://tools.ietf.org/html/rfc7515#section-4.1.1
     *
     * 4.1.1.  "alg" (Algorithm) Header Parameter
     *
     *   The "alg" (algorithm) Header Parameter identifies the cryptographic
     *   algorithm used to secure the JWS.  The JWS Signature value is not
     *   valid if the "alg" value does not represent a supported algorithm or
     *   if there is not a key for use with that algorithm associated with the
     *   party that digitally signed or MACed the content.  "alg" values
     *   should either be registered in the IANA "JSON Web Signature and
     *   Encryption Algorithms" registry established by [JWA] or be a value
     *   that contains a Collision-Resistant Name.  The "alg" value is a case-
     *   sensitive ASCII string containing a StringOrURI value.  This Header
     *   Parameter MUST be present and MUST be understood and processed by
     *   implementations.
     *
     *   A list of defined "alg" values for this use can be found in the IANA
     *   "JSON Web Signature and Encryption Algorithms" registry established
     *   by [JWA]; the initial contents of this registry are the values
     *   defined in Section 3.1 of [JWA].
     *
     * JSON Web Encryption (JWE)
     * https://tools.ietf.org/html/rfc7516#section-4.1.1
     *
     * 4.1.1.  "alg" (Algorithm) Header Parameter
     *
     *   This parameter has the same meaning, syntax, and processing rules as
     *   the "alg" Header Parameter defined in Section 4.1.1 of [JWS], except
     *   that the Header Parameter identifies the cryptographic algorithm used
     *   to encrypt or determine the value of the CEK.  The encrypted content
     *   is not usable if the "alg" value does not represent a supported
     *   algorithm, or if the recipient does not have a key that can be used
     *   with that algorithm.
     *
     *   A list of defined "alg" values for this use can be found in the IANA
     *   "JSON Web Signature and Encryption Algorithms" registry established
     *   by [JWA]; the initial contents of this registry are the values
     *   defined in Section 4.1 of [JWA].
     */
    alg: {
      type: 'string',
      format: 'StringOrURI'
    },

    /**
     * jku
     *
     * JSON Web Signature (JWS)
     * https://tools.ietf.org/html/rfc7515#section-4.1.2
     *
     * 4.1.2.  "jku" (JWK Set URL) Header Parameter (JWS)
     *
     *   The "jku" (JWK Set URL) Header Parameter is a URI [RFC3986] that
     *   refers to a resource for a set of JSON-encoded public keys, one of
     *   which corresponds to the key used to digitally sign the JWS.  The
     *   keys MUST be encoded as a JWK Set [JWK].  The protocol used to
     *   acquire the resource MUST provide integrity protection; an HTTP GET
     *   request to retrieve the JWK Set MUST use Transport Layer Security
     *   (TLS) [RFC2818] [RFC5246]; and the identity of the server MUST be
     *   validated, as per Section 6 of RFC 6125 [RFC6125].  Also, see
     *   Section 8 on TLS requirements.  Use of this Header Parameter is
     *   OPTIONAL.
     *
     * JSON Web Encryption (JWE)
     * https://tools.ietf.org/html/rfc7516#section-4.1.4
     *
     * 4.1.4.  "jku" (JWK Set URL) Header Parameter (JWE)
     *
     *   This parameter has the same meaning, syntax, and processing rules as
     *   the "jku" Header Parameter defined in Section 4.1.2 of [JWS], except
     *   that the JWK Set resource contains the public key to which the JWE
     *   was encrypted; this can be used to determine the private key needed
     *   to decrypt the JWE.
     */
    jku: {
      type: 'string',
      format: 'URI'
    },

    /**
     * jwk
     *
     * JSON Web Signature (JWS)
     * https://tools.ietf.org/html/rfc7515#section-4.1.3
     *
     * 4.1.3.  "jwk" (JSON Web Key) Header Parameter
     *
     *   The "jwk" (JSON Web Key) Header Parameter is the public key that
     *   corresponds to the key used to digitally sign the JWS.  This key is
     *   represented as a JSON Web Key [JWK].  Use of this Header Parameter is
     *   OPTIONAL.
     *
     * JSON Web Encryption (JWE)
     * https://tools.ietf.org/html/rfc7516#section-4.1.5
     *
     * 4.1.5.  "jwk" (JSON Web Key) Header Parameter
     *
     *   This parameter has the same meaning, syntax, and processing rules as
     *   the "jwk" Header Parameter defined in Section 4.1.3 of [JWS], except
     *   that the key is the public key to which the JWE was encrypted; this
     *   can be used to determine the private key needed to decrypt the JWE.
     */
    //jwk: JWKSchema,

    /**
     * kid
     *
     * JSON Web Signature (JWS)
     * https://tools.ietf.org/html/rfc7515#section-4.1.4
     *
     * 4.1.4.  "kid" (Key ID) Header Parameter
     *
     *   The "kid" (key ID) Header Parameter is a hint indicating which key
     *   was used to secure the JWS.  This parameter allows originators to
     *   explicitly signal a change of key to recipients.  The structure of
     *   the "kid" value is unspecified.  Its value MUST be a case-sensitive
     *   string.  Use of this Header Parameter is OPTIONAL.
     *
     *   When used with a JWK, the "kid" value is used to match a JWK "kid"
     *   parameter value.
     *
     *
     * JSON Web Encryption (JWE)
     * https://tools.ietf.org/html/rfc7516#section-4.1.6
     *
     * 4.1.6.  "kid" (Key ID) Header Parameter
     *
     *   This parameter has the same meaning, syntax, and processing rules as
     *   the "kid" Header Parameter defined in Section 4.1.4 of [JWS], except
     *   that the key hint references the public key to which the JWE was
     *   encrypted; this can be used to determine the private key needed to
     *   decrypt the JWE.  This parameter allows originators to explicitly
     *   signal a change of key to JWE recipients.
     */
    kid: {
      type: 'string'
    },

    /**
     * x5u
     *
     * JSON Web Signature (JWS)
     * https://tools.ietf.org/html/rfc7515#section-4.1.5
     *
     * 4.1.5.  "x5u" (X.509 URL) Header Parameter
     *
     *   The "x5u" (X.509 URL) Header Parameter is a URI [RFC3986] that refers
     *   to a resource for the X.509 public key certificate or certificate
     *   chain [RFC5280] corresponding to the key used to digitally sign the
     *   JWS.  The identified resource MUST provide a representation of the
     *   certificate or certificate chain that conforms to RFC 5280 [RFC5280]
     *   in PEM-encoded form, with each certificate delimited as specified in
     *   Section 6.1 of RFC 4945 [RFC4945].  The certificate containing the
     *   public key corresponding to the key used to digitally sign the JWS
     *   MUST be the first certificate.  This MAY be followed by additional
     *   certificates, with each subsequent certificate being the one used to
     *   certify the previous one.  The protocol used to acquire the resource
     *   MUST provide integrity protection; an HTTP GET request to retrieve
     *   the certificate MUST use TLS [RFC2818] [RFC5246]; and the identity of
     *   the server MUST be validated, as per Section 6 of RFC 6125 [RFC6125].
     *   Also, see Section 8 on TLS requirements.  Use of this Header
     *   Parameter is OPTIONAL.
     *
     * JSON Web Encryption (JWE)
     * https://tools.ietf.org/html/rfc7516#section-4.1.7
     *
     * 4.1.7.  "x5u" (X.509 URL) Header Parameter
     *
     *   This parameter has the same meaning, syntax, and processing rules as
     *   the "x5u" Header Parameter defined in Section 4.1.5 of [JWS], except
     *   that the X.509 public key certificate or certificate chain [RFC5280]
     *   contains the public key to which the JWE was encrypted; this can be
     *   used to determine the private key needed to decrypt the JWE.
     */
    x5u: {
      type: 'string',
      format: 'URI'
    },

    /**
     * x5c
     *
     * JSON Web Signature (JWS)
     * https://tools.ietf.org/html/rfc7515#section-4.1.6
     *
     * 4.1.6.  "x5c" (X.509 Certificate Chain) Header Parameter
     *
     *   The "x5c" (X.509 certificate chain) Header Parameter contains the
     *   X.509 public key certificate or certificate chain [RFC5280]
     *   corresponding to the key used to digitally sign the JWS.  The
     *   certificate or certificate chain is represented as a JSON array of
     *   certificate value strings.  Each string in the array is a
     *   base64-encoded (Section 4 of [RFC4648] -- not base64url-encoded) DER
     *   [ITU.X690.2008] PKIX certificate value.  The certificate containing
     *   the public key corresponding to the key used to digitally sign the
     *   JWS MUST be the first certificate.  This MAY be followed by
     *   additional certificates, with each subsequent certificate being the
     *   one used to certify the previous one.  The recipient MUST validate
     *   the certificate chain according to RFC 5280 [RFC5280] and consider
     *   the certificate or certificate chain to be invalid if any validation
     *   failure occurs.  Use of this Header Parameter is OPTIONAL.
     *
     * JSON Web Encryption (JWE)
     * https://tools.ietf.org/html/rfc7516#section-4.1.8
     *
     * 4.1.8.  "x5c" (X.509 Certificate Chain) Header Parameter
     *
     *   This parameter has the same meaning, syntax, and processing rules as
     *   the "x5c" Header Parameter defined in Section 4.1.6 of [JWS], except
     *   that the X.509 public key certificate or certificate chain [RFC5280]
     *   contains the public key to which the JWE was encrypted; this can be
     *   used to determine the private key needed to decrypt the JWE.
     */
    x5c: {
      type: 'array',
      items: {
        type: 'string',
        format: 'base64'
      }
    },

    /**
     * x5t
     *
     * JSON Web Signature (JWS)
     * https://tools.ietf.org/html/rfc7515#section-4.1.7
     *
     * 4.1.7.  "x5t" (X.509 Certificate SHA-1 Thumbprint) Header Parameter
     *
     *   The "x5t" (X.509 certificate SHA-1 thumbprint) Header Parameter is a
     *   base64url-encoded SHA-1 thumbprint (a.k.a. digest) of the DER
     *   encoding of the X.509 certificate [RFC5280] corresponding to the key
     *   used to digitally sign the JWS.  Note that certificate thumbprints
     *   are also sometimes known as certificate fingerprints.  Use of this
     *   Header Parameter is OPTIONAL.
     *
     * JSON Web Encryption (JWE)
     * https://tools.ietf.org/html/rfc7516#section-4.1.9
     *
     * 4.1.9.  "x5t" (X.509 Certificate SHA-1 Thumbprint) Header Parameter
     *
     *   This parameter has the same meaning, syntax, and processing rules as
     *   the "x5t" Header Parameter defined in Section 4.1.7 of [JWS], except
     *   that the certificate referenced by the thumbprint contains the public
     *   key to which the JWE was encrypted; this can be used to determine the
     *   private key needed to decrypt the JWE.  Note that certificate
     *   thumbprints are also sometimes known as certificate fingerprints.
     */
    x5t: {
      type: 'string',
      format: 'base64url'
    },

    /**
     * x5t#S256
     *
     * JSON Web Signature (JWS)
     * https://tools.ietf.org/html/rfc7515#section-4.1.8
     *
     * 4.1.8.  "x5t#S256" (X.509 Certificate SHA-256 Thumbprint) Header
     *         Parameter
     *
     *   The "x5t#S256" (X.509 certificate SHA-256 thumbprint) Header
     *   Parameter is a base64url-encoded SHA-256 thumbprint (a.k.a. digest)
     *   of the DER encoding of the X.509 certificate [RFC5280] corresponding
     *   to the key used to digitally sign the JWS.  Note that certificate
     *   thumbprints are also sometimes known as certificate fingerprints.
     *   Use of this Header Parameter is OPTIONAL.
     *
     *
     * JSON Web Encryption (JWE)
     * https://tools.ietf.org/html/rfc7516#section-4.1.10
     *
     * 4.1.10.  "x5t#S256" (X.509 Certificate SHA-256 Thumbprint) Header
     *          Parameter
     *
     *   This parameter has the same meaning, syntax, and processing rules as
     *   the "x5t#S256" Header Parameter defined in Section 4.1.8 of [JWS],
     *   except that the certificate referenced by the thumbprint contains the
     *   public key to which the JWE was encrypted; this can be used to
     *   determine the private key needed to decrypt the JWE.  Note that
     *   certificate thumbprints are also sometimes known as certificate
     *   fingerprints.
     */
    //'x5t#S256': {
    //  type: 'string',
    //  format: 'base64url'
    //},

    /**
     * crit
     *
     * JSON Web Signature (JWS)
     * https://tools.ietf.org/html/rfc7515#section-4.1.11
     *
     * 4.1.11.  "crit" (Critical) Header Parameter
     *
     *   The "crit" (critical) Header Parameter indicates that extensions to
     *   this specification and/or [JWA] are being used that MUST be
     *   understood and processed.  Its value is an array listing the Header
     *   Parameter names present in the JOSE Header that use those extensions.
     *   If any of the listed extension Header Parameters are not understood
     *   and supported by the recipient, then the JWS is invalid.  Producers
     *   MUST NOT include Header Parameter names defined by this specification
     *   or [JWA] for use with JWS, duplicate names, or names that do not
     *   occur as Header Parameter names within the JOSE Header in the "crit"
     *   list.  Producers MUST NOT use the empty list "[]" as the "crit"
     *   value.  Recipients MAY consider the JWS to be invalid if the critical
     *   list contains any Header Parameter names defined by this
     *   specification or [JWA] for use with JWS or if any other constraints
     *   on its use are violated.  When used, this Header Parameter MUST be
     *   integrity protected; therefore, it MUST occur only within the JWS
     *   Protected Header.  Use of this Header Parameter is OPTIONAL.  This
     *   Header Parameter MUST be understood and processed by implementations.
     *
     *   An example use, along with a hypothetical "exp" (expiration time)
     *   field is:
     *
     *     {"alg":"ES256",
     *     "crit":["exp"],
     *     "exp":1363284000
     *     }
     *
     * JSON Web Encryption (JWE)
     * https://tools.ietf.org/html/rfc7516#section-4.1.13
     *
     *   4.1.13.  "crit" (Critical) Header Parameter
     *
     *   This parameter has the same meaning, syntax, and processing rules as
     *   the "crit" Header Parameter defined in Section 4.1.11 of [JWS],
     *   except that Header Parameters for a JWE are being referred to, rather
     *   than Header Parameters for a JWS.
     */
    crit: {
      type: 'array',
      items: {
        type: 'string'
      },
      minItems: 1
    },

    /**
     * enc
     *
     * JSON Web Encryption (JWE)
     * https://tools.ietf.org/html/rfc7516#section-4.1.2
     *
     * 4.1.2.  "enc" (Encryption Algorithm) Header Parameter
     *
     *   The "enc" (encryption algorithm) Header Parameter identifies the
     *   content encryption algorithm used to perform authenticated encryption
     *   on the plaintext to produce the ciphertext and the Authentication
     *   Tag.  This algorithm MUST be an AEAD algorithm with a specified key
     *   length.  The encrypted content is not usable if the "enc" value does
     *   not represent a supported algorithm.  "enc" values should either be
     *   registered in the IANA "JSON Web Signature and Encryption Algorithms"
     *   registry established by [JWA] or be a value that contains a
     *   Collision-Resistant Name.  The "enc" value is a case-sensitive ASCII
     *   string containing a StringOrURI value.  This Header Parameter MUST be
     *   present and MUST be understood and processed by implementations.
     *
     *   A list of defined "enc" values for this use can be found in the IANA
     *   "JSON Web Signature and Encryption Algorithms" registry established
     *   by [JWA]; the initial contents of this registry are the values
     *   defined in Section 5.1 of [JWA].
     */
    enc: {
      type: 'string',
      format: 'StringOrURI'
    },

    /**
     * zip
     *
     * JSON Web Encryption (JWE)
     * https://tools.ietf.org/html/rfc7516#section-4.1.3
     *
     * 4.1.3.  "zip" (Compression Algorithm) Header Parameter
     *
     *   The "zip" (compression algorithm) applied to the plaintext before
     *   encryption, if any.  The "zip" value defined by this specification
     *   is:
     *
     *   o  "DEF" - Compression with the DEFLATE [RFC1951] algorithm
     *
     *   Other values MAY be used.  Compression algorithm values can be
     *   registered in the IANA "JSON Web Encryption Compression Algorithms"
     *   registry established by [JWA].  The "zip" value is a case-sensitive
     *   string.  If no "zip" parameter is present, no compression is applied
     *   to the plaintext before encryption.  When used, this Header Parameter
     *   MUST be integrity protected; therefore, it MUST occur only within the
     *   JWE Protected Header.  Use of this Header Parameter is OPTIONAL.
     *   This Header Parameter MUST be understood and processed by
     *   implementations.
     */
    zip: {
      type: 'string'
    }
  }
});

/**
 * Export
 */
module.exports = JOSEHeaderSchema;

/***/ }),
/* 109 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var _slicedToArray = function () { function sliceIterator(arr, i) { var _arr = []; var _n = true; var _d = false; var _e = undefined; try { for (var _i = arr[Symbol.iterator](), _s; !(_n = (_s = _i.next()).done); _n = true) { _arr.push(_s.value); if (i && _arr.length === i) break; } } catch (err) { _d = true; _e = err; } finally { try { if (!_n && _i["return"]) _i["return"](); } finally { if (_d) throw _e; } } return _arr; } return function (arr, i) { if (Array.isArray(arr)) { return arr; } else if (Symbol.iterator in Object(arr)) { return sliceIterator(arr, i); } else { throw new TypeError("Invalid attempt to destructure non-iterable instance"); } }; }();

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

/**
 * Dependencies
 */
var base64url = __webpack_require__(14);
var JWA = __webpack_require__(65);

var _require = __webpack_require__(101

/**
 * JWS
 */
),
    DataError = _require.DataError;

var JWS = function () {
  function JWS() {
    _classCallCheck(this, JWS);
  }

  _createClass(JWS, null, [{
    key: 'sign',


    /**
     * sign
     *
     * @description
     * Encode a JWT instance
     *
     * @param {Object} token
     * @returns {Promise}
     */
    value: function sign(token) {
      var payload = base64url(JSON.stringify(token.payload)

      // compact serialization
      );if (token.serialization === 'compact') {
        var key = token.key,
            alg = token.header.alg;

        var header = base64url(JSON.stringify(token.header));
        var data = header + '.' + payload;

        return JWA.sign(alg, key, data).then(function (signature) {
          return data + '.' + signature;
        });
      }

      // JSON serialization
      if (token.serialization === 'json') {}

      // Flattened serialization
      if (token.serialization === 'flattened') {}

      return Promise.reject(new DataError('Unsupported serialization'));
    }

    /**
     * verify
     */

  }, {
    key: 'verify',
    value: function verify(jwt) {
      // multiple signatures
      if (jwt.signatures) {
        // ...
      }

      var key = jwt.key,
          signature = jwt.signature,
          alg = jwt.header.alg;

      // one signature

      if (jwt.signature) {
        var _jwt$segments = _slicedToArray(jwt.segments, 2),
            header = _jwt$segments[0],
            payload = _jwt$segments[1];

        var data = header + '.' + payload;

        if (alg === 'none') {
          return Promise.reject(new DataError('Signature provided to verify with alg: none'));
        }

        return JWA.verify(alg, key, signature, data).then(function (verified) {
          jwt.verified = verified;
          return verified;
        });
      }

      if (alg === 'none') {
        if (!key && !signature) {
          jwt.verified = true;

          return Promise.resolve(true);
        }

        if (key) {
          return Promise.reject(new DataError('Key provided to verify signature with alg: none'));
        }
      }

      // no signatures to verify
      return Promise.reject(new DataError('Missing signature(s)'));
    }
  }]);

  return JWS;
}();

/**
 * Export
 */


module.exports = JWS;

/***/ }),
/* 110 */
/***/ (function(module, exports, __webpack_require__) {

module.exports = { "default": __webpack_require__(192), __esModule: true };

/***/ }),
/* 111 */
/***/ (function(module, exports, __webpack_require__) {

module.exports = { "default": __webpack_require__(201), __esModule: true };

/***/ }),
/* 112 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var _keys = __webpack_require__(110);

var _keys2 = _interopRequireDefault(_keys);

var _classCallCheck2 = __webpack_require__(20);

var _classCallCheck3 = _interopRequireDefault(_classCallCheck2);

var _createClass2 = __webpack_require__(21);

var _createClass3 = _interopRequireDefault(_createClass2);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/**
 * Dependencies
 */

/**
 * FormUrlEncoded
 */
var FormUrlEncoded = function () {
  function FormUrlEncoded() {
    (0, _classCallCheck3.default)(this, FormUrlEncoded);
  }

  (0, _createClass3.default)(FormUrlEncoded, null, [{
    key: 'encode',


    /**
     * Encode
     *
     * @description
     * Represent an object as x-www-form-urlencoded string.
     *
     * @param {Object} data
     * @returns {string}
     */
    value: function encode(data) {
      var pairs = [];

      (0, _keys2.default)(data).forEach(function (key) {
        pairs.push(encodeURIComponent(key) + '=' + encodeURIComponent(data[key]));
      });

      return pairs.join('&');
    }

    /**
     * Decode
     *
     * @description
     * Parse a x-www-form-urlencoded into an object.
     *
     * @param {string} data
     * @returns {Object}
     */

  }, {
    key: 'decode',
    value: function decode(data) {
      var obj = {};

      data.split('&').forEach(function (property) {
        var pair = property.split('=');
        var key = decodeURIComponent(pair[0]);
        var val = decodeURIComponent(pair[1]);

        obj[key] = val;
      });

      return obj;
    }
  }]);
  return FormUrlEncoded;
}();

/**
 * Export
 */


module.exports = FormUrlEncoded;

/***/ }),
/* 113 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


/**
 * Throws an error when a fetch response status code indicates a 400 or 500
 * HTTP error. (The whatwg fetch api does not normally reject on http error
 * responses).
 *
 * Usage:
 *
 * ```
 * return fetch(url)
 *   .then(onHttpError('Error while fetching resource')
 *   .catch(err => console.log(err))
 *
 * // -> 'Error while fetching resource: 404 Not Found' error
 * // if a 404 response is encountered
 * ```
 *
 * @param [message] {string} Optional error message to clarify context
 *
 * @throws {Error} For http status codes > 300
 *
 * @return {Object} fetch response object (passed through if no error)
 */

function onHttpError() {
  var message = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : 'fetch error';

  return function (response) {
    if (response.status >= 200 && response.status < 300) {
      return response;
    }

    var errorMessage = message + ': ' + response.status + ' ' + response.statusText;
    var error = new Error(errorMessage);
    error.response = response;
    error.statusCode = response.status;
    throw error;
  };
}

module.exports = onHttpError;

/***/ }),
/* 114 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.requiresAuth = exports.login = undefined;

__webpack_require__(55);

var _authHeader = __webpack_require__(86);

var authorization = _interopRequireWildcard(_authHeader);

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

/* global fetch, Response */
var login = exports.login = function login(idp) {
  return fetch(idp, { method: 'HEAD', credentials: 'include' }).then(function (resp) {
    return resp.headers.get('user');
  }).then(function (webId) {
    return webId ? { authType: 'WebID-TLS', idp: idp, webId: webId } : null;
  });
};

var requiresAuth = exports.requiresAuth = function requiresAuth(resp) {
  if (resp.status !== 401) {
    return false;
  }
  var wwwAuthHeader = resp.headers.get('www-authenticate');
  if (!wwwAuthHeader) {
    return false;
  }
  var auth = authorization.parse(wwwAuthHeader);
  return auth.scheme === 'WebID-TLS';
};

/***/ }),
/* 115 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


Object.defineProperty(exports, "__esModule", {
  value: true
});

var _api = __webpack_require__(116);

Object.defineProperty(exports, 'login', {
  enumerable: true,
  get: function get() {
    return _api.login;
  }
});
Object.defineProperty(exports, 'popupLogin', {
  enumerable: true,
  get: function get() {
    return _api.popupLogin;
  }
});
Object.defineProperty(exports, 'currentSession', {
  enumerable: true,
  get: function get() {
    return _api.currentSession;
  }
});
Object.defineProperty(exports, 'logout', {
  enumerable: true,
  get: function get() {
    return _api.logout;
  }
});
Object.defineProperty(exports, 'fetch', {
  enumerable: true,
  get: function get() {
    return _api.fetch;
  }
});

/***/ }),
/* 116 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.logout = exports.currentSession = exports.popupLogin = exports.login = exports.fetch = undefined;

var _extends2 = __webpack_require__(29);

var _extends3 = _interopRequireDefault(_extends2);

var _regenerator = __webpack_require__(11);

var _regenerator2 = _interopRequireDefault(_regenerator);

var _asyncToGenerator2 = __webpack_require__(12);

var _asyncToGenerator3 = _interopRequireDefault(_asyncToGenerator2);

var firstSession = function () {
  var _ref = (0, _asyncToGenerator3.default)( /*#__PURE__*/_regenerator2.default.mark(function _callee(storage, authFns) {
    var session;
    return _regenerator2.default.wrap(function _callee$(_context) {
      while (1) {
        switch (_context.prev = _context.next) {
          case 0:
            if (!(authFns.length === 0)) {
              _context.next = 2;
              break;
            }

            return _context.abrupt('return', null);

          case 2:
            _context.prev = 2;
            _context.next = 5;
            return authFns[0]();

          case 5:
            session = _context.sent;

            if (!session) {
              _context.next = 8;
              break;
            }

            return _context.abrupt('return', (0, _session.saveSession)(storage)(session));

          case 8:
            _context.next = 13;
            break;

          case 10:
            _context.prev = 10;
            _context.t0 = _context['catch'](2);

            console.error(_context.t0);

          case 13:
            return _context.abrupt('return', firstSession(storage, authFns.slice(1)));

          case 14:
          case 'end':
            return _context.stop();
        }
      }
    }, _callee, this, [[2, 10]]);
  }));

  return function firstSession(_x, _x2) {
    return _ref.apply(this, arguments);
  };
}();

var login = exports.login = function () {
  var _ref2 = (0, _asyncToGenerator3.default)( /*#__PURE__*/_regenerator2.default.mark(function _callee2(idp, options) {
    var webIdTlsSession, webIdOidcLoginRedirectFn;
    return _regenerator2.default.wrap(function _callee2$(_context2) {
      while (1) {
        switch (_context2.prev = _context2.next) {
          case 0:
            options = (0, _extends3.default)({}, defaultLoginOptions(), options);
            _context2.next = 3;
            return WebIdTls.login(idp);

          case 3:
            webIdTlsSession = _context2.sent;

            if (!webIdTlsSession) {
              _context2.next = 6;
              break;
            }

            return _context2.abrupt('return', (0, _session.saveSession)(options.storage)(webIdTlsSession));

          case 6:
            _context2.next = 8;
            return WebIdOidc.login(idp, options);

          case 8:
            webIdOidcLoginRedirectFn = _context2.sent;
            return _context2.abrupt('return', webIdOidcLoginRedirectFn);

          case 10:
          case 'end':
            return _context2.stop();
        }
      }
    }, _callee2, this);
  }));

  return function login(_x3, _x4) {
    return _ref2.apply(this, arguments);
  };
}();

var popupLogin = exports.popupLogin = function () {
  var _ref3 = (0, _asyncToGenerator3.default)( /*#__PURE__*/_regenerator2.default.mark(function _callee3(options) {
    var childWindow, session;
    return _regenerator2.default.wrap(function _callee3$(_context3) {
      while (1) {
        switch (_context3.prev = _context3.next) {
          case 0:
            if (options.popupUri) {
              _context3.next = 2;
              break;
            }

            throw new Error('Must provide options.popupUri');

          case 2:
            if (!options.callbackUri) {
              options.callbackUri = options.popupUri;
            }
            options = (0, _extends3.default)({}, defaultLoginOptions(), options);
            childWindow = (0, _popup.openIdpSelector)(options);
            _context3.next = 7;
            return (0, _popup.startPopupServer)(options.storage, childWindow, options);

          case 7:
            session = _context3.sent;
            return _context3.abrupt('return', session);

          case 9:
          case 'end':
            return _context3.stop();
        }
      }
    }, _callee3, this);
  }));

  return function popupLogin(_x5) {
    return _ref3.apply(this, arguments);
  };
}();

var currentSession = exports.currentSession = function () {
  var _ref4 = (0, _asyncToGenerator3.default)( /*#__PURE__*/_regenerator2.default.mark(function _callee4() {
    var storage = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : (0, _storage.defaultStorage)();
    var session;
    return _regenerator2.default.wrap(function _callee4$(_context4) {
      while (1) {
        switch (_context4.prev = _context4.next) {
          case 0:
            _context4.next = 2;
            return (0, _session.getSession)(storage);

          case 2:
            session = _context4.sent;

            if (!session) {
              _context4.next = 5;
              break;
            }

            return _context4.abrupt('return', session);

          case 5:
            return _context4.abrupt('return', firstSession(storage, [WebIdOidc.currentSession.bind(null, storage)]));

          case 6:
          case 'end':
            return _context4.stop();
        }
      }
    }, _callee4, this);
  }));

  return function currentSession() {
    return _ref4.apply(this, arguments);
  };
}();

var logout = exports.logout = function () {
  var _ref5 = (0, _asyncToGenerator3.default)( /*#__PURE__*/_regenerator2.default.mark(function _callee5() {
    var storage = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : (0, _storage.defaultStorage)();
    var session;
    return _regenerator2.default.wrap(function _callee5$(_context5) {
      while (1) {
        switch (_context5.prev = _context5.next) {
          case 0:
            _context5.next = 2;
            return (0, _session.getSession)(storage);

          case 2:
            session = _context5.sent;

            if (session) {
              _context5.next = 5;
              break;
            }

            return _context5.abrupt('return');

          case 5:
            _context5.t0 = session.authType;
            _context5.next = _context5.t0 === 'WebID-OIDC' ? 8 : _context5.t0 === 'WebID-TLS' ? 18 : 18;
            break;

          case 8:
            _context5.prev = 8;
            _context5.next = 11;
            return WebIdOidc.logout(storage, session.idp);

          case 11:
            _context5.next = 17;
            break;

          case 13:
            _context5.prev = 13;
            _context5.t1 = _context5['catch'](8);

            console.warn('Error logging out:');
            console.error(_context5.t1);

          case 17:
            return _context5.abrupt('break', 19);

          case 18:
            return _context5.abrupt('break', 19);

          case 19:
            return _context5.abrupt('return', (0, _session.clearSession)(storage));

          case 20:
          case 'end':
            return _context5.stop();
        }
      }
    }, _callee5, this, [[8, 13]]);
  }));

  return function logout() {
    return _ref5.apply(this, arguments);
  };
}();

var _authnFetch = __webpack_require__(140);

var _popup = __webpack_require__(210);

var _session = __webpack_require__(57);

var _storage = __webpack_require__(37);

var _urlUtil = __webpack_require__(66);

var _webidTls = __webpack_require__(114);

var WebIdTls = _interopRequireWildcard(_webidTls);

var _webidOidc = __webpack_require__(61);

var WebIdOidc = _interopRequireWildcard(_webidOidc);

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

var defaultLoginOptions = function defaultLoginOptions() {
  var url = (0, _urlUtil.currentUrlNoParams)();
  return {
    callbackUri: url ? url.split('#')[0] : null,
    popupUri: null,
    storage: (0, _storage.defaultStorage)()
  };
};
/* global RequestInfo, Response */
var fetch = exports.fetch = function fetch(url, options) {
  return (0, _authnFetch.authnFetch)((0, _storage.defaultStorage)())(url, options);
};

/***/ }),
/* 117 */
/***/ (function(module, exports, __webpack_require__) {

__webpack_require__(118);
module.exports = __webpack_require__(0).Object.assign;


/***/ }),
/* 118 */
/***/ (function(module, exports, __webpack_require__) {

// 19.1.3.1 Object.assign(target, source)
var $export = __webpack_require__(4);

$export($export.S + $export.F, 'Object', { assign: __webpack_require__(119) });


/***/ }),
/* 119 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";

// 19.1.2.1 Object.assign(target, source, ...)
var getKeys = __webpack_require__(24);
var gOPS = __webpack_require__(50);
var pIE = __webpack_require__(33);
var toObject = __webpack_require__(26);
var IObject = __webpack_require__(69);
var $assign = Object.assign;

// should work with symbols and should have deterministic property order (V8 bug)
module.exports = !$assign || __webpack_require__(16)(function () {
  var A = {};
  var B = {};
  // eslint-disable-next-line no-undef
  var S = Symbol();
  var K = 'abcdefghijklmnopqrst';
  A[S] = 7;
  K.split('').forEach(function (k) { B[k] = k; });
  return $assign({}, A)[S] != 7 || Object.keys($assign({}, B)).join('') != K;
}) ? function assign(target, source) { // eslint-disable-line no-unused-vars
  var T = toObject(target);
  var aLen = arguments.length;
  var index = 1;
  var getSymbols = gOPS.f;
  var isEnum = pIE.f;
  while (aLen > index) {
    var S = IObject(arguments[index++]);
    var keys = getSymbols ? getKeys(S).concat(getSymbols(S)) : getKeys(S);
    var length = keys.length;
    var j = 0;
    var key;
    while (length > j) if (isEnum.call(S, key = keys[j++])) T[key] = S[key];
  } return T;
} : $assign;


/***/ }),
/* 120 */
/***/ (function(module, exports, __webpack_require__) {

// false -> Array#indexOf
// true  -> Array#includes
var toIObject = __webpack_require__(17);
var toLength = __webpack_require__(45);
var toAbsoluteIndex = __webpack_require__(121);
module.exports = function (IS_INCLUDES) {
  return function ($this, el, fromIndex) {
    var O = toIObject($this);
    var length = toLength(O.length);
    var index = toAbsoluteIndex(fromIndex, length);
    var value;
    // Array#includes uses SameValueZero equality algorithm
    // eslint-disable-next-line no-self-compare
    if (IS_INCLUDES && el != el) while (length > index) {
      value = O[index++];
      // eslint-disable-next-line no-self-compare
      if (value != value) return true;
    // Array#indexOf ignores holes, Array#includes - not
    } else for (;length > index; index++) if (IS_INCLUDES || index in O) {
      if (O[index] === el) return IS_INCLUDES || index || 0;
    } return !IS_INCLUDES && -1;
  };
};


/***/ }),
/* 121 */
/***/ (function(module, exports, __webpack_require__) {

var toInteger = __webpack_require__(46);
var max = Math.max;
var min = Math.min;
module.exports = function (index, length) {
  index = toInteger(index);
  return index < 0 ? max(index + length, 0) : min(index, length);
};


/***/ }),
/* 122 */
/***/ (function(module, exports, __webpack_require__) {

/**
 * Copyright (c) 2014-present, Facebook, Inc.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

// This method of obtaining a reference to the global object needs to be
// kept identical to the way it is obtained in runtime.js
var g = (function() { return this })() || Function("return this")();

// Use `getOwnPropertyNames` because not all browsers support calling
// `hasOwnProperty` on the global `self` object in a worker. See #183.
var hadRuntime = g.regeneratorRuntime &&
  Object.getOwnPropertyNames(g).indexOf("regeneratorRuntime") >= 0;

// Save the old regeneratorRuntime in case it needs to be restored later.
var oldRuntime = hadRuntime && g.regeneratorRuntime;

// Force reevalutation of runtime.js.
g.regeneratorRuntime = undefined;

module.exports = __webpack_require__(123);

if (hadRuntime) {
  // Restore the original runtime.
  g.regeneratorRuntime = oldRuntime;
} else {
  // Remove the global property added by runtime.js.
  try {
    delete g.regeneratorRuntime;
  } catch(e) {
    g.regeneratorRuntime = undefined;
  }
}


/***/ }),
/* 123 */
/***/ (function(module, exports) {

/**
 * Copyright (c) 2014-present, Facebook, Inc.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

!(function(global) {
  "use strict";

  var Op = Object.prototype;
  var hasOwn = Op.hasOwnProperty;
  var undefined; // More compressible than void 0.
  var $Symbol = typeof Symbol === "function" ? Symbol : {};
  var iteratorSymbol = $Symbol.iterator || "@@iterator";
  var asyncIteratorSymbol = $Symbol.asyncIterator || "@@asyncIterator";
  var toStringTagSymbol = $Symbol.toStringTag || "@@toStringTag";

  var inModule = typeof module === "object";
  var runtime = global.regeneratorRuntime;
  if (runtime) {
    if (inModule) {
      // If regeneratorRuntime is defined globally and we're in a module,
      // make the exports object identical to regeneratorRuntime.
      module.exports = runtime;
    }
    // Don't bother evaluating the rest of this file if the runtime was
    // already defined globally.
    return;
  }

  // Define the runtime globally (as expected by generated code) as either
  // module.exports (if we're in a module) or a new, empty object.
  runtime = global.regeneratorRuntime = inModule ? module.exports : {};

  function wrap(innerFn, outerFn, self, tryLocsList) {
    // If outerFn provided and outerFn.prototype is a Generator, then outerFn.prototype instanceof Generator.
    var protoGenerator = outerFn && outerFn.prototype instanceof Generator ? outerFn : Generator;
    var generator = Object.create(protoGenerator.prototype);
    var context = new Context(tryLocsList || []);

    // The ._invoke method unifies the implementations of the .next,
    // .throw, and .return methods.
    generator._invoke = makeInvokeMethod(innerFn, self, context);

    return generator;
  }
  runtime.wrap = wrap;

  // Try/catch helper to minimize deoptimizations. Returns a completion
  // record like context.tryEntries[i].completion. This interface could
  // have been (and was previously) designed to take a closure to be
  // invoked without arguments, but in all the cases we care about we
  // already have an existing method we want to call, so there's no need
  // to create a new function object. We can even get away with assuming
  // the method takes exactly one argument, since that happens to be true
  // in every case, so we don't have to touch the arguments object. The
  // only additional allocation required is the completion record, which
  // has a stable shape and so hopefully should be cheap to allocate.
  function tryCatch(fn, obj, arg) {
    try {
      return { type: "normal", arg: fn.call(obj, arg) };
    } catch (err) {
      return { type: "throw", arg: err };
    }
  }

  var GenStateSuspendedStart = "suspendedStart";
  var GenStateSuspendedYield = "suspendedYield";
  var GenStateExecuting = "executing";
  var GenStateCompleted = "completed";

  // Returning this object from the innerFn has the same effect as
  // breaking out of the dispatch switch statement.
  var ContinueSentinel = {};

  // Dummy constructor functions that we use as the .constructor and
  // .constructor.prototype properties for functions that return Generator
  // objects. For full spec compliance, you may wish to configure your
  // minifier not to mangle the names of these two functions.
  function Generator() {}
  function GeneratorFunction() {}
  function GeneratorFunctionPrototype() {}

  // This is a polyfill for %IteratorPrototype% for environments that
  // don't natively support it.
  var IteratorPrototype = {};
  IteratorPrototype[iteratorSymbol] = function () {
    return this;
  };

  var getProto = Object.getPrototypeOf;
  var NativeIteratorPrototype = getProto && getProto(getProto(values([])));
  if (NativeIteratorPrototype &&
      NativeIteratorPrototype !== Op &&
      hasOwn.call(NativeIteratorPrototype, iteratorSymbol)) {
    // This environment has a native %IteratorPrototype%; use it instead
    // of the polyfill.
    IteratorPrototype = NativeIteratorPrototype;
  }

  var Gp = GeneratorFunctionPrototype.prototype =
    Generator.prototype = Object.create(IteratorPrototype);
  GeneratorFunction.prototype = Gp.constructor = GeneratorFunctionPrototype;
  GeneratorFunctionPrototype.constructor = GeneratorFunction;
  GeneratorFunctionPrototype[toStringTagSymbol] =
    GeneratorFunction.displayName = "GeneratorFunction";

  // Helper for defining the .next, .throw, and .return methods of the
  // Iterator interface in terms of a single ._invoke method.
  function defineIteratorMethods(prototype) {
    ["next", "throw", "return"].forEach(function(method) {
      prototype[method] = function(arg) {
        return this._invoke(method, arg);
      };
    });
  }

  runtime.isGeneratorFunction = function(genFun) {
    var ctor = typeof genFun === "function" && genFun.constructor;
    return ctor
      ? ctor === GeneratorFunction ||
        // For the native GeneratorFunction constructor, the best we can
        // do is to check its .name property.
        (ctor.displayName || ctor.name) === "GeneratorFunction"
      : false;
  };

  runtime.mark = function(genFun) {
    if (Object.setPrototypeOf) {
      Object.setPrototypeOf(genFun, GeneratorFunctionPrototype);
    } else {
      genFun.__proto__ = GeneratorFunctionPrototype;
      if (!(toStringTagSymbol in genFun)) {
        genFun[toStringTagSymbol] = "GeneratorFunction";
      }
    }
    genFun.prototype = Object.create(Gp);
    return genFun;
  };

  // Within the body of any async function, `await x` is transformed to
  // `yield regeneratorRuntime.awrap(x)`, so that the runtime can test
  // `hasOwn.call(value, "__await")` to determine if the yielded value is
  // meant to be awaited.
  runtime.awrap = function(arg) {
    return { __await: arg };
  };

  function AsyncIterator(generator) {
    function invoke(method, arg, resolve, reject) {
      var record = tryCatch(generator[method], generator, arg);
      if (record.type === "throw") {
        reject(record.arg);
      } else {
        var result = record.arg;
        var value = result.value;
        if (value &&
            typeof value === "object" &&
            hasOwn.call(value, "__await")) {
          return Promise.resolve(value.__await).then(function(value) {
            invoke("next", value, resolve, reject);
          }, function(err) {
            invoke("throw", err, resolve, reject);
          });
        }

        return Promise.resolve(value).then(function(unwrapped) {
          // When a yielded Promise is resolved, its final value becomes
          // the .value of the Promise<{value,done}> result for the
          // current iteration. If the Promise is rejected, however, the
          // result for this iteration will be rejected with the same
          // reason. Note that rejections of yielded Promises are not
          // thrown back into the generator function, as is the case
          // when an awaited Promise is rejected. This difference in
          // behavior between yield and await is important, because it
          // allows the consumer to decide what to do with the yielded
          // rejection (swallow it and continue, manually .throw it back
          // into the generator, abandon iteration, whatever). With
          // await, by contrast, there is no opportunity to examine the
          // rejection reason outside the generator function, so the
          // only option is to throw it from the await expression, and
          // let the generator function handle the exception.
          result.value = unwrapped;
          resolve(result);
        }, reject);
      }
    }

    var previousPromise;

    function enqueue(method, arg) {
      function callInvokeWithMethodAndArg() {
        return new Promise(function(resolve, reject) {
          invoke(method, arg, resolve, reject);
        });
      }

      return previousPromise =
        // If enqueue has been called before, then we want to wait until
        // all previous Promises have been resolved before calling invoke,
        // so that results are always delivered in the correct order. If
        // enqueue has not been called before, then it is important to
        // call invoke immediately, without waiting on a callback to fire,
        // so that the async generator function has the opportunity to do
        // any necessary setup in a predictable way. This predictability
        // is why the Promise constructor synchronously invokes its
        // executor callback, and why async functions synchronously
        // execute code before the first await. Since we implement simple
        // async functions in terms of async generators, it is especially
        // important to get this right, even though it requires care.
        previousPromise ? previousPromise.then(
          callInvokeWithMethodAndArg,
          // Avoid propagating failures to Promises returned by later
          // invocations of the iterator.
          callInvokeWithMethodAndArg
        ) : callInvokeWithMethodAndArg();
    }

    // Define the unified helper method that is used to implement .next,
    // .throw, and .return (see defineIteratorMethods).
    this._invoke = enqueue;
  }

  defineIteratorMethods(AsyncIterator.prototype);
  AsyncIterator.prototype[asyncIteratorSymbol] = function () {
    return this;
  };
  runtime.AsyncIterator = AsyncIterator;

  // Note that simple async functions are implemented on top of
  // AsyncIterator objects; they just return a Promise for the value of
  // the final result produced by the iterator.
  runtime.async = function(innerFn, outerFn, self, tryLocsList) {
    var iter = new AsyncIterator(
      wrap(innerFn, outerFn, self, tryLocsList)
    );

    return runtime.isGeneratorFunction(outerFn)
      ? iter // If outerFn is a generator, return the full iterator.
      : iter.next().then(function(result) {
          return result.done ? result.value : iter.next();
        });
  };

  function makeInvokeMethod(innerFn, self, context) {
    var state = GenStateSuspendedStart;

    return function invoke(method, arg) {
      if (state === GenStateExecuting) {
        throw new Error("Generator is already running");
      }

      if (state === GenStateCompleted) {
        if (method === "throw") {
          throw arg;
        }

        // Be forgiving, per 25.3.3.3.3 of the spec:
        // https://people.mozilla.org/~jorendorff/es6-draft.html#sec-generatorresume
        return doneResult();
      }

      context.method = method;
      context.arg = arg;

      while (true) {
        var delegate = context.delegate;
        if (delegate) {
          var delegateResult = maybeInvokeDelegate(delegate, context);
          if (delegateResult) {
            if (delegateResult === ContinueSentinel) continue;
            return delegateResult;
          }
        }

        if (context.method === "next") {
          // Setting context._sent for legacy support of Babel's
          // function.sent implementation.
          context.sent = context._sent = context.arg;

        } else if (context.method === "throw") {
          if (state === GenStateSuspendedStart) {
            state = GenStateCompleted;
            throw context.arg;
          }

          context.dispatchException(context.arg);

        } else if (context.method === "return") {
          context.abrupt("return", context.arg);
        }

        state = GenStateExecuting;

        var record = tryCatch(innerFn, self, context);
        if (record.type === "normal") {
          // If an exception is thrown from innerFn, we leave state ===
          // GenStateExecuting and loop back for another invocation.
          state = context.done
            ? GenStateCompleted
            : GenStateSuspendedYield;

          if (record.arg === ContinueSentinel) {
            continue;
          }

          return {
            value: record.arg,
            done: context.done
          };

        } else if (record.type === "throw") {
          state = GenStateCompleted;
          // Dispatch the exception by looping back around to the
          // context.dispatchException(context.arg) call above.
          context.method = "throw";
          context.arg = record.arg;
        }
      }
    };
  }

  // Call delegate.iterator[context.method](context.arg) and handle the
  // result, either by returning a { value, done } result from the
  // delegate iterator, or by modifying context.method and context.arg,
  // setting context.delegate to null, and returning the ContinueSentinel.
  function maybeInvokeDelegate(delegate, context) {
    var method = delegate.iterator[context.method];
    if (method === undefined) {
      // A .throw or .return when the delegate iterator has no .throw
      // method always terminates the yield* loop.
      context.delegate = null;

      if (context.method === "throw") {
        if (delegate.iterator.return) {
          // If the delegate iterator has a return method, give it a
          // chance to clean up.
          context.method = "return";
          context.arg = undefined;
          maybeInvokeDelegate(delegate, context);

          if (context.method === "throw") {
            // If maybeInvokeDelegate(context) changed context.method from
            // "return" to "throw", let that override the TypeError below.
            return ContinueSentinel;
          }
        }

        context.method = "throw";
        context.arg = new TypeError(
          "The iterator does not provide a 'throw' method");
      }

      return ContinueSentinel;
    }

    var record = tryCatch(method, delegate.iterator, context.arg);

    if (record.type === "throw") {
      context.method = "throw";
      context.arg = record.arg;
      context.delegate = null;
      return ContinueSentinel;
    }

    var info = record.arg;

    if (! info) {
      context.method = "throw";
      context.arg = new TypeError("iterator result is not an object");
      context.delegate = null;
      return ContinueSentinel;
    }

    if (info.done) {
      // Assign the result of the finished delegate to the temporary
      // variable specified by delegate.resultName (see delegateYield).
      context[delegate.resultName] = info.value;

      // Resume execution at the desired location (see delegateYield).
      context.next = delegate.nextLoc;

      // If context.method was "throw" but the delegate handled the
      // exception, let the outer generator proceed normally. If
      // context.method was "next", forget context.arg since it has been
      // "consumed" by the delegate iterator. If context.method was
      // "return", allow the original .return call to continue in the
      // outer generator.
      if (context.method !== "return") {
        context.method = "next";
        context.arg = undefined;
      }

    } else {
      // Re-yield the result returned by the delegate method.
      return info;
    }

    // The delegate iterator is finished, so forget it and continue with
    // the outer generator.
    context.delegate = null;
    return ContinueSentinel;
  }

  // Define Generator.prototype.{next,throw,return} in terms of the
  // unified ._invoke helper method.
  defineIteratorMethods(Gp);

  Gp[toStringTagSymbol] = "Generator";

  // A Generator should always return itself as the iterator object when the
  // @@iterator function is called on it. Some browsers' implementations of the
  // iterator prototype chain incorrectly implement this, causing the Generator
  // object to not be returned from this call. This ensures that doesn't happen.
  // See https://github.com/facebook/regenerator/issues/274 for more details.
  Gp[iteratorSymbol] = function() {
    return this;
  };

  Gp.toString = function() {
    return "[object Generator]";
  };

  function pushTryEntry(locs) {
    var entry = { tryLoc: locs[0] };

    if (1 in locs) {
      entry.catchLoc = locs[1];
    }

    if (2 in locs) {
      entry.finallyLoc = locs[2];
      entry.afterLoc = locs[3];
    }

    this.tryEntries.push(entry);
  }

  function resetTryEntry(entry) {
    var record = entry.completion || {};
    record.type = "normal";
    delete record.arg;
    entry.completion = record;
  }

  function Context(tryLocsList) {
    // The root entry object (effectively a try statement without a catch
    // or a finally block) gives us a place to store values thrown from
    // locations where there is no enclosing try statement.
    this.tryEntries = [{ tryLoc: "root" }];
    tryLocsList.forEach(pushTryEntry, this);
    this.reset(true);
  }

  runtime.keys = function(object) {
    var keys = [];
    for (var key in object) {
      keys.push(key);
    }
    keys.reverse();

    // Rather than returning an object with a next method, we keep
    // things simple and return the next function itself.
    return function next() {
      while (keys.length) {
        var key = keys.pop();
        if (key in object) {
          next.value = key;
          next.done = false;
          return next;
        }
      }

      // To avoid creating an additional object, we just hang the .value
      // and .done properties off the next function object itself. This
      // also ensures that the minifier will not anonymize the function.
      next.done = true;
      return next;
    };
  };

  function values(iterable) {
    if (iterable) {
      var iteratorMethod = iterable[iteratorSymbol];
      if (iteratorMethod) {
        return iteratorMethod.call(iterable);
      }

      if (typeof iterable.next === "function") {
        return iterable;
      }

      if (!isNaN(iterable.length)) {
        var i = -1, next = function next() {
          while (++i < iterable.length) {
            if (hasOwn.call(iterable, i)) {
              next.value = iterable[i];
              next.done = false;
              return next;
            }
          }

          next.value = undefined;
          next.done = true;

          return next;
        };

        return next.next = next;
      }
    }

    // Return an iterator with no values.
    return { next: doneResult };
  }
  runtime.values = values;

  function doneResult() {
    return { value: undefined, done: true };
  }

  Context.prototype = {
    constructor: Context,

    reset: function(skipTempReset) {
      this.prev = 0;
      this.next = 0;
      // Resetting context._sent for legacy support of Babel's
      // function.sent implementation.
      this.sent = this._sent = undefined;
      this.done = false;
      this.delegate = null;

      this.method = "next";
      this.arg = undefined;

      this.tryEntries.forEach(resetTryEntry);

      if (!skipTempReset) {
        for (var name in this) {
          // Not sure about the optimal order of these conditions:
          if (name.charAt(0) === "t" &&
              hasOwn.call(this, name) &&
              !isNaN(+name.slice(1))) {
            this[name] = undefined;
          }
        }
      }
    },

    stop: function() {
      this.done = true;

      var rootEntry = this.tryEntries[0];
      var rootRecord = rootEntry.completion;
      if (rootRecord.type === "throw") {
        throw rootRecord.arg;
      }

      return this.rval;
    },

    dispatchException: function(exception) {
      if (this.done) {
        throw exception;
      }

      var context = this;
      function handle(loc, caught) {
        record.type = "throw";
        record.arg = exception;
        context.next = loc;

        if (caught) {
          // If the dispatched exception was caught by a catch block,
          // then let that catch block handle the exception normally.
          context.method = "next";
          context.arg = undefined;
        }

        return !! caught;
      }

      for (var i = this.tryEntries.length - 1; i >= 0; --i) {
        var entry = this.tryEntries[i];
        var record = entry.completion;

        if (entry.tryLoc === "root") {
          // Exception thrown outside of any try block that could handle
          // it, so set the completion value of the entire function to
          // throw the exception.
          return handle("end");
        }

        if (entry.tryLoc <= this.prev) {
          var hasCatch = hasOwn.call(entry, "catchLoc");
          var hasFinally = hasOwn.call(entry, "finallyLoc");

          if (hasCatch && hasFinally) {
            if (this.prev < entry.catchLoc) {
              return handle(entry.catchLoc, true);
            } else if (this.prev < entry.finallyLoc) {
              return handle(entry.finallyLoc);
            }

          } else if (hasCatch) {
            if (this.prev < entry.catchLoc) {
              return handle(entry.catchLoc, true);
            }

          } else if (hasFinally) {
            if (this.prev < entry.finallyLoc) {
              return handle(entry.finallyLoc);
            }

          } else {
            throw new Error("try statement without catch or finally");
          }
        }
      }
    },

    abrupt: function(type, arg) {
      for (var i = this.tryEntries.length - 1; i >= 0; --i) {
        var entry = this.tryEntries[i];
        if (entry.tryLoc <= this.prev &&
            hasOwn.call(entry, "finallyLoc") &&
            this.prev < entry.finallyLoc) {
          var finallyEntry = entry;
          break;
        }
      }

      if (finallyEntry &&
          (type === "break" ||
           type === "continue") &&
          finallyEntry.tryLoc <= arg &&
          arg <= finallyEntry.finallyLoc) {
        // Ignore the finally entry if control is not jumping to a
        // location outside the try/catch block.
        finallyEntry = null;
      }

      var record = finallyEntry ? finallyEntry.completion : {};
      record.type = type;
      record.arg = arg;

      if (finallyEntry) {
        this.method = "next";
        this.next = finallyEntry.finallyLoc;
        return ContinueSentinel;
      }

      return this.complete(record);
    },

    complete: function(record, afterLoc) {
      if (record.type === "throw") {
        throw record.arg;
      }

      if (record.type === "break" ||
          record.type === "continue") {
        this.next = record.arg;
      } else if (record.type === "return") {
        this.rval = this.arg = record.arg;
        this.method = "return";
        this.next = "end";
      } else if (record.type === "normal" && afterLoc) {
        this.next = afterLoc;
      }

      return ContinueSentinel;
    },

    finish: function(finallyLoc) {
      for (var i = this.tryEntries.length - 1; i >= 0; --i) {
        var entry = this.tryEntries[i];
        if (entry.finallyLoc === finallyLoc) {
          this.complete(entry.completion, entry.afterLoc);
          resetTryEntry(entry);
          return ContinueSentinel;
        }
      }
    },

    "catch": function(tryLoc) {
      for (var i = this.tryEntries.length - 1; i >= 0; --i) {
        var entry = this.tryEntries[i];
        if (entry.tryLoc === tryLoc) {
          var record = entry.completion;
          if (record.type === "throw") {
            var thrown = record.arg;
            resetTryEntry(entry);
          }
          return thrown;
        }
      }

      // The context.catch method must only be called with a location
      // argument that corresponds to a known catch block.
      throw new Error("illegal catch attempt");
    },

    delegateYield: function(iterable, resultName, nextLoc) {
      this.delegate = {
        iterator: values(iterable),
        resultName: resultName,
        nextLoc: nextLoc
      };

      if (this.method === "next") {
        // Deliberately forget the last sent value so that we don't
        // accidentally pass it on to the delegate.
        this.arg = undefined;
      }

      return ContinueSentinel;
    }
  };
})(
  // In sloppy mode, unbound `this` refers to the global object, fallback to
  // Function constructor if we're in global strict mode. That is sadly a form
  // of indirect eval which violates Content Security Policy.
  (function() { return this })() || Function("return this")()
);


/***/ }),
/* 124 */
/***/ (function(module, exports, __webpack_require__) {

__webpack_require__(70);
__webpack_require__(27);
__webpack_require__(36);
__webpack_require__(131);
__webpack_require__(138);
__webpack_require__(139);
module.exports = __webpack_require__(0).Promise;


/***/ }),
/* 125 */
/***/ (function(module, exports, __webpack_require__) {

var toInteger = __webpack_require__(46);
var defined = __webpack_require__(44);
// true  -> String#at
// false -> String#codePointAt
module.exports = function (TO_STRING) {
  return function (that, pos) {
    var s = String(defined(that));
    var i = toInteger(pos);
    var l = s.length;
    var a, b;
    if (i < 0 || i >= l) return TO_STRING ? '' : undefined;
    a = s.charCodeAt(i);
    return a < 0xd800 || a > 0xdbff || i + 1 === l || (b = s.charCodeAt(i + 1)) < 0xdc00 || b > 0xdfff
      ? TO_STRING ? s.charAt(i) : a
      : TO_STRING ? s.slice(i, i + 2) : (a - 0xd800 << 10) + (b - 0xdc00) + 0x10000;
  };
};


/***/ }),
/* 126 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";

var create = __webpack_require__(51);
var descriptor = __webpack_require__(23);
var setToStringTag = __webpack_require__(35);
var IteratorPrototype = {};

// 25.1.2.1.1 %IteratorPrototype%[@@iterator]()
__webpack_require__(9)(IteratorPrototype, __webpack_require__(1)('iterator'), function () { return this; });

module.exports = function (Constructor, NAME, next) {
  Constructor.prototype = create(IteratorPrototype, { next: descriptor(1, next) });
  setToStringTag(Constructor, NAME + ' Iterator');
};


/***/ }),
/* 127 */
/***/ (function(module, exports, __webpack_require__) {

var dP = __webpack_require__(6);
var anObject = __webpack_require__(5);
var getKeys = __webpack_require__(24);

module.exports = __webpack_require__(8) ? Object.defineProperties : function defineProperties(O, Properties) {
  anObject(O);
  var keys = getKeys(Properties);
  var length = keys.length;
  var i = 0;
  var P;
  while (length > i) dP.f(O, P = keys[i++], Properties[P]);
  return O;
};


/***/ }),
/* 128 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";

var addToUnscopables = __webpack_require__(129);
var step = __webpack_require__(130);
var Iterators = __webpack_require__(18);
var toIObject = __webpack_require__(17);

// 22.1.3.4 Array.prototype.entries()
// 22.1.3.13 Array.prototype.keys()
// 22.1.3.29 Array.prototype.values()
// 22.1.3.30 Array.prototype[@@iterator]()
module.exports = __webpack_require__(71)(Array, 'Array', function (iterated, kind) {
  this._t = toIObject(iterated); // target
  this._i = 0;                   // next index
  this._k = kind;                // kind
// 22.1.5.2.1 %ArrayIteratorPrototype%.next()
}, function () {
  var O = this._t;
  var kind = this._k;
  var index = this._i++;
  if (!O || index >= O.length) {
    this._t = undefined;
    return step(1);
  }
  if (kind == 'keys') return step(0, index);
  if (kind == 'values') return step(0, O[index]);
  return step(0, [index, O[index]]);
}, 'values');

// argumentsList[@@iterator] is %ArrayProto_values% (9.4.4.6, 9.4.4.7)
Iterators.Arguments = Iterators.Array;

addToUnscopables('keys');
addToUnscopables('values');
addToUnscopables('entries');


/***/ }),
/* 129 */
/***/ (function(module, exports) {

module.exports = function () { /* empty */ };


/***/ }),
/* 130 */
/***/ (function(module, exports) {

module.exports = function (done, value) {
  return { value: value, done: !!done };
};


/***/ }),
/* 131 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";

var LIBRARY = __webpack_require__(34);
var global = __webpack_require__(2);
var ctx = __webpack_require__(15);
var classof = __webpack_require__(52);
var $export = __webpack_require__(4);
var isObject = __webpack_require__(7);
var aFunction = __webpack_require__(31);
var anInstance = __webpack_require__(132);
var forOf = __webpack_require__(133);
var speciesConstructor = __webpack_require__(77);
var task = __webpack_require__(78).set;
var microtask = __webpack_require__(135)();
var newPromiseCapabilityModule = __webpack_require__(54);
var perform = __webpack_require__(79);
var promiseResolve = __webpack_require__(80);
var PROMISE = 'Promise';
var TypeError = global.TypeError;
var process = global.process;
var $Promise = global[PROMISE];
var isNode = classof(process) == 'process';
var empty = function () { /* empty */ };
var Internal, newGenericPromiseCapability, OwnPromiseCapability, Wrapper;
var newPromiseCapability = newGenericPromiseCapability = newPromiseCapabilityModule.f;

var USE_NATIVE = !!function () {
  try {
    // correct subclassing with @@species support
    var promise = $Promise.resolve(1);
    var FakePromise = (promise.constructor = {})[__webpack_require__(1)('species')] = function (exec) {
      exec(empty, empty);
    };
    // unhandled rejections tracking support, NodeJS Promise without it fails @@species test
    return (isNode || typeof PromiseRejectionEvent == 'function') && promise.then(empty) instanceof FakePromise;
  } catch (e) { /* empty */ }
}();

// helpers
var isThenable = function (it) {
  var then;
  return isObject(it) && typeof (then = it.then) == 'function' ? then : false;
};
var notify = function (promise, isReject) {
  if (promise._n) return;
  promise._n = true;
  var chain = promise._c;
  microtask(function () {
    var value = promise._v;
    var ok = promise._s == 1;
    var i = 0;
    var run = function (reaction) {
      var handler = ok ? reaction.ok : reaction.fail;
      var resolve = reaction.resolve;
      var reject = reaction.reject;
      var domain = reaction.domain;
      var result, then, exited;
      try {
        if (handler) {
          if (!ok) {
            if (promise._h == 2) onHandleUnhandled(promise);
            promise._h = 1;
          }
          if (handler === true) result = value;
          else {
            if (domain) domain.enter();
            result = handler(value); // may throw
            if (domain) {
              domain.exit();
              exited = true;
            }
          }
          if (result === reaction.promise) {
            reject(TypeError('Promise-chain cycle'));
          } else if (then = isThenable(result)) {
            then.call(result, resolve, reject);
          } else resolve(result);
        } else reject(value);
      } catch (e) {
        if (domain && !exited) domain.exit();
        reject(e);
      }
    };
    while (chain.length > i) run(chain[i++]); // variable length - can't use forEach
    promise._c = [];
    promise._n = false;
    if (isReject && !promise._h) onUnhandled(promise);
  });
};
var onUnhandled = function (promise) {
  task.call(global, function () {
    var value = promise._v;
    var unhandled = isUnhandled(promise);
    var result, handler, console;
    if (unhandled) {
      result = perform(function () {
        if (isNode) {
          process.emit('unhandledRejection', value, promise);
        } else if (handler = global.onunhandledrejection) {
          handler({ promise: promise, reason: value });
        } else if ((console = global.console) && console.error) {
          console.error('Unhandled promise rejection', value);
        }
      });
      // Browsers should not trigger `rejectionHandled` event if it was handled here, NodeJS - should
      promise._h = isNode || isUnhandled(promise) ? 2 : 1;
    } promise._a = undefined;
    if (unhandled && result.e) throw result.v;
  });
};
var isUnhandled = function (promise) {
  return promise._h !== 1 && (promise._a || promise._c).length === 0;
};
var onHandleUnhandled = function (promise) {
  task.call(global, function () {
    var handler;
    if (isNode) {
      process.emit('rejectionHandled', promise);
    } else if (handler = global.onrejectionhandled) {
      handler({ promise: promise, reason: promise._v });
    }
  });
};
var $reject = function (value) {
  var promise = this;
  if (promise._d) return;
  promise._d = true;
  promise = promise._w || promise; // unwrap
  promise._v = value;
  promise._s = 2;
  if (!promise._a) promise._a = promise._c.slice();
  notify(promise, true);
};
var $resolve = function (value) {
  var promise = this;
  var then;
  if (promise._d) return;
  promise._d = true;
  promise = promise._w || promise; // unwrap
  try {
    if (promise === value) throw TypeError("Promise can't be resolved itself");
    if (then = isThenable(value)) {
      microtask(function () {
        var wrapper = { _w: promise, _d: false }; // wrap
        try {
          then.call(value, ctx($resolve, wrapper, 1), ctx($reject, wrapper, 1));
        } catch (e) {
          $reject.call(wrapper, e);
        }
      });
    } else {
      promise._v = value;
      promise._s = 1;
      notify(promise, false);
    }
  } catch (e) {
    $reject.call({ _w: promise, _d: false }, e); // wrap
  }
};

// constructor polyfill
if (!USE_NATIVE) {
  // 25.4.3.1 Promise(executor)
  $Promise = function Promise(executor) {
    anInstance(this, $Promise, PROMISE, '_h');
    aFunction(executor);
    Internal.call(this);
    try {
      executor(ctx($resolve, this, 1), ctx($reject, this, 1));
    } catch (err) {
      $reject.call(this, err);
    }
  };
  // eslint-disable-next-line no-unused-vars
  Internal = function Promise(executor) {
    this._c = [];             // <- awaiting reactions
    this._a = undefined;      // <- checked in isUnhandled reactions
    this._s = 0;              // <- state
    this._d = false;          // <- done
    this._v = undefined;      // <- value
    this._h = 0;              // <- rejection state, 0 - default, 1 - handled, 2 - unhandled
    this._n = false;          // <- notify
  };
  Internal.prototype = __webpack_require__(136)($Promise.prototype, {
    // 25.4.5.3 Promise.prototype.then(onFulfilled, onRejected)
    then: function then(onFulfilled, onRejected) {
      var reaction = newPromiseCapability(speciesConstructor(this, $Promise));
      reaction.ok = typeof onFulfilled == 'function' ? onFulfilled : true;
      reaction.fail = typeof onRejected == 'function' && onRejected;
      reaction.domain = isNode ? process.domain : undefined;
      this._c.push(reaction);
      if (this._a) this._a.push(reaction);
      if (this._s) notify(this, false);
      return reaction.promise;
    },
    // 25.4.5.1 Promise.prototype.catch(onRejected)
    'catch': function (onRejected) {
      return this.then(undefined, onRejected);
    }
  });
  OwnPromiseCapability = function () {
    var promise = new Internal();
    this.promise = promise;
    this.resolve = ctx($resolve, promise, 1);
    this.reject = ctx($reject, promise, 1);
  };
  newPromiseCapabilityModule.f = newPromiseCapability = function (C) {
    return C === $Promise || C === Wrapper
      ? new OwnPromiseCapability(C)
      : newGenericPromiseCapability(C);
  };
}

$export($export.G + $export.W + $export.F * !USE_NATIVE, { Promise: $Promise });
__webpack_require__(35)($Promise, PROMISE);
__webpack_require__(137)(PROMISE);
Wrapper = __webpack_require__(0)[PROMISE];

// statics
$export($export.S + $export.F * !USE_NATIVE, PROMISE, {
  // 25.4.4.5 Promise.reject(r)
  reject: function reject(r) {
    var capability = newPromiseCapability(this);
    var $$reject = capability.reject;
    $$reject(r);
    return capability.promise;
  }
});
$export($export.S + $export.F * (LIBRARY || !USE_NATIVE), PROMISE, {
  // 25.4.4.6 Promise.resolve(x)
  resolve: function resolve(x) {
    return promiseResolve(LIBRARY && this === Wrapper ? $Promise : this, x);
  }
});
$export($export.S + $export.F * !(USE_NATIVE && __webpack_require__(81)(function (iter) {
  $Promise.all(iter)['catch'](empty);
})), PROMISE, {
  // 25.4.4.1 Promise.all(iterable)
  all: function all(iterable) {
    var C = this;
    var capability = newPromiseCapability(C);
    var resolve = capability.resolve;
    var reject = capability.reject;
    var result = perform(function () {
      var values = [];
      var index = 0;
      var remaining = 1;
      forOf(iterable, false, function (promise) {
        var $index = index++;
        var alreadyCalled = false;
        values.push(undefined);
        remaining++;
        C.resolve(promise).then(function (value) {
          if (alreadyCalled) return;
          alreadyCalled = true;
          values[$index] = value;
          --remaining || resolve(values);
        }, reject);
      });
      --remaining || resolve(values);
    });
    if (result.e) reject(result.v);
    return capability.promise;
  },
  // 25.4.4.4 Promise.race(iterable)
  race: function race(iterable) {
    var C = this;
    var capability = newPromiseCapability(C);
    var reject = capability.reject;
    var result = perform(function () {
      forOf(iterable, false, function (promise) {
        C.resolve(promise).then(capability.resolve, reject);
      });
    });
    if (result.e) reject(result.v);
    return capability.promise;
  }
});


/***/ }),
/* 132 */
/***/ (function(module, exports) {

module.exports = function (it, Constructor, name, forbiddenField) {
  if (!(it instanceof Constructor) || (forbiddenField !== undefined && forbiddenField in it)) {
    throw TypeError(name + ': incorrect invocation!');
  } return it;
};


/***/ }),
/* 133 */
/***/ (function(module, exports, __webpack_require__) {

var ctx = __webpack_require__(15);
var call = __webpack_require__(75);
var isArrayIter = __webpack_require__(76);
var anObject = __webpack_require__(5);
var toLength = __webpack_require__(45);
var getIterFn = __webpack_require__(53);
var BREAK = {};
var RETURN = {};
var exports = module.exports = function (iterable, entries, fn, that, ITERATOR) {
  var iterFn = ITERATOR ? function () { return iterable; } : getIterFn(iterable);
  var f = ctx(fn, that, entries ? 2 : 1);
  var index = 0;
  var length, step, iterator, result;
  if (typeof iterFn != 'function') throw TypeError(iterable + ' is not iterable!');
  // fast case for arrays with default iterator
  if (isArrayIter(iterFn)) for (length = toLength(iterable.length); length > index; index++) {
    result = entries ? f(anObject(step = iterable[index])[0], step[1]) : f(iterable[index]);
    if (result === BREAK || result === RETURN) return result;
  } else for (iterator = iterFn.call(iterable); !(step = iterator.next()).done;) {
    result = call(iterator, f, step.value, entries);
    if (result === BREAK || result === RETURN) return result;
  }
};
exports.BREAK = BREAK;
exports.RETURN = RETURN;


/***/ }),
/* 134 */
/***/ (function(module, exports) {

// fast apply, http://jsperf.lnkit.com/fast-apply/5
module.exports = function (fn, args, that) {
  var un = that === undefined;
  switch (args.length) {
    case 0: return un ? fn()
                      : fn.call(that);
    case 1: return un ? fn(args[0])
                      : fn.call(that, args[0]);
    case 2: return un ? fn(args[0], args[1])
                      : fn.call(that, args[0], args[1]);
    case 3: return un ? fn(args[0], args[1], args[2])
                      : fn.call(that, args[0], args[1], args[2]);
    case 4: return un ? fn(args[0], args[1], args[2], args[3])
                      : fn.call(that, args[0], args[1], args[2], args[3]);
  } return fn.apply(that, args);
};


/***/ }),
/* 135 */
/***/ (function(module, exports, __webpack_require__) {

var global = __webpack_require__(2);
var macrotask = __webpack_require__(78).set;
var Observer = global.MutationObserver || global.WebKitMutationObserver;
var process = global.process;
var Promise = global.Promise;
var isNode = __webpack_require__(25)(process) == 'process';

module.exports = function () {
  var head, last, notify;

  var flush = function () {
    var parent, fn;
    if (isNode && (parent = process.domain)) parent.exit();
    while (head) {
      fn = head.fn;
      head = head.next;
      try {
        fn();
      } catch (e) {
        if (head) notify();
        else last = undefined;
        throw e;
      }
    } last = undefined;
    if (parent) parent.enter();
  };

  // Node.js
  if (isNode) {
    notify = function () {
      process.nextTick(flush);
    };
  // browsers with MutationObserver, except iOS Safari - https://github.com/zloirock/core-js/issues/339
  } else if (Observer && !(global.navigator && global.navigator.standalone)) {
    var toggle = true;
    var node = document.createTextNode('');
    new Observer(flush).observe(node, { characterData: true }); // eslint-disable-line no-new
    notify = function () {
      node.data = toggle = !toggle;
    };
  // environments with maybe non-completely correct, but existent Promise
  } else if (Promise && Promise.resolve) {
    var promise = Promise.resolve();
    notify = function () {
      promise.then(flush);
    };
  // for other environments - macrotask based on:
  // - setImmediate
  // - MessageChannel
  // - window.postMessag
  // - onreadystatechange
  // - setTimeout
  } else {
    notify = function () {
      // strange IE + webpack dev server bug - use .call(global)
      macrotask.call(global, flush);
    };
  }

  return function (fn) {
    var task = { fn: fn, next: undefined };
    if (last) last.next = task;
    if (!head) {
      head = task;
      notify();
    } last = task;
  };
};


/***/ }),
/* 136 */
/***/ (function(module, exports, __webpack_require__) {

var hide = __webpack_require__(9);
module.exports = function (target, src, safe) {
  for (var key in src) {
    if (safe && target[key]) target[key] = src[key];
    else hide(target, key, src[key]);
  } return target;
};


/***/ }),
/* 137 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";

var global = __webpack_require__(2);
var core = __webpack_require__(0);
var dP = __webpack_require__(6);
var DESCRIPTORS = __webpack_require__(8);
var SPECIES = __webpack_require__(1)('species');

module.exports = function (KEY) {
  var C = typeof core[KEY] == 'function' ? core[KEY] : global[KEY];
  if (DESCRIPTORS && C && !C[SPECIES]) dP.f(C, SPECIES, {
    configurable: true,
    get: function () { return this; }
  });
};


/***/ }),
/* 138 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";
// https://github.com/tc39/proposal-promise-finally

var $export = __webpack_require__(4);
var core = __webpack_require__(0);
var global = __webpack_require__(2);
var speciesConstructor = __webpack_require__(77);
var promiseResolve = __webpack_require__(80);

$export($export.P + $export.R, 'Promise', { 'finally': function (onFinally) {
  var C = speciesConstructor(this, core.Promise || global.Promise);
  var isFunction = typeof onFinally == 'function';
  return this.then(
    isFunction ? function (x) {
      return promiseResolve(C, onFinally()).then(function () { return x; });
    } : onFinally,
    isFunction ? function (e) {
      return promiseResolve(C, onFinally()).then(function () { throw e; });
    } : onFinally
  );
} });


/***/ }),
/* 139 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";

// https://github.com/tc39/proposal-promise-try
var $export = __webpack_require__(4);
var newPromiseCapability = __webpack_require__(54);
var perform = __webpack_require__(79);

$export($export.S, 'Promise', { 'try': function (callbackfn) {
  var promiseCapability = newPromiseCapability.f(this);
  var result = perform(callbackfn);
  (result.e ? promiseCapability.reject : promiseCapability.resolve)(result.v);
  return promiseCapability.promise;
} });


/***/ }),
/* 140 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


Object.defineProperty(exports, "__esModule", {
  value: true
});

var _regenerator = __webpack_require__(11);

var _regenerator2 = _interopRequireDefault(_regenerator);

var _asyncToGenerator2 = __webpack_require__(12);

var _asyncToGenerator3 = _interopRequireDefault(_asyncToGenerator2);

exports.authnFetch = authnFetch;

__webpack_require__(55);

var _host = __webpack_require__(142);

var _session = __webpack_require__(57);

var _webidOidc = __webpack_require__(61);

var WebIdOidc = _interopRequireWildcard(_webidOidc);

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/* global fetch, RequestInfo, Response */
function authnFetch(storage) {
  var _this = this;

  return function () {
    var _ref = (0, _asyncToGenerator3.default)( /*#__PURE__*/_regenerator2.default.mark(function _callee(url, options) {
      var session, shouldShareCreds, resp, _shouldShareCreds;

      return _regenerator2.default.wrap(function _callee$(_context) {
        while (1) {
          switch (_context.prev = _context.next) {
            case 0:
              options = options || {};
              _context.next = 3;
              return (0, _session.getSession)(storage);

            case 3:
              session = _context.sent;
              _context.next = 6;
              return shouldShareCredentials(storage)(url);

            case 6:
              shouldShareCreds = _context.sent;

              if (!(session && shouldShareCreds)) {
                _context.next = 9;
                break;
              }

              return _context.abrupt('return', fetchWithCredentials(session, url, options));

            case 9:
              _context.next = 11;
              return fetch(url, options);

            case 11:
              resp = _context.sent;

              if (!(resp.status === 401)) {
                _context.next = 20;
                break;
              }

              _context.next = 15;
              return (0, _host.updateHostFromResponse)(storage)(resp);

            case 15:
              _context.next = 17;
              return shouldShareCredentials(storage)(url);

            case 17:
              _shouldShareCreds = _context.sent;

              if (!(session && _shouldShareCreds)) {
                _context.next = 20;
                break;
              }

              return _context.abrupt('return', fetchWithCredentials(session, url, options));

            case 20:
              return _context.abrupt('return', resp);

            case 21:
            case 'end':
              return _context.stop();
          }
        }
      }, _callee, _this);
    }));

    return function (_x, _x2) {
      return _ref.apply(this, arguments);
    };
  }();
}

function shouldShareCredentials(storage) {
  var _this2 = this;

  return function () {
    var _ref2 = (0, _asyncToGenerator3.default)( /*#__PURE__*/_regenerator2.default.mark(function _callee2(url) {
      var session, requestHost;
      return _regenerator2.default.wrap(function _callee2$(_context2) {
        while (1) {
          switch (_context2.prev = _context2.next) {
            case 0:
              _context2.next = 2;
              return (0, _session.getSession)(storage);

            case 2:
              session = _context2.sent;

              if (session) {
                _context2.next = 5;
                break;
              }

              return _context2.abrupt('return', false);

            case 5:
              _context2.next = 7;
              return (0, _host.getHost)(storage)(url);

            case 7:
              requestHost = _context2.sent;
              return _context2.abrupt('return', requestHost != null && session.authType === requestHost.authType);

            case 9:
            case 'end':
              return _context2.stop();
          }
        }
      }, _callee2, _this2);
    }));

    return function (_x3) {
      return _ref2.apply(this, arguments);
    };
  }();
}

var fetchWithCredentials = function () {
  var _ref3 = (0, _asyncToGenerator3.default)( /*#__PURE__*/_regenerator2.default.mark(function _callee3(session, url, options) {
    return _regenerator2.default.wrap(function _callee3$(_context3) {
      while (1) {
        switch (_context3.prev = _context3.next) {
          case 0:
            _context3.t0 = session.authType;
            _context3.next = _context3.t0 === 'WebID-OIDC' ? 3 : _context3.t0 === 'WebID-TLS' ? 4 : 4;
            break;

          case 3:
            return _context3.abrupt('return', WebIdOidc.fetchWithCredentials(session)(url, options));

          case 4:
            return _context3.abrupt('return', fetch(url, options));

          case 5:
          case 'end':
            return _context3.stop();
        }
      }
    }, _callee3, undefined);
  }));

  return function fetchWithCredentials(_x4, _x5, _x6) {
    return _ref3.apply(this, arguments);
  };
}();

/***/ }),
/* 141 */
/***/ (function(module, exports) {

(function(self) {
  'use strict';

  if (self.fetch) {
    return
  }

  var support = {
    searchParams: 'URLSearchParams' in self,
    iterable: 'Symbol' in self && 'iterator' in Symbol,
    blob: 'FileReader' in self && 'Blob' in self && (function() {
      try {
        new Blob()
        return true
      } catch(e) {
        return false
      }
    })(),
    formData: 'FormData' in self,
    arrayBuffer: 'ArrayBuffer' in self
  }

  if (support.arrayBuffer) {
    var viewClasses = [
      '[object Int8Array]',
      '[object Uint8Array]',
      '[object Uint8ClampedArray]',
      '[object Int16Array]',
      '[object Uint16Array]',
      '[object Int32Array]',
      '[object Uint32Array]',
      '[object Float32Array]',
      '[object Float64Array]'
    ]

    var isDataView = function(obj) {
      return obj && DataView.prototype.isPrototypeOf(obj)
    }

    var isArrayBufferView = ArrayBuffer.isView || function(obj) {
      return obj && viewClasses.indexOf(Object.prototype.toString.call(obj)) > -1
    }
  }

  function normalizeName(name) {
    if (typeof name !== 'string') {
      name = String(name)
    }
    if (/[^a-z0-9\-#$%&'*+.\^_`|~]/i.test(name)) {
      throw new TypeError('Invalid character in header field name')
    }
    return name.toLowerCase()
  }

  function normalizeValue(value) {
    if (typeof value !== 'string') {
      value = String(value)
    }
    return value
  }

  // Build a destructive iterator for the value list
  function iteratorFor(items) {
    var iterator = {
      next: function() {
        var value = items.shift()
        return {done: value === undefined, value: value}
      }
    }

    if (support.iterable) {
      iterator[Symbol.iterator] = function() {
        return iterator
      }
    }

    return iterator
  }

  function Headers(headers) {
    this.map = {}

    if (headers instanceof Headers) {
      headers.forEach(function(value, name) {
        this.append(name, value)
      }, this)
    } else if (Array.isArray(headers)) {
      headers.forEach(function(header) {
        this.append(header[0], header[1])
      }, this)
    } else if (headers) {
      Object.getOwnPropertyNames(headers).forEach(function(name) {
        this.append(name, headers[name])
      }, this)
    }
  }

  Headers.prototype.append = function(name, value) {
    name = normalizeName(name)
    value = normalizeValue(value)
    var oldValue = this.map[name]
    this.map[name] = oldValue ? oldValue+','+value : value
  }

  Headers.prototype['delete'] = function(name) {
    delete this.map[normalizeName(name)]
  }

  Headers.prototype.get = function(name) {
    name = normalizeName(name)
    return this.has(name) ? this.map[name] : null
  }

  Headers.prototype.has = function(name) {
    return this.map.hasOwnProperty(normalizeName(name))
  }

  Headers.prototype.set = function(name, value) {
    this.map[normalizeName(name)] = normalizeValue(value)
  }

  Headers.prototype.forEach = function(callback, thisArg) {
    for (var name in this.map) {
      if (this.map.hasOwnProperty(name)) {
        callback.call(thisArg, this.map[name], name, this)
      }
    }
  }

  Headers.prototype.keys = function() {
    var items = []
    this.forEach(function(value, name) { items.push(name) })
    return iteratorFor(items)
  }

  Headers.prototype.values = function() {
    var items = []
    this.forEach(function(value) { items.push(value) })
    return iteratorFor(items)
  }

  Headers.prototype.entries = function() {
    var items = []
    this.forEach(function(value, name) { items.push([name, value]) })
    return iteratorFor(items)
  }

  if (support.iterable) {
    Headers.prototype[Symbol.iterator] = Headers.prototype.entries
  }

  function consumed(body) {
    if (body.bodyUsed) {
      return Promise.reject(new TypeError('Already read'))
    }
    body.bodyUsed = true
  }

  function fileReaderReady(reader) {
    return new Promise(function(resolve, reject) {
      reader.onload = function() {
        resolve(reader.result)
      }
      reader.onerror = function() {
        reject(reader.error)
      }
    })
  }

  function readBlobAsArrayBuffer(blob) {
    var reader = new FileReader()
    var promise = fileReaderReady(reader)
    reader.readAsArrayBuffer(blob)
    return promise
  }

  function readBlobAsText(blob) {
    var reader = new FileReader()
    var promise = fileReaderReady(reader)
    reader.readAsText(blob)
    return promise
  }

  function readArrayBufferAsText(buf) {
    var view = new Uint8Array(buf)
    var chars = new Array(view.length)

    for (var i = 0; i < view.length; i++) {
      chars[i] = String.fromCharCode(view[i])
    }
    return chars.join('')
  }

  function bufferClone(buf) {
    if (buf.slice) {
      return buf.slice(0)
    } else {
      var view = new Uint8Array(buf.byteLength)
      view.set(new Uint8Array(buf))
      return view.buffer
    }
  }

  function Body() {
    this.bodyUsed = false

    this._initBody = function(body) {
      this._bodyInit = body
      if (!body) {
        this._bodyText = ''
      } else if (typeof body === 'string') {
        this._bodyText = body
      } else if (support.blob && Blob.prototype.isPrototypeOf(body)) {
        this._bodyBlob = body
      } else if (support.formData && FormData.prototype.isPrototypeOf(body)) {
        this._bodyFormData = body
      } else if (support.searchParams && URLSearchParams.prototype.isPrototypeOf(body)) {
        this._bodyText = body.toString()
      } else if (support.arrayBuffer && support.blob && isDataView(body)) {
        this._bodyArrayBuffer = bufferClone(body.buffer)
        // IE 10-11 can't handle a DataView body.
        this._bodyInit = new Blob([this._bodyArrayBuffer])
      } else if (support.arrayBuffer && (ArrayBuffer.prototype.isPrototypeOf(body) || isArrayBufferView(body))) {
        this._bodyArrayBuffer = bufferClone(body)
      } else {
        throw new Error('unsupported BodyInit type')
      }

      if (!this.headers.get('content-type')) {
        if (typeof body === 'string') {
          this.headers.set('content-type', 'text/plain;charset=UTF-8')
        } else if (this._bodyBlob && this._bodyBlob.type) {
          this.headers.set('content-type', this._bodyBlob.type)
        } else if (support.searchParams && URLSearchParams.prototype.isPrototypeOf(body)) {
          this.headers.set('content-type', 'application/x-www-form-urlencoded;charset=UTF-8')
        }
      }
    }

    if (support.blob) {
      this.blob = function() {
        var rejected = consumed(this)
        if (rejected) {
          return rejected
        }

        if (this._bodyBlob) {
          return Promise.resolve(this._bodyBlob)
        } else if (this._bodyArrayBuffer) {
          return Promise.resolve(new Blob([this._bodyArrayBuffer]))
        } else if (this._bodyFormData) {
          throw new Error('could not read FormData body as blob')
        } else {
          return Promise.resolve(new Blob([this._bodyText]))
        }
      }

      this.arrayBuffer = function() {
        if (this._bodyArrayBuffer) {
          return consumed(this) || Promise.resolve(this._bodyArrayBuffer)
        } else {
          return this.blob().then(readBlobAsArrayBuffer)
        }
      }
    }

    this.text = function() {
      var rejected = consumed(this)
      if (rejected) {
        return rejected
      }

      if (this._bodyBlob) {
        return readBlobAsText(this._bodyBlob)
      } else if (this._bodyArrayBuffer) {
        return Promise.resolve(readArrayBufferAsText(this._bodyArrayBuffer))
      } else if (this._bodyFormData) {
        throw new Error('could not read FormData body as text')
      } else {
        return Promise.resolve(this._bodyText)
      }
    }

    if (support.formData) {
      this.formData = function() {
        return this.text().then(decode)
      }
    }

    this.json = function() {
      return this.text().then(JSON.parse)
    }

    return this
  }

  // HTTP methods whose capitalization should be normalized
  var methods = ['DELETE', 'GET', 'HEAD', 'OPTIONS', 'POST', 'PUT']

  function normalizeMethod(method) {
    var upcased = method.toUpperCase()
    return (methods.indexOf(upcased) > -1) ? upcased : method
  }

  function Request(input, options) {
    options = options || {}
    var body = options.body

    if (input instanceof Request) {
      if (input.bodyUsed) {
        throw new TypeError('Already read')
      }
      this.url = input.url
      this.credentials = input.credentials
      if (!options.headers) {
        this.headers = new Headers(input.headers)
      }
      this.method = input.method
      this.mode = input.mode
      if (!body && input._bodyInit != null) {
        body = input._bodyInit
        input.bodyUsed = true
      }
    } else {
      this.url = String(input)
    }

    this.credentials = options.credentials || this.credentials || 'omit'
    if (options.headers || !this.headers) {
      this.headers = new Headers(options.headers)
    }
    this.method = normalizeMethod(options.method || this.method || 'GET')
    this.mode = options.mode || this.mode || null
    this.referrer = null

    if ((this.method === 'GET' || this.method === 'HEAD') && body) {
      throw new TypeError('Body not allowed for GET or HEAD requests')
    }
    this._initBody(body)
  }

  Request.prototype.clone = function() {
    return new Request(this, { body: this._bodyInit })
  }

  function decode(body) {
    var form = new FormData()
    body.trim().split('&').forEach(function(bytes) {
      if (bytes) {
        var split = bytes.split('=')
        var name = split.shift().replace(/\+/g, ' ')
        var value = split.join('=').replace(/\+/g, ' ')
        form.append(decodeURIComponent(name), decodeURIComponent(value))
      }
    })
    return form
  }

  function parseHeaders(rawHeaders) {
    var headers = new Headers()
    // Replace instances of \r\n and \n followed by at least one space or horizontal tab with a space
    // https://tools.ietf.org/html/rfc7230#section-3.2
    var preProcessedHeaders = rawHeaders.replace(/\r?\n[\t ]+/g, ' ')
    preProcessedHeaders.split(/\r?\n/).forEach(function(line) {
      var parts = line.split(':')
      var key = parts.shift().trim()
      if (key) {
        var value = parts.join(':').trim()
        headers.append(key, value)
      }
    })
    return headers
  }

  Body.call(Request.prototype)

  function Response(bodyInit, options) {
    if (!options) {
      options = {}
    }

    this.type = 'default'
    this.status = options.status === undefined ? 200 : options.status
    this.ok = this.status >= 200 && this.status < 300
    this.statusText = 'statusText' in options ? options.statusText : 'OK'
    this.headers = new Headers(options.headers)
    this.url = options.url || ''
    this._initBody(bodyInit)
  }

  Body.call(Response.prototype)

  Response.prototype.clone = function() {
    return new Response(this._bodyInit, {
      status: this.status,
      statusText: this.statusText,
      headers: new Headers(this.headers),
      url: this.url
    })
  }

  Response.error = function() {
    var response = new Response(null, {status: 0, statusText: ''})
    response.type = 'error'
    return response
  }

  var redirectStatuses = [301, 302, 303, 307, 308]

  Response.redirect = function(url, status) {
    if (redirectStatuses.indexOf(status) === -1) {
      throw new RangeError('Invalid status code')
    }

    return new Response(null, {status: status, headers: {location: url}})
  }

  self.Headers = Headers
  self.Request = Request
  self.Response = Response

  self.fetch = function(input, init) {
    return new Promise(function(resolve, reject) {
      var request = new Request(input, init)
      var xhr = new XMLHttpRequest()

      xhr.onload = function() {
        var options = {
          status: xhr.status,
          statusText: xhr.statusText,
          headers: parseHeaders(xhr.getAllResponseHeaders() || '')
        }
        options.url = 'responseURL' in xhr ? xhr.responseURL : options.headers.get('X-Request-URL')
        var body = 'response' in xhr ? xhr.response : xhr.responseText
        resolve(new Response(body, options))
      }

      xhr.onerror = function() {
        reject(new TypeError('Network request failed'))
      }

      xhr.ontimeout = function() {
        reject(new TypeError('Network request failed'))
      }

      xhr.open(request.method, request.url, true)

      if (request.credentials === 'include') {
        xhr.withCredentials = true
      } else if (request.credentials === 'omit') {
        xhr.withCredentials = false
      }

      if ('responseType' in xhr && support.blob) {
        xhr.responseType = 'blob'
      }

      request.headers.forEach(function(value, name) {
        xhr.setRequestHeader(name, value)
      })

      xhr.send(typeof request._bodyInit === 'undefined' ? null : request._bodyInit)
    })
  }
  self.fetch.polyfill = true
})(typeof self !== 'undefined' ? self : this);


/***/ }),
/* 142 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.hostNameFromRequestInfo = undefined;

var _defineProperty2 = __webpack_require__(82);

var _defineProperty3 = _interopRequireDefault(_defineProperty2);

var _extends3 = __webpack_require__(29);

var _extends4 = _interopRequireDefault(_extends3);

var _regenerator = __webpack_require__(11);

var _regenerator2 = _interopRequireDefault(_regenerator);

var _asyncToGenerator2 = __webpack_require__(12);

var _asyncToGenerator3 = _interopRequireDefault(_asyncToGenerator2);

exports.getHost = getHost;
exports.saveHost = saveHost;
exports.updateHostFromResponse = updateHostFromResponse;

var _session = __webpack_require__(57);

var _storage = __webpack_require__(37);

var _webidOidc = __webpack_require__(61);

var WebIdOidc = _interopRequireWildcard(_webidOidc);

var _webidTls = __webpack_require__(114);

var WebIdTls = _interopRequireWildcard(_webidTls);

function _interopRequireWildcard(obj) { if (obj && obj.__esModule) { return obj; } else { var newObj = {}; if (obj != null) { for (var key in obj) { if (Object.prototype.hasOwnProperty.call(obj, key)) newObj[key] = obj[key]; } } newObj.default = obj; return newObj; } }

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/* global RequestInfo, Request, Response, URL */
var hostNameFromRequestInfo = exports.hostNameFromRequestInfo = function hostNameFromRequestInfo(url) {
  var _url = url instanceof URL ? url : url instanceof Request ? new URL(url.url) : new URL(url);
  return _url.host;
};

function getHost(storage) {
  var _this = this;

  return function () {
    var _ref = (0, _asyncToGenerator3.default)( /*#__PURE__*/_regenerator2.default.mark(function _callee(url) {
      var requestHostName, session, _ref2, hosts;

      return _regenerator2.default.wrap(function _callee$(_context) {
        while (1) {
          switch (_context.prev = _context.next) {
            case 0:
              requestHostName = hostNameFromRequestInfo(url);
              _context.next = 3;
              return (0, _session.getSession)(storage);

            case 3:
              session = _context.sent;

              if (!(session && hostNameFromRequestInfo(session.idp) === requestHostName)) {
                _context.next = 6;
                break;
              }

              return _context.abrupt('return', { url: requestHostName, authType: session.authType });

            case 6:
              _context.next = 8;
              return (0, _storage.getData)(storage);

            case 8:
              _ref2 = _context.sent;
              hosts = _ref2.hosts;

              if (hosts) {
                _context.next = 12;
                break;
              }

              return _context.abrupt('return', null);

            case 12:
              return _context.abrupt('return', hosts[requestHostName] || null);

            case 13:
            case 'end':
              return _context.stop();
          }
        }
      }, _callee, _this);
    }));

    return function (_x) {
      return _ref.apply(this, arguments);
    };
  }();
}

function saveHost(storage) {
  var _this2 = this;

  return function () {
    var _ref4 = (0, _asyncToGenerator3.default)( /*#__PURE__*/_regenerator2.default.mark(function _callee2(_ref3) {
      var url = _ref3.url,
          authType = _ref3.authType;
      return _regenerator2.default.wrap(function _callee2$(_context2) {
        while (1) {
          switch (_context2.prev = _context2.next) {
            case 0:
              _context2.next = 2;
              return (0, _storage.updateStorage)(storage, function (data) {
                return (0, _extends4.default)({}, data, {
                  hosts: (0, _extends4.default)({}, data.hosts, (0, _defineProperty3.default)({}, url, { authType: authType }))
                });
              });

            case 2:
              return _context2.abrupt('return', { url: url, authType: authType });

            case 3:
            case 'end':
              return _context2.stop();
          }
        }
      }, _callee2, _this2);
    }));

    return function (_x2) {
      return _ref4.apply(this, arguments);
    };
  }();
}

function updateHostFromResponse(storage) {
  var _this3 = this;

  return function () {
    var _ref5 = (0, _asyncToGenerator3.default)( /*#__PURE__*/_regenerator2.default.mark(function _callee3(resp) {
      var authType, hostName;
      return _regenerator2.default.wrap(function _callee3$(_context3) {
        while (1) {
          switch (_context3.prev = _context3.next) {
            case 0:
              authType = void 0;

              if (WebIdOidc.requiresAuth(resp)) {
                authType = 'WebID-OIDC';
              } else if (WebIdTls.requiresAuth(resp)) {
                authType = 'WebID-TLS';
              } else {
                authType = null;
              }

              hostName = hostNameFromRequestInfo(resp.url);

              if (!authType) {
                _context3.next = 6;
                break;
              }

              _context3.next = 6;
              return saveHost(storage)({ url: hostName, authType: authType });

            case 6:
            case 'end':
              return _context3.stop();
          }
        }
      }, _callee3, _this3);
    }));

    return function (_x3) {
      return _ref5.apply(this, arguments);
    };
  }();
}

/***/ }),
/* 143 */
/***/ (function(module, exports, __webpack_require__) {

__webpack_require__(144);
var $Object = __webpack_require__(0).Object;
module.exports = function defineProperty(it, key, desc) {
  return $Object.defineProperty(it, key, desc);
};


/***/ }),
/* 144 */
/***/ (function(module, exports, __webpack_require__) {

var $export = __webpack_require__(4);
// 19.1.2.4 / 15.2.3.6 Object.defineProperty(O, P, Attributes)
$export($export.S + $export.F * !__webpack_require__(8), 'Object', { defineProperty: __webpack_require__(6).f });


/***/ }),
/* 145 */
/***/ (function(module, exports, __webpack_require__) {

var core = __webpack_require__(0);
var $JSON = core.JSON || (core.JSON = { stringify: JSON.stringify });
module.exports = function stringify(it) { // eslint-disable-line no-unused-vars
  return $JSON.stringify.apply($JSON, arguments);
};


/***/ }),
/* 146 */
/***/ (function(module, exports, __webpack_require__) {

module.exports = { "default": __webpack_require__(147), __esModule: true };

/***/ }),
/* 147 */
/***/ (function(module, exports, __webpack_require__) {

__webpack_require__(27);
__webpack_require__(36);
module.exports = __webpack_require__(59).f('iterator');


/***/ }),
/* 148 */
/***/ (function(module, exports, __webpack_require__) {

module.exports = { "default": __webpack_require__(149), __esModule: true };

/***/ }),
/* 149 */
/***/ (function(module, exports, __webpack_require__) {

__webpack_require__(150);
__webpack_require__(70);
__webpack_require__(155);
__webpack_require__(156);
module.exports = __webpack_require__(0).Symbol;


/***/ }),
/* 150 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";

// ECMAScript 6 symbols shim
var global = __webpack_require__(2);
var has = __webpack_require__(10);
var DESCRIPTORS = __webpack_require__(8);
var $export = __webpack_require__(4);
var redefine = __webpack_require__(72);
var META = __webpack_require__(151).KEY;
var $fails = __webpack_require__(16);
var shared = __webpack_require__(48);
var setToStringTag = __webpack_require__(35);
var uid = __webpack_require__(32);
var wks = __webpack_require__(1);
var wksExt = __webpack_require__(59);
var wksDefine = __webpack_require__(60);
var enumKeys = __webpack_require__(152);
var isArray = __webpack_require__(153);
var anObject = __webpack_require__(5);
var isObject = __webpack_require__(7);
var toIObject = __webpack_require__(17);
var toPrimitive = __webpack_require__(43);
var createDesc = __webpack_require__(23);
var _create = __webpack_require__(51);
var gOPNExt = __webpack_require__(154);
var $GOPD = __webpack_require__(85);
var $DP = __webpack_require__(6);
var $keys = __webpack_require__(24);
var gOPD = $GOPD.f;
var dP = $DP.f;
var gOPN = gOPNExt.f;
var $Symbol = global.Symbol;
var $JSON = global.JSON;
var _stringify = $JSON && $JSON.stringify;
var PROTOTYPE = 'prototype';
var HIDDEN = wks('_hidden');
var TO_PRIMITIVE = wks('toPrimitive');
var isEnum = {}.propertyIsEnumerable;
var SymbolRegistry = shared('symbol-registry');
var AllSymbols = shared('symbols');
var OPSymbols = shared('op-symbols');
var ObjectProto = Object[PROTOTYPE];
var USE_NATIVE = typeof $Symbol == 'function';
var QObject = global.QObject;
// Don't use setters in Qt Script, https://github.com/zloirock/core-js/issues/173
var setter = !QObject || !QObject[PROTOTYPE] || !QObject[PROTOTYPE].findChild;

// fallback for old Android, https://code.google.com/p/v8/issues/detail?id=687
var setSymbolDesc = DESCRIPTORS && $fails(function () {
  return _create(dP({}, 'a', {
    get: function () { return dP(this, 'a', { value: 7 }).a; }
  })).a != 7;
}) ? function (it, key, D) {
  var protoDesc = gOPD(ObjectProto, key);
  if (protoDesc) delete ObjectProto[key];
  dP(it, key, D);
  if (protoDesc && it !== ObjectProto) dP(ObjectProto, key, protoDesc);
} : dP;

var wrap = function (tag) {
  var sym = AllSymbols[tag] = _create($Symbol[PROTOTYPE]);
  sym._k = tag;
  return sym;
};

var isSymbol = USE_NATIVE && typeof $Symbol.iterator == 'symbol' ? function (it) {
  return typeof it == 'symbol';
} : function (it) {
  return it instanceof $Symbol;
};

var $defineProperty = function defineProperty(it, key, D) {
  if (it === ObjectProto) $defineProperty(OPSymbols, key, D);
  anObject(it);
  key = toPrimitive(key, true);
  anObject(D);
  if (has(AllSymbols, key)) {
    if (!D.enumerable) {
      if (!has(it, HIDDEN)) dP(it, HIDDEN, createDesc(1, {}));
      it[HIDDEN][key] = true;
    } else {
      if (has(it, HIDDEN) && it[HIDDEN][key]) it[HIDDEN][key] = false;
      D = _create(D, { enumerable: createDesc(0, false) });
    } return setSymbolDesc(it, key, D);
  } return dP(it, key, D);
};
var $defineProperties = function defineProperties(it, P) {
  anObject(it);
  var keys = enumKeys(P = toIObject(P));
  var i = 0;
  var l = keys.length;
  var key;
  while (l > i) $defineProperty(it, key = keys[i++], P[key]);
  return it;
};
var $create = function create(it, P) {
  return P === undefined ? _create(it) : $defineProperties(_create(it), P);
};
var $propertyIsEnumerable = function propertyIsEnumerable(key) {
  var E = isEnum.call(this, key = toPrimitive(key, true));
  if (this === ObjectProto && has(AllSymbols, key) && !has(OPSymbols, key)) return false;
  return E || !has(this, key) || !has(AllSymbols, key) || has(this, HIDDEN) && this[HIDDEN][key] ? E : true;
};
var $getOwnPropertyDescriptor = function getOwnPropertyDescriptor(it, key) {
  it = toIObject(it);
  key = toPrimitive(key, true);
  if (it === ObjectProto && has(AllSymbols, key) && !has(OPSymbols, key)) return;
  var D = gOPD(it, key);
  if (D && has(AllSymbols, key) && !(has(it, HIDDEN) && it[HIDDEN][key])) D.enumerable = true;
  return D;
};
var $getOwnPropertyNames = function getOwnPropertyNames(it) {
  var names = gOPN(toIObject(it));
  var result = [];
  var i = 0;
  var key;
  while (names.length > i) {
    if (!has(AllSymbols, key = names[i++]) && key != HIDDEN && key != META) result.push(key);
  } return result;
};
var $getOwnPropertySymbols = function getOwnPropertySymbols(it) {
  var IS_OP = it === ObjectProto;
  var names = gOPN(IS_OP ? OPSymbols : toIObject(it));
  var result = [];
  var i = 0;
  var key;
  while (names.length > i) {
    if (has(AllSymbols, key = names[i++]) && (IS_OP ? has(ObjectProto, key) : true)) result.push(AllSymbols[key]);
  } return result;
};

// 19.4.1.1 Symbol([description])
if (!USE_NATIVE) {
  $Symbol = function Symbol() {
    if (this instanceof $Symbol) throw TypeError('Symbol is not a constructor!');
    var tag = uid(arguments.length > 0 ? arguments[0] : undefined);
    var $set = function (value) {
      if (this === ObjectProto) $set.call(OPSymbols, value);
      if (has(this, HIDDEN) && has(this[HIDDEN], tag)) this[HIDDEN][tag] = false;
      setSymbolDesc(this, tag, createDesc(1, value));
    };
    if (DESCRIPTORS && setter) setSymbolDesc(ObjectProto, tag, { configurable: true, set: $set });
    return wrap(tag);
  };
  redefine($Symbol[PROTOTYPE], 'toString', function toString() {
    return this._k;
  });

  $GOPD.f = $getOwnPropertyDescriptor;
  $DP.f = $defineProperty;
  __webpack_require__(84).f = gOPNExt.f = $getOwnPropertyNames;
  __webpack_require__(33).f = $propertyIsEnumerable;
  __webpack_require__(50).f = $getOwnPropertySymbols;

  if (DESCRIPTORS && !__webpack_require__(34)) {
    redefine(ObjectProto, 'propertyIsEnumerable', $propertyIsEnumerable, true);
  }

  wksExt.f = function (name) {
    return wrap(wks(name));
  };
}

$export($export.G + $export.W + $export.F * !USE_NATIVE, { Symbol: $Symbol });

for (var es6Symbols = (
  // 19.4.2.2, 19.4.2.3, 19.4.2.4, 19.4.2.6, 19.4.2.8, 19.4.2.9, 19.4.2.10, 19.4.2.11, 19.4.2.12, 19.4.2.13, 19.4.2.14
  'hasInstance,isConcatSpreadable,iterator,match,replace,search,species,split,toPrimitive,toStringTag,unscopables'
).split(','), j = 0; es6Symbols.length > j;)wks(es6Symbols[j++]);

for (var wellKnownSymbols = $keys(wks.store), k = 0; wellKnownSymbols.length > k;) wksDefine(wellKnownSymbols[k++]);

$export($export.S + $export.F * !USE_NATIVE, 'Symbol', {
  // 19.4.2.1 Symbol.for(key)
  'for': function (key) {
    return has(SymbolRegistry, key += '')
      ? SymbolRegistry[key]
      : SymbolRegistry[key] = $Symbol(key);
  },
  // 19.4.2.5 Symbol.keyFor(sym)
  keyFor: function keyFor(sym) {
    if (!isSymbol(sym)) throw TypeError(sym + ' is not a symbol!');
    for (var key in SymbolRegistry) if (SymbolRegistry[key] === sym) return key;
  },
  useSetter: function () { setter = true; },
  useSimple: function () { setter = false; }
});

$export($export.S + $export.F * !USE_NATIVE, 'Object', {
  // 19.1.2.2 Object.create(O [, Properties])
  create: $create,
  // 19.1.2.4 Object.defineProperty(O, P, Attributes)
  defineProperty: $defineProperty,
  // 19.1.2.3 Object.defineProperties(O, Properties)
  defineProperties: $defineProperties,
  // 19.1.2.6 Object.getOwnPropertyDescriptor(O, P)
  getOwnPropertyDescriptor: $getOwnPropertyDescriptor,
  // 19.1.2.7 Object.getOwnPropertyNames(O)
  getOwnPropertyNames: $getOwnPropertyNames,
  // 19.1.2.8 Object.getOwnPropertySymbols(O)
  getOwnPropertySymbols: $getOwnPropertySymbols
});

// 24.3.2 JSON.stringify(value [, replacer [, space]])
$JSON && $export($export.S + $export.F * (!USE_NATIVE || $fails(function () {
  var S = $Symbol();
  // MS Edge converts symbol values to JSON as {}
  // WebKit converts symbol values to JSON as null
  // V8 throws on boxed symbols
  return _stringify([S]) != '[null]' || _stringify({ a: S }) != '{}' || _stringify(Object(S)) != '{}';
})), 'JSON', {
  stringify: function stringify(it) {
    var args = [it];
    var i = 1;
    var replacer, $replacer;
    while (arguments.length > i) args.push(arguments[i++]);
    $replacer = replacer = args[1];
    if (!isObject(replacer) && it === undefined || isSymbol(it)) return; // IE8 returns string on undefined
    if (!isArray(replacer)) replacer = function (key, value) {
      if (typeof $replacer == 'function') value = $replacer.call(this, key, value);
      if (!isSymbol(value)) return value;
    };
    args[1] = replacer;
    return _stringify.apply($JSON, args);
  }
});

// 19.4.3.4 Symbol.prototype[@@toPrimitive](hint)
$Symbol[PROTOTYPE][TO_PRIMITIVE] || __webpack_require__(9)($Symbol[PROTOTYPE], TO_PRIMITIVE, $Symbol[PROTOTYPE].valueOf);
// 19.4.3.5 Symbol.prototype[@@toStringTag]
setToStringTag($Symbol, 'Symbol');
// 20.2.1.9 Math[@@toStringTag]
setToStringTag(Math, 'Math', true);
// 24.3.3 JSON[@@toStringTag]
setToStringTag(global.JSON, 'JSON', true);


/***/ }),
/* 151 */
/***/ (function(module, exports, __webpack_require__) {

var META = __webpack_require__(32)('meta');
var isObject = __webpack_require__(7);
var has = __webpack_require__(10);
var setDesc = __webpack_require__(6).f;
var id = 0;
var isExtensible = Object.isExtensible || function () {
  return true;
};
var FREEZE = !__webpack_require__(16)(function () {
  return isExtensible(Object.preventExtensions({}));
});
var setMeta = function (it) {
  setDesc(it, META, { value: {
    i: 'O' + ++id, // object ID
    w: {}          // weak collections IDs
  } });
};
var fastKey = function (it, create) {
  // return primitive with prefix
  if (!isObject(it)) return typeof it == 'symbol' ? it : (typeof it == 'string' ? 'S' : 'P') + it;
  if (!has(it, META)) {
    // can't set metadata to uncaught frozen object
    if (!isExtensible(it)) return 'F';
    // not necessary to add metadata
    if (!create) return 'E';
    // add missing metadata
    setMeta(it);
  // return object ID
  } return it[META].i;
};
var getWeak = function (it, create) {
  if (!has(it, META)) {
    // can't set metadata to uncaught frozen object
    if (!isExtensible(it)) return true;
    // not necessary to add metadata
    if (!create) return false;
    // add missing metadata
    setMeta(it);
  // return hash weak collections IDs
  } return it[META].w;
};
// add metadata on freeze-family methods calling
var onFreeze = function (it) {
  if (FREEZE && meta.NEED && isExtensible(it) && !has(it, META)) setMeta(it);
  return it;
};
var meta = module.exports = {
  KEY: META,
  NEED: false,
  fastKey: fastKey,
  getWeak: getWeak,
  onFreeze: onFreeze
};


/***/ }),
/* 152 */
/***/ (function(module, exports, __webpack_require__) {

// all enumerable object keys, includes symbols
var getKeys = __webpack_require__(24);
var gOPS = __webpack_require__(50);
var pIE = __webpack_require__(33);
module.exports = function (it) {
  var result = getKeys(it);
  var getSymbols = gOPS.f;
  if (getSymbols) {
    var symbols = getSymbols(it);
    var isEnum = pIE.f;
    var i = 0;
    var key;
    while (symbols.length > i) if (isEnum.call(it, key = symbols[i++])) result.push(key);
  } return result;
};


/***/ }),
/* 153 */
/***/ (function(module, exports, __webpack_require__) {

// 7.2.2 IsArray(argument)
var cof = __webpack_require__(25);
module.exports = Array.isArray || function isArray(arg) {
  return cof(arg) == 'Array';
};


/***/ }),
/* 154 */
/***/ (function(module, exports, __webpack_require__) {

// fallback for IE11 buggy Object.getOwnPropertyNames with iframe and window
var toIObject = __webpack_require__(17);
var gOPN = __webpack_require__(84).f;
var toString = {}.toString;

var windowNames = typeof window == 'object' && window && Object.getOwnPropertyNames
  ? Object.getOwnPropertyNames(window) : [];

var getWindowNames = function (it) {
  try {
    return gOPN(it);
  } catch (e) {
    return windowNames.slice();
  }
};

module.exports.f = function getOwnPropertyNames(it) {
  return windowNames && toString.call(it) == '[object Window]' ? getWindowNames(it) : gOPN(toIObject(it));
};


/***/ }),
/* 155 */
/***/ (function(module, exports, __webpack_require__) {

__webpack_require__(60)('asyncIterator');


/***/ }),
/* 156 */
/***/ (function(module, exports, __webpack_require__) {

__webpack_require__(60)('observable');


/***/ }),
/* 157 */
/***/ (function(module, exports, __webpack_require__) {

var rng = __webpack_require__(158);
var bytesToUuid = __webpack_require__(159);

function v4(options, buf, offset) {
  var i = buf && offset || 0;

  if (typeof(options) == 'string') {
    buf = options === 'binary' ? new Array(16) : null;
    options = null;
  }
  options = options || {};

  var rnds = options.random || (options.rng || rng)();

  // Per 4.4, set bits for version and `clock_seq_hi_and_reserved`
  rnds[6] = (rnds[6] & 0x0f) | 0x40;
  rnds[8] = (rnds[8] & 0x3f) | 0x80;

  // Copy bytes to buffer, if provided
  if (buf) {
    for (var ii = 0; ii < 16; ++ii) {
      buf[i + ii] = rnds[ii];
    }
  }

  return buf || bytesToUuid(rnds);
}

module.exports = v4;


/***/ }),
/* 158 */
/***/ (function(module, exports) {

// Unique ID creation requires a high quality random # generator.  In the
// browser this is a little complicated due to unknown quality of Math.random()
// and inconsistent support for the `crypto` API.  We do the best we can via
// feature-detection

// getRandomValues needs to be invoked in a context where "this" is a Crypto implementation.
var getRandomValues = (typeof(crypto) != 'undefined' && crypto.getRandomValues.bind(crypto)) ||
                      (typeof(msCrypto) != 'undefined' && msCrypto.getRandomValues.bind(msCrypto));
if (getRandomValues) {
  // WHATWG crypto RNG - http://wiki.whatwg.org/wiki/Crypto
  var rnds8 = new Uint8Array(16); // eslint-disable-line no-undef

  module.exports = function whatwgRNG() {
    getRandomValues(rnds8);
    return rnds8;
  };
} else {
  // Math.random()-based (RNG)
  //
  // If all else fails, use Math.random().  It's fast, but is of unspecified
  // quality.
  var rnds = new Array(16);

  module.exports = function mathRNG() {
    for (var i = 0, r; i < 16; i++) {
      if ((i & 0x03) === 0) r = Math.random() * 0x100000000;
      rnds[i] = r >>> ((i & 0x03) << 3) & 0xff;
    }

    return rnds;
  };
}


/***/ }),
/* 159 */
/***/ (function(module, exports) {

/**
 * Convert array of 16 byte values to UUID string format of the form:
 * XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
 */
var byteToHex = [];
for (var i = 0; i < 256; ++i) {
  byteToHex[i] = (i + 0x100).toString(16).substr(1);
}

function bytesToUuid(buf, offset) {
  var i = offset || 0;
  var bth = byteToHex;
  return bth[buf[i++]] + bth[buf[i++]] +
          bth[buf[i++]] + bth[buf[i++]] + '-' +
          bth[buf[i++]] + bth[buf[i++]] + '-' +
          bth[buf[i++]] + bth[buf[i++]] + '-' +
          bth[buf[i++]] + bth[buf[i++]] + '-' +
          bth[buf[i++]] + bth[buf[i++]] +
          bth[buf[i++]] + bth[buf[i++]] +
          bth[buf[i++]] + bth[buf[i++]];
}

module.exports = bytesToUuid;


/***/ }),
/* 160 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var _typeof = typeof Symbol === "function" && typeof Symbol.iterator === "symbol" ? function (obj) { return typeof obj; } : function (obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol ? "symbol" : typeof obj; };

var _slicedToArray = function () { function sliceIterator(arr, i) { var _arr = []; var _n = true; var _d = false; var _e = undefined; try { for (var _i = arr[Symbol.iterator](), _s; !(_n = (_s = _i.next()).done); _n = true) { _arr.push(_s.value); if (i && _arr.length === i) break; } } catch (err) { _d = true; _e = err; } finally { try { if (!_n && _i["return"]) _i["return"](); } finally { if (_d) throw _e; } } return _arr; } return function (arr, i) { if (Array.isArray(arr)) { return arr; } else if (Symbol.iterator in Object(arr)) { return sliceIterator(arr, i); } else { throw new TypeError("Invalid attempt to destructure non-iterable instance"); } }; }();

Object.defineProperty(exports, "__esModule", {
  value: true
});

var _util = __webpack_require__(87);

function _toConsumableArray(arr) { if (Array.isArray(arr)) { for (var i = 0, arr2 = Array(arr.length); i < arr.length; i++) { arr2[i] = arr[i]; } return arr2; } else { return Array.from(arr); } }

var xxx = function xxx(key) {
  return function (value) {
    return key + '=' + (value && !(0, _util.isToken)(value) ? (0, _util.quote)(value) : value);
  };
};

var build = function build(params) {
  return params.reduce(function (prev, _ref) {
    var _ref2 = _slicedToArray(_ref, 2);

    var key = _ref2[0];
    var values = _ref2[1];

    var transform = xxx(key);
    if (!(0, _util.isToken)(key)) {
      throw new TypeError();
    }
    if (Array.isArray(values)) {
      return [].concat(_toConsumableArray(prev), _toConsumableArray(values.map(transform)));
    }
    return [].concat(_toConsumableArray(prev), [transform(values)]);
  }, []);
};

var challenge = function challenge(params, options) {
  if (Array.isArray(params)) {
    return build(params);
  } else if ((typeof params === 'undefined' ? 'undefined' : _typeof(params)) === 'object') {
    return challenge(Object.keys(params).map(function (key) {
      return [key, params[key]];
    }), options);
  }
  throw new TypeError();
};

exports.default = function (scheme, token, params) {
  var obj = typeof scheme === 'string' ? { scheme: scheme, token: token, params: params } : scheme;

  if ((typeof obj === 'undefined' ? 'undefined' : _typeof(obj)) !== 'object') {
    throw new TypeError();
  } else if (!(0, _util.isScheme)(obj.scheme)) {
    throw new TypeError('Invalid scheme.');
  }

  return [obj.scheme].concat(_toConsumableArray(typeof obj.token !== 'undefined' ? [obj.token] : []), _toConsumableArray(typeof obj.params !== 'undefined' ? challenge(obj.params) : [])).join(' ');
};
//# sourceMappingURL=format.js.map

/***/ }),
/* 161 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


Object.defineProperty(exports, "__esModule", {
  value: true
});

var _util = __webpack_require__(87);

// lol dis
var body = /((?:[a-zA-Z0-9._~+\/-]+=*(?:\s+|$))|[^\u0000-\u001F\u007F()<>@,;:\\"/?={}\[\]\u0020\u0009]+)(?:=([^\\"=\s,]+|"(?:[^"\\]|\\.)*"))?/g; // eslint-disable-line

var normalize = function normalize(prev, _cur) {
  // Fixup quoted strings and tokens with spaces around them
  var cur = _cur.charAt(0) === '"' ? (0, _util.unquote)(_cur) : _cur.trim();

  // Marshal
  if (Array.isArray(prev)) {
    return prev.concat(cur);
  } else if (prev) {
    return [prev, cur];
  }
  return cur;
};

var parseProperties = function parseProperties(scheme, string) {
  var res = null;
  var token = null;
  var params = {};

  while ((res = body.exec(string)) !== null) {
    if (res[2]) {
      params[res[1]] = normalize(params[res[1]], res[2]);
    } else {
      token = normalize(token, res[1]);
    }
  }

  return { scheme: scheme, params: params, token: token };
};

exports.default = function (str) {
  if (typeof str !== 'string') {
    throw new TypeError('Header value must be a string.');
  }

  var start = str.indexOf(' ');
  var scheme = str.substr(0, start);

  if (!(0, _util.isScheme)(scheme)) {
    throw new TypeError('Invalid scheme ' + scheme);
  }

  return parseProperties(scheme, str.substr(start));
};
//# sourceMappingURL=parse.js.map

/***/ }),
/* 162 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


module.exports = __webpack_require__(88);

/***/ }),
/* 163 */
/***/ (function(module, exports, __webpack_require__) {

__webpack_require__(164);
module.exports = __webpack_require__(0).Object.getPrototypeOf;


/***/ }),
/* 164 */
/***/ (function(module, exports, __webpack_require__) {

// 19.1.2.9 Object.getPrototypeOf(O)
var toObject = __webpack_require__(26);
var $getPrototypeOf = __webpack_require__(74);

__webpack_require__(89)('getPrototypeOf', function () {
  return function getPrototypeOf(it) {
    return $getPrototypeOf(toObject(it));
  };
});


/***/ }),
/* 165 */
/***/ (function(module, exports, __webpack_require__) {

__webpack_require__(166);
module.exports = __webpack_require__(0).Object.setPrototypeOf;


/***/ }),
/* 166 */
/***/ (function(module, exports, __webpack_require__) {

// 19.1.3.19 Object.setPrototypeOf(O, proto)
var $export = __webpack_require__(4);
$export($export.S, 'Object', { setPrototypeOf: __webpack_require__(167).set });


/***/ }),
/* 167 */
/***/ (function(module, exports, __webpack_require__) {

// Works with __proto__ only. Old v8 can't work with null proto objects.
/* eslint-disable no-proto */
var isObject = __webpack_require__(7);
var anObject = __webpack_require__(5);
var check = function (O, proto) {
  anObject(O);
  if (!isObject(proto) && proto !== null) throw TypeError(proto + ": can't set as prototype!");
};
module.exports = {
  set: Object.setPrototypeOf || ('__proto__' in {} ? // eslint-disable-line
    function (test, buggy, set) {
      try {
        set = __webpack_require__(15)(Function.call, __webpack_require__(85).f(Object.prototype, '__proto__').set, 2);
        set(test, []);
        buggy = !(test instanceof Array);
      } catch (e) { buggy = true; }
      return function setPrototypeOf(O, proto) {
        check(O, proto);
        if (buggy) O.__proto__ = proto;
        else set(O, proto);
        return O;
      };
    }({}, false) : undefined),
  check: check
};


/***/ }),
/* 168 */
/***/ (function(module, exports, __webpack_require__) {

__webpack_require__(169);
var $Object = __webpack_require__(0).Object;
module.exports = function create(P, D) {
  return $Object.create(P, D);
};


/***/ }),
/* 169 */
/***/ (function(module, exports, __webpack_require__) {

var $export = __webpack_require__(4);
// 19.1.2.2 / 15.2.3.5 Object.create(O [, Properties])
$export($export.S, 'Object', { create: __webpack_require__(51) });


/***/ }),
/* 170 */
/***/ (function(module, exports, __webpack_require__) {

/* WEBPACK VAR INJECTION */(function(global, process) {// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

var formatRegExp = /%[sdj%]/g;
exports.format = function(f) {
  if (!isString(f)) {
    var objects = [];
    for (var i = 0; i < arguments.length; i++) {
      objects.push(inspect(arguments[i]));
    }
    return objects.join(' ');
  }

  var i = 1;
  var args = arguments;
  var len = args.length;
  var str = String(f).replace(formatRegExp, function(x) {
    if (x === '%%') return '%';
    if (i >= len) return x;
    switch (x) {
      case '%s': return String(args[i++]);
      case '%d': return Number(args[i++]);
      case '%j':
        try {
          return JSON.stringify(args[i++]);
        } catch (_) {
          return '[Circular]';
        }
      default:
        return x;
    }
  });
  for (var x = args[i]; i < len; x = args[++i]) {
    if (isNull(x) || !isObject(x)) {
      str += ' ' + x;
    } else {
      str += ' ' + inspect(x);
    }
  }
  return str;
};


// Mark that a method should not be used.
// Returns a modified function which warns once by default.
// If --no-deprecation is set, then it is a no-op.
exports.deprecate = function(fn, msg) {
  // Allow for deprecating things in the process of starting up.
  if (isUndefined(global.process)) {
    return function() {
      return exports.deprecate(fn, msg).apply(this, arguments);
    };
  }

  if (process.noDeprecation === true) {
    return fn;
  }

  var warned = false;
  function deprecated() {
    if (!warned) {
      if (process.throwDeprecation) {
        throw new Error(msg);
      } else if (process.traceDeprecation) {
        console.trace(msg);
      } else {
        console.error(msg);
      }
      warned = true;
    }
    return fn.apply(this, arguments);
  }

  return deprecated;
};


var debugs = {};
var debugEnviron;
exports.debuglog = function(set) {
  if (isUndefined(debugEnviron))
    debugEnviron = process.env.NODE_DEBUG || '';
  set = set.toUpperCase();
  if (!debugs[set]) {
    if (new RegExp('\\b' + set + '\\b', 'i').test(debugEnviron)) {
      var pid = process.pid;
      debugs[set] = function() {
        var msg = exports.format.apply(exports, arguments);
        console.error('%s %d: %s', set, pid, msg);
      };
    } else {
      debugs[set] = function() {};
    }
  }
  return debugs[set];
};


/**
 * Echos the value of a value. Trys to print the value out
 * in the best way possible given the different types.
 *
 * @param {Object} obj The object to print out.
 * @param {Object} opts Optional options object that alters the output.
 */
/* legacy: obj, showHidden, depth, colors*/
function inspect(obj, opts) {
  // default options
  var ctx = {
    seen: [],
    stylize: stylizeNoColor
  };
  // legacy...
  if (arguments.length >= 3) ctx.depth = arguments[2];
  if (arguments.length >= 4) ctx.colors = arguments[3];
  if (isBoolean(opts)) {
    // legacy...
    ctx.showHidden = opts;
  } else if (opts) {
    // got an "options" object
    exports._extend(ctx, opts);
  }
  // set default options
  if (isUndefined(ctx.showHidden)) ctx.showHidden = false;
  if (isUndefined(ctx.depth)) ctx.depth = 2;
  if (isUndefined(ctx.colors)) ctx.colors = false;
  if (isUndefined(ctx.customInspect)) ctx.customInspect = true;
  if (ctx.colors) ctx.stylize = stylizeWithColor;
  return formatValue(ctx, obj, ctx.depth);
}
exports.inspect = inspect;


// http://en.wikipedia.org/wiki/ANSI_escape_code#graphics
inspect.colors = {
  'bold' : [1, 22],
  'italic' : [3, 23],
  'underline' : [4, 24],
  'inverse' : [7, 27],
  'white' : [37, 39],
  'grey' : [90, 39],
  'black' : [30, 39],
  'blue' : [34, 39],
  'cyan' : [36, 39],
  'green' : [32, 39],
  'magenta' : [35, 39],
  'red' : [31, 39],
  'yellow' : [33, 39]
};

// Don't use 'blue' not visible on cmd.exe
inspect.styles = {
  'special': 'cyan',
  'number': 'yellow',
  'boolean': 'yellow',
  'undefined': 'grey',
  'null': 'bold',
  'string': 'green',
  'date': 'magenta',
  // "name": intentionally not styling
  'regexp': 'red'
};


function stylizeWithColor(str, styleType) {
  var style = inspect.styles[styleType];

  if (style) {
    return '\u001b[' + inspect.colors[style][0] + 'm' + str +
           '\u001b[' + inspect.colors[style][1] + 'm';
  } else {
    return str;
  }
}


function stylizeNoColor(str, styleType) {
  return str;
}


function arrayToHash(array) {
  var hash = {};

  array.forEach(function(val, idx) {
    hash[val] = true;
  });

  return hash;
}


function formatValue(ctx, value, recurseTimes) {
  // Provide a hook for user-specified inspect functions.
  // Check that value is an object with an inspect function on it
  if (ctx.customInspect &&
      value &&
      isFunction(value.inspect) &&
      // Filter out the util module, it's inspect function is special
      value.inspect !== exports.inspect &&
      // Also filter out any prototype objects using the circular check.
      !(value.constructor && value.constructor.prototype === value)) {
    var ret = value.inspect(recurseTimes, ctx);
    if (!isString(ret)) {
      ret = formatValue(ctx, ret, recurseTimes);
    }
    return ret;
  }

  // Primitive types cannot have properties
  var primitive = formatPrimitive(ctx, value);
  if (primitive) {
    return primitive;
  }

  // Look up the keys of the object.
  var keys = Object.keys(value);
  var visibleKeys = arrayToHash(keys);

  if (ctx.showHidden) {
    keys = Object.getOwnPropertyNames(value);
  }

  // IE doesn't make error fields non-enumerable
  // http://msdn.microsoft.com/en-us/library/ie/dww52sbt(v=vs.94).aspx
  if (isError(value)
      && (keys.indexOf('message') >= 0 || keys.indexOf('description') >= 0)) {
    return formatError(value);
  }

  // Some type of object without properties can be shortcutted.
  if (keys.length === 0) {
    if (isFunction(value)) {
      var name = value.name ? ': ' + value.name : '';
      return ctx.stylize('[Function' + name + ']', 'special');
    }
    if (isRegExp(value)) {
      return ctx.stylize(RegExp.prototype.toString.call(value), 'regexp');
    }
    if (isDate(value)) {
      return ctx.stylize(Date.prototype.toString.call(value), 'date');
    }
    if (isError(value)) {
      return formatError(value);
    }
  }

  var base = '', array = false, braces = ['{', '}'];

  // Make Array say that they are Array
  if (isArray(value)) {
    array = true;
    braces = ['[', ']'];
  }

  // Make functions say that they are functions
  if (isFunction(value)) {
    var n = value.name ? ': ' + value.name : '';
    base = ' [Function' + n + ']';
  }

  // Make RegExps say that they are RegExps
  if (isRegExp(value)) {
    base = ' ' + RegExp.prototype.toString.call(value);
  }

  // Make dates with properties first say the date
  if (isDate(value)) {
    base = ' ' + Date.prototype.toUTCString.call(value);
  }

  // Make error with message first say the error
  if (isError(value)) {
    base = ' ' + formatError(value);
  }

  if (keys.length === 0 && (!array || value.length == 0)) {
    return braces[0] + base + braces[1];
  }

  if (recurseTimes < 0) {
    if (isRegExp(value)) {
      return ctx.stylize(RegExp.prototype.toString.call(value), 'regexp');
    } else {
      return ctx.stylize('[Object]', 'special');
    }
  }

  ctx.seen.push(value);

  var output;
  if (array) {
    output = formatArray(ctx, value, recurseTimes, visibleKeys, keys);
  } else {
    output = keys.map(function(key) {
      return formatProperty(ctx, value, recurseTimes, visibleKeys, key, array);
    });
  }

  ctx.seen.pop();

  return reduceToSingleString(output, base, braces);
}


function formatPrimitive(ctx, value) {
  if (isUndefined(value))
    return ctx.stylize('undefined', 'undefined');
  if (isString(value)) {
    var simple = '\'' + JSON.stringify(value).replace(/^"|"$/g, '')
                                             .replace(/'/g, "\\'")
                                             .replace(/\\"/g, '"') + '\'';
    return ctx.stylize(simple, 'string');
  }
  if (isNumber(value))
    return ctx.stylize('' + value, 'number');
  if (isBoolean(value))
    return ctx.stylize('' + value, 'boolean');
  // For some reason typeof null is "object", so special case here.
  if (isNull(value))
    return ctx.stylize('null', 'null');
}


function formatError(value) {
  return '[' + Error.prototype.toString.call(value) + ']';
}


function formatArray(ctx, value, recurseTimes, visibleKeys, keys) {
  var output = [];
  for (var i = 0, l = value.length; i < l; ++i) {
    if (hasOwnProperty(value, String(i))) {
      output.push(formatProperty(ctx, value, recurseTimes, visibleKeys,
          String(i), true));
    } else {
      output.push('');
    }
  }
  keys.forEach(function(key) {
    if (!key.match(/^\d+$/)) {
      output.push(formatProperty(ctx, value, recurseTimes, visibleKeys,
          key, true));
    }
  });
  return output;
}


function formatProperty(ctx, value, recurseTimes, visibleKeys, key, array) {
  var name, str, desc;
  desc = Object.getOwnPropertyDescriptor(value, key) || { value: value[key] };
  if (desc.get) {
    if (desc.set) {
      str = ctx.stylize('[Getter/Setter]', 'special');
    } else {
      str = ctx.stylize('[Getter]', 'special');
    }
  } else {
    if (desc.set) {
      str = ctx.stylize('[Setter]', 'special');
    }
  }
  if (!hasOwnProperty(visibleKeys, key)) {
    name = '[' + key + ']';
  }
  if (!str) {
    if (ctx.seen.indexOf(desc.value) < 0) {
      if (isNull(recurseTimes)) {
        str = formatValue(ctx, desc.value, null);
      } else {
        str = formatValue(ctx, desc.value, recurseTimes - 1);
      }
      if (str.indexOf('\n') > -1) {
        if (array) {
          str = str.split('\n').map(function(line) {
            return '  ' + line;
          }).join('\n').substr(2);
        } else {
          str = '\n' + str.split('\n').map(function(line) {
            return '   ' + line;
          }).join('\n');
        }
      }
    } else {
      str = ctx.stylize('[Circular]', 'special');
    }
  }
  if (isUndefined(name)) {
    if (array && key.match(/^\d+$/)) {
      return str;
    }
    name = JSON.stringify('' + key);
    if (name.match(/^"([a-zA-Z_][a-zA-Z_0-9]*)"$/)) {
      name = name.substr(1, name.length - 2);
      name = ctx.stylize(name, 'name');
    } else {
      name = name.replace(/'/g, "\\'")
                 .replace(/\\"/g, '"')
                 .replace(/(^"|"$)/g, "'");
      name = ctx.stylize(name, 'string');
    }
  }

  return name + ': ' + str;
}


function reduceToSingleString(output, base, braces) {
  var numLinesEst = 0;
  var length = output.reduce(function(prev, cur) {
    numLinesEst++;
    if (cur.indexOf('\n') >= 0) numLinesEst++;
    return prev + cur.replace(/\u001b\[\d\d?m/g, '').length + 1;
  }, 0);

  if (length > 60) {
    return braces[0] +
           (base === '' ? '' : base + '\n ') +
           ' ' +
           output.join(',\n  ') +
           ' ' +
           braces[1];
  }

  return braces[0] + base + ' ' + output.join(', ') + ' ' + braces[1];
}


// NOTE: These type checking functions intentionally don't use `instanceof`
// because it is fragile and can be easily faked with `Object.create()`.
function isArray(ar) {
  return Array.isArray(ar);
}
exports.isArray = isArray;

function isBoolean(arg) {
  return typeof arg === 'boolean';
}
exports.isBoolean = isBoolean;

function isNull(arg) {
  return arg === null;
}
exports.isNull = isNull;

function isNullOrUndefined(arg) {
  return arg == null;
}
exports.isNullOrUndefined = isNullOrUndefined;

function isNumber(arg) {
  return typeof arg === 'number';
}
exports.isNumber = isNumber;

function isString(arg) {
  return typeof arg === 'string';
}
exports.isString = isString;

function isSymbol(arg) {
  return typeof arg === 'symbol';
}
exports.isSymbol = isSymbol;

function isUndefined(arg) {
  return arg === void 0;
}
exports.isUndefined = isUndefined;

function isRegExp(re) {
  return isObject(re) && objectToString(re) === '[object RegExp]';
}
exports.isRegExp = isRegExp;

function isObject(arg) {
  return typeof arg === 'object' && arg !== null;
}
exports.isObject = isObject;

function isDate(d) {
  return isObject(d) && objectToString(d) === '[object Date]';
}
exports.isDate = isDate;

function isError(e) {
  return isObject(e) &&
      (objectToString(e) === '[object Error]' || e instanceof Error);
}
exports.isError = isError;

function isFunction(arg) {
  return typeof arg === 'function';
}
exports.isFunction = isFunction;

function isPrimitive(arg) {
  return arg === null ||
         typeof arg === 'boolean' ||
         typeof arg === 'number' ||
         typeof arg === 'string' ||
         typeof arg === 'symbol' ||  // ES6 symbol
         typeof arg === 'undefined';
}
exports.isPrimitive = isPrimitive;

exports.isBuffer = __webpack_require__(172);

function objectToString(o) {
  return Object.prototype.toString.call(o);
}


function pad(n) {
  return n < 10 ? '0' + n.toString(10) : n.toString(10);
}


var months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep',
              'Oct', 'Nov', 'Dec'];

// 26 Feb 16:19:34
function timestamp() {
  var d = new Date();
  var time = [pad(d.getHours()),
              pad(d.getMinutes()),
              pad(d.getSeconds())].join(':');
  return [d.getDate(), months[d.getMonth()], time].join(' ');
}


// log is just a thin wrapper to console.log that prepends a timestamp
exports.log = function() {
  console.log('%s - %s', timestamp(), exports.format.apply(exports, arguments));
};


/**
 * Inherit the prototype methods from one constructor into another.
 *
 * The Function.prototype.inherits from lang.js rewritten as a standalone
 * function (not on Function.prototype). NOTE: If this file is to be loaded
 * during bootstrapping this function needs to be rewritten using some native
 * functions as prototype setup using normal JavaScript does not work as
 * expected during bootstrapping (see mirror.js in r114903).
 *
 * @param {function} ctor Constructor function which needs to inherit the
 *     prototype.
 * @param {function} superCtor Constructor function to inherit prototype from.
 */
exports.inherits = __webpack_require__(173);

exports._extend = function(origin, add) {
  // Don't do anything if add isn't an object
  if (!add || !isObject(add)) return origin;

  var keys = Object.keys(add);
  var i = keys.length;
  while (i--) {
    origin[keys[i]] = add[keys[i]];
  }
  return origin;
};

function hasOwnProperty(obj, prop) {
  return Object.prototype.hasOwnProperty.call(obj, prop);
}

/* WEBPACK VAR INJECTION */}.call(exports, __webpack_require__(19), __webpack_require__(171)))

/***/ }),
/* 171 */
/***/ (function(module, exports) {

// shim for using process in browser
var process = module.exports = {};

// cached from whatever global is present so that test runners that stub it
// don't break things.  But we need to wrap it in a try catch in case it is
// wrapped in strict mode code which doesn't define any globals.  It's inside a
// function because try/catches deoptimize in certain engines.

var cachedSetTimeout;
var cachedClearTimeout;

function defaultSetTimout() {
    throw new Error('setTimeout has not been defined');
}
function defaultClearTimeout () {
    throw new Error('clearTimeout has not been defined');
}
(function () {
    try {
        if (typeof setTimeout === 'function') {
            cachedSetTimeout = setTimeout;
        } else {
            cachedSetTimeout = defaultSetTimout;
        }
    } catch (e) {
        cachedSetTimeout = defaultSetTimout;
    }
    try {
        if (typeof clearTimeout === 'function') {
            cachedClearTimeout = clearTimeout;
        } else {
            cachedClearTimeout = defaultClearTimeout;
        }
    } catch (e) {
        cachedClearTimeout = defaultClearTimeout;
    }
} ())
function runTimeout(fun) {
    if (cachedSetTimeout === setTimeout) {
        //normal enviroments in sane situations
        return setTimeout(fun, 0);
    }
    // if setTimeout wasn't available but was latter defined
    if ((cachedSetTimeout === defaultSetTimout || !cachedSetTimeout) && setTimeout) {
        cachedSetTimeout = setTimeout;
        return setTimeout(fun, 0);
    }
    try {
        // when when somebody has screwed with setTimeout but no I.E. maddness
        return cachedSetTimeout(fun, 0);
    } catch(e){
        try {
            // When we are in I.E. but the script has been evaled so I.E. doesn't trust the global object when called normally
            return cachedSetTimeout.call(null, fun, 0);
        } catch(e){
            // same as above but when it's a version of I.E. that must have the global object for 'this', hopfully our context correct otherwise it will throw a global error
            return cachedSetTimeout.call(this, fun, 0);
        }
    }


}
function runClearTimeout(marker) {
    if (cachedClearTimeout === clearTimeout) {
        //normal enviroments in sane situations
        return clearTimeout(marker);
    }
    // if clearTimeout wasn't available but was latter defined
    if ((cachedClearTimeout === defaultClearTimeout || !cachedClearTimeout) && clearTimeout) {
        cachedClearTimeout = clearTimeout;
        return clearTimeout(marker);
    }
    try {
        // when when somebody has screwed with setTimeout but no I.E. maddness
        return cachedClearTimeout(marker);
    } catch (e){
        try {
            // When we are in I.E. but the script has been evaled so I.E. doesn't  trust the global object when called normally
            return cachedClearTimeout.call(null, marker);
        } catch (e){
            // same as above but when it's a version of I.E. that must have the global object for 'this', hopfully our context correct otherwise it will throw a global error.
            // Some versions of I.E. have different rules for clearTimeout vs setTimeout
            return cachedClearTimeout.call(this, marker);
        }
    }



}
var queue = [];
var draining = false;
var currentQueue;
var queueIndex = -1;

function cleanUpNextTick() {
    if (!draining || !currentQueue) {
        return;
    }
    draining = false;
    if (currentQueue.length) {
        queue = currentQueue.concat(queue);
    } else {
        queueIndex = -1;
    }
    if (queue.length) {
        drainQueue();
    }
}

function drainQueue() {
    if (draining) {
        return;
    }
    var timeout = runTimeout(cleanUpNextTick);
    draining = true;

    var len = queue.length;
    while(len) {
        currentQueue = queue;
        queue = [];
        while (++queueIndex < len) {
            if (currentQueue) {
                currentQueue[queueIndex].run();
            }
        }
        queueIndex = -1;
        len = queue.length;
    }
    currentQueue = null;
    draining = false;
    runClearTimeout(timeout);
}

process.nextTick = function (fun) {
    var args = new Array(arguments.length - 1);
    if (arguments.length > 1) {
        for (var i = 1; i < arguments.length; i++) {
            args[i - 1] = arguments[i];
        }
    }
    queue.push(new Item(fun, args));
    if (queue.length === 1 && !draining) {
        runTimeout(drainQueue);
    }
};

// v8 likes predictible objects
function Item(fun, array) {
    this.fun = fun;
    this.array = array;
}
Item.prototype.run = function () {
    this.fun.apply(null, this.array);
};
process.title = 'browser';
process.browser = true;
process.env = {};
process.argv = [];
process.version = ''; // empty string to avoid regexp issues
process.versions = {};

function noop() {}

process.on = noop;
process.addListener = noop;
process.once = noop;
process.off = noop;
process.removeListener = noop;
process.removeAllListeners = noop;
process.emit = noop;
process.prependListener = noop;
process.prependOnceListener = noop;

process.listeners = function (name) { return [] }

process.binding = function (name) {
    throw new Error('process.binding is not supported');
};

process.cwd = function () { return '/' };
process.chdir = function (dir) {
    throw new Error('process.chdir is not supported');
};
process.umask = function() { return 0; };


/***/ }),
/* 172 */
/***/ (function(module, exports) {

module.exports = function isBuffer(arg) {
  return arg && typeof arg === 'object'
    && typeof arg.copy === 'function'
    && typeof arg.fill === 'function'
    && typeof arg.readUInt8 === 'function';
}

/***/ }),
/* 173 */
/***/ (function(module, exports) {

if (typeof Object.create === 'function') {
  // implementation from standard node.js 'util' module
  module.exports = function inherits(ctor, superCtor) {
    ctor.super_ = superCtor
    ctor.prototype = Object.create(superCtor.prototype, {
      constructor: {
        value: ctor,
        enumerable: false,
        writable: true,
        configurable: true
      }
    });
  };
} else {
  // old school shim for old browsers
  module.exports = function inherits(ctor, superCtor) {
    ctor.super_ = superCtor
    var TempCtor = function () {}
    TempCtor.prototype = superCtor.prototype
    ctor.prototype = new TempCtor()
    ctor.prototype.constructor = ctor
  }
}


/***/ }),
/* 174 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


/**
 * Module dependencies
 * @ignore
 */

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

var JSONPatch = __webpack_require__(97);

/**
 * JSONDocument
 *
 * @class
 * JSONDocument is a high level interface that binds together all other features of
 * this package and provides the principle method of data modeling.
 */

var JSONDocument = function () {
  _createClass(JSONDocument, null, [{
    key: 'schema',


    /**
     * Schema
     */
    get: function get() {
      throw new Error('Schema must be defined by classes extending JSONDocument');
    }

    /**
     * Constructor
     *
     * @param {Object} data
     * @param {Object} options
     */

  }]);

  function JSONDocument() {
    var data = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {};
    var options = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : {};

    _classCallCheck(this, JSONDocument);

    this.initialize(data, options);
  }

  /**
   * Initialize
   *
   * @param {Object} data
   * @param {Object} options
   */


  _createClass(JSONDocument, [{
    key: 'initialize',
    value: function initialize() {
      var data = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {};
      var options = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : {};
      var schema = this.constructor.schema;

      schema.initialize(this, data, options);
    }

    /**
     * Validate
     *
     * @param {JSONSchema} alternate - OPTIONAL alternate schema
     * @returns {Object}
     */

  }, {
    key: 'validate',
    value: function validate(alternate) {
      var schema = this.constructor.schema;

      return (alternate || schema).validate(this);
    }

    /**
     * Patch
     *
     * @param {Array} ops
     */

  }, {
    key: 'patch',
    value: function patch(ops) {
      var patch = new JSONPatch(ops);
      patch.apply(this);
    }

    /**
     * Select
     */

  }, {
    key: 'select',
    value: function select() {}

    /**
     * Project
     *
     * @description
     * Given a mapping, return an object projected from the current instance.
     *
     * @example
     * let schema = new JSONSchema({
     *   properties: {
     *     foo: { type: 'Array' }
     *   }
     * })
     *
     * let mapping = new JSONMapping({
     *   '/foo/0': '/bar/baz'
     * })
     *
     * class FooTracker extends JSONDocument {
     *   static get schema () { return schema }
     * }
     *
     * let instance = new FooTracker({ foo: ['qux'] })
     * instance.project(mapping)
     * // => { bar: { baz: 'qux' } }
     *
     * @param {JSONMapping} mapping
     * @return {Object}
     */

  }, {
    key: 'project',
    value: function project(mapping) {
      return mapping.project(this);
    }

    /**
     * Serialize
     *
     * @param {Object} object
     * @returns {string}
     */

  }], [{
    key: 'serialize',
    value: function serialize(object) {
      return JSON.stringify(object);
    }

    /**
     * Deserialize
     *
     * @param {string} data
     * @return {*}
     */

  }, {
    key: 'deserialize',
    value: function deserialize(data) {
      try {
        return JSON.parse(data);
      } catch (e) {
        throw new Error('Failed to parse JSON');
      }
    }
  }]);

  return JSONDocument;
}();

/**
 * Export
 */


module.exports = JSONDocument;

/***/ }),
/* 175 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


/**
 * Module dependencies
 * @ignore
 */

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

var JSONPointer = __webpack_require__(64);

/**
 * JSONPointer mode
 */
var RECOVER = 1;

/**
 * JSONMapping
 *
 * @class
 * Defines a means to declaratively translate between object
 * representations using JSON Pointer syntax.
 */

var JSONMapping = function () {

  /**
   * Constructor
   *
   * @description Translate pointers from JSON Strings into Pointer objects
   * @param {Object} mapping
   */
  function JSONMapping(mapping) {
    var _this = this;

    _classCallCheck(this, JSONMapping);

    Object.defineProperty(this, 'mapping', {
      enumerable: false,
      value: new Map()
    });

    Object.keys(mapping).forEach(function (key) {
      var value = mapping[key];
      _this.mapping.set(new JSONPointer(key, RECOVER), new JSONPointer(value, RECOVER));
    });
  }

  /**
   * Map
   *
   * @description Assign values from source to target by reading the mapping
   * from right to left.
   * @param {Object} target
   * @param {Object} source
   */


  _createClass(JSONMapping, [{
    key: 'map',
    value: function map(target, source) {
      this.mapping.forEach(function (right, left) {
        left.add(target, right.get(source));
      });
    }

    /**
     * Project
     *
     * @description Assign values from source to target by reading the mapping
     * from left to right.
     * @param {Object} source
     * @param {Object} target
     */

  }, {
    key: 'project',
    value: function project(source, target) {
      this.mapping.forEach(function (right, left) {
        right.add(target, left.get(source));
      });
    }
  }]);

  return JSONMapping;
}();

/**
 * Exports
 */


module.exports = JSONMapping;

/***/ }),
/* 176 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


/**
 * Module dependencies
 * @ignore
 */

var _typeof = typeof Symbol === "function" && typeof Symbol.iterator === "symbol" ? function (obj) { return typeof obj; } : function (obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj; };

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

function _defineProperty(obj, key, value) { if (key in obj) { Object.defineProperty(obj, key, { value: value, enumerable: true, configurable: true, writable: true }); } else { obj[key] = value; } return obj; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

var Initializer = __webpack_require__(96);
var Validator = __webpack_require__(98);

/**
 * JSONSchema
 *
 * @class
 * Compiles JSON Schema documents to an object with object initialization
 * and validation methods.
 */

var JSONSchema = function () {

  /**
   * Constructor
   *
   * @param {Object} schema
   */
  function JSONSchema(schema) {
    _classCallCheck(this, JSONSchema);

    // TODO: optionally parse JSON string?
    Object.assign(this, schema);

    // add schema-derived initialize and validate methods
    Object.defineProperties(this, {
      initialize: {
        enumerable: false,
        writeable: false,
        value: Initializer.compile(schema)
      },
      validate: {
        enumerable: false,
        writeable: false,
        value: Validator.compile(schema)
      }
    });
  }

  /**
   * Extend
   *
   * @description
   * ...
   * Dear future,
   *
   * This function was meticulously plagiarized from some curious amalgam of
   * stackoverflow posts whilst dozing off at my keyboard, too deprived of REM-
   * sleep to recurse unassisted. If it sucks, you have only yourself to blame.
   *
   * Goodnight.
   *
   * @param {Object} schema
   * @returns {JSONSchema}
   */


  _createClass(JSONSchema, [{
    key: 'extend',
    value: function extend(schema) {
      function isObject(data) {
        return data && (typeof data === 'undefined' ? 'undefined' : _typeof(data)) === 'object' && data !== null && !Array.isArray(data);
      }

      function extender(target, source) {
        var result = Object.assign({}, target);
        if (isObject(target) && isObject(source)) {
          Object.keys(source).forEach(function (key) {
            if (isObject(source[key])) {
              if (!(key in target)) {
                Object.assign(result, _defineProperty({}, key, source[key]));
              } else {
                result[key] = extender(target[key], source[key]);
              }
            } else {
              Object.assign(result, _defineProperty({}, key, source[key]));
            }
          });
        }
        return result;
      }

      var descriptor = extender(this, schema);
      return new JSONSchema(descriptor);
    }
  }]);

  return JSONSchema;
}();

/**
 * Export
 */


module.exports = JSONSchema;

/***/ }),
/* 177 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";
/* WEBPACK VAR INJECTION */(function(Buffer) {
var pad_string_1 = __webpack_require__(181);
function encode(input, encoding) {
    if (encoding === void 0) { encoding = "utf8"; }
    if (Buffer.isBuffer(input)) {
        return fromBase64(input.toString("base64"));
    }
    return fromBase64(new Buffer(input, encoding).toString("base64"));
}
;
function decode(base64url, encoding) {
    if (encoding === void 0) { encoding = "utf8"; }
    return new Buffer(toBase64(base64url), "base64").toString(encoding);
}
function toBase64(base64url) {
    base64url = base64url.toString();
    return pad_string_1.default(base64url)
        .replace(/\-/g, "+")
        .replace(/_/g, "/");
}
function fromBase64(base64) {
    return base64
        .replace(/=/g, "")
        .replace(/\+/g, "-")
        .replace(/\//g, "_");
}
function toBuffer(base64url) {
    return new Buffer(toBase64(base64url), "base64");
}
var base64url = encode;
base64url.encode = encode;
base64url.decode = decode;
base64url.toBase64 = toBase64;
base64url.fromBase64 = fromBase64;
base64url.toBuffer = toBuffer;
Object.defineProperty(exports, "__esModule", { value: true });
exports.default = base64url;

/* WEBPACK VAR INJECTION */}.call(exports, __webpack_require__(22).Buffer))

/***/ }),
/* 178 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


exports.byteLength = byteLength
exports.toByteArray = toByteArray
exports.fromByteArray = fromByteArray

var lookup = []
var revLookup = []
var Arr = typeof Uint8Array !== 'undefined' ? Uint8Array : Array

var code = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
for (var i = 0, len = code.length; i < len; ++i) {
  lookup[i] = code[i]
  revLookup[code.charCodeAt(i)] = i
}

// Support decoding URL-safe base64 strings, as Node.js does.
// See: https://en.wikipedia.org/wiki/Base64#URL_applications
revLookup['-'.charCodeAt(0)] = 62
revLookup['_'.charCodeAt(0)] = 63

function getLens (b64) {
  var len = b64.length

  if (len % 4 > 0) {
    throw new Error('Invalid string. Length must be a multiple of 4')
  }

  // Trim off extra bytes after placeholder bytes are found
  // See: https://github.com/beatgammit/base64-js/issues/42
  var validLen = b64.indexOf('=')
  if (validLen === -1) validLen = len

  var placeHoldersLen = validLen === len
    ? 0
    : 4 - (validLen % 4)

  return [validLen, placeHoldersLen]
}

// base64 is 4/3 + up to two characters of the original data
function byteLength (b64) {
  var lens = getLens(b64)
  var validLen = lens[0]
  var placeHoldersLen = lens[1]
  return ((validLen + placeHoldersLen) * 3 / 4) - placeHoldersLen
}

function _byteLength (b64, validLen, placeHoldersLen) {
  return ((validLen + placeHoldersLen) * 3 / 4) - placeHoldersLen
}

function toByteArray (b64) {
  var tmp
  var lens = getLens(b64)
  var validLen = lens[0]
  var placeHoldersLen = lens[1]

  var arr = new Arr(_byteLength(b64, validLen, placeHoldersLen))

  var curByte = 0

  // if there are placeholders, only get up to the last complete 4 chars
  var len = placeHoldersLen > 0
    ? validLen - 4
    : validLen

  for (var i = 0; i < len; i += 4) {
    tmp =
      (revLookup[b64.charCodeAt(i)] << 18) |
      (revLookup[b64.charCodeAt(i + 1)] << 12) |
      (revLookup[b64.charCodeAt(i + 2)] << 6) |
      revLookup[b64.charCodeAt(i + 3)]
    arr[curByte++] = (tmp >> 16) & 0xFF
    arr[curByte++] = (tmp >> 8) & 0xFF
    arr[curByte++] = tmp & 0xFF
  }

  if (placeHoldersLen === 2) {
    tmp =
      (revLookup[b64.charCodeAt(i)] << 2) |
      (revLookup[b64.charCodeAt(i + 1)] >> 4)
    arr[curByte++] = tmp & 0xFF
  }

  if (placeHoldersLen === 1) {
    tmp =
      (revLookup[b64.charCodeAt(i)] << 10) |
      (revLookup[b64.charCodeAt(i + 1)] << 4) |
      (revLookup[b64.charCodeAt(i + 2)] >> 2)
    arr[curByte++] = (tmp >> 8) & 0xFF
    arr[curByte++] = tmp & 0xFF
  }

  return arr
}

function tripletToBase64 (num) {
  return lookup[num >> 18 & 0x3F] +
    lookup[num >> 12 & 0x3F] +
    lookup[num >> 6 & 0x3F] +
    lookup[num & 0x3F]
}

function encodeChunk (uint8, start, end) {
  var tmp
  var output = []
  for (var i = start; i < end; i += 3) {
    tmp =
      ((uint8[i] << 16) & 0xFF0000) +
      ((uint8[i + 1] << 8) & 0xFF00) +
      (uint8[i + 2] & 0xFF)
    output.push(tripletToBase64(tmp))
  }
  return output.join('')
}

function fromByteArray (uint8) {
  var tmp
  var len = uint8.length
  var extraBytes = len % 3 // if we have 1 byte left, pad 2 bytes
  var parts = []
  var maxChunkLength = 16383 // must be multiple of 3

  // go through the array every three bytes, we'll deal with trailing stuff later
  for (var i = 0, len2 = len - extraBytes; i < len2; i += maxChunkLength) {
    parts.push(encodeChunk(
      uint8, i, (i + maxChunkLength) > len2 ? len2 : (i + maxChunkLength)
    ))
  }

  // pad the end with zeros, but make sure to not forget the extra bytes
  if (extraBytes === 1) {
    tmp = uint8[len - 1]
    parts.push(
      lookup[tmp >> 2] +
      lookup[(tmp << 4) & 0x3F] +
      '=='
    )
  } else if (extraBytes === 2) {
    tmp = (uint8[len - 2] << 8) + uint8[len - 1]
    parts.push(
      lookup[tmp >> 10] +
      lookup[(tmp >> 4) & 0x3F] +
      lookup[(tmp << 2) & 0x3F] +
      '='
    )
  }

  return parts.join('')
}


/***/ }),
/* 179 */
/***/ (function(module, exports) {

exports.read = function (buffer, offset, isLE, mLen, nBytes) {
  var e, m
  var eLen = (nBytes * 8) - mLen - 1
  var eMax = (1 << eLen) - 1
  var eBias = eMax >> 1
  var nBits = -7
  var i = isLE ? (nBytes - 1) : 0
  var d = isLE ? -1 : 1
  var s = buffer[offset + i]

  i += d

  e = s & ((1 << (-nBits)) - 1)
  s >>= (-nBits)
  nBits += eLen
  for (; nBits > 0; e = (e * 256) + buffer[offset + i], i += d, nBits -= 8) {}

  m = e & ((1 << (-nBits)) - 1)
  e >>= (-nBits)
  nBits += mLen
  for (; nBits > 0; m = (m * 256) + buffer[offset + i], i += d, nBits -= 8) {}

  if (e === 0) {
    e = 1 - eBias
  } else if (e === eMax) {
    return m ? NaN : ((s ? -1 : 1) * Infinity)
  } else {
    m = m + Math.pow(2, mLen)
    e = e - eBias
  }
  return (s ? -1 : 1) * m * Math.pow(2, e - mLen)
}

exports.write = function (buffer, value, offset, isLE, mLen, nBytes) {
  var e, m, c
  var eLen = (nBytes * 8) - mLen - 1
  var eMax = (1 << eLen) - 1
  var eBias = eMax >> 1
  var rt = (mLen === 23 ? Math.pow(2, -24) - Math.pow(2, -77) : 0)
  var i = isLE ? 0 : (nBytes - 1)
  var d = isLE ? 1 : -1
  var s = value < 0 || (value === 0 && 1 / value < 0) ? 1 : 0

  value = Math.abs(value)

  if (isNaN(value) || value === Infinity) {
    m = isNaN(value) ? 1 : 0
    e = eMax
  } else {
    e = Math.floor(Math.log(value) / Math.LN2)
    if (value * (c = Math.pow(2, -e)) < 1) {
      e--
      c *= 2
    }
    if (e + eBias >= 1) {
      value += rt / c
    } else {
      value += rt * Math.pow(2, 1 - eBias)
    }
    if (value * c >= 2) {
      e++
      c /= 2
    }

    if (e + eBias >= eMax) {
      m = 0
      e = eMax
    } else if (e + eBias >= 1) {
      m = ((value * c) - 1) * Math.pow(2, mLen)
      e = e + eBias
    } else {
      m = value * Math.pow(2, eBias - 1) * Math.pow(2, mLen)
      e = 0
    }
  }

  for (; mLen >= 8; buffer[offset + i] = m & 0xff, i += d, m /= 256, mLen -= 8) {}

  e = (e << mLen) | m
  eLen += mLen
  for (; eLen > 0; buffer[offset + i] = e & 0xff, i += d, e /= 256, eLen -= 8) {}

  buffer[offset + i - d] |= s * 128
}


/***/ }),
/* 180 */
/***/ (function(module, exports) {

var toString = {}.toString;

module.exports = Array.isArray || function (arr) {
  return toString.call(arr) == '[object Array]';
};


/***/ }),
/* 181 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";
/* WEBPACK VAR INJECTION */(function(Buffer) {
function padString(input) {
    var segmentLength = 4;
    var stringLength = input.length;
    var diff = stringLength % segmentLength;
    if (!diff) {
        return input;
    }
    var position = stringLength;
    var padLength = segmentLength - diff;
    var paddedStringLength = stringLength + padLength;
    var buffer = new Buffer(paddedStringLength);
    buffer.write(input);
    while (padLength--) {
        buffer.write("=", position++);
    }
    return buffer.toString();
}
Object.defineProperty(exports, "__esModule", { value: true });
exports.default = padString;

/* WEBPACK VAR INJECTION */}.call(exports, __webpack_require__(22).Buffer))

/***/ }),
/* 182 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


/**
 * Local dependencies
 */
var None = __webpack_require__(183);
var HMAC = __webpack_require__(184);
var RSASSA_PKCS1_v1_5 = __webpack_require__(186);
var SupportedAlgorithms = __webpack_require__(187

/**
 * Register Supported Algorithms
 */
);var supportedAlgorithms = new SupportedAlgorithms();

/**
 * Sign
 */
supportedAlgorithms.define('HS256', 'sign', new HMAC({
  name: 'HMAC',
  hash: {
    name: 'SHA-256'
  }
}));

supportedAlgorithms.define('HS384', 'sign', new HMAC({
  name: 'HMAC',
  hash: {
    name: 'SHA-384'
  }
}));

supportedAlgorithms.define('HS512', 'sign', new HMAC({
  name: 'HMAC',
  hash: {
    name: 'SHA-512'
  }
}));

supportedAlgorithms.define('RS256', 'sign', new RSASSA_PKCS1_v1_5({
  name: 'RSASSA-PKCS1-v1_5',
  hash: {
    name: 'SHA-256'
  }
}));

supportedAlgorithms.define('RS384', 'sign', new RSASSA_PKCS1_v1_5({
  name: 'RSASSA-PKCS1-v1_5',
  hash: {
    name: 'SHA-384'
  }
}));

supportedAlgorithms.define('RS512', 'sign', new RSASSA_PKCS1_v1_5({
  name: 'RSASSA-PKCS1-v1_5',
  hash: {
    name: 'SHA-512'
  }
})
//supportedAlgorithms.define('ES256', 'sign', {})
//supportedAlgorithms.define('ES384', 'sign', {})
//supportedAlgorithms.define('ES512', 'sign', {})
//supportedAlgorithms.define('PS256', 'sign', {})
//supportedAlgorithms.define('PS384', 'sign', {})
//supportedAlgorithms.define('PS512', 'sign', {})

);supportedAlgorithms.define('none', 'sign', new None({
  // nothing goes here
})

/**
 * Verify
 */
);supportedAlgorithms.define('HS256', 'verify', new HMAC({
  name: 'HMAC',
  hash: {
    name: 'SHA-256'
  }
}));

supportedAlgorithms.define('HS384', 'verify', new HMAC({
  name: 'HMAC',
  hash: {
    name: 'SHA-384'
  }
}));

supportedAlgorithms.define('HS512', 'verify', new HMAC({
  name: 'HMAC',
  hash: {
    name: 'SHA-512'
  }
}));

supportedAlgorithms.define('RS256', 'verify', new RSASSA_PKCS1_v1_5({
  name: 'RSASSA-PKCS1-v1_5',
  hash: {
    name: 'SHA-256'
  }
}));

supportedAlgorithms.define('RS384', 'verify', new RSASSA_PKCS1_v1_5({
  name: 'RSASSA-PKCS1-v1_5',
  hash: {
    name: 'SHA-384'
  }
}));

supportedAlgorithms.define('RS512', 'verify', new RSASSA_PKCS1_v1_5({
  name: 'RSASSA-PKCS1-v1_5',
  hash: {
    name: 'SHA-512'
  }
})
//supportedAlgorithms.define('ES256', 'verify', {})
//supportedAlgorithms.define('ES384', 'verify', {})
//supportedAlgorithms.define('ES512', 'verify', {})
//supportedAlgorithms.define('PS256', 'verify', {})
//supportedAlgorithms.define('PS384', 'verify', {})
//supportedAlgorithms.define('PS512', 'verify', {})

);supportedAlgorithms.define('none', 'verify', new None({
  // nothing goes here
}));

supportedAlgorithms.define('RS256', 'importKey', new RSASSA_PKCS1_v1_5({
  name: 'RSASSA-PKCS1-v1_5',
  hash: {
    name: 'SHA-256'
  }
}));

supportedAlgorithms.define('RS384', 'importKey', new RSASSA_PKCS1_v1_5({
  name: 'RSASSA-PKCS1-v1_5',
  hash: {
    name: 'SHA-384'
  }
}));

supportedAlgorithms.define('RS512', 'importKey', new RSASSA_PKCS1_v1_5({
  name: 'RSASSA-PKCS1-v1_5',
  hash: {
    name: 'SHA-512'
  }
})

/**
 * Export
 */
);module.exports = supportedAlgorithms;

/***/ }),
/* 183 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

/**
 * None
 */
var None = function () {
  function None() {
    _classCallCheck(this, None);
  }

  _createClass(None, [{
    key: 'sign',

    /**
     * sign
     */
    value: function sign() {
      return Promise.resolve('');
    }

    /**
     * verify
     */

  }, {
    key: 'verify',
    value: function verify() {
      // this will never get called. but you looked.
    }
  }]);

  return None;
}();

/**
 * Export
 */


module.exports = None;

/***/ }),
/* 184 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";
/* WEBPACK VAR INJECTION */(function(Buffer) {

/**
 * Dependencies
 * @ignore
 */

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

var base64url = __webpack_require__(14);
var crypto = __webpack_require__(40);
var TextEncoder = __webpack_require__(99

/**
 * HMAC with SHA-2 Functions
 */
);
var HMAC = function () {

  /**
   * Constructor
   *
   * @param {string} bitlength
   */
  function HMAC(params) {
    _classCallCheck(this, HMAC);

    this.params = params;
  }

  /**
   * Sign
   *
   * @description
   * Generate a hash-based message authentication code for a
   * given input and key. Enforce the key length is equal to
   * or greater than the bitlength.
   *
   * @param {CryptoKey} key
   * @param {string} data
   *
   * @returns {string}
   */


  _createClass(HMAC, [{
    key: 'sign',
    value: function sign(key, data) {
      var algorithm = this.params;

      // TODO: validate key length

      data = new TextEncoder().encode(data);

      return crypto.subtle.sign(algorithm, key, data).then(function (signature) {
        return base64url(Buffer.from(signature));
      });
    }

    /**
     * Verify
     *
     * @description
     * Verify a digital signature for a given input and private key.
     *
     * @param {CryptoKey} key
     * @param {string} signature
     * @param {string} data
     *
     * @returns {Boolean}
     */

  }, {
    key: 'verify',
    value: function verify(key, signature, data) {
      var algorithm = this.params;

      if (typeof signature === 'string') {
        signature = Uint8Array.from(base64url.toBuffer(signature));
      }

      if (typeof data === 'string') {
        data = new TextEncoder().encode(data);
      }

      return crypto.subtle.verify(algorithm, key, signature, data);
    }

    /**
     * Assert Sufficient Key Length
     *
     * @description Assert that the key length is sufficient
     * @param {string} key
     */

  }, {
    key: 'assertSufficientKeyLength',
    value: function assertSufficientKeyLength(key) {
      if (key.length < this.bitlength) {
        throw new Error('The key is too short.');
      }
    }
  }]);

  return HMAC;
}();

/**
 * Export
 */


module.exports = HMAC;
/* WEBPACK VAR INJECTION */}.call(exports, __webpack_require__(22).Buffer))

/***/ }),
/* 185 */
/***/ (function(module, exports) {

module.exports = __WEBPACK_EXTERNAL_MODULE_185__;

/***/ }),
/* 186 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";
/* WEBPACK VAR INJECTION */(function(Buffer) {

/**
 * Dependencies
 * @ignore
 */

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

var base64url = __webpack_require__(14);
var crypto = __webpack_require__(40);
var TextEncoder = __webpack_require__(99

/**
 * RSASSA-PKCS1-v1_5
 */
);
var RSASSA_PKCS1_v1_5 = function () {

  /**
   * constructor
   *
   * @param {string} bitlength
   */
  function RSASSA_PKCS1_v1_5(params) {
    _classCallCheck(this, RSASSA_PKCS1_v1_5);

    this.params = params;
  }

  /**
   * sign
   *
   * @description
   * Generate a digital signature for a given input and private key.
   *
   * @param {CryptoKey} key
   * @param {BufferSource} data
   *
   * @returns {Promise}
   */


  _createClass(RSASSA_PKCS1_v1_5, [{
    key: 'sign',
    value: function sign(key, data) {
      var algorithm = this.params;

      // TODO
      //if (!this.sufficientKeySize()) {
      //  return Promise.reject(
      //    new Error(
      //      'A key size of 2048 bits or larger must be used with RSASSA-PKCS1-v1_5'
      //    )
      //  )
      //}

      data = new TextEncoder().encode(data);

      return crypto.subtle.sign(algorithm, key, data).then(function (signature) {
        return base64url(Buffer.from(signature));
      });
    }

    /**
     * verify
     *
     * @description
     * Verify a digital signature for a given input and private key.
     *
     * @param {CryptoKey} key
     * @param {BufferSource} signature
     * @param {BufferSource} data
     *
     * @returns {Promise}
     */

  }, {
    key: 'verify',
    value: function verify(key, signature, data) {
      var algorithm = this.params;

      if (typeof signature === 'string') {
        signature = Uint8Array.from(base64url.toBuffer(signature));
      }

      if (typeof data === 'string') {
        data = new TextEncoder().encode(data);
      }
      // ...

      return crypto.subtle.verify(algorithm, key, signature, data);
    }

    /**
     * importKey
     *
     * @param {JWK} key
     * @returns {Promise}
     */

  }, {
    key: 'importKey',
    value: function importKey(key) {
      var jwk = Object.assign({}, key);
      var algorithm = this.params;
      var usages = key['key_ops'] || [];

      if (key.use === 'sig') {
        usages.push('verify');
      }

      if (key.use === 'enc') {
        // TODO: handle encryption keys
        return Promise.resolve(key);
      }

      if (key.key_ops) {
        usages = key.key_ops;
      }

      return crypto.subtle.importKey('jwk', jwk, algorithm, true, usages).then(function (cryptoKey) {
        Object.defineProperty(jwk, 'cryptoKey', {
          enumerable: false,
          value: cryptoKey
        });

        return jwk;
      });
    }
  }]);

  return RSASSA_PKCS1_v1_5;
}();

/**
 * Export
 */


module.exports = RSASSA_PKCS1_v1_5;
/* WEBPACK VAR INJECTION */}.call(exports, __webpack_require__(22).Buffer))

/***/ }),
/* 187 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

/**
 * Dependencies
 */
var NotSupportedError = __webpack_require__(100

/**
 * Operations
 */
);var operations = ['sign', 'verify', 'encrypt', 'decrypt', 'importKey'];

/**
 * SupportedAlgorithms
 */

var SupportedAlgorithms = function () {

  /**
   * constructor
   */
  function SupportedAlgorithms() {
    var _this = this;

    _classCallCheck(this, SupportedAlgorithms);

    operations.forEach(function (op) {
      _this[op] = {};
    });
  }

  /**
   * Supported Operations
   */


  _createClass(SupportedAlgorithms, [{
    key: 'define',


    /**
     * define
     *
     * @description
     * Register Web Crypto API algorithm parameter for an algorithm
     * and operation.
     *
     * @param {string} alg
     * @param {string} op
     * @param {Object} argument
     */
    value: function define(alg, op, argument) {
      var registeredAlgorithms = this[op];
      registeredAlgorithms[alg] = argument;
    }

    /**
     * normalize
     *
     * @description
     * Map JWA alg name to Web Crypto API algorithm parameter
     *
     * @param {string} op
     * @param {Object} alg
     *
     * @returns {Object}
     */

  }, {
    key: 'normalize',
    value: function normalize(op, alg) {
      var registeredAlgorithms = this[op];

      if (!registeredAlgorithms) {
        return new SyntaxError(); // what kind of error should this be?
      }

      var argument = registeredAlgorithms[alg];

      if (!argument) {
        return new NotSupportedError(alg);
      }

      return argument;
    }
  }], [{
    key: 'operations',
    get: function get() {
      return operations;
    }
  }]);

  return SupportedAlgorithms;
}();

/**
 * Export
 */


module.exports = SupportedAlgorithms;

/***/ }),
/* 188 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


/**
 * Package dependencies
 */
var _require = __webpack_require__(3

/**
 * Format extensions
 */
),
    Formats = _require.Formats;

Formats.register('StringOrURI', new RegExp());
Formats.register('NumericDate', new RegExp());
Formats.register('URI', new RegExp());
Formats.register('url', new RegExp());
Formats.register('base64', new RegExp());
Formats.register('base64url', new RegExp());
Formats.register('MediaType', new RegExp());

/***/ }),
/* 189 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


/**
 * Dependencies
 */

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _possibleConstructorReturn(self, call) { if (!self) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return call && (typeof call === "object" || typeof call === "function") ? call : self; }

function _inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }

var _require = __webpack_require__(3),
    JSONDocument = _require.JSONDocument;

var JWKSetSchema = __webpack_require__(104);
var JWK = __webpack_require__(103

/**
 * JWKSet
 *
 * @class
 * JWKSet represents a JSON Web Key Set as described in Section 5 of RFC 7517:
 * https://tools.ietf.org/html/rfc7517#section-5
 */
);
var JWKSet = function (_JSONDocument) {
  _inherits(JWKSet, _JSONDocument);

  function JWKSet() {
    _classCallCheck(this, JWKSet);

    return _possibleConstructorReturn(this, (JWKSet.__proto__ || Object.getPrototypeOf(JWKSet)).apply(this, arguments));
  }

  _createClass(JWKSet, null, [{
    key: 'importKeys',


    /**
     * importKeys
     */
    value: function importKeys(jwks) {
      var validation = this.schema.validate(jwks);

      if (!validation.valid) {
        return Promise.reject(new Error('Invalid JWKSet: ' + JSON.stringify(validation, null, 2)));
      }

      if (!jwks.keys) {
        return Promise.reject(new Error('Cannot import JWKSet: keys property is empty'));
      }

      var imported = void 0,
          importing = void 0;

      try {
        imported = new JWKSet(jwks);
        importing = jwks.keys.map(function (key) {
          return JWK.importKey(key);
        });
      } catch (err) {
        return Promise.reject(err);
      }

      return Promise.all(importing).then(function (keys) {
        imported.keys = keys;
        return imported;
      });
    }
  }, {
    key: 'schema',


    /**
     * schema
     */
    get: function get() {
      return JWKSetSchema;
    }
  }]);

  return JWKSet;
}(JSONDocument);

/**
 * Export
 */


module.exports = JWKSet;

/***/ }),
/* 190 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var _typeof = typeof Symbol === "function" && typeof Symbol.iterator === "symbol" ? function (obj) { return typeof obj; } : function (obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj; };

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _possibleConstructorReturn(self, call) { if (!self) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return call && (typeof call === "object" || typeof call === "function") ? call : self; }

function _inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; }

/**
 * Dependencies
 */
var base64url = __webpack_require__(14);

var _require = __webpack_require__(3),
    JSONDocument = _require.JSONDocument;

var JWTSchema = __webpack_require__(105);
var JWS = __webpack_require__(109);
var DataError = __webpack_require__(102

/**
 * JWT
 */
);
var JWT = function (_JSONDocument) {
  _inherits(JWT, _JSONDocument);

  function JWT() {
    _classCallCheck(this, JWT);

    return _possibleConstructorReturn(this, (JWT.__proto__ || Object.getPrototypeOf(JWT)).apply(this, arguments));
  }

  _createClass(JWT, [{
    key: 'isJWE',


    /**
     * isJWE
     */
    value: function isJWE() {
      return !!this.header.enc;
    }

    /**
     * resolveKeys
     */

  }, {
    key: 'resolveKeys',
    value: function resolveKeys(jwks) {
      var kid = this.header.kid;
      var keys = void 0,
          match = void 0;

      // treat an array as the "keys" property of a JWK Set
      if (Array.isArray(jwks)) {
        keys = jwks;
      }

      // presence of keys indicates object is a JWK Set
      if (jwks.keys) {
        keys = jwks.keys;
      }

      // wrap a plain object they is not a JWK Set in Array
      if (!jwks.keys && (typeof jwks === 'undefined' ? 'undefined' : _typeof(jwks)) === 'object') {
        keys = [jwks];
      }

      // ensure there are keys to search
      if (!keys) {
        throw new DataError('Invalid JWK argument');
      }

      // match by "kid" or "use" header
      if (kid) {
        match = keys.find(function (jwk) {
          return jwk.kid === kid;
        });
      } else {
        match = keys.find(function (jwk) {
          return jwk.use === 'sig';
        });
      }

      // assign matching key to JWT and return a boolean
      if (match) {
        this.key = match.cryptoKey;
        return true;
      } else {
        return false;
      }
    }

    /**
     * encode
     *
     * @description
     * Encode a JWT instance
     *
     * @returns {Promise}
     */

  }, {
    key: 'encode',
    value: function encode() {
      // validate
      var validation = this.validate();

      if (!validation.valid) {
        return Promise.reject(validation);
      }

      var token = this;

      if (this.isJWE()) {
        return JWE.encrypt(token);
      } else {
        return JWS.sign(token);
      }
    }

    /**
     * verify
     *
     * @description
     * Verify a decoded JWT instance
     *
     * @returns {Promise}
     */

  }, {
    key: 'verify',
    value: function verify() {
      var validation = this.validate();

      if (!validation.valid) {
        return Promise.reject(validation);
      }

      return JWS.verify(this);
    }
  }], [{
    key: 'decode',


    /**
     * decode
     *
     * @description
     * Decode a JSON Web Token
     *
     * @param {string} data
     * @returns {JWT}
     */
    value: function decode(data) {
      var ExtendedJWT = this;
      var jwt = void 0;

      if (typeof data !== 'string') {
        throw new DataError('JWT must be a string');
      }

      // JSON of Flattened JSON Serialization
      if (data.startsWith('{')) {
        try {
          data = JSON.parse(data, function () {});
        } catch (error) {
          throw new DataError('Invalid JWT serialization');
        }

        if (data.signatures || data.recipients) {
          data.serialization = 'json';
        } else {
          data.serialization = 'flattened';
        }

        jwt = new ExtendedJWT(data, { filter: false });

        // Compact Serialization
      } else {
        try {
          var serialization = 'compact';
          var segments = data.split('.');
          var length = segments.length;

          if (length !== 3 && length !== 5) {
            throw new Error('Malformed JWT');
          }

          var header = JSON.parse(base64url.decode(segments[0])

          // JSON Web Signature
          );if (length === 3) {
            var type = 'JWS';
            var payload = JSON.parse(base64url.decode(segments[1]));
            var signature = segments[2];

            jwt = new ExtendedJWT({ type: type, segments: segments, header: header, payload: payload, signature: signature, serialization: serialization }, { filter: false });
          }

          // JSON Web Encryption
          if (length === 5) {
            //let type = 'JWE'
            //let [protected, encryption_key, iv, ciphertext, tag] = segments

            //jwt = new ExtendedJWT({
            //  type,
            //  protected: base64url.decode(JSON.parse(protected)),
            //  encryption_key,
            //  iv,
            //  ciphertext,
            //  tag,
            //  serialization
            //})
          }
        } catch (error) {
          throw new DataError('Invalid JWT compact serialization');
        }
      }

      return jwt;
    }

    /**
     * encode
     *
     * @description
     * Encode a JSON Web Token
     *
     * @param {Object} header
     * @param {Object} payload
     * @param {CryptoKey} key
     *
     * @returns {Promise}
     */

  }, {
    key: 'encode',
    value: function encode(header, payload, key) {
      var jwt = new JWT(header, payload);
      return jwt.encode(key);
    }

    /**
     * verify
     *
     * @description
     *
     * @param {CryptoKey} key
     * @param {string} token
     *
     * @returns {Promise}
     */

  }, {
    key: 'verify',
    value: function verify(key, token) {
      var jwt = JWT.decode(token);
      jwt.key = key;
      return jwt.verify().then(function (verified) {
        return jwt;
      });
    }
  }, {
    key: 'schema',


    /**
     * schema
     */
    get: function get() {
      return JWTSchema;
    }
  }]);

  return JWT;
}(JSONDocument);

/**
 * Export
 */


module.exports = JWT;

/***/ }),
/* 191 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";
/* WEBPACK VAR INJECTION */(function(Buffer) {

var _keys = __webpack_require__(110);

var _keys2 = _interopRequireDefault(_keys);

var _slicedToArray2 = __webpack_require__(194);

var _slicedToArray3 = _interopRequireDefault(_slicedToArray2);

var _stringify = __webpack_require__(58);

var _stringify2 = _interopRequireDefault(_stringify);

var _from = __webpack_require__(111);

var _from2 = _interopRequireDefault(_from);

var _assign = __webpack_require__(30);

var _assign2 = _interopRequireDefault(_assign);

var _promise = __webpack_require__(13);

var _promise2 = _interopRequireDefault(_promise);

var _classCallCheck2 = __webpack_require__(20);

var _classCallCheck3 = _interopRequireDefault(_classCallCheck2);

var _createClass2 = __webpack_require__(21);

var _createClass3 = _interopRequireDefault(_createClass2);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/**
 * Dependencies
 */
var assert = __webpack_require__(63);
var base64url = __webpack_require__(14);
var crypto = __webpack_require__(40);

var _require = __webpack_require__(28),
    JWT = _require.JWT;

var FormUrlEncoded = __webpack_require__(112);

var _require2 = __webpack_require__(39),
    URL = _require2.URL;

/**
 * Authentication Request
 */


var AuthenticationRequest = function () {
  function AuthenticationRequest() {
    (0, _classCallCheck3.default)(this, AuthenticationRequest);
  }

  (0, _createClass3.default)(AuthenticationRequest, null, [{
    key: 'create',

    /**
     * create
     *
     * @description
     * Create a new authentication request with generated state and nonce,
     * validate presence of required parameters, serialize the request data and
     * persist it to the session, and return a promise for an authentication
     * request URI.
     *
     * @param {RelyingParty} rp – instance of RelyingParty
     * @param {Object} options - optional request parameters
     * @param {Object} session – reference to localStorage or other session object
     *
     * @returns {Promise}
     */
    value: function create(rp, options, session) {
      var provider = rp.provider,
          defaults = rp.defaults,
          registration = rp.registration;


      var issuer = void 0,
          endpoint = void 0,
          client = void 0,
          params = void 0;

      return _promise2.default.resolve().then(function () {
        // validate presence of OP configuration, RP client registration,
        // and default parameters
        assert(provider.configuration, 'RelyingParty provider OpenID Configuration is missing');

        assert(defaults.authenticate, 'RelyingParty default authentication parameters are missing');

        assert(registration, 'RelyingParty client registration is missing');

        // define basic elements of the request
        issuer = provider.configuration.issuer;
        endpoint = provider.configuration.authorization_endpoint;
        client = { client_id: registration.client_id };
        params = (0, _assign2.default)(defaults.authenticate, client, options);

        // validate presence of required configuration and parameters
        assert(issuer, 'Missing issuer in provider OpenID Configuration');

        assert(endpoint, 'Missing authorization_endpoint in provider OpenID Configuration');

        assert(params.scope, 'Missing scope parameter in authentication request');

        assert(params.response_type, 'Missing response_type parameter in authentication request');

        assert(params.client_id, 'Missing client_id parameter in authentication request');

        assert(params.redirect_uri, 'Missing redirect_uri parameter in authentication request');

        // generate state and nonce random octets
        params.state = (0, _from2.default)(crypto.getRandomValues(new Uint8Array(16)));
        params.nonce = (0, _from2.default)(crypto.getRandomValues(new Uint8Array(16)));

        // hash the state and nonce parameter values
        return _promise2.default.all([crypto.subtle.digest({ name: 'SHA-256' }, new Uint8Array(params.state)), crypto.subtle.digest({ name: 'SHA-256' }, new Uint8Array(params.nonce))]);
      })

      // serialize the request with original values, store in session by
      // encoded state param, and replace state/nonce octets with encoded
      // digests
      .then(function (digests) {
        var state = base64url(Buffer.from(digests[0]));
        var nonce = base64url(Buffer.from(digests[1]));
        var key = issuer + '/requestHistory/' + state;

        // store the request params for response validation
        // with serialized octet values for state and nonce
        session[key] = (0, _stringify2.default)(params);

        // replace state and nonce octets with base64url encoded digests
        params.state = state;
        params.nonce = nonce;
      }).then(function () {
        return AuthenticationRequest.generateSessionKeys();
      }).then(function (sessionKeys) {
        AuthenticationRequest.storeSessionKeys(sessionKeys, params, session);
      })

      // optionally encode a JWT with the request parameters
      // and replace params with `{ request: <jwt> }
      .then(function () {
        if (provider.configuration.request_parameter_supported) {
          return AuthenticationRequest.encodeRequestParams(params).then(function (encodedParams) {
            params = encodedParams;
          });
        }
      })

      // render the request URI and terminate the algorithm
      .then(function () {
        var url = new URL(endpoint);
        url.search = FormUrlEncoded.encode(params);

        return url.href;
      });
    }
  }, {
    key: 'generateSessionKeys',
    value: function generateSessionKeys() {
      return crypto.subtle.generateKey({
        name: "RSASSA-PKCS1-v1_5",
        modulusLength: 2048,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: { name: "SHA-256" }
      }, true, ["sign", "verify"]).then(function (keyPair) {
        // returns a keypair object
        return _promise2.default.all([crypto.subtle.exportKey('jwk', keyPair.publicKey), crypto.subtle.exportKey('jwk', keyPair.privateKey)]);
      }).then(function (jwkPair) {
        var _jwkPair = (0, _slicedToArray3.default)(jwkPair, 2),
            publicJwk = _jwkPair[0],
            privateJwk = _jwkPair[1];

        return { public: publicJwk, private: privateJwk };
      });
    }
  }, {
    key: 'storeSessionKeys',
    value: function storeSessionKeys(sessionKeys, params, session) {
      // store the private one in session, public one goes into params
      session['oidc.session.privateKey'] = (0, _stringify2.default)(sessionKeys.private);
      params.key = sessionKeys.public;
    }
  }, {
    key: 'encodeRequestParams',
    value: function encodeRequestParams(params) {
      var excludeParams = ['scope', 'client_id', 'response_type', 'state'];

      var keysToEncode = (0, _keys2.default)(params).filter(function (key) {
        return !excludeParams.includes(key);
      });

      var payload = {};

      keysToEncode.forEach(function (key) {
        payload[key] = params[key];
      });

      var requestParamJwt = new JWT({
        header: { alg: 'none' },
        payload: payload
      }, { filter: false });

      return requestParamJwt.encode().then(function (requestParamCompact) {
        var newParams = {
          scope: params['scope'],
          client_id: params['client_id'],
          response_type: params['response_type'],
          request: requestParamCompact,
          state: params['state']
        };

        return newParams;
      });
    }
  }]);
  return AuthenticationRequest;
}();

/**
 * Export
 */


module.exports = AuthenticationRequest;
/* WEBPACK VAR INJECTION */}.call(exports, __webpack_require__(22).Buffer))

/***/ }),
/* 192 */
/***/ (function(module, exports, __webpack_require__) {

__webpack_require__(193);
module.exports = __webpack_require__(0).Object.keys;


/***/ }),
/* 193 */
/***/ (function(module, exports, __webpack_require__) {

// 19.1.2.14 Object.keys(O)
var toObject = __webpack_require__(26);
var $keys = __webpack_require__(24);

__webpack_require__(89)('keys', function () {
  return function keys(it) {
    return $keys(toObject(it));
  };
});


/***/ }),
/* 194 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


exports.__esModule = true;

var _isIterable2 = __webpack_require__(195);

var _isIterable3 = _interopRequireDefault(_isIterable2);

var _getIterator2 = __webpack_require__(198);

var _getIterator3 = _interopRequireDefault(_getIterator2);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

exports.default = function () {
  function sliceIterator(arr, i) {
    var _arr = [];
    var _n = true;
    var _d = false;
    var _e = undefined;

    try {
      for (var _i = (0, _getIterator3.default)(arr), _s; !(_n = (_s = _i.next()).done); _n = true) {
        _arr.push(_s.value);

        if (i && _arr.length === i) break;
      }
    } catch (err) {
      _d = true;
      _e = err;
    } finally {
      try {
        if (!_n && _i["return"]) _i["return"]();
      } finally {
        if (_d) throw _e;
      }
    }

    return _arr;
  }

  return function (arr, i) {
    if (Array.isArray(arr)) {
      return arr;
    } else if ((0, _isIterable3.default)(Object(arr))) {
      return sliceIterator(arr, i);
    } else {
      throw new TypeError("Invalid attempt to destructure non-iterable instance");
    }
  };
}();

/***/ }),
/* 195 */
/***/ (function(module, exports, __webpack_require__) {

module.exports = { "default": __webpack_require__(196), __esModule: true };

/***/ }),
/* 196 */
/***/ (function(module, exports, __webpack_require__) {

__webpack_require__(36);
__webpack_require__(27);
module.exports = __webpack_require__(197);


/***/ }),
/* 197 */
/***/ (function(module, exports, __webpack_require__) {

var classof = __webpack_require__(52);
var ITERATOR = __webpack_require__(1)('iterator');
var Iterators = __webpack_require__(18);
module.exports = __webpack_require__(0).isIterable = function (it) {
  var O = Object(it);
  return O[ITERATOR] !== undefined
    || '@@iterator' in O
    // eslint-disable-next-line no-prototype-builtins
    || Iterators.hasOwnProperty(classof(O));
};


/***/ }),
/* 198 */
/***/ (function(module, exports, __webpack_require__) {

module.exports = { "default": __webpack_require__(199), __esModule: true };

/***/ }),
/* 199 */
/***/ (function(module, exports, __webpack_require__) {

__webpack_require__(36);
__webpack_require__(27);
module.exports = __webpack_require__(200);


/***/ }),
/* 200 */
/***/ (function(module, exports, __webpack_require__) {

var anObject = __webpack_require__(5);
var get = __webpack_require__(53);
module.exports = __webpack_require__(0).getIterator = function (it) {
  var iterFn = get(it);
  if (typeof iterFn != 'function') throw TypeError(it + ' is not iterable!');
  return anObject(iterFn.call(it));
};


/***/ }),
/* 201 */
/***/ (function(module, exports, __webpack_require__) {

__webpack_require__(27);
__webpack_require__(202);
module.exports = __webpack_require__(0).Array.from;


/***/ }),
/* 202 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";

var ctx = __webpack_require__(15);
var $export = __webpack_require__(4);
var toObject = __webpack_require__(26);
var call = __webpack_require__(75);
var isArrayIter = __webpack_require__(76);
var toLength = __webpack_require__(45);
var createProperty = __webpack_require__(203);
var getIterFn = __webpack_require__(53);

$export($export.S + $export.F * !__webpack_require__(81)(function (iter) { Array.from(iter); }), 'Array', {
  // 22.1.2.1 Array.from(arrayLike, mapfn = undefined, thisArg = undefined)
  from: function from(arrayLike /* , mapfn = undefined, thisArg = undefined */) {
    var O = toObject(arrayLike);
    var C = typeof this == 'function' ? this : Array;
    var aLen = arguments.length;
    var mapfn = aLen > 1 ? arguments[1] : undefined;
    var mapping = mapfn !== undefined;
    var index = 0;
    var iterFn = getIterFn(O);
    var length, result, step, iterator;
    if (mapping) mapfn = ctx(mapfn, aLen > 2 ? arguments[2] : undefined, 2);
    // if object isn't iterable or it's array with default iterator - use simple case
    if (iterFn != undefined && !(C == Array && isArrayIter(iterFn))) {
      for (iterator = iterFn.call(O), result = new C(); !(step = iterator.next()).done; index++) {
        createProperty(result, index, mapping ? call(iterator, mapfn, [step.value, index], true) : step.value);
      }
    } else {
      length = toLength(O.length);
      for (result = new C(length); length > index; index++) {
        createProperty(result, index, mapping ? mapfn(O[index], index) : O[index]);
      }
    }
    result.length = index;
    return result;
  }
});


/***/ }),
/* 203 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";

var $defineProperty = __webpack_require__(6);
var createDesc = __webpack_require__(23);

module.exports = function (object, index, value) {
  if (index in object) $defineProperty.f(object, index, createDesc(0, value));
  else object[index] = value;
};


/***/ }),
/* 204 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";
/* WEBPACK VAR INJECTION */(function(global, Buffer) {

var _assign = __webpack_require__(30);

var _assign2 = _interopRequireDefault(_assign);

var _promise = __webpack_require__(13);

var _promise2 = _interopRequireDefault(_promise);

var _classCallCheck2 = __webpack_require__(20);

var _classCallCheck3 = _interopRequireDefault(_classCallCheck2);

var _createClass2 = __webpack_require__(21);

var _createClass3 = _interopRequireDefault(_createClass2);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/**
 * Dependencies
 */
var _require = __webpack_require__(39),
    URL = _require.URL;

var assert = __webpack_require__(63);
var crypto = __webpack_require__(40);
var base64url = __webpack_require__(14);
var fetch = __webpack_require__(94);
var Headers = fetch.Headers ? fetch.Headers : global.Headers;
var FormUrlEncoded = __webpack_require__(112);
var IDToken = __webpack_require__(205);
var Session = __webpack_require__(207);
var onHttpError = __webpack_require__(113);

/**
 * AuthenticationResponse
 */

var AuthenticationResponse = function () {
  function AuthenticationResponse() {
    (0, _classCallCheck3.default)(this, AuthenticationResponse);
  }

  (0, _createClass3.default)(AuthenticationResponse, null, [{
    key: 'validateResponse',


    /**
     * validateResponse
     *
     * @description
     * Authentication response validation.
     *
     * @param {string|Object} response
     * @returns {Promise}
     */
    value: function validateResponse(response) {
      return _promise2.default.resolve(response).then(this.parseResponse).then(this.matchRequest).then(this.validateStateParam).then(this.errorResponse).then(this.validateResponseMode).then(this.validateResponseParams).then(this.exchangeAuthorizationCode).then(this.validateIDToken).then(Session.fromAuthResponse);
    }

    /**
     * parseResponse
     *
     * @param {Object} response
     * @returns {Promise}
     */

  }, {
    key: 'parseResponse',
    value: function parseResponse(response) {
      var redirect = response.redirect,
          body = response.body;

      // response must be either a redirect uri or request body, but not both

      if (redirect && body || !redirect && !body) {
        throw new Error('Invalid response mode');
      }

      // parse redirect uri
      if (redirect) {
        var url = new URL(redirect);
        var search = url.search,
            hash = url.hash;


        if (search && hash || !search && !hash) {
          throw new Error('Invalid response mode');
        }

        if (search) {
          response.params = FormUrlEncoded.decode(search.substring(1));
          response.mode = 'query';
        }

        if (hash) {
          response.params = FormUrlEncoded.decode(hash.substring(1));
          response.mode = 'fragment';
        }
      }

      // parse request form body
      if (body) {
        response.params = FormUrlEncoded.decode(body);
        response.mode = 'form_post';
      }

      return response;
    }

    /**
     * matchRequest
     *
     * @param {Object} response
     * @returns {Promise}
     */

  }, {
    key: 'matchRequest',
    value: function matchRequest(response) {
      var rp = response.rp,
          params = response.params,
          session = response.session;

      var state = params.state;
      var issuer = rp.provider.configuration.issuer;

      if (!state) {
        throw new Error('Missing state parameter in authentication response');
      }

      var key = issuer + '/requestHistory/' + state;
      var request = session[key];

      if (!request) {
        throw new Error('Mismatching state parameter in authentication response');
      }

      response.request = JSON.parse(request);
      return response;
    }

    /**
     * validateStateParam
     *
     * @param {Object} response
     * @returns {Promise}
     */

  }, {
    key: 'validateStateParam',
    value: function validateStateParam(response) {
      var octets = new Uint8Array(response.request.state);
      var encoded = response.params.state;

      return crypto.subtle.digest({ name: 'SHA-256' }, octets).then(function (digest) {
        if (encoded !== base64url(Buffer.from(digest))) {
          throw new Error('Mismatching state parameter in authentication response');
        }

        return response;
      });
    }

    /**
     * errorResponse
     *
     * @param {Object} response
     * @returns {Promise}
     */

  }, {
    key: 'errorResponse',
    value: function errorResponse(response) {
      var error = response.params.error;

      if (error) {
        return _promise2.default.reject(error);
      }

      return _promise2.default.resolve(response);
    }

    /**
     * validateResponseMode
     *
     * @param {Object} response
     * @returns {Promise}
     */

  }, {
    key: 'validateResponseMode',
    value: function validateResponseMode(response) {
      if (response.request.response_type !== 'code' && response.mode === 'query') {
        throw new Error('Invalid response mode');
      }

      return response;
    }

    /**
     * validateResponseParams
     *
     * @param {Object} response
     * @returns {Promise}
     */

  }, {
    key: 'validateResponseParams',
    value: function validateResponseParams(response) {
      var request = response.request,
          params = response.params;

      var expectedParams = request.response_type.split(' ');

      if (expectedParams.includes('code')) {
        assert(params.code, 'Missing authorization code in authentication response');
        // TODO assert novelty of code
      }

      if (expectedParams.includes('id_token')) {
        assert(params.id_token, 'Missing id_token in authentication response');
      }

      if (expectedParams.includes('token')) {
        assert(params.access_token, 'Missing access_token in authentication response');

        assert(params.token_type, 'Missing token_type in authentication response');
      }

      return response;
    }

    /**
     * exchangeAuthorizationCode
     *
     * @param {Object} response
     * @returns {Promise} response object
     */

  }, {
    key: 'exchangeAuthorizationCode',
    value: function exchangeAuthorizationCode(response) {
      var rp = response.rp,
          params = response.params,
          request = response.request;

      var code = params.code;

      // only exchange the authorization code when the response type is "code"
      if (!code || request['response_type'] !== 'code') {
        return _promise2.default.resolve(response);
      }

      var provider = rp.provider,
          registration = rp.registration;

      var id = registration['client_id'];
      var secret = registration['client_secret'];

      // verify the client is not public
      if (!secret) {
        return _promise2.default.reject(new Error('Client cannot exchange authorization code because ' + 'it is not a confidential client'));
      }

      // initialize token request arguments
      var endpoint = provider.configuration.token_endpoint;
      var method = 'POST';

      // initialize headers
      var headers = new Headers({
        'Content-Type': 'application/x-www-form-urlencoded'
      });

      // initialize the token request parameters
      var bodyContents = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': request['redirect_uri']

        // determine client authentication method
      };var authMethod = registration['token_endpoint_auth_method'] || 'client_secret_basic';

      // client secret basic authentication
      if (authMethod === 'client_secret_basic') {
        var credentials = new Buffer(id + ':' + secret).toString('base64');
        headers.set('Authorization', 'Basic ' + credentials);
      }

      // client secret post authentication
      if (authMethod === 'client_secret_post') {
        bodyContents['client_id'] = id;
        bodyContents['client_secret'] = secret;
      }

      var body = FormUrlEncoded.encode(bodyContents);

      // TODO
      // client_secret_jwt authentication
      // private_key_jwt

      // make the token request

      return fetch(endpoint, { method: method, headers: headers, body: body }).then(onHttpError('Error exchanging authorization code')).then(function (tokenResponse) {
        return tokenResponse.json();
      }).then(function (tokenResponse) {
        assert(tokenResponse['access_token'], 'Missing access_token in token response');

        assert(tokenResponse['token_type'], 'Missing token_type in token response');

        assert(tokenResponse['id_token'], 'Missing id_token in token response');

        // anything else?

        // IS THIS THE RIGHT THING TO DO HERE?
        response.params = (0, _assign2.default)(response.params, tokenResponse);
        return response;
      });
    }

    /**
     * validateIDToken
     *
     * @param {Object} response
     * @returns {Promise}
     */

  }, {
    key: 'validateIDToken',
    value: function validateIDToken(response) {
      // only validate the ID Token if present in the response
      if (!response.params.id_token) {
        return _promise2.default.resolve(response);
      }

      return _promise2.default.resolve(response).then(AuthenticationResponse.decryptIDToken).then(AuthenticationResponse.decodeIDToken).then(AuthenticationResponse.validateIssuer).then(AuthenticationResponse.validateAudience).then(AuthenticationResponse.resolveKeys).then(AuthenticationResponse.verifySignature).then(AuthenticationResponse.validateExpires).then(AuthenticationResponse.verifyNonce).then(AuthenticationResponse.validateAcr).then(AuthenticationResponse.validateAuthTime).then(AuthenticationResponse.validateAccessTokenHash).then(AuthenticationResponse.validateAuthorizationCodeHash);
    }

    /**
     * decryptIDToken
     *
     * @param {Object} response
     * @returns {Promise}
     */

  }, {
    key: 'decryptIDToken',
    value: function decryptIDToken(response) {
      // TODO
      return _promise2.default.resolve(response);
    }

    /**
     * decodeIDToken
     *
     * @param {Object} response
     * @returns {Promise}
     */

  }, {
    key: 'decodeIDToken',
    value: function decodeIDToken(response) {
      var jwt = response.params.id_token;

      if (jwt) {
        response.decoded = IDToken.decode(jwt);
      }

      return response;
    }

    /**
     * validateIssuer
     *
     * @param {Object} response
     * @returns {Promise}
     */

  }, {
    key: 'validateIssuer',
    value: function validateIssuer(response) {
      var configuration = response.rp.provider.configuration;
      var payload = response.decoded.payload;

      // validate issuer of token matches this relying party's provider
      if (payload.iss !== configuration.issuer) {
        throw new Error('Mismatching issuer in ID Token');
      }

      return response;
    }

    /**
     * validateAudience
     *
     * @param {Object} response
     * @returns {Promise}
     */

  }, {
    key: 'validateAudience',
    value: function validateAudience(response) {
      var registration = response.rp.registration;
      var _response$decoded$pay = response.decoded.payload,
          aud = _response$decoded$pay.aud,
          azp = _response$decoded$pay.azp;

      // validate audience includes this relying party

      if (typeof aud === 'string' && aud !== registration['client_id']) {
        throw new Error('Mismatching audience in id_token');
      }

      // validate audience includes this relying party
      if (Array.isArray(aud) && !aud.includes(registration['client_id'])) {
        throw new Error('Mismatching audience in id_token');
      }

      // validate authorized party is present if required
      if (Array.isArray(aud) && !azp) {
        throw new Error('Missing azp claim in id_token');
      }

      // validate authorized party is this relying party
      if (azp && azp !== registration['client_id']) {
        throw new Error('Mismatching azp claim in id_token');
      }

      return response;
    }

    /**
     * resolveKeys
     *
     * @param {Object} response
     * @returns {Promise}
     */

  }, {
    key: 'resolveKeys',
    value: function resolveKeys(response) {
      var rp = response.rp;
      var provider = rp.provider;
      var decoded = response.decoded;

      return _promise2.default.resolve(provider.jwks).then(function (jwks) {
        return jwks ? jwks : rp.jwks();
      }).then(function (jwks) {
        if (decoded.resolveKeys(jwks)) {
          return _promise2.default.resolve(response);
        } else {
          throw new Error('Cannot resolve signing key for ID Token');
        }
      });
    }

    /**
     * verifySignature
     *
     * @param {Object} response
     * @returns {Promise}
     */

  }, {
    key: 'verifySignature',
    value: function verifySignature(response) {
      var alg = response.decoded.header.alg;
      var registration = response.rp.registration;
      var expectedAlgorithm = registration['id_token_signed_response_alg'] || 'RS256';

      // validate signing algorithm matches expectation
      if (alg !== expectedAlgorithm) {
        throw new Error('Expected ID Token to be signed with ' + expectedAlgorithm);
      }

      return response.decoded.verify().then(function (verified) {
        if (!verified) {
          throw new Error('Invalid ID Token signature');
        }

        return response;
      });
    }

    /**
     * validateExpires
     *
     * @param {Object} response
     * @returns {Promise}
     */

  }, {
    key: 'validateExpires',
    value: function validateExpires(response) {
      var exp = response.decoded.payload.exp;

      // validate expiration of token
      if (exp <= Math.floor(Date.now() / 1000)) {
        throw new Error('Expired ID Token');
      }

      return response;
    }

    /**
     * verifyNonce
     *
     * @param {Object} response
     * @returns {Promise}
     */

  }, {
    key: 'verifyNonce',
    value: function verifyNonce(response) {
      var octets = new Uint8Array(response.request.nonce);
      var nonce = response.decoded.payload.nonce;

      if (!nonce) {
        throw new Error('Missing nonce in ID Token');
      }

      return crypto.subtle.digest({ name: 'SHA-256' }, octets).then(function (digest) {
        if (nonce !== base64url(Buffer.from(digest))) {
          throw new Error('Mismatching nonce in ID Token');
        }

        return response;
      });
    }

    /**
     * validateAcr
     *
     * @param {Object} response
     * @returns {Object}
     */

  }, {
    key: 'validateAcr',
    value: function validateAcr(response) {
      // TODO
      return response;
    }

    /**
     * validateAuthTime
     *
     * @param {Object} response
     * @returns {Promise}
     */

  }, {
    key: 'validateAuthTime',
    value: function validateAuthTime(response) {
      // TODO
      return response;
    }

    /**
     * validateAccessTokenHash
     *
     * @param {Object} response
     * @returns {Promise}
     */

  }, {
    key: 'validateAccessTokenHash',
    value: function validateAccessTokenHash(response) {
      // TODO
      return response;
    }

    /**
     * validateAuthorizationCodeHash
     *
     * @param {Object} response
     * @returns {Promise}
     */

  }, {
    key: 'validateAuthorizationCodeHash',
    value: function validateAuthorizationCodeHash(response) {
      // TODO
      return response;
    }
  }]);
  return AuthenticationResponse;
}();

/**
 * Export
 */


module.exports = AuthenticationResponse;
/* WEBPACK VAR INJECTION */}.call(exports, __webpack_require__(19), __webpack_require__(22).Buffer))

/***/ }),
/* 205 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var _getPrototypeOf = __webpack_require__(62);

var _getPrototypeOf2 = _interopRequireDefault(_getPrototypeOf);

var _classCallCheck2 = __webpack_require__(20);

var _classCallCheck3 = _interopRequireDefault(_classCallCheck2);

var _createClass2 = __webpack_require__(21);

var _createClass3 = _interopRequireDefault(_createClass2);

var _possibleConstructorReturn2 = __webpack_require__(90);

var _possibleConstructorReturn3 = _interopRequireDefault(_possibleConstructorReturn2);

var _inherits2 = __webpack_require__(91);

var _inherits3 = _interopRequireDefault(_inherits2);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

/**
 * Local dependencies
 */
var _require = __webpack_require__(28),
    JWT = _require.JWT;

var IDTokenSchema = __webpack_require__(206);

/**
 * IDToken
 */

var IDToken = function (_JWT) {
  (0, _inherits3.default)(IDToken, _JWT);

  function IDToken() {
    (0, _classCallCheck3.default)(this, IDToken);
    return (0, _possibleConstructorReturn3.default)(this, (IDToken.__proto__ || (0, _getPrototypeOf2.default)(IDToken)).apply(this, arguments));
  }

  (0, _createClass3.default)(IDToken, null, [{
    key: 'schema',


    /**
     * Schema
     */
    get: function get() {
      return IDTokenSchema;
    }
  }]);
  return IDToken;
}(JWT);

/**
 * Export
 */


module.exports = IDToken;

/***/ }),
/* 206 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


/**
 * Local dependencies
 */
var _require = __webpack_require__(28),
    JWTSchema = _require.JWTSchema;

/**
 * IDToken Schema
 */


var IDTokenSchema = JWTSchema.extend({
  properties: {

    /**
     * header
     * http://openid.net/specs/openid-connect-core-1_0.html#IDToken
     * ID Tokens SHOULD NOT use the JWS or JWE x5u, x5c, jku, or jwk Header
     * Parameter fields. Instead, references to keys used are communicated in
     * advance using Discovery and Registration parameters, per Section 10.
     */
    header: {
      //not: { required: ['x5u', 'x5c', 'jku', 'jwk'] }
    },

    /**
     * payload
     */
    payload: {
      properties: {

        /**
         * iss
         *
         * REQUIRED. Issuer Identifier for the Issuer of the response.
         * The iss value is a case sensitive URL using the https scheme
         * that contains scheme, host, and optionally, port number and
         * path components and no query or fragment components.
         */
        iss: { type: 'string', format: 'url' },

        /**
         * sub
         *
         * REQUIRED. Subject Identifier. A locally unique and never
         * reassigned identifier within the Issuer for the End-User, which
         * is intended to be consumed by the Client, e.g., 24400320 or
         * AItOawmwtWwcT0k51BayewNvutrJUqsvl6qs7A4. It MUST NOT exceed 255
         * ASCII characters in length. The sub value is a case sensitive
         * string.
         */
        sub: { type: 'string', maxLength: 255 },

        /**
         * aud
         *
         * REQUIRED. Audience(s) that this ID Token is intended for. It
         * MUST contain the OAuth 2.0 client_id of the Relying Party as an
         * audience value. It MAY also contain identifiers for other audiences.
         * In the general case, the aud value is an array of case sensitive
         * strings. In the common special case when there is one audience,
         * the aud value MAY be a single case sensitive string.
         */
        // inherited from JWTClaimsSetSchema

        /**
         * exp
         *
         * REQUIRED. Expiration time on or after which the ID Token MUST NOT
         * be accepted for processing. The processing of this parameter
         * requires that the current date/time MUST be before the expiration
         * date/time listed in the value. Implementers MAY provide for some
         * small leeway, usually no more than a few minutes, to account for
         * clock skew. Its value is a JSON number representing the number of
         * seconds from 1970-01-01T0:0:0Z as measured in UTC until the
         * date/time. See RFC 3339 [RFC3339] for details regarding date/times
         * in general and UTC in particular.
         */
        // inherited from JWTClaimsSetSchema

        /**
         * iat
         *
         * REQUIRED. Time at which the JWT was issued. Its value is a
         * JSON number representing the number of seconds from
         * 1970-01-01T0:0:0Z as measured in UTC until the date/time.
         */
        // inherited from JWTClaimsSetSchema

        /**
         * auth_time
         *
         * Time when the End-User authentication occurred. Its value is a
         * JSON number representing the number of seconds from
         * 1970-01-01T0:0:0Z as measured in UTC until the date/time. When a
         * max_age request is made or when auth_time is requested as an
         * Essential Claim, then this Claim is REQUIRED; otherwise, its
         * inclusion is OPTIONAL. (The auth_time Claim semantically
         * corresponds to the OpenID 2.0 PAPE [OpenID.PAPE] auth_time
         * response parameter.)
         */
        auth_time: { type: 'integer', format: 'NumericDate' },

        /**
         * nonce
         *
         * String value used to associate a Client session with an ID Token,
         * and to mitigate replay attacks. The value is passed through
         * unmodified from the Authentication Request to the ID Token. If
         * present in the ID Token, Clients MUST verify that the nonce Claim
         * Value is equal to the value of the nonce parameter sent in the
         * Authentication Request. If present in the Authentication Request,
         * Authorization Servers MUST include a nonce Claim in the ID Token
         * with the Claim Value being the nonce value sent in the
         * Authentication Request. Authorization Servers SHOULD perform no
         * other processing on nonce values used. The nonce value is a case
         * sensitive string.
         */
        nonce: { type: 'string' },

        /**
         * acr
         *
         * OPTIONAL. Authentication Context Class Reference. String
         * specifying an Authentication Context Class Reference value that
         * identifies the Authentication Context Class that the authentication
         * performed satisfied. The value "0" indicates the End-User
         * authentication did not meet the requirements of ISO/IEC 29115
         * [ISO29115] level 1. Authentication using a long-lived browser
         * cookie, for instance, is one example where the use of "level 0" is
         * appropriate. Authentications with level 0 SHOULD NOT be used to
         * authorize access to any resource of any monetary value. (This
         * corresponds to the OpenID 2.0 PAPE [OpenID.PAPE] nist_auth_level
         * 0.) An absolute URI or an RFC 6711 [RFC6711] registered name
         * SHOULD be used as the acr value; registered names MUST NOT be used
         * with a different meaning than that which is registered. Parties
         * using this claim will need to agree upon the meanings of the
         * values used, which may be context-specific. The acr value is a
         * case sensitive string.
         */
        acr: { type: 'string' },

        /**
         * amr
         * OPTIONAL. Authentication Methods References. JSON array of strings
         * that are identifiers for authentication methods used in the
         * authentication. For instance, values might indicate that both
         * password and OTP authentication methods were used. The definition
         * of particular values to be used in the amr Claim is beyond the
         * scope of this specification. Parties using this claim will need to
         * agree upon the meanings of the values used, which may be context-
         * specific. The amr value is an array of case sensitive strings.
         */
        amr: { type: 'array', items: { type: 'string' } },

        /**
         * azp
         * OPTIONAL. Authorized party - the party to which the ID Token was
         * issued. If present, it MUST contain the OAuth 2.0 Client ID of this
         * party. This Claim is only needed when the ID Token has a single
         * audience value and that audience is different than the authorized
         * party. It MAY be included even when the authorized party is the
         * same as the sole audience. The azp value is a case sensitive string
         * containing a StringOrURI value.
         */
        azp: { type: 'string', format: 'StringOrURI' }
      },

      /**
       * Required Claims
       */
      required: ['iss', 'sub', 'aud', 'exp', 'iat']
    }
  }
});

/**
 * Export
 */
module.exports = IDTokenSchema;

/***/ }),
/* 207 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var _classCallCheck2 = __webpack_require__(20);

var _classCallCheck3 = _interopRequireDefault(_classCallCheck2);

var _createClass2 = __webpack_require__(21);

var _createClass3 = _interopRequireDefault(_createClass2);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

var Session = function () {
  /**
   * @param options {Object}
   *
   * @param options.idp {string} Identity provider (issuer of ID Token)
   *
   * @param options.clientId {string} Relying Party client_id
   *
   * @param options.sessionKey {string} Serialized client session key generated
   *   during the Authentication Request, used to issue PoPTokens
   *
   * @param options.decoded {IDToken} Decoded/verified ID Token JWT
   *
   * @param options.accessToken {string} Compact-serialized access_token param
   *
   * @param options.idToken {string} Compact-serialized id_token param
   */
  function Session(options) {
    (0, _classCallCheck3.default)(this, Session);

    this.idp = options.idp;
    this.clientId = options.clientId;
    this.sessionKey = options.sessionKey;
    this.decoded = options.decoded;

    // Raw (string-encoded) tokens
    this.accessToken = options.accessToken;
    this.idToken = options.idToken;
  }

  /**
   * @param response {AuthenticationResponse}
   *
   * @returns {Session}
   */


  (0, _createClass3.default)(Session, null, [{
    key: 'fromAuthResponse',
    value: function fromAuthResponse(response) {
      var RelyingParty = __webpack_require__(88); // import here due to circular dep

      var payload = response.decoded.payload;
      var registration = response.rp.registration;
      var sessionKey = response.session[RelyingParty.SESSION_PRIVATE_KEY];

      var options = {
        sessionKey: sessionKey,
        idp: payload.iss,
        clientId: registration['client_id'],
        decoded: response.decoded,
        accessToken: response.params['access_token'],
        idToken: response.params['id_token']
      };

      return new Session(options);
    }
  }]);
  return Session;
}();

module.exports = Session;

/***/ }),
/* 208 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


/**
 * Dependencies
 */
var _require = __webpack_require__(3),
    JSONSchema = _require.JSONSchema;

/**
 * RelyingParty Schema
 *
 * This schema initializes and verifies Relying Party client configuration.
 * RelyingParty objects can be persisted and rehydrated. By encapsulating this data in
 * it's own class, it's possible to have multiple RP configurations running
 * simultaneously.
 */


var RelyingPartySchema = new JSONSchema({
  type: 'object',
  properties: {

    /**
     * provider
     *
     * Information about the provider, including issuer URL, human readable name,
     * and any configuration or provider metadata retrieved from the OP.
     */
    provider: {
      type: 'object',
      properties: {
        name: { type: 'string' },
        url: { type: 'string', format: 'uri' },
        // NOTE:
        // OpenID Configuration (discovery response) and JSON Web Keys Set for an
        // issuer can be cached here. However the cache should not be persisted or
        // relied upon.
        //
        configuration: {}, // .well-known/openid-configuration
        jwks: {} // /jwks
      },
      required: ['url']
    },

    /**
     * defaults
     *
     * Default request parameters for authentication and dynamic registration requests.
     * These values can be extended or overridden via arguments to the respective
     * request methods.
     *
     * These are part of the relying party client configuration and can be serialized
     * and persisted.
     */
    defaults: {
      type: 'object',
      properties: {

        /**
         * Default authentication request parameters
         */
        authenticate: {
          type: 'object',
          properties: {
            redirect_uri: {
              type: 'string',
              format: 'uri'
            },
            response_type: {
              type: 'string',
              default: 'id_token token', // browser detection
              enum: ['code', 'token', 'id_token token', 'id_token token code']
            },
            display: {
              type: 'string',
              default: 'page',
              enum: ['page', 'popup']
            },
            scope: {
              type: ['string', 'array'],
              default: ['openid']
            }
          }
        },

        /**
         * Default client registration parameters
         */
        register: {}
      }
    },

    /**
     * registration
     *
     * This is the client registration response from dynamic registration. It should
     * always reflect the client configuration on the openid provider. A client access
     * token is stored here
     */
    registration: {}, // ClientMetadataSchema

    /**
     * store
     */
    store: {
      type: 'object',
      default: {}
    }
  }
});

/**
 * Export
 */
module.exports = RelyingPartySchema;

/***/ }),
/* 209 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


var _getPrototypeOf = __webpack_require__(62);

var _getPrototypeOf2 = _interopRequireDefault(_getPrototypeOf);

var _setPrototypeOf = __webpack_require__(92);

var _setPrototypeOf2 = _interopRequireDefault(_setPrototypeOf);

var _create = __webpack_require__(93);

var _create2 = _interopRequireDefault(_create);

var _typeof2 = __webpack_require__(38);

var _typeof3 = _interopRequireDefault(_typeof2);

var _defineProperty = __webpack_require__(56);

var _defineProperty2 = _interopRequireDefault(_defineProperty);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

var _createClass = function () {
  function defineProperties(target, props) {
    for (var i = 0; i < props.length; i++) {
      var descriptor = props[i];descriptor.enumerable = descriptor.enumerable || false;descriptor.configurable = true;if ("value" in descriptor) descriptor.writable = true;(0, _defineProperty2.default)(target, descriptor.key, descriptor);
    }
  }return function (Constructor, protoProps, staticProps) {
    if (protoProps) defineProperties(Constructor.prototype, protoProps);if (staticProps) defineProperties(Constructor, staticProps);return Constructor;
  };
}();

function _classCallCheck(instance, Constructor) {
  if (!(instance instanceof Constructor)) {
    throw new TypeError("Cannot call a class as a function");
  }
}

function _possibleConstructorReturn(self, call) {
  if (!self) {
    throw new ReferenceError("this hasn't been initialised - super() hasn't been called");
  }return call && ((typeof call === "undefined" ? "undefined" : (0, _typeof3.default)(call)) === "object" || typeof call === "function") ? call : self;
}

function _inherits(subClass, superClass) {
  if (typeof superClass !== "function" && superClass !== null) {
    throw new TypeError("Super expression must either be null or a function, not " + (typeof superClass === "undefined" ? "undefined" : (0, _typeof3.default)(superClass)));
  }subClass.prototype = (0, _create2.default)(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } });if (superClass) _setPrototypeOf2.default ? (0, _setPrototypeOf2.default)(subClass, superClass) : subClass.__proto__ = superClass;
}

var _require = __webpack_require__(39),
    URL = _require.URL;

var _require2 = __webpack_require__(28),
    JWT = _require2.JWT,
    JWK = _require2.JWK;

var DEFAULT_MAX_AGE = 3600; // Default token expiration, in seconds

var PoPToken = function (_JWT) {
  _inherits(PoPToken, _JWT);

  function PoPToken() {
    _classCallCheck(this, PoPToken);

    return _possibleConstructorReturn(this, (PoPToken.__proto__ || (0, _getPrototypeOf2.default)(PoPToken)).apply(this, arguments));
  }

  _createClass(PoPToken, null, [{
    key: 'issueFor',

    /**
     * @param resourceServerUri {string} RS URI for which this token is intended
     *
     * @param session {Session}
     * @param session.clientId {string}
     * @param session.idToken {string}
     * @param session.sessionKey {string}
     *
     * @returns {Promise<string>} PoPToken, encoded as compact JWT
     */
    value: function issueFor(resourceServerUri, session) {
      if (!resourceServerUri) {
        throw new Error('Cannot issue PoPToken - missing resource server URI');
      }

      if (!session.sessionKey) {
        throw new Error('Cannot issue PoPToken - missing session key');
      }

      if (!session.idToken) {
        throw new Error('Cannot issue PoPToken - missing id token');
      }

      var jwk = JSON.parse(session.sessionKey);

      return JWK.importKey(jwk).then(function (importedSessionJwk) {
        var options = {
          aud: new URL(resourceServerUri).origin,
          key: importedSessionJwk,
          iss: session.clientId,
          id_token: session.idToken
        };

        return PoPToken.issue(options);
      }).then(function (jwt) {
        return jwt.encode();
      });
    }

    /**
     * issue
     *
     * @param options {Object}
     * @param options.iss {string} Token issuer (RP client_id)
     * @param options.aud {string|Array<string>} Audience for the token
     *   (such as the Resource Server url)
     * @param options.key {JWK} Proof of Possession (private) signing key, see
     *   https://tools.ietf.org/html/rfc7800#section-3.1
     *
     * @param options.id_token {string} JWT compact encoded ID Token
     *
     * Optional:
     * @param [options.iat] {number} Issued at timestamp (in seconds)
     * @param [options.max] {number} Max token lifetime in seconds
     *
     * @returns {PoPToken} Proof of Possession Token (JWT instance)
     */

  }, {
    key: 'issue',
    value: function issue(options) {
      var aud = options.aud,
          iss = options.iss,
          key = options.key;

      var alg = key.alg;
      var iat = options.iat || Math.floor(Date.now() / 1000);
      var max = options.max || DEFAULT_MAX_AGE;

      var exp = iat + max; // token expiration

      var header = { alg: alg };
      var payload = { iss: iss, aud: aud, exp: exp, iat: iat, id_token: options.id_token, token_type: 'pop' };

      var jwt = new PoPToken({ header: header, payload: payload, key: key.cryptoKey }, { filter: false });

      return jwt;
    }
  }]);

  return PoPToken;
}(JWT);

module.exports = PoPToken;

/***/ }),
/* 210 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


Object.defineProperty(exports, "__esModule", {
  value: true
});
exports.openIdpSelector = exports.startPopupServer = exports.appOriginHandler = exports.loginHandler = exports.storageHandler = undefined;

var _promise = __webpack_require__(13);

var _promise2 = _interopRequireDefault(_promise);

var _toConsumableArray2 = __webpack_require__(211);

var _toConsumableArray3 = _interopRequireDefault(_toConsumableArray2);

var _ipc = __webpack_require__(83);

var _urlUtil = __webpack_require__(66);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

var popupAppRequestHandler = function popupAppRequestHandler(store, options, foundSessionCb) {
  return (0, _ipc.combineHandlers)(storageHandler(store), loginHandler(options, foundSessionCb), appOriginHandler);
};

var storageHandler = exports.storageHandler = function storageHandler(store) {
  return function (req) {
    var id = req.id,
        method = req.method,
        args = req.args;

    switch (method) {
      case 'storage/getItem':
        return store.getItem.apply(store, (0, _toConsumableArray3.default)(args)).then(function (item) {
          return { id: id, ret: item };
        });
      case 'storage/setItem':
        return store.setItem.apply(store, (0, _toConsumableArray3.default)(args)).then(function () {
          return { id: id, ret: null };
        });
      case 'storage/removeItem':
        return store.removeItem.apply(store, (0, _toConsumableArray3.default)(args)).then(function () {
          return { id: id, ret: null };
        });
      default:
        return null;
    }
  };
};

var loginHandler = exports.loginHandler = function loginHandler(options, foundSessionCb) {
  return function (req) {
    var id = req.id,
        method = req.method,
        args = req.args;

    switch (method) {
      case 'getLoginOptions':
        return _promise2.default.resolve({
          id: id,
          ret: {
            popupUri: options.popupUri,
            callbackUri: options.callbackUri
          }
        });
      case 'foundSession':
        foundSessionCb(args[0]);
        return _promise2.default.resolve({ id: id, ret: null });
      default:
        return null;
    }
  };
};

var appOriginHandler = exports.appOriginHandler = function appOriginHandler(req) {
  var id = req.id,
      method = req.method;

  return method === 'getAppOrigin' ? _promise2.default.resolve({ id: id, ret: window.location.origin }) : null;
};

var startPopupServer = exports.startPopupServer = function startPopupServer(store, childWindow, options) {
  return new _promise2.default(function (resolve, reject) {
    if (!(options.popupUri && options.callbackUri)) {
      return reject(new Error('Cannot serve a popup without both "options.popupUri" and "options.callbackUri"'));
    }
    var popupServer = (0, _ipc.server)(childWindow, (0, _urlUtil.originOf)(options.popupUri || ''))(popupAppRequestHandler(store, options, function (session) {
      popupServer.stop();
      resolve(session);
    }));
    popupServer.start();
  });
};

var openIdpSelector = exports.openIdpSelector = function openIdpSelector(options) {
  if (!(options.popupUri && options.callbackUri)) {
    throw new Error('Cannot open IDP select UI.  Must provide both "options.popupUri" and "options.callbackUri".');
  }
  var width = 650;
  var height = 400;
  var w = window.open(options.popupUri, '_blank', 'width=' + width + ',height=' + height + ',left=' + (window.innerWidth - width) / 2 + ',top=' + (window.innerHeight - height) / 2);
  return w;
};

/***/ }),
/* 211 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


exports.__esModule = true;

var _from = __webpack_require__(111);

var _from2 = _interopRequireDefault(_from);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

exports.default = function (arr) {
  if (Array.isArray(arr)) {
    for (var i = 0, arr2 = Array(arr.length); i < arr.length; i++) {
      arr2[i] = arr[i];
    }

    return arr2;
  } else {
    return (0, _from2.default)(arr);
  }
};

/***/ })
/******/ ]);
});
//# sourceMappingURL=solid-auth-client.bundle.js.map