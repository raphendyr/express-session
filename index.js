/*!
 * express-session
 * Copyright(c) 2010 Sencha Inc.
 * Copyright(c) 2011 TJ Holowaychuk
 * Copyright(c) 2014-2015 Douglas Christopher Wilson
 * MIT Licensed
 */

'use strict';

/**
 * Module dependencies.
 * @private
 */

var Buffer = require('safe-buffer').Buffer
var crypto = require('crypto')
var debug = require('debug')('express-session');
var deprecate = require('depd')('express-session');
var onHeaders = require('on-headers')
var uid = require('uid-safe').sync

var Cookie = require('./session/cookie')
var MemoryStore = require('./session/memory')
var Session = require('./session/session')
var Store = require('./session/store')
const { CookieTokenManager } = require('./session/token-manager-cookie');

// environment

var env = process.env.NODE_ENV;

/**
 * Expose the middleware.
 */

exports = module.exports = session;

/**
 * Expose constructors.
 */

exports.Store = Store;
exports.Cookie = Cookie;
exports.Session = Session;
exports.MemoryStore = MemoryStore;

/**
 * Warning message for `MemoryStore` usage in production.
 * @private
 */

var warning = 'Warning: connect.session() MemoryStore is not\n'
  + 'designed for a production environment, as it will leak\n'
  + 'memory, and will not scale past a single process.';

/**
 * Node.js 0.8+ async implementation.
 * @private
 */

/* istanbul ignore next */
var defer = typeof setImmediate === 'function'
  ? setImmediate
  : function(fn) { process.nextTick(fn.bind.apply(fn, arguments)) }

/**
 * Setup session store with the given `options`.
 *
 * @param {Object} [options]
 * @param {Object} [options.cookie] Options for cookie
 * @param {Function} [options.genid]
 * @param {String} [options.name=connect.sid] Session ID cookie name
 * @param {Boolean} [options.proxy]
 * @param {Boolean} [options.resave] Resave unmodified sessions back to the store
 * @param {Boolean} [options.rolling] Enable/disable rolling session expiration
 * @param {Boolean} [options.saveUninitialized] Save uninitialized sessions to the store
 * @param {String|Array} [options.secret] Secret for signing session ID
 * @param {Object} [options.store=MemoryStore] Session store
 * @param {String} [options.unset]
 * @return {Function} middleware
 * @public
 */

function session(options) {
  var opts = options || {}

  // get the session id generate function
  var generateId = opts.genid || generateSessionId

  // get the session store
  var store = opts.store || new MemoryStore()

  // get the resave session option
  var resaveSession = opts.resave;

  // get the save uninitialized session option
  var saveUninitializedSession = opts.saveUninitialized

  if (typeof generateId !== 'function') {
    throw new TypeError('genid option must be a function');
  }

  if (resaveSession === undefined) {
    deprecate('undefined resave option; provide resave option');
    resaveSession = true;
  }

  if (saveUninitializedSession === undefined) {
    deprecate('undefined saveUninitialized option; provide saveUninitialized option');
    saveUninitializedSession = true;
  }

  if (opts.unset && opts.unset !== 'destroy' && opts.unset !== 'keep') {
    throw new TypeError('unset option must be "destroy" or "keep"');
  }

  // TODO: switch to "destroy" on next major
  var unsetDestroy = opts.unset === 'destroy'

  // notify user that this store is not
  // meant for a production environment
  /* istanbul ignore next: not tested */
  if (env === 'production' && store instanceof MemoryStore) {
    console.warn(warning);
  }

  // generates the new session
  store.generate = function(req) {
    req.sessionID = generateId(req);
    req.session = new Session(req);
    req.session.cookie = tokenManager.generateState(req)
  };

  var storeImplementsTouch = typeof store.touch === 'function';

  // register event listeners for the store to track readiness
  var storeReady = true
  store.on('disconnect', function ondisconnect() {
    storeReady = false
  })
  store.on('connect', function onconnect() {
    storeReady = true
  })

  // Token Manager
  let tokenManager = opts.tokenManager
  if (!tokenManager) {
    // get the session cookie name
    const name = opts.name || opts.key || 'connect.sid'
    // get the cookie signing secret
    if (Array.isArray(opts.secret) && opts.secret.length === 0) {
      throw new TypeError('secret option array must contain one or more strings');
    }
    if (!opts.secret) {
      deprecate('req.secret; provide secret option');
    }
    const secrets =
      !opts.secret
        ? []
        : !Array.isArray(opts.secret)
          ? [opts.secret]
          : opts.secret
    // get the rolling session option
    const rollingSessions = Boolean(opts.rolling)
    // get the trust proxy setting
    const trustProxy = opts.proxy
    // get the cookie options
    const cookieOptions = opts.cookie || {}

    tokenManager = new CookieTokenManager(name, secrets, saveUninitializedSession, rollingSessions, trustProxy, cookieOptions)
  }

  return function session(req, res, next) {
    // self-awareness
    if (req.session) {
      next()
      return
    }

    // Handle connection as if there is no session if
    // the store has temporarily disconnected etc
    if (!storeReady) {
      debug('store is disconnected')
      next()
      return
    }

    // TODO: remove backwards compatibility for signed cookies
    // req.secret is passed from the cookie parser middleware
    if (req.secret) {
      tokenManager.secrets = [req.secret]
    }
    if (tokenManager.secrets.length === 0) {
      next(new Error('secret option required for sessions'));
      return;
    }

    var originalHash;
    var originalId;
    var savedHash;
    var touched = false

    // expose store
    req.sessionStore = store;

    // get the session ID from the request
    let token
    try {
      token = tokenManager.get(req)
    } catch (err) {
      debug('token manager is not enabled for request, error: %s', err)
      next()
    }
    req.sessionID = token?.sessionID

    // set headers (e.g., cookie)
    onHeaders(res, function() {
      if (!req.session) {
        debug('no session');
        return;
      }

      /* FIXME: remove
      if (!shouldSetCookie(req)) {
        return;
      }
      */

      if (!tokenManager.shouldSet(req, token, isModified(req.session))) {
        debug('token not set, shouldSet returned false')
        return
      }

      if (!touched) {
        // touch session
        debug('TOUCH SESSION on onHeaders()');
        req.session.touch()
        touched = true
      }

      // set token in response (e.g., cookie)
      try {
        tokenManager.set(res, req.session)
      } catch (err) {
        defer(next, err)
      }
    });

    // proxy end() to commit the session
    var _end = res.end;
    var _write = res.write;
    var ended = false;
    res.end = function end(chunk, encoding) {
      if (ended) {
        return false;
      }

      ended = true;

      var ret;
      var sync = true;

      function writeend() {
        if (sync) {
          ret = _end.call(res, chunk, encoding);
          sync = false;
          return;
        }

        _end.call(res);
      }

      function writetop() {
        if (!sync) {
          return ret;
        }

        if (!res._header) {
          res._implicitHeader()
        }

        if (chunk == null) {
          ret = true;
          return ret;
        }

        var contentLength = Number(res.getHeader('Content-Length'));

        if (!isNaN(contentLength) && contentLength > 0) {
          // measure chunk
          chunk = !Buffer.isBuffer(chunk)
            ? Buffer.from(chunk, encoding)
            : chunk;
          encoding = undefined;

          if (chunk.length !== 0) {
            debug('split response');
            ret = _write.call(res, chunk.slice(0, chunk.length - 1));
            chunk = chunk.slice(chunk.length - 1, chunk.length);
            return ret;
          }
        }

        ret = _write.call(res, chunk, encoding);
        sync = false;

        return ret;
      }

      if (shouldDestroy(req)) {
        // destroy session
        debug('destroying');
        store.destroy(req.sessionID, function ondestroy(err) {
          if (err) {
            defer(next, err);
          }

          debug('destroyed');
          writeend();
        });

        return writetop();
      }

      // no session to save
      if (!req.sessionID || !req.session) {
        debug('no session');
        return _end.call(res, chunk, encoding);
      }

      if (!touched) {
        // touch session
        debug('TOUCH SESSION on req.end()');
        req.session.touch()
        touched = true
      }

      if (shouldSave(req)) {
        req.session.save(function onsave(err) {
          if (err) {
            defer(next, err);
          }

          writeend();
        });

        return writetop();
      } else if (storeImplementsTouch && shouldTouch(req)) {
        // store implements touch method
        debug('touching');
        store.touch(req.sessionID, req.session, function ontouch(err) {
          if (err) {
            defer(next, err);
          }

          debug('touched');
          writeend();
        });

        return writetop();
      }

      return _end.call(res, chunk, encoding);
    };

    // generate the session
    function generate() {
      store.generate(req);
      originalId = req.sessionID;
      originalHash = hash(req.session);
      wrapmethods(req.session);
    }

    // inflate the session
    function inflate(req, sess) {
      store.createSession(req, sess)
      originalId = req.sessionID
      originalHash = hash(sess)

      if (!resaveSession) {
        savedHash = originalHash
      }

      wrapmethods(req.session)
    }

    function rewrapmethods(sess, callback) {
      return function() {
        if (req.session !== sess) {
          wrapmethods(req.session)
        }

        callback.apply(this, arguments)
      }
    }

    // wrap session methods
    function wrapmethods(sess) {
      var _reload = sess.reload
      var _save = sess.save;

      function reload(callback) {
        debug('reloading %s', this.id)
        _reload.call(this, rewrapmethods(this, callback))
      }

      function save() {
        debug('saving %s', this.id);
        savedHash = hash(this);
        _save.apply(this, arguments);
      }

      Object.defineProperty(sess, 'reload', {
        configurable: true,
        enumerable: false,
        value: reload,
        writable: true
      })

      Object.defineProperty(sess, 'save', {
        configurable: true,
        enumerable: false,
        value: save,
        writable: true
      });
    }

    // check if session has been modified
    function isModified(sess) {
      return originalId !== sess.id || originalHash !== hash(sess);
    }

    // check if session has been saved
    function isSaved(sess) {
      return originalId === sess.id && savedHash === hash(sess);
    }

    // determine if session should be destroyed
    function shouldDestroy(req) {
      return req.sessionID && unsetDestroy && req.session == null;
    }

    // determine if session should be saved to store
    function shouldSave(req) {
      // cannot save without a session ID
      if (typeof req.sessionID !== 'string') {
        debug('session ignored because of bogus req.sessionID %o', req.sessionID);
        return false;
      }

      return !saveUninitializedSession && !savedHash && token?.sessionID !== req.sessionID
        ? isModified(req.session)
        : !isSaved(req.session)
    }

    // determine if session should be touched
    function shouldTouch(req) {
      // cannot touch without a session ID
      if (typeof req.sessionID !== 'string') {
        debug('session ignored because of bogus req.sessionID %o', req.sessionID);
        return false;
      }

      return token?.sessionID === req.sessionID && !shouldSave(req);
    }

    /* FIXME: remove shouldSetCookie
    // determine if cookie should be set on response
    function shouldSetCookie(req) {
      // cannot set cookie without a session ID
      if (typeof req.sessionID !== 'string') {
        return false;
      }

      return cookieId !== req.sessionID
        ? saveUninitializedSession || isModified(req.session)
        : rollingSessions || req.session.cookie.expires != null && isModified(req.session);
    }
    */

    // generate a session if the browser doesn't send a sessionID
    if (!req.sessionID) {
      debug('no SID sent, generating session');
      generate();
      next();
      return;
    }

    // generate the session object
    debug('fetching %s', req.sessionID);
    store.get(req.sessionID, function(err, sess) {
      // error handling
      if (err && err.code !== 'ENOENT') {
        debug('error %j', err);
        next(err)
        return
      }

      try {
        if (err || !sess) {
          debug('no session found')
          generate()
        } else {
          debug('session found')
          inflate(req, sess)
        }
      } catch (e) {
        next(e)
        return
      }

      next()
    });
  };
};

/**
 * Generate a session ID for a new session.
 *
 * @return {String}
 * @private
 */

function generateSessionId(sess) {
  return uid(24);
}

/**
 * Hash the given `sess` object omitting changes to `.cookie`.
 *
 * @param {Object} sess
 * @return {String}
 * @private
 */

function hash(sess) {
  // serialize
  var str = JSON.stringify(sess, function(key, val) {
    // ignore sess.cookie property
    if (this === sess && key === 'cookie') {
      return
    }

    return val
  })

  // hash
  return crypto
    .createHash('sha1')
    .update(str, 'utf8')
    .digest('hex')
}
