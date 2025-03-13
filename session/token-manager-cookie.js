'use strict';

const { Token } = require("./token")
const { TokenManager } = require('./token-manager')
const Cookie = require('./cookie');
const cookie = require('cookie')
const debug = require('debug')('express-session')
const parseUrl = require('parseurl').original
const Session = require('./session')
const signature = require('cookie-signature')

/**
 * Get cookie from request.
 *
 * @return {String|undefined}
 * @private
 */
function getcookie(req, name, secrets) {
  var header = req.headers.cookie;
  var raw;
  var val;

  // read from cookie header
  if (header) {
    var cookies = cookie.parse(header);

    raw = cookies[name];

    if (raw) {
      if (raw.substr(0, 2) === 's:') {
        val = unsigncookie(raw.slice(2), secrets);

        if (val === false) {
          debug('cookie signature invalid');
          val = undefined;
        }
      } else {
        debug('cookie unsigned')
      }
    }
  }

  // back-compat read from cookieParser() signedCookies data
  if (!val && req.signedCookies) {
    val = req.signedCookies[name];

    if (val) {
      deprecate('cookie should be available in req.headers.cookie');
    }
  }

  // back-compat read from cookieParser() cookies data
  if (!val && req.cookies) {
    raw = req.cookies[name];

    if (raw) {
      if (raw.substr(0, 2) === 's:') {
        val = unsigncookie(raw.slice(2), secrets);

        if (val) {
          deprecate('cookie should be available in req.headers.cookie');
        }

        if (val === false) {
          debug('cookie signature invalid');
          val = undefined;
        }
      } else {
        debug('cookie unsigned')
      }
    }
  }

  return val;
}

/**
 * Set cookie on response.
 *
 * @param {Response} res
 * @param {String} name
 * @param {String} val
 * @param {String} secret
 * @param {Object.<string, string>} options
 * @private
 */

function setcookie(res, name, val, secret, options) {
  var signed = 's:' + signature.sign(val, secret);
  var data = cookie.serialize(name, signed, options);

  debug('set-cookie %s', data);

  var prev = res.getHeader('Set-Cookie') || []
  var header = Array.isArray(prev) ? prev.concat(data) : [prev, data];

  res.setHeader('Set-Cookie', header)
}

/**
 * Verify and decode the given `val` with `secrets`.
 *
 * @param {String} val
 * @param {String[]} secrets
 * @returns {String|Boolean}
 * @private
 */
function unsigncookie(val, secrets) {
  for (var i = 0; i < secrets.length; i++) {
    var result = signature.unsign(val, secrets[i]);

    if (result !== false) {
      return result;
    }
  }

  return false;
}

/**
 * Determine if request is secure.
 *
 * @param {Object} req
 * @param {Boolean} [trustProxy]
 * @return {Boolean}
 * @private
 */
function issecure(req, trustProxy) {
  // socket is https server
  if (req.connection && req.connection.encrypted) {
    return true;
  }

  // do not trust proxy
  if (trustProxy === false) {
    return false;
  }

  // no explicit trust; try req.secure from express
  if (trustProxy !== true) {
    return req.secure === true
  }

  // read the proto from x-forwarded-proto header
  var header = req.headers['x-forwarded-proto'] || '';
  var index = header.indexOf(',');
  var proto = index !== -1
    ? header.substr(0, index).toLowerCase().trim()
    : header.toLowerCase().trim()

  return proto === 'https';
}

/**
 * FIXME:
 * @param {string|undefined} token
 * @return {Token|undefined}
 * @api public
 */
function decodeToken(token) {
  if (token === undefined) {
    return
  }
  const parts = token.split(':')
  if (parts.length !== 3) {
    debug('cookie token has invalid format, token is: %s', token)
    return
  }

  const [sessionID, nonce, expiresStr] = parts
  let expiresAt
  try {
    expiresAt = Number(expiresStr)
  } catch (err) {
    debug('cookie expiresAt is not a number: %s', err)
    return
  }

  if (expiresAt > 0 && expiresAt < Date.now()) {
    debug('cookie expired at: %s', new Date(expiresAt))
    return
  }

  return new Token(sessionID, nonce, expiresAt)
}

/**
 * FIXME:
 * @param {Session} session
 * @return {string}
 * @api public
 */
function encodeToken(session) {
  const cookie = session.cookie
  const nonce = cookie.nonce ?? ''
  const expiresAt = cookie.expires?.getTime() || 0
  return `${session.id}:${nonce}:${expiresAt}`
}

/**
 * Token Manager on top of cookies.
 *
 * @class
 * @constructor
 * @public
 */
class CookieTokenManager extends TokenManager {
  /**
   * @param {String} name
   * @param {String[]} secrets
   * @param {Boolean} saveUninitializedSession
   * @param {Boolean} rollingSessions
   * @param {Boolean} trustProxy
   * @param {{maxAge?: number, partitioned?: string, priority?: string, secure?: boolean, httpOnly?: boolean, domain?: string, path?: string, sameSite?: boolean}} options Options for cookie
   */
  constructor(name, secrets, saveUninitializedSession, rollingSessions, trustProxy, options) {
    super()

    /**
     * The name of the cookie
     * @type {String}
     * @private
     */
    this.name = name

    /**
     * Array of secrets which are used to decrypt cookies.
     * The first secret is used to encrypt cookies.
     * @type {String[]}
     * @private
     */
    this.secrets = secrets

    /**
     * @type {Boolean}
     * @private
     */
    this.saveUninitializedSession = saveUninitializedSession

    /**
     * @type {Boolean}
     * @private
     */
    this.rollingSessions = rollingSessions

    /**
     * @type {Boolean}
     * @private
     */
    this.trustProxy = trustProxy

    /**
     * @type {{maxAge?: number, partitioned?: string, priority?: string, secure?: boolean, httpOnly?: boolean, domain?: string, path?: string, sameSite?: boolean}}
     * @private
     */
    this.options = options

    this.encodeToken = encodeToken
    this.decodeToken = decodeToken
  }

  /**
   * @param {Request} req
   * @returns {Cookie}
   */
  generateState(req) {
    const state = new Cookie(this.options)
    if (state.secure === 'auto') {
      state.secure = issecure(req, this.trustProxy);
    }
    return state
  }

  /**
   * Get session token.
   *
   * @param {Request} req
   * @return {Token|undefined}
   * @api public
   */
  get(req) {
    // validate path
    const requestPath = parseUrl(req).pathname || '/'
    const cookiePath = this.options?.path || '/'
    if (!requestPath.startsWith(cookiePath)) {
      throw new Error('cookie not configured for the request path')
    }

    const token = getcookie(req, this.name, this.secrets)
    return this.decodeToken(token)
  }

  /**
   *
   * @param {Request} req
   * @param {Token|undefined} token
   * @param {Boolean} isModified
   * @returns {Boolean}
   */
  shouldSet(req, token, isModified) {
    // cannot set cookie without a session ID
    if (typeof req.sessionID !== 'string') {
      return false;
    }

    // only send secure cookies via https
    if (req.session.cookie.secure && !issecure(req, this.trustProxy)) {
      debug('cookie not set, connection not secured');
      return false
    }

    const isNewSession = token?.sessionID !== req.sessionID
    return isNewSession
      ? this.saveUninitializedSession || isModified
      : this.rollingSessions || req.session.cookie.expires != null && isModified
  }

  /**
   * Get session token.
   *
   * @param {Response} res
   * @param {Session} session
   * @api public
   */
  set(res, session) {
    const val = this.encodeToken(session)
    setcookie(res, this.name, val, this.secrets[0], session.cookie.data)
  }
}

module.exports = {
  CookieTokenManager
}
