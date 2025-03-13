'use strict';

/**
 * Token
 * @class
 * @constructor
 * @public
 */
class Token {
  /**
   * @param {String} sessionID
   * @param {String} nonce
   * @param {Number} expiresAt
   */
  constructor(sessionID, nonce, expiresAt) {
    /**
     * The session ID this token is associated with
     * @type {String}
     * @public
     */
    this.sessionID = sessionID

    /**
     * A random string that makes the token absolutely unique
     * @type {String}
     * @public
     */
    this.nonce = nonce

    /**
     * The epoch seconds, after this token is not valid anymore
     * @type {String}
     * @public
     */
    this.expiresAt = expiresAt
  }
}

module.exports = {
  Token,
}
