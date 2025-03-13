'use strict';

/**
 * Abstract base class for session token parsing and setting.
 * @public
 */
class TokenManager {
  /**
   * Get session token.
   *
   * @abstract
   * @param {Request} req
   * @return {Token}
   * @api public
   */
  get(req) {
    throw new Error('must be implemented by subclass!');
  }

  /**
   * Get session token.
   *
   * @abstract
   * @param {Response} res
   * @param {Session} session
   * @api public
   */
  set(res, session) {
    throw new Error('must be implemented by subclass!');
  }
}

module.exports = {
  TokenManager
}
