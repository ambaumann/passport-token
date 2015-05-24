/**
 * Module dependencies.
 */
var passport = require('passport')
  , util = require('util')
  , BadRequestError = require('./errors/badrequesterror');


/**
 * `Strategy` constructor.
 *
 * The token authentication strategy authenticates requests based on the
 * credentials submitted through standard request headers or body.
 *
 * Applications must supply a `verify` callback which accepts `username` and
 * `token` credentials, and then calls the `done` callback supplying a
 * `user`, which should be set to `false` if the credentials are not valid.
 * If an exception occured, `err` should be set.
 *
 * Examples:
 *
 *     passport.use(new TokenStrategy(
 *       function(username, token, done) {
 *         User.findOne({ username: username, token: token }, function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Function} verify
 * @api public
 */
function Strategy(verify) {
  if (!verify) throw new Error('token authentication strategy requires a verify function');
  passport.Strategy.call(this);
  this.name = 'token';
  this._verify = verify;
}

/**
 * Inherit from `passport.Strategy`.
 */
util.inherits(Strategy, passport.Strategy);

/**
 * Authenticate request based on the contents of a form submission.
 *
 * @param {Object} req
 * @api protected
 */
Strategy.prototype.authenticate = function(req, options) {
  options = options || {};
  var self = this;
  var username = req.cookies.username;
  var token    = req.cookies.token;

  if (!username || !token) {
    return this.fail(new BadRequestError(options.badRequestMessage || 'Missing credentials'));
  }
  
  function verified(err, user, info) {
    if (err) { return self.error(err); }
    if (!user) { return self.fail(info); }
    self.success(user, info);
  }
  this._verify(username, token, verified);
}


/**
 * Expose `Strategy`.
 */ 
module.exports = Strategy;
