'use strict'
/* eslint-disable no-mixed-operators */

const debug = require('./../debug').authentication

const AuthRequest = require('./auth-request')
const { PasswordAuthenticator, TlsAuthenticator } = require('../models/authenticator')

const PASSWORD_AUTH = 'password'
const TLS_AUTH = 'tls'

/**
 * Models a local Login request
 */
class LoginRequest extends AuthRequest {
  /**
   * @constructor
   * @param options {Object}
   *
   * @param [options.response] {ServerResponse} middleware `res` object
   * @param [options.session] {Session} req.session
   * @param [options.userStore] {UserStore}
   * @param [options.accountManager] {AccountManager}
   * @param [options.returnToUrl] {string}
   * @param [options.authQueryParams] {Object} Key/value hashmap of parsed query
   *   parameters that will be passed through to the /authorize endpoint.
   * @param [options.authenticator] {Authenticator} Auth strategy by which to
   *   log in
   */
  constructor (options) {
    super(options)

    this.authenticator = options.authenticator
    this.clientId = this.authQueryParams['client_id']
    this.authMethod = options.authMethod
  }

  /**
   * Factory method, returns an initialized instance of LoginRequest
   * from an incoming http request.
   *
   * @param req {IncomingRequest}
   * @param res {ServerResponse}
   * @param authMethod {string}
   *
   * @return {LoginRequest}
   */
  static fromParams (req, res, authMethod) {
    const options = AuthRequest.requestOptions(req, res)
    options.authMethod = authMethod

    switch (authMethod) {
      case PASSWORD_AUTH:
        options.authenticator = PasswordAuthenticator.fromParams(req, options)
        break

      case TLS_AUTH:
        options.authenticator = TlsAuthenticator.fromParams(req, options)
        break

      default:
        options.authenticator = null
        break
    }

    return new LoginRequest(options)
  }

  /**
   * Handles a Login GET request on behalf of a middleware handler, displays
   * the Login page.
   * Usage:
   *
   *   ```
   *   app.get('/login', LoginRequest.get)
   *   ```
   *
   * @param req {IncomingRequest}
   * @param res {ServerResponse}
   */
  static get (req, res) {
    const request = LoginRequest.fromParams(req, res)

    request.renderForm(null, req)
  }

  /**
   * Handles a Login via Username+Password.
   * Errors encountered are displayed on the Login form.
   * Usage:
   *
   *   ```
   *   app.post('/login/password', LoginRequest.loginPassword)
   *   ```
   *
   * @param req
   * @param res
   *
   * @return {Promise}
   */
  static loginPassword (req, res) {
    debug('Logging in via username + password')

    const request = LoginRequest.fromParams(req, res, PASSWORD_AUTH)

    return LoginRequest.login(request)
  }

  /**
   * Handles a Login via WebID-TLS.
   * Errors encountered are displayed on the Login form.
   * Usage:
   *
   *   ```
   *   app.post('/login/tls', LoginRequest.loginTls)
   *   ```
   *
   * @param req
   * @param res
   *
   * @return {Promise}
   */
  static loginTls (req, res) {
    debug('Logging in via WebID-TLS certificate')

    const request = LoginRequest.fromParams(req, res, TLS_AUTH)

    return LoginRequest.login(request)
  }

  /**
   * Performs the login operation -- loads and validates the
   * appropriate user, inits the session with credentials, and redirects the
   * user to continue their auth flow.
   *
   * @param request {LoginRequest}
   *
   * @return {Promise}
   */
  static login (request) {
    return request.authenticator.findValidUser()

      .then(validUser => {
        request.initUserSession(validUser)

        request.redirectPostLogin(validUser)
      })

      .catch(error => request.error(error))
  }

  /**
   * Returns a URL to redirect the user to after login.
   * Either uses the provided `redirect_uri` auth query param, or simply
   * returns the user profile URI if none was provided.
   *
   * @param validUser {UserAccount}
   *
   * @return {string}
   */
  postLoginUrl (validUser) {
    // Login request is part of an app's auth flow
    if (/token|code/.test(this.authQueryParams.response_type)) {
      return this.sharingUrl()
    // Login request is a user going to /login in browser
    } else if (validUser) {
      return this.authQueryParams.redirect_uri || validUser.accountUri
//??was     return this.authQueryParams['redirect_uri'] || this.accountManager.accountUriFor(validUser.username)      
    }
  }

  /**
   * Redirects the Login request to continue on the OIDC auth workflow.
   */
  redirectPostLogin (validUser) {
    const uri = this.postLoginUrl(validUser)

    // debug(`validUser: ${JSON.stringify(validUser)}`)
    this.response.setHeader('User', validUser.webId)

    if (this.clientId) {
      this.response.redirect(uri)
      debug('Login successful, redirect to uri ', uri)
    } else {
      if (this.authMethod === TLS_AUTH) {
        this.response.writeHead(200, {'Content-Type': 'test/plain'})
        this.response.write(uri)
        this.response.end()
      } else {
        this.response.redirect(uri)
      }
      debug('Login successful, return $HOME uri ', uri)
    }

  }

  /**
   * Renders the login form
   */
  renderForm (error, req) {
    const queryString = req && req.url && req.url.replace(/[^?]+\?/, '') || ''
    const solidVersion = this.req && this.req.app.locals.solidVersion || ''
    const authMethod = this.accountManager.authMethod
    const params = Object.assign({}, this.authQueryParams,
      {
        registerUrl: this.registerUrl(),
        returnToUrl: this.returnToUrl,
        enablePassword: this.localAuth.password,
        enableTls: this.localAuth.tls,
        tlsUrl: `/login/tls?${encodeURIComponent(queryString)}`,
        authTls: authMethod === TLS_AUTH,
        solidVersion
      })

    if (error) {
      params.error = error.message
      this.response.status(error.statusCode)
    }
    this.response.render('auth/login', params)
  }
}

module.exports = {
  LoginRequest,
  PASSWORD_AUTH,
  TLS_AUTH
}
