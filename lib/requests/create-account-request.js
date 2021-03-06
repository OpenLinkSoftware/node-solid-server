'use strict'

const AuthRequest = require('./auth-request')
const WebIdTlsCertificate = require('../models/webid-tls-certificate')
const WebIdTls = require('../api/authn/webid-tls')
const debug = require('../debug').accounts
const ResourceMapper = require('../resource-mapper')
const fs = require('fs')
const forge = require('node-forge')
const pki = forge.pki
const blacklistService = require('../services/blacklist-service')
const { isValidUsername } = require('../common/user-utils')

/**
 * Represents a 'create new user account' http request (either a POST to the
 * `/accounts/api/new` endpoint, or a GET to `/register`).
 *
 * Intended just for browser-based requests; to create new user accounts from
 * a command line, use the `AccountManager` class directly.
 *
 * This is an abstract class, subclasses are created (for example
 * `CreateOidcAccountRequest`) depending on which Authentication mode the server
 * is running in.
 *
 * @class CreateAccountRequest
 */
class CreateAccountRequest extends AuthRequest {
  /**
   * @param [options={}] {Object}
   * @param [options.accountManager] {AccountManager}
   * @param [options.userAccount] {UserAccount}
   * @param [options.session] {Session} e.g. req.session
   * @param [options.response] {HttpResponse}
   * @param [options.returnToUrl] {string} If present, redirect the agent to
   *   this url on successful account creation
   * @param [options.enforceToc] {boolean} Whether or not to enforce the service provider's T&C
   * @param [options.tocUri] {string} URI to the service provider's T&C
   * @param [options.acceptToc] {boolean} Whether or not user has accepted T&C
   */
  constructor (options) {
    super(options)

    this.username = options.username
    this.userAccount = options.userAccount
    this.acceptToc = options.acceptToc
    this.disablePasswordChecks = options.disablePasswordChecks
    this.certPEM = options.certPEM
    this.certPKCS12 = options.certPKCS12

    if (this.userAccount &&
        this.userAccount.externalWebId &&
        this.userAccount.webId !== this.userAccount.externalWebId &&
        this.userAccount.externalWebId.length > 1) {
      let rc = WebIdTls.getRequestCertificate(this.req)
      if (rc.certificate) {
        let cert = rc.certificate
        let uris = getUris(cert)

        if (uris.length > 0) {
          this.userAccount.tlsCertificate = cert
          this.userAccount.tlsCertificateWebid = uris[0]
          this.userAccount.tlsCertificateModulus = cert.modulus
          this.userAccount.tlsCertificateExponent = parseInt(cert.exponent)
        }
      }
    }

    function getUris (certificate) {
      var uris = []

      if (certificate && certificate.subjectaltname) {
        certificate
          .subjectaltname
          .replace(/URI:([^, ]+)/g, function (match, uri) {
            return uris.push(uri)
          })
      }
      return uris
    }
  }

  /**
   * Factory method, creates an appropriate CreateAccountRequest subclass from
   * an HTTP request (browser form submit), depending on the authn method.
   *
   * @param req
   * @param res
   *
   * @throws {Error} If required parameters are missing (via
   *   `userAccountFrom()`), or it encounters an unsupported authentication
   *   scheme.
   *
   * @return {CreateOidcAccountRequest|CreateTlsAccountRequest}
   */
  static fromParams (req, res) {
    const options = AuthRequest.requestOptions(req, res)

    const locals = req.app.locals
    const authMethod = locals.authMethod
    const accountManager = locals.accountManager

    const body = req.body || {}

    if (body.username) {
      options.username = body.username.toLowerCase()
      body.webId = accountManager.accountWebIdFor(body.username)
      options.userAccount = accountManager.userAccountFrom(body)
    }

    options.enforceToc = locals.enforceToc
    options.tocUri = locals.tocUri
    options.disablePasswordChecks = locals.disablePasswordChecks

    switch (authMethod) {
      case 'oidc':
        options.password = body.password
        return new CreateOidcAccountRequest(options)
      case 'tls':
        options.spkac = body.spkac
        return new CreateTlsAccountRequest(options)
      default:
        throw new TypeError('Unsupported authentication scheme')
    }
  }

  static async post (req, res) {
    const request = CreateAccountRequest.fromParams(req, res)

    try {
      request.validate()
      await request.createAccount()
    } catch (error) {
      request.error(error, req.body)
    }
  }
/**??*WAS
renegotiate doesn't supported by TLS1.3
  static async post (req, res) {
    let request = null
    const connection = req.connection

    try {
      await Promise.resolve()
        .then(() => {
          return new Promise(function (resolve, reject) {
          // Typically, certificates for WebID-TLS are not signed or self-signed,
          // and would hence be rejected by Node.js for security reasons.
          // However, since WebID-TLS instead dereferences the profile URL to validate ownership,
          // we can safely skip the security check.
            connection.renegotiate({ requestCert: true, rejectUnauthorized: false }, (error) => {
              request = CreateAccountRequest.fromParams(req, res)
              if (error) {
                debug('Error renegotiating TLS:', error)
                return reject(error)
              }

              resolve()
            })
          })
        })

      request.validate()
      await request.createAccount()
    } catch (error) {
      request.error(error, req.body)
    }
  }
***/

  static get (req, res) {
    const request = CreateAccountRequest.fromParams(req, res)

    return Promise.resolve()
      .then(() => request.renderForm())
      .catch(error => request.error(error))
  }

  /**
   * Renders the Register form
   */
  renderForm (error, data = {}) {
    const authMethod = this.accountManager.authMethod

    const params = Object.assign({}, this.authQueryParams, {
      enforceToc: this.enforceToc,
      loginUrl: this.loginUrl(),
      multiuser: this.accountManager.multiuser,
      registerDisabled: authMethod === 'tls',
      returnToUrl: this.returnToUrl,
      authTls: authMethod === 'tls',
      tocUri: this.tocUri,
      disablePasswordChecks: this.disablePasswordChecks,
      username: data.username,
      name: data.name,
      email: data.email,
      externalWebId: data.externalWebId,
      acceptToc: data.acceptToc,
      connectExternalWebId: data.connectExternalWebId
    })

    if (error) {
      params.error = error.message
      this.response.status(error.statusCode || 401)
    }

    if (data) { params.webid = data.webid || '' }

    if (authMethod === 'tls' && data) {
      if (data.name) {
        params.name = data.name
      } else if (data.certificate && data.certificate.subject) {
        params.name = data.certificate.subject.CN
      }
    }

    this.response.render('account/register', params)
  }

  /**
   * Creates an account for a given user (from a POST to `/api/accounts/new`)
   *
   * @throws {Error} If errors were encountering while validating the username.
   *
   * @return {Promise<UserAccount>} Resolves with newly created account instance
   */
  async createAccount () {
    const userAccount = this.userAccount
    const accountManager = this.accountManager

    if (userAccount.externalWebId) {
      const error = new Error('Linked users not currently supported, sorry (external WebID without TLS?)')
      error.statusCode = 400
      throw error
    }
    this.cancelIfUsernameInvalid(userAccount)
    this.cancelIfBlacklistedUsername(userAccount)
    await this.cancelIfAccountExists(userAccount)
    await this.createAccountStorage(userAccount)
    await this.saveCredentialsFor(userAccount)
    this.saveCertificateFor(userAccount)
    this.resetUserSession(userAccount)
    await this.sendResponse(userAccount)

    // 'return' not used deliberately, no need to block and wait for email
    if (userAccount && userAccount.email) {
      debug('Sending Welcome email')
      accountManager.sendWelcomeEmail(userAccount)
    }

    return userAccount
  }

  saveCertificateFor (userAccount) {
    let certificate = null

    if (this.certPEM && this.certPEM.length > 0) {
      let cert = pki.certificateFromPem(this.certPEM)
      if (cert) {
        let webId
        let ext = cert.getExtension('subjectAltName')
        if (ext !== null && ext.altNames) {
          for (var i = 0; i < ext.altNames.length; ++i) {
            let altName = ext.altNames[i]
            if (altName.type === 6) {
              webId = altName.value
              break
            }
          }
        }

        if (webId && webId === userAccount.webId) {
          try {
            let profileUri = webId.split('#')[0]
            let keyUri = profileUri + '#key-' + cert.validity.notBefore.getTime()
            let CN = cert.subject.getField('CN')
            let commonName = (CN && CN.value) ? CN.value : this.username
            let exponent = cert.publicKey.e.toString(10)
            let modulus = cert.publicKey.n.toString(16).toLowerCase()
            let YMD = cert.validity.notBefore.toISOString().substring(0, 10).replace(/-/g, '_')
            let fname = 'cert_' + YMD + '_' + cert.validity.notBefore.getTime() + '.p12'
            let rootUrl = userAccount.accountUri
            let ldp = this.req.app.locals.ldp
            let rm = new ResourceMapper(
              {
                rootUrl,
                rootPath: ldp.root,
                includeHost: ldp.multiuser
              })
            let path = rm.getFullPath(rootUrl + '/profile/' + fname)
            certificate = {
              certificate: cert,
              date: cert.validity.notBefore,
              modulus,
              exponent,
              commonName,
              webId,
              keyUri,
              pathP12: path
            }
          } catch (err) {
            err.status = 400
            err.message = 'Error adding certificate to profile: ' + err.message
            throw err
          }

          this.accountManager.addCertKeyToProfile(certificate, userAccount)
          .catch(err => {
            debug('Error adding certificate to profile: ' + err.message)
          })
          .then(() => {
            if (certificate && this.certPKCS12 && this.certPKCS12.length > 1) {
              let fd = fs.openSync(certificate.pathP12, 'w')
              fs.writeSync(fd, new Buffer(this.certPKCS12, 'base64'))
            }
          })
        }
      }
    }
    return userAccount
  }

  resetUserSession (userAccount) {
    this.req.session.userId = null
    this.req.session.subject = {}

    return userAccount
  }

  /**
   * Rejects with an error if an account already exists, otherwise simply
   * resolves with the account.
   *
   * @param userAccount {UserAccount} Instance of the account to be created
   *
   * @return {Promise<UserAccount>} Chainable
   */
  cancelIfAccountExists (userAccount) {
    const accountManager = this.accountManager

    return accountManager.accountExists(userAccount.username)
      .then(exists => {
        if (exists) {
          debug(`Canceling account creation, ${userAccount.webId} already exists`)
          const error = new Error('Account already exists')
          error.status = 400
          throw error
        }
        // Account does not exist, proceed
        return userAccount
      })
  }

  /**
   * Creates the root storage folder, initializes default containers and
   * resources for the new account.
   *
   * @param userAccount {UserAccount} Instance of the account to be created
   *
   * @throws {Error} If errors were encountering while creating new account
   *   resources.
   *
   * @return {Promise<UserAccount>} Chainable
   */
  createAccountStorage (userAccount) {
    return this.accountManager.createAccountFor(userAccount)
      .catch(error => {
        error.message = 'Error creating account storage: ' + error.message
        throw error
      })
      .then(() => {
        debug('Account storage resources created')
        return userAccount
      })
  }

  /**
   * Check if a username is a valid slug.
   *
   * @param userAccount {UserAccount} Instance of the account to be created
   *
   * @throws {Error} If errors were encountering while validating the
   *   username.
   *
   * @return {UserAccount} Chainable
   */
  cancelIfUsernameInvalid (userAccount) {
    if (!userAccount.username || !isValidUsername(userAccount.username)) {
      debug('Invalid username ' + userAccount.username)
      const error = new Error('Invalid username (contains invalid characters)')
      error.status = 400
      throw error
    }

    return userAccount
  }

  /**
   * Check if a username is a valid slug.
   *
   * @param userAccount {UserAccount} Instance of the account to be created
   *
   * @throws {Error} If username is blacklisted
   *
   * @return {UserAccount} Chainable
   */
  cancelIfBlacklistedUsername (userAccount) {
    const validUsername = blacklistService.validate(userAccount.username)
    if (!validUsername) {
      debug('Invalid username ' + userAccount.username)
      const error = new Error('Invalid username (username is blacklisted)')
      error.status = 400
      throw error
    }

    return userAccount
  }
}

/**
 * Models a Create Account request for a server using WebID-OIDC (OpenID Connect)
 * as a primary authentication mode. Handles saving user credentials to the
 * `UserStore`, etc.
 *
 * @class CreateOidcAccountRequest
 * @extends CreateAccountRequest
 */
class CreateOidcAccountRequest extends CreateAccountRequest {
  /**
   * @constructor
   *
   * @param [options={}] {Object} See `CreateAccountRequest` constructor docstring
   * @param [options.password] {string} Password, as entered by the user at signup
   * @param [options.acceptToc] {boolean} Whether or not user has accepted T&C
   */
  constructor (options) {
    super(options)

    this.password = options.password
  }

  /**
   * Validates the Login request (makes sure required parameters are present),
   * and throws an error if not.
   *
   * @throws {Error} If missing required params
   */
  validate () {
    let error

    if (!this.username) {
      error = new Error('Username required')
      error.statusCode = 400
      throw error
    }

    if (!this.password) {
      error = new Error('Password required')
      error.statusCode = 400
      throw error
    }

    if (this.enforceToc && !this.acceptToc) {
      error = new Error('Accepting Terms & Conditions is required for this service')
      error.statusCode = 400
      throw error
    }
  }

  /**
   * Generate salted password hash, etc.
   *
   * @param userAccount {UserAccount}
   *
   * @return {Promise<null|Graph>}
   */
  saveCredentialsFor (userAccount) {
    return this.userStore.createUser(userAccount, this.password)
      .then(() => {
        debug('User credentials stored')
        return userAccount
      })
  }

  /**
   * Generate the response for the account creation
   *
   * @param userAccount {UserAccount}
   *
   * @return {UserAccount}
   */
  sendResponse (userAccount) {
    const redirectUrl = this.returnToUrl || userAccount.podUri
    this.response.redirect(redirectUrl)

    return userAccount
  }
}

/**
 * Models a Create Account request for a server using WebID-TLS as primary
 * authentication mode. Handles generating and saving a TLS certificate, etc.
 *
 * @class CreateTlsAccountRequest
 * @extends CreateAccountRequest
 */
class CreateTlsAccountRequest extends CreateAccountRequest {
  /**
   * @constructor
   *
   * @param [options={}] {Object} See `CreateAccountRequest` constructor docstring
   * @param [options.spkac] {string}
   * @param [options.acceptToc] {boolean} Whether or not user has accepted T&C
   */
  constructor (options) {
    super(options)

    this.spkac = options.spkac
    this.certificate = null
  }

  /**
   * Validates the Signup request (makes sure required parameters are present),
   * and throws an error if not.
   *
   * @throws {Error} If missing required params
   */
  validate () {
    let error

    if (!this.username) {
      error = new Error('Username required')
      error.statusCode = 400
      throw error
    }

    if (this.userAccount && this.userAccount.externalWebId.length === 0) {
      error = new Error('External WebId required')
      error.statusCode = 400
      throw error
    }

    if (this.enforceToc && !this.acceptToc) {
      error = new Error('Accepting Terms & Conditions is required for this service')
      error.statusCode = 400
      throw error
    }
  }

  /**
   * Generates a new X.509v3 RSA certificate (if `spkac` was passed in) and
   * adds it to the user account. Used for storage in an agent's WebID
   * Profile, for WebID-TLS authentication.
   *
   * @param userAccount {UserAccount}
   * @param userAccount.webId {string} An agent's WebID URI
   *
   * @throws {Error} HTTP 400 error if errors were encountering during
   *   certificate generation.
   *
   * @return {Promise<UserAccount>} Chainable
   */
  generateTlsCertificate (userAccount) {
    if (!this.spkac) {
      debug('Missing spkac param, not generating cert during account creation')
      return Promise.resolve(userAccount)
    }

    return Promise.resolve()
      .then(() => {
        const host = this.accountManager.host
        return WebIdTlsCertificate.fromSpkacPost(this.spkac, userAccount, host)
          .generateCertificate()
      })
      .catch(err => {
        err.status = 400
        err.message = 'Error generating a certificate: ' + err.message
        throw err
      })
      .then(certificate => {
        debug('Generated a WebID-TLS certificate as part of account creation')
        this.certificate = certificate
        return userAccount
      })
  }

  /**
   * Generates a WebID-TLS certificate and saves it to the user's profile
   * graph.
   *
   * @param userAccount {UserAccount}
   *
   * @return {Promise<UserAccount>} Chainable
   */
  saveCredentialsFor (userAccount) {
    return this.generateTlsCertificate(userAccount)
      .then(userAccount => {
        if (this.certificate) {
          return this.accountManager
            .addCertKeyToProfile(this.certificate, userAccount)
            .then(() => {
              debug('Saved generated WebID-TLS certificate to profile')
            })
        } else {
          debug('No certificate generated, no need to save to profile')
        }
      })
      .then(() => {
        return userAccount
      })
  }

  /**
   * Writes the generated TLS certificate to the http Response object.
   *
   * @param userAccount {UserAccount}
   *
   * @return {UserAccount} Chainable
   */
  sendResponse (userAccount) {
    const res = this.response
    res.set('User', userAccount.webId)
    res.status(200)

    if (this.certificate) {
      res.set('Content-Type', 'application/x-x509-user-cert')
      res.send(this.certificate.toDER())
    } else {
      res.end()
    }

    return userAccount
  }
}

module.exports = CreateAccountRequest
module.exports.CreateAccountRequest = CreateAccountRequest
module.exports.CreateTlsAccountRequest = CreateTlsAccountRequest
