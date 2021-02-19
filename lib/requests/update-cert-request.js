'use strict'

const express = require('express')
const bodyParser = require('body-parser').urlencoded({ extended: false })
const forge = require('node-forge')
const pki = forge.pki
const debug = require('./../debug').accounts
const ResourceMapper = require('../resource-mapper')
const allow = require('../handlers/allow')
const fs = require('fs')

/**
 * Represents an 'add new certificate to account' request
 * (a POST to `/api/accounts/cert` endpoint).
 *
 * Note: The account has to exist, and the user must be already logged in,
 * for this to succeed.
 */
class UpdateCertificateRequest {
  /**
   * @param [options={}] {Object}
   * @param [options.accountManager] {AccountManager}
   * @param [options.userAccount] {UserAccount}
   * @param [options.certificate] {WebIdTlsCertificate}
   * @param [options.response] {HttpResponse}
   */
  constructor (options) {
    this.accountManager = options.accountManager
    this.userAccount = options.userAccount
    this.certificate = options.certificate
    this.certPEM = options.certPEM
    this.certPKCS12 = options.certPKCS12
    this.response = options.response
  }

  /**
   * Handles the HTTP request (from an Express route handler).
   *
   * @param req
   * @param res
   * @param accountManager {AccountManager}
   *
   * @throws {TypeError}
   * @throws {Error} HTTP 401 if the user is not logged in (`req.session.userId`
   *   does not match the intended account to which the cert is being added).
   *
   * @return {Promise}
   */
  static handle (req, res, accountManager) {
    let request
    try {
      request = UpdateCertificateRequest.fromParams(req, res, accountManager)
    } catch (error) {
      return Promise.reject(error)
    }

    return new Promise((resolve, reject) => {
      res.locals.path = '/profile/card'
      allow('Write')(req, res, (errMsg) => {
        if (errMsg) {
          let error = new Error(errMsg)
          error.status = 401
          reject(error)
        } else {
          resolve()
        }
      })
    })
    .then(() => {
      return UpdateCertificateRequest.addCertificate(request)
    })
  }

  /**
   * Factory method, returns an initialized instance of `AddCertificateRequest`.
   *
   * @param req
   * @param res
   * @param accountManager {AccountManager}
   *
   * @throws {TypeError} If required parameters missing
   * @throws {Error} HTTP 401 if the user is not logged in (`req.session.userId`
   *   does not match the intended account to which the cert is being added).
   *
   * @return {AddCertificateRequest}
   */
  static fromParams (req, res, accountManager) {
    let userAccount = accountManager.userAccountFrom(req.body)
    let certPEM = req.body.certificatePEM
    let certPKCS12 = req.body.certificatePKCS12
    let certificate = null

    debug(`Adding a new certificate for ${userAccount.webId}`)

    let cert = pki.certificateFromPem(certPEM)
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
          let commonName = CN.value || this.username
          let exponent = cert.publicKey.e.toString(10)
          let modulus = cert.publicKey.n.toString(16).toLowerCase()
          let YMD = cert.validity.notBefore.toISOString().substring(0, 10).replace(/-/g, '_')
          let fname = 'cert_' + YMD + '_' + cert.validity.notBefore.getTime() + '.p12'
          let rootUrl = userAccount.accountUri
          let ldp = req.app.locals.ldp
          let rm = new ResourceMapper(
            {
              rootUrl,
              rootPath: ldp.root,
              includeHost: ldp.multiuser})

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
      } else {
        debug(`Cannot add new certificate: certificate webId "${webId}", but user is "${userAccount.webId}"`)
        let error = new Error('You tried to use a wrong certificate')
        error.status = 401
        throw error
      }
    }

    let options = {
      accountManager,
      userAccount,
      certificate,
      certPEM,
      certPKCS12,
      response: res
    }

    return new UpdateCertificateRequest(options)
  }

  /**
   * Generates a new certificate for a given user account, and adds it to that
   * account's WebID Profile graph.
   *
   * @param request {AddCertificateRequest}
   *
   * @throws {Error} HTTP 400 if there were errors during certificate generation
   *
   * @returns {Promise}
   */
  static addCertificate (request) {
    let { certificate, userAccount, accountManager, certPKCS12 } = request

    return accountManager.addCertKeyToProfile(certificate, userAccount)
      .catch(err => {
        err.status = 400
        err.message = 'Error adding certificate to profile: ' + err.message
        throw err
      })
      .then(() => {
        if (certificate && certPKCS12 && certPKCS12.length > 1) {
          let fd = fs.openSync(certificate.pathP12, 'w')
          fs.writeSync(fd, new Buffer(certPKCS12, 'base64'))
        }
        request.sendResponse(certificate)
      })
  }

  /**
   * Sends the generated certificate in the response object.
   *
   * @param certificate {WebIdTlsCertificate}
   */
  sendResponse (certificate) {
    let { response, userAccount } = this
    response.set('User', userAccount.webId)
    response.status(200)

    response.writeHead(200, {'Content-Type': 'test/plain'})
    response.write('OK')
    response.end()
  }

}

function updateCertificate (accountManager) {
  return (req, res, next) => {
    return UpdateCertificateRequest.handle(req, res, accountManager)
      .catch(err => {
        err.status = err.status || 400
        next(err)
      })
  }
}

function middleware (accountManager) {
  const router = express.Router('/')

  router.post('/api/accounts/cert_new', bodyParser, updateCertificate(accountManager))

  return router
}

module.exports = { middleware }
