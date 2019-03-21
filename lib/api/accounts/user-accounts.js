'use strict'

const express = require('express')
const bodyParser = require('body-parser').urlencoded({ extended: false })
const debug = require('../../debug').accounts

const WebIdTls = require('../authn/webid-tls')
const restrictToTopDomain = require('../../handlers/restrict-to-top-domain')

const CreateAccountRequest = require('../../requests/create-account-request')
const AddCertificateRequest = require('../../requests/add-cert-request')
const DeleteAccountRequest = require('../../requests/delete-account-request')
const DeleteAccountConfirmRequest = require('../../requests/delete-account-confirm-request')

/**
 * Returns an Express middleware handler for checking if a particular account
 * exists (used by Signup apps).
 *
 * @param accountManager {AccountManager}
 *
 * @return {Function}
 */
function checkAccountExists (accountManager) {
  return (req, res, next) => {
    let accountUri = req.hostname

    accountManager.accountUriExists(accountUri)
      .then(found => {
        if (!found) {
          debug(`Account ${accountUri} is available (for ${req.originalUrl})`)
          return res.sendStatus(404)
        }
        debug(`Account ${accountUri} is not available (for ${req.originalUrl})`)
        next()
      })
      .catch(next)
  }
}

/**
 * Returns an Express middleware handler for adding a new certificate to an
 * existing account (POST to /api/accounts/cert).
 *
 * @param accountManager
 *
 * @return {Function}
 */
function newCertificate (accountManager) {
  return (req, res, next) => {
    return AddCertificateRequest.handle(req, res, accountManager)
      .catch(err => {
        err.status = err.status || 400
        next(err)
      })
  }
}

function handleCertDays (req, res, next) {
  let days = req.app.locals.certDays
  res.writeHead(200, {'Content-Type': 'text/plain'})
  res.write('' + days)
  res.end()
}

function handleDetectWebid (req, res, next) {
  let connection = req.connection

  Promise.resolve()
    .then(() => {
      return new Promise(function (resolve, reject) {
          // Typically, certificates for WebID-TLS are not signed or self-signed,
          // and would hence be rejected by Node.js for security reasons.
          // However, since WebID-TLS instead dereferences the profile URL to validate ownership,
          // we can safely skip the security check.
        connection.renegotiate({ requestCert: true, rejectUnauthorized: false }, (error) => {
          if (error) {
            debug('Error renegotiating TLS:', error)
            return reject(error)
          }
          resolve()
        })
      })
    })
    .then(() => {
      WebIdTls.handleRegisterWebid(req, res, function (val) {
        return Promise.resolve(val)
          .then(() => {
            let error = val.err !== null ? new Error(val.err) : null
            if (error) {
              throw error
            } else {
              let name = ''
              let webid = ''
              if (val) {
                webid = val.webid || ''

                if (val.name) {
                  name = val.name
                } else if (val.certificate && val.certificate.subject) {
                  name = val.certificate.subject.CN
                }
              }

              res.writeHead(200, {'Content-Type': 'application/json'})
              res.write(`{ "name":"${name}", "webid":"${webid}"}`)
              res.end()
            }
          })
          .catch(err => {
            err.status = err.status || 400
            next(err)
          })
      })
    })
    .catch(err => {
      err.status = err.status || 400
      next(err)
    })
}

/**
 * Returns an Express router for providing user account related middleware
 * handlers.
 *
 * @param accountManager {AccountManager}
 *
 * @return {Router}
 */
function middleware (accountManager) {
  let router = express.Router('/')

  router.get('/', checkAccountExists(accountManager))

  router.post('/api/accounts/new', restrictToTopDomain, bodyParser, CreateAccountRequest.post)
  router.get(['/register', '/api/accounts/new'], restrictToTopDomain, CreateAccountRequest.get)

  router.post('/api/accounts/cert', restrictToTopDomain, bodyParser, newCertificate(accountManager))

  router.get('/certdays', handleCertDays)
  router.get('/detect/webid', handleDetectWebid)

  router.get('/account/delete', restrictToTopDomain, DeleteAccountRequest.get)
  router.post('/account/delete', restrictToTopDomain, bodyParser, DeleteAccountRequest.post)

  router.get('/account/delete/confirm', restrictToTopDomain, DeleteAccountConfirmRequest.get)
  router.post('/account/delete/confirm', restrictToTopDomain, bodyParser, DeleteAccountConfirmRequest.post)

  return router
}

module.exports = {
  middleware,
  checkAccountExists,
  newCertificate
}
