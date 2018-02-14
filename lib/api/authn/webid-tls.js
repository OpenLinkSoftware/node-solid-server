var webid = require('webid/tls')
var debug = require('../../debug').authentication
var x509 // optional dependency, load lazily

const CERTIFICATE_MATCHER = /^-----BEGIN CERTIFICATE-----\n(?:[A-Za-z0-9+/=]+\n)+-----END CERTIFICATE-----$/m

function initialize (app, argv) {
  app.use('/', handler)
  if (argv.certificateHeader) {
    app.locals.certificateHeader = argv.certificateHeader.toLowerCase()
  }
}

function handler (req, res, next) {
  // User already logged in? skip
  if (req.session.userId) {
    debug('User: ' + req.session.userId)
    res.set('User', req.session.userId)
    return next()
  }

  // No certificate? skip
  const certificate = getCertificateViaTLS(req) || getCertificateViaHeader(req)
  if (!certificate) {
    setEmptySession(req)
    return next()
  }

  debug('#authenticate_using_web_id:');

  if (certificate.subject)
  {
    debug('CN:', certificate.subject.CN, ', SAN:', certificate.subjectaltname); 
    
    var delegator = req.headers['on-behalf-of'] || req.headers['On-Behalf-Of'];
    debug('#authenticate_using_web_id: delegator:', delegator);

    // Verify webid
    if (!delegator)
      webid.verify(certificate, authentication_callback);
    else
      webid.verify(certificate, webid_verification_callback);
  }
  else
  {
    debug('Error: The client did not supply a valid certificate when first connecting to this server.')
    setEmptySession(req)
    return next()
  }


  // authentication_cb signature: function(err, user)
  function authentication_callback(err, uri) 
  {
    if (err) {
      debug('Error processing certificate: ' + err.message)
      setEmptySession(req)
      return next()
    }
    req.session.userId = uri
    debug('Identified user: ' + req.session.userId)
    res.set('User', req.session.userId)
    return next()
  }

  function webid_verification_callback(err, delegate)
  {
    if (err)
      authentication_callback(err, delegate);
    else
      webid_verify_delegation(delegator, delegate, certificate, authentication_callback);
  }


  function webid_verify_delegation (delegator, delegate, delegate_certificate, authentication_cb) 
  {
    // logger.debug('#webid_verify_delegation: delegate_certificate: ');
    // logger.debug(util.inspect(delegate_certificate));

    // Depending on the client, it may inject an 'On-Behalf-Of' header with every request.
    // TO DO: Check - Does OSDS inject the header with every request?
    // So, the presence of an 'On-Behalf-Of' header is no guarantee that the delegate claim
    // is valid. The authenticated user, the apparent delegate, may not be a delegate at all.
    // This can only be confirmed by checking the authenticated user's WebID profile.

    // Verify the delegation claim
    req.app.locals.webid_util.verify_delegation(delegator, delegate, delegate_certificate)
    .then(function (result) {
      // result ::= true
      // The delegation claim is valid.
      // The effective user becomes the delegator.
      debug("#webid_verify_delegation: delegation claim is valid");
      authentication_cb(null, delegator);
    }).catch(function (e) {
      // The delegation claim is invalid.
      // The effective user remains the authenticated user. 
      debug("#webid_verify_delegation: delegation claim is invalid");
      authentication_cb(null, delegate);
    });
  } // webid_verify_delegation


////-------end new
}

// Tries to obtain a client certificate retrieved through the TLS handshake
function getCertificateViaTLS (req) {
  const certificate = req.connection.getPeerCertificate &&
                      req.connection.getPeerCertificate()
  if (certificate && Object.keys(certificate).length > 0) {
    return certificate
  }
  debug('No peer certificate received during TLS handshake.')
}

// Tries to obtain a client certificate retrieved through an HTTP header
function getCertificateViaHeader (req) {
  // Only allow header-based certificates if explicitly enabled
  const headerName = req.app.locals.certificateHeader
  if (!headerName) return

  // Try to retrieve the certificate from the header
  const header = req.headers[headerName]
  if (!header) {
    return debug(`No certificate received through the ${headerName} header.`)
  }
  // The certificate's newlines have been replaced by tabs
  // in order to fit in an HTTP header (NGINX does this automatically)
  const rawCertificate = header.replace(/\t/g, '\n')

  // Ensure the header contains a valid certificate
  // (x509 unsafely interprets it as a file path otherwise)
  if (!CERTIFICATE_MATCHER.test(rawCertificate)) {
    return debug(`Invalid value for the ${headerName} header.`)
  }

  // Parse and convert the certificate to the format the webid library expects
  if (!x509) x509 = require('x509')
  try {
    const { publicKey, extensions } = x509.parseCert(rawCertificate)
    return {
      modulus: publicKey.n,
      exponent: '0x' + parseInt(publicKey.e, 10).toString(16),
      subjectaltname: extensions && extensions.subjectAlternativeName
    }
  } catch (error) {
    debug(`Invalid certificate received through the ${headerName} header.`)
  }
}

function setEmptySession (req) {
  req.session.userId = ''
}

/**
 * Sets the `WWW-Authenticate` response header for 401 error responses.
 * Used by error-pages handler.
 *
 * @param req {IncomingRequest}
 * @param res {ServerResponse}
 */
function setAuthenticateHeader (req, res) {
  let locals = req.app.locals

  res.set('WWW-Authenticate', `WebID-TLS realm="${locals.host.serverUri}"`)
}

module.exports = {
  initialize,
  handler,
  setAuthenticateHeader,
  setEmptySession
}
