'use strict'

module.exports = {
  auth: 'oidc',
  localAuth: {
    tls: true,
    password: true
  },
  configPath: './config',
  dbPath: './.db',
  port: 8443,
  serverUri: 'https://localhost:8443',
  webid: true,
  certDays: 60,
  strictOrigin: true,
  trustedOrigins: [],
  dataBrowserPath: 'default'
//  'dataBrowserPath': 'https://linkeddata.uriburner.com/describe/?url={url}&sponger:get=add'

  // For use in Enterprises to configure a HTTP proxy for all outbound HTTP requests from the SOLID server (we use
  // https://www.npmjs.com/package/global-tunnel-ng).
  // "httpProxy": {
  //   "tunnel": "neither",
  //   "host": "proxy.example.com",
  //   "port": 12345
  // }
}
