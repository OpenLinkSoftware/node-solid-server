'use strict'

/**
 * Returns a partial Email object (minus the `to` and `from` properties),
 * suitable for sending with Nodemailer.
 *
 * Used to send a Welcome email after a new user account has been created.
 *
 * @param data {Object}
 *
 * @param data.webid {string}
 *
 * @return {Object}
 */
function render (data) {
  return {
    subject: 'Welcome to Solid',

    /**
     * Text version of the Welcome email
     */
    text: `Welcome to the OpenLink Node Solid Server for exploiting the Read-Write functionality offered by the Solid Platform!

A new Profile Document has been created for your WebID: ${data.webid}`,

    /**
     * HTML version of the Welcome email
     */
    html: `<p>Welcome to the OpenLink Node Solid Server for exploiting the Read-Write functionality offered by the Solid Platform!</p>

<p>A new Profile Document has been created for your WebID: ${data.webid}</p>`
  }
}

module.exports.render = render
