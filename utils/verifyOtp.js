const speakeasy = require( 'speakeasy' );

const verifyOtp = ( secret, otp ) => {

  return speakeasy.totp.verify( {
    secret: secret,
    encoding: 'base32',
    token: otp,
    window: 1,
  } );
};

module.exports = verifyOtp;
