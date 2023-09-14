const twilio = require( 'twilio' );
const { TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_PHONE_NUMBER } = process.env;

const twilioClient = twilio( TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN );

const sendSms = async ( to, body ) => {
  try
  {
    const formattedPhoneNumber = `+91${ to }`;
    await twilioClient.messages.create( {
      body,
      from: TWILIO_PHONE_NUMBER,
      to: formattedPhoneNumber,
    } );
    console.log( 'SMS sent successfully:', body );
  } catch ( error )
  {
    console.error( 'Error sending SMS:', error );
  }
};

module.exports = sendSms;
