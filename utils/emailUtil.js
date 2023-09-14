const nodemailer = require( 'nodemailer' );
const logger = require( '../logger' );

const sendWelcomeEmail = async ( toEmail, emailContent ) => {
  // Create a transporter using SMTP configuration
  const transporter = nodemailer.createTransport( {
    service: 'Gmail',
    host: 'smtp.gmail.com',
    port: 465,
    secure: true,
    auth: {
      user: process.env.GMAIL_USER,
      pass: process.env.GMAIL_PASSWORD,
    },
  } );

  const mailOptions = {
    from: process.env.GMAIL_USER,
    to: toEmail,
    subject: 'Welcome to Our Platform!',
    text: emailContent,
  };

  try
  {
    const info = await transporter.sendMail( mailOptions );
    logger.info( 'Welcome email sent:', info.response );
  } catch ( error )
  {
    logger.error( 'Error sending welcome email:', error );
  }
};

module.exports = {
  sendWelcomeEmail,
};
