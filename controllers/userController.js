const bcrypt = require( 'bcryptjs' );
const jwt = require( 'jsonwebtoken' );
const logger = require( '../logger' );
const userService = require( '../services/userService' );
const speakeasy = require( 'speakeasy' );
const secretKey = process.env.SECRET_KEY;
const validator = require( 'validator' );
const i18next = require( '../i18next' );
// const sendSms = require( '../utils/smsUtil' );
// const emailUtil = require( '../utils/emailUtil' );

//Create User
exports.userCreate = async ( req, res ) => {
  const {
    firstName,
    lastName,
    age,
    email,
    country,
    gender,
    phoneNo,
    password,
    bankAccountNumber,
    bankRoutingNumber
  } = req.body;

  const profilePicture = req.file ? req.file.filename : null;

  try
  {
    if ( !firstName || !lastName || !age || !email || !country || !gender || !phoneNo || !password || !bankAccountNumber ||
      !bankRoutingNumber )
    {
      return res.status( 400 ).json( { message: i18next.t( 'requiredFields' ) } );
    }

    if ( !firstName.match( /^[a-zA-Z]+$/ ) )
    {
      return res.status( 400 ).json( { message: i18next.t( 'invalidFirstName' ) } );
    }

    if ( !lastName.match( /^[a-zA-Z]+$/ ) )
    {
      return res.status( 400 ).json( { message: i18next.t( 'invalidLastName' ) } );
    }

    if ( !validator.isInt( age, { min: 18, max: 70 } ) )
    {
      return res.status( 400 ).json( { message: i18next.t( 'invalidAgeRange' ) } );
    }

    if ( !validator.isEmail( email ) )
    {
      return res.status( 400 ).json( { message: i18next.t( 'invalidEmail' ) } );
    }

    if ( !validator.isLength( phoneNo, { min: 10, max: 10 } ) || !validator.isNumeric( phoneNo ) )
    {
      return res.status( 400 ).json( { message: i18next.t( 'invalidPhoneNumber' ) } );
    }

    if ( !validator.isLength( password, { min: 8 } ) ||
      !/[A-Z]/.test( password ) ||
      !/[a-z]/.test( password ) ||
      !/[0-9]/.test( password ) ||
      !/[!@#$%^&*]/.test( password ) )
    {
      return res.status( 400 ).json( { message: i18next.t( 'invalidPasswordFormat' ) } );
    }

    const existingUser = await userService.getUserByLogin( phoneNo );

    if ( existingUser )
    {
      return res.status( 400 ).json( { message: i18next.t( 'phoneAlreadyRegistered' ) } );
    }

    const newUser = await userService.userCreate(
      firstName,
      lastName,
      age,
      email,
      country,
      gender,
      phoneNo,
      password,
      profilePicture,
      bankAccountNumber,
      bankRoutingNumber
    );
    res.status( 201 ).json( newUser );
  } catch ( error )
  {
    logger.error( 'Error for creating new user: ', error );
    res.status( 500 ).json( { message: i18next.t( 'createUserError' ) } );
  }
};

// Fetching all users details 
exports.getAllUsers = async ( req, res ) => {
  try
  {
    const users = await userService.getAllUsers();
    res.status( 200 ).json( users );
  } catch ( error )
  {
    logger.error( 'Error for finding all user details:', error );
    res.status( 500 ).json( { message: i18next.t( 'notFoundAllUser' ) } );
  }
};

//Fetching user details by login
exports.getUserByLogin = async ( req, res ) => {
  const phone = req.user.phoneNo;
  try
  {
    const user = await userService.getUserByLogin( phone );
    if ( !user )
    {
      res.status( 404 ).json( { message: i18next.t( 'userNotFound' ) } );
    } else
    {
      res.status( 200 ).json( user );
    }
  } catch ( error )
  {
    logger.error( 'Error for finding user details: ', error );
    res.status( 500 ).json( { message: i18next.t( 'notFoundUserByLogin' ) } );
  }
};

//Update user's details
exports.updateUser = async ( req, res ) => {
  const phone = req.user.phoneNo;
  const {
    firstName,
    lastName,
    age,
    email,
    country,
    gender,
    phoneNo
  } = req.body;

  const profilePicture = req.file ? req.file.filename : null;

  try
  {

    if ( !firstName || !lastName || !age || !email || !country || !gender || !phoneNo )
    {
      return res.status( 400 ).json( { message: i18next.t( 'requiredFields' ) } );
    }

    if ( !firstName.match( /^[a-zA-Z]+$/ ) )
    {
      return res.status( 400 ).json( { message: i18next.t( 'invalidFirstName' ) } );
    }

    if ( !lastName.match( /^[a-zA-Z]+$/ ) )
    {
      return res.status( 400 ).json( { message: i18next.t( 'invalidLastName' ) } );
    }

    if ( !validator.isInt( age, { min: 18, max: 70 } ) )
    {
      return res.status( 400 ).json( { message: i18next.t( 'invalidAgeRange' ) } );
    }

    if ( !validator.isEmail( email ) )
    {
      return res.status( 400 ).json( { message: i18next.t( 'invalidEmail' ) } );
    }

    if ( !validator.isLength( phoneNo, { min: 10, max: 10 } ) || !validator.isNumeric( phoneNo ) )
    {
      return res.status( 400 ).json( { message: i18next.t( 'invalidPhoneNumber' ) } );
    }

    const updateUser = await userService.updateUser(
      firstName,
      lastName,
      age,
      email,
      country,
      gender,
      phone,
      phoneNo,
      profilePicture
    );

    if ( !updateUser )
    {
      res.status( 404 ).json( { message: i18next.t( 'userNotFound' ) } );
    } else
    {
      // const emailContent = `Hi ${ firstName },\n\nYour profile information for your account has been successfully updated.\n\nHere are your updated details:\n
      //   First Name: ${ firstName }
      //   Last Name: ${ lastName }
      //   Age: ${ age }
      //   Email: ${ email }
      //   Country: ${ country }
      //   Gender: ${ gender }
      //   Phone Number: ${ phoneNo }`;

      // Send welcome email using the utility function
      // await emailUtil.sendWelcomeEmail( email, emailContent );

      res.status( 201 ).json( updateUser );
    }
  } catch ( error )
  {
    res.status( 500 ).json( { message: i18next.t( 'updateUserError' ) } );
    logger.error( 'Error for updating user details', error );
  }
};

//Delete user
exports.deleteUser = async ( req, res ) => {
  const phone = req.user.phoneNo;

  const user = await userService.getUserByLogin( phone );

  if ( !user )
  {
    return res.status( 400 ).json( { message: i18next.t( 'userNotFound' ) } );
  }
  if ( user.phoneNo !== phone )
  {
    return res.status( 400 ).json( { message: i18next.t( 'userNotFound' ) } );
  }
  try
  {
    const deletedUser = await userService.deleteUser( phone );
    if ( !deletedUser )
    {
      res.status( 400 ).json( { message: i18next.t( 'userNotFound' ) } );
    } else
    {
      // const emailContent = `Hi ${ user.firstName }, you have deleted your account `;

      //send mail to user
      // await emailUtil.sendWelcomeEmail( user.email, emailContent );

      res.status( 200 ).json( { message: i18next.t( 'employeeDeleteDone' ) } );
    }
  } catch ( error )
  {
    res.status( 500 ).json( { message: i18next.t( 'employeeDeleteFailed' ) } );
    logger.error( 'Error while deleting users: ', error );
  }
};

//Generate secret key
const generate2FASecret = () => {
  const secret = speakeasy.generateSecret( { step: 60 } );
  return secret.base32;
};

//Login user
exports.userLogin = async ( req, res ) => {
  const { phoneNo, password } = req.query;
  try
  {
    if ( !phoneNo || !password )
    {
      return res.status( 400 ).json( { message: i18next.t( 'requiredFields' ) } );
    }

    if ( !validator.isNumeric( phoneNo ) || phoneNo.length !== 10 )
    {
      return res.status( 400 ).json( { message: i18next.t( 'invalidPhoneNumber' ) } );

    }

    if ( !validator.isLength( password, { min: 8 } ) ||
      !/[A-Z]/.test( password ) || !/[a-z]/.test( password ) ||
      !/[0-9]/.test( password ) || !/[!@#$%^&*]/.test( password ) ) 
    {
      return res.status( 400 ).json( { message: i18next.t( 'invalidPasswordFormat' ) } );
    }

    const user = await userService.getUserByLogin( phoneNo );
    if ( !user )
    {
      return res.status( 401 ).json( { message: i18next.t( 'invalidLoginCredentials' ) } );
    }
    const isPasswordValid = await bcrypt.compare( password, user.password );
    if ( !isPasswordValid )
    {
      return res.status( 401 ).json( { message: i18next.t( 'invalidLoginCredentials' ) } );
    }

    const secret = generate2FASecret();

    await userService.store2FASecret( user.phoneNo, secret );

    //generate otp
    const otp = speakeasy.totp( {
      secret: secret,
      encoding: 'base32',
      window: 1
    } );

    const otpMessage = `Your OTP is : ${ otp }`;

    // Send the SMS using the utility function
    // await sendSms( phoneNo, otpMessage );

    res.status( 200 ).json( { message: otpMessage } );

  } catch ( error )
  {
    logger.error( 'Error during login:', error );

    res.status( 500 ).json( { message: i18next.t( 'loginError' ) } );
  }
};

//verify otp
exports.verifyOtp = async ( req, res ) => {
  const { phoneNo, otp } = req.query;
  try
  {

    if ( !phoneNo || !otp )
    {
      return res.status( 400 ).json( { message: i18next.t( 'requiredFields' ) } );
    }

    if ( !validator.isNumeric( phoneNo ) || phoneNo.length !== 10 )
    {
      return res.status( 400 ).json( { message: i18next.t( 'invalidPhoneNumber' ) } );
    }

    if ( !validator.isNumeric( otp ) || otp.length !== 6 )
    {
      return res.status( 400 ).json( { message: i18next.t( 'invalidOtpFormat' ) } );
    }


    const user = await userService.getUserByLogin( phoneNo );
    if ( !user )
    {
      return res.status( 401 ).json( { message: i18next.t( 'employeeNotFound' ) } );
    }

    const verificationResult = await userService.verifyOtp( phoneNo, otp );

    if ( verificationResult == false )
    {
      return res.status( 401 ).json( { message: i18next.t( 'invalidToken' ) } );
    }
    else
    {
      const authToken = jwt.sign( { phoneNo }, secretKey, { expiresIn: '1h' } );
      await userService.clearTwoFactorSecret( phoneNo );
      res.status( 200 ).json( { authToken } );
    }

  } catch ( error )
  {
    logger.error( 'Error during 2FA verification:', error );
    res.status( 500 ).json( { message: i18next.t( 'tokenVerifyError' ) } );
  }
};

//forgot password
exports.forgotPassword = async ( req, res ) => {
  const { phoneNo } = req.query;
  try
  {
    if ( !phoneNo )
    {
      return res.status( 400 ).json( { message: i18next.t( 'requiredFields' ) } );
    }

    if ( !validator.isNumeric( phoneNo ) || phoneNo.length !== 10 )
    {
      return res.status( 400 ).json( { message: i18next.t( 'invalidPhoneNumber' ) } );
    }

    const user = await userService.getUserByLogin( phoneNo );
    if ( !user )
    {
      return res.status( 401 ).json( { message: i18next.t( 'invalidLoginCredentials' ) } );
    }

    const secret = generate2FASecret();

    await userService.store2FASecret( user.phoneNo, secret );

    const otp = speakeasy.totp( {
      secret: secret,
      encoding: 'base32',
      window: 1
    } );

    const otpMessage = `Your 2FA token : ${ otp }`;

    // Send the SMS using the utility function
    // await sendSms( phoneNo, otpMessage );

    res.status( 200 ).json( { otpMessage } );
  } catch ( error )
  {
    logger.error( 'Error during forgot password:', error );
    res.status( 500 ).json( { message: i18next.t( 'forgotPasswordError' ) } );
  }
};

//Reset password
exports.resetPassword = async ( req, res ) => {
  const { phoneNo, otp, newPassword } = req.query;
  try
  {
    if ( !phoneNo || !otp || !newPassword )
    {
      return res.status( 400 ).json( { message: i18next.t( 'requiredFields' ) } );
    }

    if ( !validator.isNumeric( phoneNo ) || phoneNo.length !== 10 )
    {
      return res.status( 400 ).json( { message: i18next.t( 'invalidPhoneNumber' ) } );
    }

    if ( !validator.isNumeric( otp ) || otp.length !== 6 )
    {
      return res.status( 400 ).json( { message: i18next.t( 'invalidOtpFormat' ) } );
    }

    if ( !validator.isLength( newPassword, { min: 8 } ) ||
      !/[A-Z]/.test( newPassword ) || !/[a-z]/.test( newPassword ) ||
      !/[0-9]/.test( newPassword ) || !/[!@#$%^&*]/.test( newPassword ) ) 
    {
      return res.status( 400 ).json( { message: i18next.t( 'invalidPasswordFormat' ) } );
    }

    const user = await userService.getUserByLogin( phoneNo );
    if ( !user )
    {
      return res.status( 404 ).json( { message: i18next.t( 'employeeNotFound' ) } );
    }

    //Check wheather the password same as previous
    const isPasswordValid = await bcrypt.compare( newPassword, user.password, );
    if ( isPasswordValid )
    {
      return res.status( 400 ).json( { message: i18next.t( 'samePassword' ) } );
    }

    const isOtpValid = await userService.verifyOtp( phoneNo, otp );
    if ( !isOtpValid )
    {
      return res.status( 401 ).json( { message: i18next.t( 'invalidOtp' ) } );
    }

    await userService.updatePassword( phoneNo, newPassword );

    await userService.clearTwoFactorSecret( phoneNo );

    // const emailContent = `Hi ${ user.firstName },\n\nYour password for your account has been successfully changed and your updated password is ${ newPassword }.`;

    //send mail to user
    // await emailUtil.sendWelcomeEmail( user.email, emailContent );

    res.status( 200 ).json( { message: i18next.t( 'passwordResetDone' ) } );
  } catch ( error )
  {
    res.status( 500 ).json( { message: i18next.t( 'passwordResetFailed' ) } );
    logger.error( 'Error during password reset', error );
  }
};

