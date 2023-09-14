const User = require( '../models/userModel' );
const logger = require( '../logger' );
const verifyOtp = require( '../utils/verifyOtp' );
const hashPassword = require( '../utils/hashPassword' );

exports.getUserByLogin = async ( phoneNo ) => {
  try
  {
    const user = await User.findOne( {
      where: {
        phoneNo: phoneNo,
      },
    } );

    if ( !user )
    {
      logger.warn( `No user found with phone number: ${ phoneNo }` );
    } else
    {
      logger.info( `Found user with phone number: ${ phoneNo }` );
    }

    return user;
  } catch ( error )
  {
    logger.error( `Error while fetching user by phone number: ${ error }` );
    throw error;
  }
};

exports.getAllUsers = async () => {
  try
  {
    const users = await User.findAll();
    logger.info( 'Retrieved all users' );
    return users;
  } catch ( error )
  {
    logger.error( `Error while fetching all users:${ error }` );
    throw error;
  }
};

exports.userCreate = async (
  firstName,
  lastName,
  age,
  email,
  country,
  gender,
  phoneNo,
  password,
  profilePicture
) => {
  try
  {
    const newUser = await User.create( {
      firstName,
      lastName,
      age,
      email,
      country,
      gender,
      phoneNo,
      password,
      profilePicture,
    } );

    logger.info( `Created new user with ID: ${ newUser.id }` );
    return newUser;
  } catch ( error )
  {
    logger.error( `Error while creating new user: ${ error }` );
    throw error;
  }
};

exports.updateUser = async (
  firstName,
  lastName,
  age,
  email,
  country,
  gender,
  phone,
  phoneNo,
  profilePicture
) => {
  try
  {
    const user = await User.findOne( {
      where: {
        phoneNo: phone,
      },
    } );
    if ( !user )
    {
      logger.warn( `No user found` );
      return null;
    }

    user.firstName = firstName;
    user.lastName = lastName;
    user.age = age;
    user.email = email;
    user.country = country;
    user.gender = gender;
    user.phoneNo = phoneNo;

    if ( profilePicture )
    {
      user.profilePicture = profilePicture;
    }

    await user.save();

    logger.info( `Updated user with phone number: ${ phoneNo }` );
    return user;
  } catch ( error )
  {
    logger.error( `Error while updating user with phone number ${ phoneNo }: ${ error }` );
    throw error;
  }
};

exports.deleteUser = async ( phone ) => {
  try
  {
    const user = await User.findOne( {
      where: {
        phoneNo: phone,
      },
    } );
    if ( !user )
    {
      logger.warn( `No user found with ID: ${ user.id }` );
      return null;
    }
    await user.destroy();
    logger.info( `Deleted user with phone number: ${ phone }` );
    return user;
  } catch ( error )
  {
    logger.error( `Error while deleting user with phone number ${ phone }: ${ error }` );
    throw error;
  }
};

exports.store2FASecret = async ( phoneNo, secret ) => {
  try
  {
    const user = await User.findOne( { where: { phoneNo: phoneNo } } );
    if ( user )
    {
      user.twoFactorSecret = secret;
      await user.save();
      logger.info( `Stored 2FA secret for user with phone number: ${ phoneNo }` );
      return true;
    }
    logger.warn( `No user found with phone number: ${ phoneNo }` );
    return false;
  } catch ( error )
  {
    logger.error( `Error storing 2FA secret for user with phone number ${ phoneNo }: ${ error }` );
    return false;
  }
};

exports.verifyOtp = async ( phoneNo, otp ) => {
  try
  {
    const user = await User.findOne( { where: { phoneNo: phoneNo } } );

    if ( !user )
    {
      logger.info( `2FA verification failed for user with phone number: ${ phoneNo }` );
      return { verified: false };
    }

    const verified = verifyOtp( user.twoFactorSecret, otp );

    if ( verified )
    {
      logger.info( `2FA verification successful for user with phone number: ${ phoneNo }` );
    } else
    {
      logger.info( `2FA verification failed for user with phone number: ${ phoneNo }` );
    }

    return { verified };
  } catch ( error )
  {
    logger.error( `Error verifying 2FA token for user with phone number ${ phoneNo }: ${ error }` );
    return { verified: false };
  }
};

exports.updatePassword = async ( phoneNo, newPassword ) => {
  try
  {
    const user = await User.findOne( { where: { phoneNo: phoneNo } } );
    if ( !user )
    {
      return false;
    }
    const hashedPassword = await hashPassword( newPassword );
    user.password = hashedPassword;
    await user.save();

    logger.info( `Password updated for user with phone number: ${ phoneNo }` );
    return true;
  } catch ( error )
  {
    logger.error( `Error updating password for user with phone number ${ phoneNo }: ${ error }` );
    throw error;
  }
};

exports.clearTwoFactorSecret = async ( phoneNo ) => {
  try
  {
    const user = await User.findOne( { where: { phoneNo: phoneNo } } );
    if ( !user )
    {
      return false;
    }
    user.twoFactorSecret = null;
    await user.save();
    return true;
  } catch ( error )
  {
    throw error;
  }
};

