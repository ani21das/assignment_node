const i18next = require( 'i18next' );

i18next.init( {
  fallbackLng: 'en',
  resources: {
    en: {
      translation: {
        requiredFields: 'All required fields must be provided',
        invalidFirstName: 'Invalid first name. Only letters are allowed.',
        invalidLastName: 'Invalid last name. Only letters are allowed.',
        invalidAgeRange: 'Age must be between 18 and 70.',
        invalidEmail: 'Invalid email address.',
        invalidPhoneNumber: 'Invalid phone number. It should be a 10-digit number.',
        invalidPasswordFormat: 'Invalid password format',
        invalidOtpFormat: 'Invalid otp format',
        notFoundAllUser: 'Error for finding all employee details',
        notFoundUserByLogin: 'Error for finding employee details by id',
        phoneAlreadyRegistered: 'Phone number already registered',
        createUserError: 'Error for creating new employee',
        phoneNotMatched: 'Given phone number does not matched',
        samePassword: 'Same as previous password',
        userNotFound: 'Employee not found from database',
        updateUserError: 'Error for updating employee details',
        userDeleteDone: 'Employee deleted successfully',
        userDeleteFailed: 'Error while deleting employee details',
        tokenSend: 'Temporary token sent via SMS. OTP valid for up to 60 seconds...',
        loginError: 'Error while trying to login...',
        invalidToken: 'Invalid 2FA token. Token does not matched',
        tokenVerifyError: 'Error during 2FA verification',
        invalidOtp: 'Invalid OTP provided',
        noTokenProvided: 'Unauthorized: No token provided',
        invalidTokenFormat: 'Unauthorized: Invalid token format',
        invalidJwtToken: 'Unauthorized: Invalid JWT token',
      },
    },
  },
} );

module.exports = i18next;
