const { DataTypes } = require( 'sequelize' );
const sequelize = require( '../db' );
const bcrypt = require( 'bcrypt' );
const passwordValidator = require( 'password-validator' );
const validator = require( 'validator' );
const crypto = require( 'crypto' );
const logger = require( '../logger' );

const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY;

const User = sequelize.define(
    'User',
    {
        id: {
            type: DataTypes.INTEGER,
            primaryKey: true,
            autoIncrement: true,
        },
        firstName: {
            type: DataTypes.STRING,
            allowNull: false,
        },
        lastName: {
            type: DataTypes.STRING,
            allowNull: false,
        },
        age: {
            type: DataTypes.INTEGER,
            allowNull: false,
        },
        email: {
            type: DataTypes.STRING,
            allowNull: false,
            unique: true,
            validate: {
                isValidEmail ( value ) {
                    if ( !value || !validator.isEmail( value ) )
                    {
                        throw new Error( 'Invalid email address' );
                    }
                },
            },
        },
        country: {
            type: DataTypes.STRING,
            allowNull: false,
        },
        gender: {
            type: DataTypes.STRING,
            allowNull: true,
        },
        phoneNo: {
            type: DataTypes.STRING,
            allowNull: false,
            unique: true,
            validate: {
                isValidPhoneNo ( value ) {
                    const phoneRegex = /^\d{10}$/;
                    if ( !phoneRegex.test( value ) )
                    {
                        throw new Error( 'Invalid phone number.' );
                    }
                },
            },
        },
        password: {
            type: DataTypes.STRING,
            allowNull: false,
            validate: {
                isValidPassword ( value ) {
                    const passwordSchema = new passwordValidator();
                    passwordSchema
                        .is().min( 8 )
                        .has().uppercase()
                        .has().lowercase()
                        .has().digits()
                        .has().symbols()
                        .has().not().spaces();

                    if ( !passwordSchema.validate( value ) )
                    {
                        throw new Error( 'Invalid password. Password must meet the required criteria.' );
                    }
                },
            },
        },
        profilePicture: {
            type: DataTypes.STRING,
            allowNull: true,
        },
        bankAccountNumber: {
            type: DataTypes.STRING,
            allowNull: false,
        },
        bankRoutingNumber: {
            type: DataTypes.STRING,
            allowNull: false,
        },
        twoFactorSecret: {
            type: DataTypes.STRING,
            allowNull: true,
        },
    },
    {
        timestamps: true,
    }
);

User.beforeCreate( async ( user ) => {
    const saltRounds = 10;
    try
    {
        const salt = await bcrypt.genSalt( saltRounds );
        const hashedPassword = await bcrypt.hash( user.password, salt );
        user.password = hashedPassword;
    } catch ( error )
    {
        logger.error( 'Error hashing password:', error );
        throw new Error( 'Error hashing password' );
    }
} );

User.encryptField = function ( fieldValue ) {
    const cipher = crypto.createCipher( 'aes-256-cbc', ENCRYPTION_KEY );
    let encrypted = cipher.update( fieldValue, 'utf8', 'hex' );
    encrypted += cipher.final( 'hex' );
    return encrypted;
};

User.decryptField = function ( encryptedValue ) {
    const decipher = crypto.createDecipher( 'aes-256-cbc', ENCRYPTION_KEY );
    let decrypted = decipher.update( encryptedValue, 'hex', 'utf8' );
    decrypted += decipher.final( 'utf8' );
    return decrypted;
};

module.exports = User;
