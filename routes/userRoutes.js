const express = require( 'express' );
const router = express.Router();
const userController = require( '../controllers/userController' );
const authenticationToken = require( '../middleware/userAuth' );
const upload = require( '../middleware/uploadMiddleware' );
const logger = require( '../logger' );

router.post( '/userCreate', upload.single( 'profilePicture' ), ( req, res ) => {
    try
    {
        logger.info( 'POST / userCreate route called' );
        userController.userCreate( req, res );
    } catch ( error )
    {
        logger.error( 'Error in create user route:', error );
        res.send( 500 ).json( { message: 'Server Error' } );
    }
} );

router.post( '/userLogin', ( req, res ) => {
    try
    {
        logger.info( 'POST / userLogin route called' );
        userController.userLogin( req, res );
    } catch ( error )
    {
        logger.error( 'Error in login route:', error );
        res.status( 500 ).json( { message: 'Server Error' } );
    }
} );

router.post( '/verifyOtp', ( req, res ) => {
    try
    {
        logger.info( 'POST / verifyOtp route called' );
        userController.verifyOtp( req, res );
    } catch ( error )
    {
        logger.error( 'Error in verifyOtp route', error );
        res.status( 500 ).json( { message: 'Server Error' } );
    }
} );

router.get( '/getAllUsers',  ( req, res ) => {
    try
    {
        logger.info( 'GET / getAllUsers route called' );
        userController.getAllUsers( req, res );
    } catch ( error )
    {
        logger.error( 'Error in get all user route:', error );
        res.status( 500 ).json( { message: 'Server Error' } );
    }
} );

router.get( '/getUserByLogin', authenticationToken, ( req, res ) => {
    try
    {
        logger.info( 'GET / getUserByLogin route called' );
        userController.getUserByLogin( req, res );
    } catch ( error )
    {
        logger.error( 'Error in get emplpoyee by login:', error );
        res.status( 500 ).json( { message: 'Server Error' } );
    }
} );

router.put( '/updateUser', authenticationToken, upload.single
    ( 'profilePicture' ), ( req, res ) => {
        try
        {
            logger.info( 'PUT / updateUser route called' );
            userController.updateUser( req, res );
        } catch ( error )
        {
            logger.error( 'Error in update employee by login', error );
            res.status( 500 ).json( { message: 'Server Error' } );
        }
    } );

router.delete( '/deleteUser', authenticationToken, ( req, res ) => {
    try
    {
        logger.info( 'DELETE / deleteUser route called' );
        userController.deleteUser( req, res );
    } catch ( error )
    {
        logger.error( 'Error in delete user by login' );
        res.status( 500 ).json( { message: 'Server Error' } );
    }
} );

router.post( '/forgot-password', ( req, res ) => {
    try
    {
        logger.info( `POST / forgot-password route called` );
        userController.forgotPassword( req, res );
    } catch ( error )
    {
        logger.error( 'Error in forgot password route:', error );
        res.status( 500 ).json( { message: 'Server Error' } );
    }
} );

router.post( '/reset-password', ( req, res ) => {
    try
    {
        logger.info( `POST / reset-password route called` );
        userController.resetPassword( req, res );
    } catch ( error )
    {
        logger.error( 'Error in reset password route:', error );
        res.status( 500 ).json( { message: 'Server Error' } );
    }
} );

module.exports = router;