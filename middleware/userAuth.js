const jwt = require( 'jsonwebtoken' );
const secretKey = process.env.SECRET_KEY;
const logger = require( '../logger' );
const i18next = require( '../i18next' );

const authenticateToken = async ( req, res, next ) => {

  const token = req.headers[ 'authorization' ];
  if ( !token )
  {
    logger.warn( 'Unauthorized: No token provided' );
    return res.status( 401 ).json( { message: i18next.t( 'noTokenProvided' ) } );
  }

  const tokenParts = token.split( ' ' );
  if ( tokenParts.length !== 2 || tokenParts[ 0 ] !== 'Bearer' )
  {
    logger.warn( 'Unauthorized: Invalid token format' );
    return res.status( 401 ).json( { message: i18next.t( 'invalidTokenFormat' ) } );
  }
  const extractedToken = tokenParts[ 1 ];

  jwt.verify( extractedToken, secretKey, async ( err, decoded ) => {
    if ( err )
    {
      logger.warn( 'Unauthorized: Invalid token' );
      return res.status( 401 ).json( { message: i18next.t( 'invalidJwtToken' ) } );
    }

    req.user = decoded;
    next();
  } );
};

module.exports = authenticateToken;
