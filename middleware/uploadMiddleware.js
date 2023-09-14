const multer = require( 'multer' );
const path = require( 'path' );

const storage = multer.diskStorage( {
  destination: function ( req, file, cb ) {
    cb( null, 'uploads/' );
  },
  filename: function ( req, file, cb ) {
    const uniqueSuffix = Date.now() + '-' + Math.round( Math.random() * 1E9 );
    const extname = path.extname( file.originalname ).toLowerCase();
    cb( null, 'profile-' + uniqueSuffix + extname );
  }
} );

const upload = multer( {
  storage: storage,
  limits: {
    fileSize: 2 * 1024 * 1024,
  },
  fileFilter: function ( req, file, cb ) {
    const allowedExtensions = [ '.jpg', '.jpeg', '.png' ];
    const extname = path.extname( file.originalname ).toLowerCase();

    if ( allowedExtensions.includes( extname ) )
    {
      cb( null, true );
    } else
    {
      cb( new Error( 'Invalid file extension. Only JPG, JPEG, and PNG files are allowed.' ) );
    }
  }
} );

module.exports = upload;
