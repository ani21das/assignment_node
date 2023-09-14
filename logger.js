const winston = require( 'winston' );
const DailyRotateFile = require( 'winston-daily-rotate-file' ); 

const logger = winston.createLogger( {
  level: 'info',
  format: winston.format.combine(
    winston.format.timestamp( { format: 'YYYY-MM-DD HH:mm:ss' } ),
    winston.format.printf( ( { timestamp, level, message } ) => {
      return `${ timestamp } ${ level }: ${ message }`;
    } )
  ),
  transports: [
    new winston.transports.Console(),
    new DailyRotateFile( {
      filename: 'logs/%DATE%.log', 
      datePattern: 'YYYY-MM-DD',   
      zippedArchive: true,
      maxSize: '20m',              
      maxFiles: '14d'             
    } )
  ]
} );

module.exports = logger;
