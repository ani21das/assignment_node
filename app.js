require( 'dotenv' ).config();

const express = require( 'express' );
const bodyParser = require( 'body-parser' );
const swaggerUi = require( 'swagger-ui-express' );
const swaggerDocumnet = require( './swagger.json' );
const userRoutes = require( './routes/userRoutes' );

const sequelize = require( './db' );
const logger = require( './logger' );

const app = express();

const port = process.env.PORT || 3000;

app.use( bodyParser.json() );

app.use( '/userRoutes', userRoutes );

app.use( '/api-docs', swaggerUi.serve, swaggerUi.setup( swaggerDocumnet ) );

sequelize
    .sync()
    .then( () => {
        app.listen( port, () => {
            logger.info( `Server started on http://localhost:${ port }` );
        } );
    } )
    .catch( ( error ) => {
        logger.error( 'Error connecting to the database', error );
    } );
