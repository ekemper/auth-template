
const { OAuth2Client } = require('google-auth-library');
const CLIENT_ID = '817620866614-3j683eppkju965sjmamg6qf49rgtmmpq.apps.googleusercontent.com';
const client = new OAuth2Client(CLIENT_ID);
const googleAuthMiddleware = (req, res, next) => {

    async function verify () {

        console.log('calling google auth verify');

        const ticket = await client.verifyIdToken({
            idToken: token,
            audience: CLIENT_ID,  // Specify the CLIENT_ID of the app that accesses the backend
            // Or, if multiple clients access the backend:
            //[CLIENT_ID_1, CLIENT_ID_2, CLIENT_ID_3]
        });

        const payload = ticket.getPayload();

        console.log(`rx'ed payload`, { payload })

        res.userId = payload['sub'];

        next();

        // If request specified a G Suite domain:
        //const domain = payload['hd'];
    }
    verify().catch(console.error);
}

module.exports = googleAuthMiddleware;