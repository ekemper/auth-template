
const { OAuth2Client } = require('google-auth-library');
const CLIENT_ID = '817620866614-3j683eppkju965sjmamg6qf49rgtmmpq.apps.googleusercontent.com';
const client = new OAuth2Client(CLIENT_ID);
const googleAuthMiddleware = (req, res, next) => {

    async function verify () {

        const token = parseToken(req);
        if (!token) {
            res.json({ Error: 'invalid token' })
        }

        const ticket = await client.verifyIdToken({
            idToken: token,
            audience: CLIENT_ID,  // Specify the CLIENT_ID of the app that accesses the backend
            // Or, if multiple clients access the backend:
            //[CLIENT_ID_1, CLIENT_ID_2, CLIENT_ID_3]
        });

        const payload = ticket.getPayload();
        res.userId = payload['sub'];

        next();

        // If request specified a G Suite domain:
        //const domain = payload['hd'];
    }
    verify().catch(console.error);
}

const parseToken = req => {
    const items = req.headers.authorization.split(/[ ]+/);
    if (items.length > 1 && items[0].trim() == "Bearer") {
        return items[1];
    } else {
        return null
    }
}

module.exports = googleAuthMiddleware;