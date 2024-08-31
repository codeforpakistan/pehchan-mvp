require('dotenv').config();
const express = require('express');
const axios = require('axios');
const qs = require('querystring');

const app = express();
const port = 1337;

// Serve static files from 'public' directory (optional)
app.use(express.static('public'));

// Set EJS as the view engine (optional if you're using templates)
app.set('view engine', 'ejs');

// Home route
app.get('/', (req, res) => {
    res.render('home');  // Assuming you have a home.ejs template
});

// Login route
app.get('/login', (req, res) => {
    const keycloakLoginUrl = `${process.env.KEYCLOAK_URL}/realms/${process.env.KEYCLOAK_REALM}/protocol/openid-connect/auth`;
    const clientId = process.env.KEYCLOAK_CLIENT_ID;
    const redirectUri = encodeURIComponent(process.env.REDIRECT_URI);
    const state = Math.random().toString(36).substring(7);
    const nonce = Math.random().toString(36).substring(7);
    const responseType = 'code';
    const scope = 'openid';

    const loginUrl = `${keycloakLoginUrl}?client_id=${clientId}&redirect_uri=${redirectUri}&state=${state}&response_type=${responseType}&scope=${scope}&nonce=${nonce}`;

    res.redirect(loginUrl);
});

// Callback route
app.get('/callback', async (req, res) => {
    const { code } = req.query;

    try {
        const tokenResponse = await axios.post(`${process.env.KEYCLOAK_URL}/realms/${process.env.KEYCLOAK_REALM}/protocol/openid-connect/token`,
            qs.stringify({
                grant_type: 'authorization_code',
                client_id: process.env.KEYCLOAK_CLIENT_ID,
                client_secret: process.env.KEYCLOAK_CLIENT_SECRET,
                code: code,
                redirect_uri: process.env.REDIRECT_URI
            }), {
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded'
                }
            }
        );

        const { access_token, refresh_token, id_token } = tokenResponse.data;

        // Render the callback view with the authorization code
        res.render('callback', { code: code });

    } catch (error) {
        console.error('Error exchanging code for tokens:', error.response ? error.response.data : error.message);
        res.status(500).send('Authentication failed');
    }
});

// Logout route
app.get('/logout', (req, res) => {
    const keycloakLogoutUrl = `${process.env.KEYCLOAK_URL}/realms/${process.env.KEYCLOAK_REALM}/protocol/openid-connect/logout`;
    const redirectUri = encodeURIComponent('http://localhost:1337/'); // Redirect back to home after logout

    // Clear session or tokens
    // req.session.destroy();

    const logoutUrl = `${keycloakLogoutUrl}?post_logout_redirect_uri=${redirectUri}&client_id=${process.env.KEYCLOAK_CLIENT_ID}`;
    
    res.redirect(logoutUrl);
});

// Start the server
app.listen(port, () => {
    console.log(`Demo government portal running at http://localhost:${port}`);
});