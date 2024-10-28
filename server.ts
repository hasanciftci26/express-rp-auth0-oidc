import express, { Request, Response } from 'express';
import dotenv from 'dotenv';
import axios from 'axios';
import cookieParser from 'cookie-parser';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import { URLSearchParams } from 'url';

dotenv.config();

const app = express();
const port = 3000;

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static('public'));

// Function to generate a random code verifier and code challenge
const generateCodeChallenge = (codeVerifier: string) => {
    const hashed = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
    return hashed;
};

// Route to initiate OIDC login without PKCE
app.get('/oidc/login', (req: Request, res: Response) => {
    const { CLIENT_ID, AUTHORIZATION_ENDPOINT, REDIRECT_URI } = process.env;

    const params = new URLSearchParams({
        response_type: 'code',
        client_id: CLIENT_ID || '',
        redirect_uri: REDIRECT_URI || '',
        scope: 'openid profile email',
        state: crypto.randomBytes(16).toString('hex'), // Random state
    });

    const authorizationUrl = `${AUTHORIZATION_ENDPOINT}?${params.toString()}`;
    res.redirect(authorizationUrl);
});

// Route to initiate OIDC login with PKCE
app.get('/oidc/login/pkce', (req: Request, res: Response) => {
    const { CLIENT_ID, AUTHORIZATION_ENDPOINT, REDIRECT_URI } = process.env;

    const codeVerifier = crypto.randomBytes(32).toString('hex'); // Generate code verifier
    const codeChallenge = generateCodeChallenge(codeVerifier); // Generate code challenge

    // Store code verifier in cookies for later use
    res.cookie('code_verifier', codeVerifier, { httpOnly: true });

    const params = new URLSearchParams({
        response_type: 'code',
        client_id: CLIENT_ID || '',
        redirect_uri: REDIRECT_URI || '',
        scope: 'openid profile email',
        state: crypto.randomBytes(16).toString('hex'), // Random state
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
    });

    const authorizationUrl = `${AUTHORIZATION_ENDPOINT}?${params.toString()}`;
    res.redirect(authorizationUrl);
});

// Callback endpoint to receive authorization code
app.get('/oidc/callback', async (req: Request, res: Response) => {
    const { code } = req.query;
    const { CLIENT_ID, CLIENT_SECRET, TOKEN_ENDPOINT, REDIRECT_URI } = process.env;

    const codeVerifier = req.cookies['code_verifier'];

    const params = new URLSearchParams({
        grant_type: 'authorization_code',
        code: code as string,
        redirect_uri: REDIRECT_URI || '',
        client_id: CLIENT_ID || '',
        ...(codeVerifier ? { code_verifier: codeVerifier } : {}),
        client_secret: CLIENT_SECRET || '',
    });

    try {
        const response = await axios.post(TOKEN_ENDPOINT as string, params);
        const { id_token, access_token } = response.data;

        // Decode the tokens
        const decodedIdToken = jwt.decode(id_token);

        // Send the decoded tokens as JSON
        res.json({
            id_token: decodedIdToken,
            access_token: access_token
        });
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Token request failed' });
    }
});

// Start the server
app.listen(port, () => {
    console.log(`Server is running at http://localhost:${port}`);
});
