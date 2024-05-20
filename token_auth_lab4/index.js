const uuid = require('uuid');
const express = require('express');
const onFinished = require('on-finished');
const bodyParser = require('body-parser');
const path = require('path');
const port = 3000;
const fs = require('fs');
const jwt = require('jsonwebtoken');
const jwksClient = require('jwks-rsa');
const axios = require('axios');

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const SESSION_KEY = 'Authorization';

const AUTH0_DOMAIN = 'dev-6gy1y55ygvp8ber7.us.auth0.com';
const AUTH0_CLIENT_ID = 'Fp4vHhmHKfQV05jF4LBIZihJMPTy483I';
const AUTH0_CLIENT_SECRET = 'j68WJUS60IBU0erhLteumFFtXBEGcfNxTQupCjAO3X6hfBtIrKi4zOs52bzIvQU4';

class Session {
    #sessions = {}

    constructor() {
        try {
            this.#sessions = fs.readFileSync('./sessions.json', 'utf8');
            this.#sessions = JSON.parse(this.#sessions.trim());

            //console.log(this.#sessions);
        } catch(e) {
            this.#sessions = {};
        }
    }

    #storeSessions() {
        fs.writeFileSync('./sessions.json', JSON.stringify(this.#sessions), 'utf-8');
    }

    set(key, value) {
        if (!value) {
            value = {};
        }
        this.#sessions[key] = value;
        this.#storeSessions();
    }

    get(key) {
        return this.#sessions[key];
    }

    init(res) {
        const sessionId = uuid.v4();
        this.set(sessionId);

        return sessionId;
    }

    destroy(req, res) {
        const sessionId = req.sessionId;
        delete this.#sessions[sessionId];
        this.#storeSessions();
    }
}

const sessions = new Session();

// Функція, що отримує ключ Auth0
const getPublicKey = (header, callback) => {
    const client = jwksClient({
        jwksUri: `https://${AUTH0_DOMAIN}/.well-known/jwks.json`
    });
    client.getSigningKey(header.kid, (err, key) => {
        if (err) {
            callback(err);
        } else {
            const signingKey = key.publicKey || key.rsaPublicKey;
            callback(null, signingKey);
        }
    });
};

app.use((req, res, next) => {
    let currentSession = {};
    let sessionId = req.get(SESSION_KEY);

    if (sessionId) {
        currentSession = sessions.get(sessionId);
        if (!currentSession) {
            currentSession = {};
            sessionId = sessions.init(res);
        }
    } else {
        sessionId = sessions.init(res);
    }

    req.session = currentSession;
    req.sessionId = sessionId;

    onFinished(req, () => {
        const currentSession = req.session;
        const sessionId = req.sessionId;
        sessions.set(sessionId, currentSession);
    });

    if (req.session.access_token && req.session.refresh_token) {
        const accessToken = req.session.access_token;
        const refreshToken = req.session.refresh_token;

        jwt.verify(accessToken, getPublicKey, (err, decoded) => {
            if (err) {
                console.error('Invalid access token:', err);
                return res.status(401).send('Invalid access token');
            } else {
                const currentTime = Math.floor(Date.now() / 1000);

                if (decoded.exp-60 < currentTime) {
                    // Токен прострочений, необхідно оновити
                    axios.post('http://localhost:3000/api/refreshToken', {
                        refresh_token: refreshToken
                    })
                        .then(response => {
                            req.session.access_token = response.data.access_token;
                            req.session.refresh_token = response.data.refresh_token;
                            next();
                        })
                        .catch(error => {
                            console.error('Token refresh failed:', error.response ? error.response.data : error.message);
                            res.status(401).send('Token refresh failed');
                        });
                } else {
                    next();
                }
            }
        });
    } else {
        next();
    }
})

app.get('/', (req, res) => {
    if (req.session.access_token) {
        return res.json({
            username: req.session.username,
            logout: 'http://localhost:3000/logout'
        })
    }
    res.sendFile(path.join(__dirname+'/index.html'));
})

app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname+'/register.html'));
})

app.get('/logout', (req, res) => {
    sessions.destroy(req, res);
    res.redirect('/');
});

app.post('/api/login', async (req, res) => {
    const {login, password} = req.body;

    try {
        const response = await axios.post(`https://${AUTH0_DOMAIN}/oauth/token`, {
            audience: `https://${AUTH0_DOMAIN}/api/v2/`,
            grant_type: 'password',
            username: login,
            password: password,
            client_id: AUTH0_CLIENT_ID,
            client_secret: AUTH0_CLIENT_SECRET,
            scope: 'offline_access'
        });

        const { access_token, refresh_token } = response.data;
        const userId = jwt.decode(access_token).sub;

        req.session.username = userId;
        req.session.access_token = access_token;
        req.session.refresh_token = refresh_token;

        res.json({ token: req.sessionId });
    } catch (error) {
        console.error('Login failed:', error.response ? error.response.data : error.message);
        res.status(401).send('Login failed');
    }
});

app.post('/api/createUser', async (req, res) => {
    const {email, password} = req.body;
    console.log(email);
    try {
        const response = await axios.post(`https://${AUTH0_DOMAIN}/dbconnections/signup`, {
            email: email,
            password: password,
            client_id: AUTH0_CLIENT_ID,
            connection: 'Username-Password-Authentication'
        });

        res.status(201).send('User created successfully');
    } catch (error) {
        console.error('User creation failed:', error.response ? error.response.data : error.message);
        res.status(500).send('User creation failed');
    }
});

app.post('/api/refreshToken', async (req, res) => {
    const refreshToken = req.body.refresh_token;

    try {
        const response = await axios.post(`https://${AUTH0_DOMAIN}/oauth/token`, {
            grant_type: 'refresh_token',
            client_id: AUTH0_CLIENT_ID,
            client_secret: AUTH0_CLIENT_SECRET,
            refresh_token: refreshToken
        });

        const { access_token, refresh_token } = response.data;

        console.log(refresh_token);
        res.json({ access_token, refresh_token });
    } catch (error) {
        console.error('Token refresh failed:', error.response ? error.response.data : error.message);
        res.status(401).send('Token refresh failed');
    }
});

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
})