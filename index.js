require('dotenv').config();

const uuid = require('uuid');
const express = require('express');
const onFinished = require('on-finished');
const bodyParser = require('body-parser');
const path = require('path');
const fs = require('fs');
const axios = require('axios');

const port = 3000;
const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const SESSION_KEY = 'Authorization';

class Session {
    #sessions = {}

    constructor() {
        try {
            this.#sessions = fs.readFileSync('./sessions.json', 'utf8');
            this.#sessions = JSON.parse(this.#sessions.trim());
        } catch (e) {
            this.#sessions = {};
        }
    }

    #storeSessions() {
        fs.writeFileSync('./sessions.json', JSON.stringify(this.#sessions, null, 2), 'utf-8');
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

    init() {
        const sessionId = uuid.v4();
        this.#sessions[sessionId] = {};
        return sessionId;
    }

    discard(sessionId) {
        delete this.#sessions[sessionId];
        this.#storeSessions();
    }

    destroy(req) {
        clearSession(req.session);
        delete this.#sessions[req.sessionId];
        this.#storeSessions();
        req.sessionDestroyed = true;
    }
}

const sessions = new Session();

function auth0Message(error) {
    const data = error.response && error.response.data;
    if (!data) {
        return error.message;
    }
    if (typeof data === 'string') {
        return data;
    }
    return data.error_description || data.message || data.error || error.message;
}

function tokenUrl() {
    return `https://${process.env.AUTH0_DOMAIN}/oauth/token`;
}

function clearSession(session) {
    for (const key of Object.keys(session)) {
        delete session[key];
    }
}

function decodeIdToken(idToken) {
    if (!idToken) {
        return null;
    }
    const part = idToken.split('.')[1];
    if (!part) {
        return null;
    }
    return JSON.parse(Buffer.from(part, 'base64url').toString('utf8'));
}

function usernameFromClaims(claims) {
    if (!claims) {
        return undefined;
    }
    return claims.name || claims.nickname || claims.email || claims.sub;
}

function sessionFromTokens(tokens, previous = {}) {
    const claims = decodeIdToken(tokens.id_token);
    return {
        access_token: tokens.access_token || previous.access_token,
        id_token: tokens.id_token || previous.id_token,
        refresh_token: tokens.refresh_token || previous.refresh_token,
        expires_at: Date.now() + (Number(tokens.expires_in) * 1000),
        username: usernameFromClaims(claims) || previous.username,
    };
}

async function passwordGrant(username, password) {
    const body = new URLSearchParams({
        grant_type: 'password',
        username,
        password,
        client_id: process.env.AUTH0_CLIENT_ID,
        client_secret: process.env.AUTH0_CLIENT_SECRET,
        scope: 'openid profile email offline_access',
    });
    const response = await axios.post(tokenUrl(), body.toString(), {
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
    });
    return response.data;
}

async function refreshGrant(refreshToken) {
    const body = new URLSearchParams({
        grant_type: 'refresh_token',
        client_id: process.env.AUTH0_CLIENT_ID,
        client_secret: process.env.AUTH0_CLIENT_SECRET,
        refresh_token: refreshToken,
    });
    const response = await axios.post(tokenUrl(), body.toString(), {
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
    });
    return response.data;
}

async function managementToken() {
    const body = new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: process.env.AUTH0_M2M_CLIENT_ID,
        client_secret: process.env.AUTH0_M2M_CLIENT_SECRET,
        audience: `https://${process.env.AUTH0_DOMAIN}/api/v2/`,
    });
    const response = await axios.post(tokenUrl(), body.toString(), {
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
    });
    return response.data.access_token;
}

app.use((req, res, next) => {
    let sessionId = req.get(SESSION_KEY);
    let currentSession;

    if (sessionId) {
        currentSession = sessions.get(sessionId);
        if (!currentSession) {
            sessionId = sessions.init();
            currentSession = sessions.get(sessionId);
        }
    } else {
        sessionId = sessions.init();
        currentSession = sessions.get(sessionId);
    }

    req.session = currentSession;
    req.sessionId = sessionId;

    onFinished(res, () => {
        if (req.sessionDestroyed) {
            return;
        }
        if (Object.keys(req.session).length === 0) {
            sessions.discard(req.sessionId);
            return;
        }
        sessions.set(req.sessionId, req.session);
    });

    next();
});

app.use(async (req, res, next) => {
    try {
        if (req.session.expires_at && req.session.expires_at <= Date.now() && !req.session.refresh_token) {
            sessions.destroy(req);
            return next();
        }

        if (!req.session.refresh_token || !req.session.expires_at) {
            return next();
        }

        const skewMs = Number(process.env.TOKEN_REFRESH_SKEW_SECONDS || 60) * 1000;
        if (req.session.expires_at - Date.now() >= skewMs) {
            return next();
        }

        const tokens = await refreshGrant(req.session.refresh_token);
        const updated = sessionFromTokens(tokens, req.session);
        clearSession(req.session);
        Object.assign(req.session, updated);
        console.log('токен оновлено через refresh_token');
        return next();
    } catch (error) {
        console.error(auth0Message(error));
        sessions.destroy(req);
        return next();
    }
});

app.get('/', (req, res) => {
    if (req.session.username) {
        return res.json({
            username: req.session.username,
            logout: 'http://localhost:3000/logout',
        });
    }
    if (req.get(SESSION_KEY)) {
        return res.status(401).json({ error: 'Сесія недійсна' });
    }
    res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/logout', (req, res) => {
    sessions.destroy(req);
    res.redirect('/');
});

app.post('/api/login', async (req, res) => {
    const { login, password } = req.body;

    if (!login || !password) {
        return res.status(401).json({ error: 'Вкажіть email і пароль' });
    }

    try {
        const tokens = await passwordGrant(login, password);
        const updated = sessionFromTokens(tokens);
        clearSession(req.session);
        Object.assign(req.session, updated);
        sessions.set(req.sessionId, req.session);
        return res.json({ token: req.sessionId });
    } catch (error) {
        console.error(auth0Message(error));
        return res.status(401).json({ error: auth0Message(error) });
    }
});

app.post('/api/register', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Вкажіть email і пароль' });
    }

    try {
        const token = await managementToken();
        await axios.post(`https://${process.env.AUTH0_DOMAIN}/api/v2/users`, {
            email,
            password,
            connection: 'Username-Password-Authentication',
            email_verified: true,
        }, {
            headers: {
                authorization: `Bearer ${token}`,
                'content-type': 'application/json',
            },
        });
        return res.json({ created: true });
    } catch (error) {
        console.error(auth0Message(error));
        return res.status(400).json({ error: auth0Message(error) });
    }
});

app.listen(port, () => {
    console.log(`Lab 4 listening on port ${port}`);
});
