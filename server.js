
require('dotenv').config();

const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { Redis } = require('@upstash/redis');

const app = express();

app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// =============================================================================
// REDIS
// =============================================================================

const redis = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL,
  token: process.env.UPSTASH_REDIS_REST_TOKEN
});

// =============================================================================
// CONFIG
// =============================================================================

const PORT = process.env.PORT || 10000;

const GRAPH_VERSION = process.env.META_GRAPH_VERSION || 'v26.0';

const PUBLIC_BASE_URL = (
  process.env.PUBLIC_BASE_URL || 'https://cloudflow-app.onrender.com'
).replace(/\/$/, '');

const REDIRECT_URI =
  process.env.META_REDIRECT_URI || `${PUBLIC_BASE_URL}/api/auth/instagram/callback`;

const VERIFY_TOKEN = (process.env.VERIFY_TOKEN || 'my_secret_token_123').trim();

const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_jwt_key_99';

const META_APP_ID = process.env.META_APP_ID;
const META_APP_SECRET = process.env.META_APP_SECRET;

const FALLBACK_PAGE_TOKEN = process.env.FACEBOOK_PAGE_ACCESS_TOKEN;

const GRAPH_BASE = `https://graph.facebook.com/${GRAPH_VERSION}`;

// =============================================================================
// HELPERS
// =============================================================================

const safeParse = (val) => {
  if (!val) return null;
  if (typeof val === 'object') return val;
  try {
    return JSON.parse(val);
  } catch {
    return null;
  }
};

function requireEnv(name, value) {
  if (!value) {
    throw new Error(`${name} is not configured`);
  }
}

function graphUrl(pathname, params = {}) {
  const pathValue = pathname.startsWith('/') ? pathname : `/${pathname}`;
  const url = new URL(`${GRAPH_BASE}${pathValue}`);

  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== '') {
      url.searchParams.set(key, value);
    }
  }

  return url;
}

async function graphFetch(pathname, { method = 'GET', token, params = {}, body } = {}) {
  const url = graphUrl(pathname, params);
  const headers = { Accept: 'application/json' };

  if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
  }

  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

  const response = await fetch(url, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body)
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    const message = data?.error?.message || `Meta API returned HTTP ${response.status}`;
    const error = new Error(message);
    error.status = response.status;
    error.meta = data?.error || data;
    throw error;
  }

  return data;
}

// =============================================================================
// AUTH MIDDLEWARE
// =============================================================================

function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ')
    ? authHeader.slice(7)
    : (req.query.token || null);

  if (!token || token === 'undefined') {
    return res.status(401).json({ error: 'Authentication required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired session' });
    }
    req.user = user;
    next();
  });
}

// =============================================================================
// HEALTH / DEBUG
// =============================================================================

app.get('/health', (req, res) => {
  res.status(200).send('OK');
});

app.get('/api/debug/status', async (req, res) => {
  try {
    const fallbackUser = await redis.get('fallback_user_id');
    const rules = fallbackUser
      ? await redis.hgetall(`post_rules:${fallbackUser}`)
      : {};

    res.json({
      status: 'Online',
      graphVersion: GRAPH_VERSION,
      appIdConfigured: Boolean(META_APP_ID),
      appSecretConfigured: Boolean(META_APP_SECRET),
      redirectUri: REDIRECT_URI,
      webhookConfigured: Boolean(VERIFY_TOKEN),
      envPageTokenConfigured: Boolean(FALLBACK_PAGE_TOKEN),
      fallbackUser,
      rulesCount: Object.keys(rules || {}).length
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// =============================================================================
// SIGNUP & LOGIN & ACCOUNT MANAGEMENT
// =============================================================================

app.post('/api/signup', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const normalizedEmail = String(email || '').trim().toLowerCase();

    if (!normalizedEmail || !/^\S+@\S+\.\S+$/.test(normalizedEmail)) {
      return res.status(400).json({ error: 'Enter a valid email address.' });
    }

    if (!password || String(password).length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters.' });
    }

    const existing = await redis.hget('users', normalizedEmail);
    if (existing) {
      return res.status(409).json({ error: 'An account with that email already exists.' });
    }

    const userId = crypto.randomUUID();
    const hashedPassword = await bcrypt.hash(password, 10);

    await redis.hset('users', {
      [normalizedEmail]: JSON.stringify({
        id: userId,
        email: normalizedEmail,
        password: hashedPassword
      })
    });

    const token = jwt.sign({ id: userId, email: normalizedEmail }, JWT_SECRET, { expiresIn: '7d' });

    res.json({
      success: true,
      token,
      user: { id: userId, email: normalizedEmail }
    });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ error: 'Unable to create account.' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const normalizedEmail = String(email || '').trim().toLowerCase();

    const userStr = await redis.hget('users', normalizedEmail);
    if (!userStr) {
      return res.status(400).json({ error: 'User not found' });
    }

    const user = safeParse(userStr);
    if (!user || !(await bcrypt.compare(String(password || ''), user.password))) {
      return res.status(400).json({ error: 'Wrong password' });
    }

    const token = jwt.sign({ id: user.id, email: normalizedEmail }, JWT_SECRET, { expiresIn: '7d' });

    res.json({
      token,
      user: { id: user.id, email: normalizedEmail }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed.' });
  }
});

// =============================================================================
// ✅ FIX #4: MISSING PASSWORD UPDATE ENDPOINT (was called by frontend but didn't exist)
// =============================================================================

app.post('/api/user/settings', authenticateToken, async (req, res) => {
  try {
    const { newPassword } = req.body || {};

    if (!newPassword || String(newPassword).length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters.' });
    }

    const lowerEmail = req.user.email ? req.user.email.toLowerCase() : null;
    if (!lowerEmail) {
      return res.status(400).json({ error: 'User email not found in session.' });
    }

    const userStr = await redis.hget('users', lowerEmail);
    const user = safeParse(userStr);
    if (!user) {
      return res.status(404).json({ error: 'User not found.' });
    }

    user.password = await bcrypt.hash(String(newPassword), 10);
    await redis.hset('users', { [lowerEmail]: JSON.stringify(user) });

    res.json({ success: true, message: 'Password updated.' });
  } catch (err) {
    console.error('Update password error:', err);
    res.status(500).json({ error: 'Unable to update password.' });
  }
});

app.delete('/api/user/account', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const lowerEmail = req.user.email ? req.user.email.toLowerCase() : null;

    if (lowerEmail) {
      await redis.hdel('users', lowerEmail);
    }

    await redis.del(`user_pages:${userId}`);
    await redis.del(`post_rules:${userId}`);

    console.log(`��️ Account deleted: ${userId}`);
    res.json({ success: true, message: 'Account deleted successfully.' });
  } catch (err) {
    res.status(500).json({ error: 'Unable to delete account.' });
  }
});

// =============================================================================
// META OAUTH
// =============================================================================

app.get('/api/auth/instagram', async (req, res) => {
  try {
    requireEnv('META_APP_ID', META_APP_ID);
    requireEnv('JWT_SECRET', JWT_SECRET);

    const sessionToken = String(req.query.token || '');
    const user = jwt.verify(sessionToken, JWT_SECRET);

    const state = crypto.randomBytes(32).toString('hex');

    await redis.set(
      `oauth_state:${state}`,
      JSON.stringify({ userId: user.id, email: user.email }),
      { ex: 600 }
    );

    const scopes = [
      'instagram_basic',
      'instagram_manage_comments',
      'instagram_manage_messages',
      'pages_show_list',
      'pages_read_engagement',
      'pages_messaging',
      'business_management'
    ].join(',');

    const url = new URL(`https://www.facebook.com/${GRAPH_VERSION}/dialog/oauth`);
    url.searchParams.set('client_id', META_APP_ID);
    url.searchParams.set('redirect_uri', REDIRECT_URI);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('scope', scopes);
    url.searchParams.set('state', state);

    console.log('�� Starting Meta OAuth:', { redirectUri: REDIRECT_URI, graphVersion: GRAPH_VERSION, scopes });

    res.redirect(url.toString());
  } catch (err) {
    console.error('OAuth start error:', err);
    res.redirect(`/?error=${encodeURIComponent(err.message)}`);
  }
});

// =============================================================================
// ✅ FIX #3: SEND subscribed_fields IN POST BODY (was query param — could silently fail)
// =============================================================================

async function subscribePage(pageId, pageAccessToken) {
  try {
    const result = await graphFetch(`/${pageId}/subscribed_apps`, {
      method: 'POST',
      token: pageAccessToken,
      body: {
        subscrib
