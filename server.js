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
const GRAPH_VERSION = process.env.META_GRAPH_VERSION || 'v20.0';
const PUBLIC_BASE_URL = (process.env.PUBLIC_BASE_URL || 'https://cloudflow-app.onrender.com').replace(/\/$/, '');
const REDIRECT_URI = process.env.META_REDIRECT_URI || `${PUBLIC_BASE_URL}/api/auth/instagram/callback`;
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
  try { return JSON.parse(val); } catch { return null; }
};

function requireEnv(name, value) {
  if (!value) throw new Error(`${name} is not configured`);
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
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (token) headers.Authorization = `Bearer ${token}`;

  const response = await fetch(url, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body)
  });

  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(data?.error?.message || `Meta API error`);
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
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : (req.query.token || null);
  if (!token || token === 'undefined') return res.status(401).json({ error: 'Authentication required' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired session' });
    req.user = user;
    next();
  });
}

// =============================================================================
// WEBHOOK RECEIVER & AUTOMATION
// =============================================================================

app.get('/webhook', (req, res) => {
  const mode = req.query['hub.mode'];
  const token = req.query['hub.verify_token'];
  const challenge = req.query['hub.challenge'];
  if (mode === 'subscribe' && token === VERIFY_TOKEN) {
    console.log('✅ Webhook verified');
    return res.status(200).send(challenge);
  }
  res.sendStatus(403);
});

app.post('/webhook', async (req, res) => {
  res.status(200).send('EVENT_RECEIVED');
  const body = req.body;

  if (body.object === 'instagram' || body.object === 'page') {
    for (const entry of body.entry) {
      if (entry.messaging) {
        for (const event of entry.messaging) {
          const senderId = event.sender.id;
          const igId = entry.id;

          if (event.message && event.message.text) {
            await handleAutomation(igId, senderId, event.message.text);
          } else if (event.optin) {
            const payload = event.optin.payload || "OPTIN_TRIGGER";
            await handleAutomation(igId, senderId, payload);
          } else if (event.postback) {
            await handleAutomation(igId, senderId, event.postback.payload);
          }
        }
      }
    }
  }
});

async function handleAutomation(igId, senderId, trigger) {
  const userId = await redis.get(`page_owner:${igId}`);
  if (!userId) return;

  const rules = await redis.hgetall(`post_rules:${userId}`);
  const token = (await redis.hget('page_tokens', igId)) || FALLBACK_PAGE_TOKEN;

  for (const ruleStr of Object.values(rules || {})) {
    const rule = safeParse(ruleStr);
    if (rule && trigger.toUpperCase().includes(rule.keyword.toUpperCase())) {
      await sendInstagramMessage({ token, senderId, text: rule.responseText });
    }
  }
}

async function sendInstagramMessage({ token, senderId, commentId, text }) {
  try {
    const endpoint = commentId ? `/${commentId}/private_replies` : `/me/messages`;
    const body = commentId ? { message: text } : { recipient: { id: senderId }, message: { text } };
    await graphFetch(endpoint, { method: 'POST', token, body });
  } catch (err) {
    console.error(`❌ Send failed:`, err.meta || err.message);
  }
}

// =============================================================================
// OAUTH & SUBSCRIPTION
// =============================================================================

async function subscribePage(pageId, pageAccessToken) {
  try {
    await graphFetch(`/${pageId}/subscribed_apps`, {
      method: 'POST',
      token: pageAccessToken,
      params: { subscribed_fields: 'messages,messaging_postbacks,messaging_optins,feed' }
    });
  } catch (err) {
    console.error(`⚠️ Subscription failed:`, err.message);
  }
}

app.get('/api/auth/instagram', async (req, res) => {
  try {
    requireEnv('META_APP_ID', META_APP_ID);
    const sessionToken = String(req.query.token || '');
    const user = jwt.verify(sessionToken, JWT_SECRET);
    const state = crypto.randomBytes(32).toString('hex');
    await redis.set(`oauth_state:${state}`, JSON.stringify({ userId: user.id, email: user.email }), { ex: 600 });

    const scopes = ['instagram_basic','instagram_manage_comments','instagram_manage_messages','pages_show_list','pages_read_engagement','pages_messaging','business_management'].join(',');
    const url = new URL(`https://www.facebook.com/${GRAPH_VERSION}/dialog/oauth`);
    url.searchParams.set('client_id', META_APP_ID);
    url.searchParams.set('redirect_uri', REDIRECT_URI);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('scope', scopes);
    url.searchParams.set('state', state);
    res.redirect(url.toString());
  } catch (err) {
    res.redirect(`/?error=${encodeURIComponent(err.message)}`);
  }
});

app.get('/api/auth/instagram/callback', async (req, res) => {
  try {
    const { code, state } = req.query;
    const stateKey = `oauth_state:${String(state)}`;
    const stateData = safeParse(await redis.get(stateKey));
    await redis.del(stateKey);

    const tokenData = await graphFetch('/oauth/access_token', {
      params: { client_id: META_APP_ID, redirect_uri: REDIRECT_URI, client_secret: META_APP_SECRET, code }
    });

    const pagesData = await graphFetch('/me/accounts', {
      token: tokenData.access_token,
      params: { fields: 'id,name,access_token,instagram_business_account' }
    });

    for (const page of pagesData.data) {
      const igId = page.instagram_business_account?.id;
      if (!igId) continue;

      await redis.hset('page_tokens', { [page.id]: page.access_token, [igId]: page.access_token });
      await redis.hset(`user_pages:${stateData.userId}`, { [page.id]: JSON.stringify({ pageId: page.id, pageName: page.name, igId }) });
      await redis.set(`page_owner:${page.id}`, stateData.userId);
      await redis.set(`page_owner:${igId}`, stateData.userId);
      await subscribePage(page.id, page.access_token);
    }
    res.redirect('/?meta_connect=success');
  } catch (err) {
    res.redirect(`/?error=${encodeURIComponent(err.message)}`);
  }
});

// =============================================================================
// USER & RULES API
// =============================================================================

app.post('/api/signup', async (req, res) => {
  const { email, password } = req.body;
  const userId = crypto.randomUUID();
  const hashedPassword = await bcrypt.hash(password, 10);
  await redis.hset('users', { [email.toLowerCase()]: JSON.stringify({ id: userId, email, password: hashedPassword }) });
  const token = jwt.sign({ id: userId, email }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ success: true, token, user: { id: userId, email } });
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const userStr = await redis.hget('users', email.toLowerCase());
  const user = safeParse(userStr);
  if (!user || !(await bcrypt.compare(password, user.password))) return res.status(400).json({ error: 'Invalid credentials' });
  const token = jwt.sign({ id: user.id, email }, JWT_SECRET, { expiresIn: '7d' });
  res.json({ token, user: { id: user.id, email } });
});

app.post('/api/rules/post', authenticateToken, async (req, res) => {
  const { mediaId, keyword, responseText } = req.body;
  await redis.hset(`post_rules:${req.user.id}`, { [mediaId]: JSON.stringify({ mediaId, keyword, responseText }) });
  res.json({ success: true });
});

app.get('/api/dashboard-data', authenticateToken, async (req, res) => {
  const postRules = await redis.hgetall(`post_rules:${req.user.id}`);
  const parsedRules = {};
  for (const [k, v] of Object.entries(postRules || {})) parsedRules[k] = safeParse(v);
  res.json({ postRules: parsedRules });
});

app.listen(PORT, () => console.log(`🚀 Cloudflow running on port ${PORT}`));
