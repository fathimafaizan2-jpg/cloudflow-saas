require('dotenv').config();

const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
<<<<<<< HEAD
=======
const crypto = require('crypto');
>>>>>>> e09eed7732a3a7bc51e4a6425bd15d8eb90697b4
const { Redis } = require('@upstash/redis');

const app = express();

app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

<<<<<<< HEAD
// Initialize Redis
const redis = new Redis({ 
  url: process.env.UPSTASH_REDIS_REST_URL, 
  token: process.env.UPSTASH_REDIS_REST_TOKEN 
});

const PORT = process.env.PORT || 10000;
=======
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
const PUBLIC_BASE_URL = (process.env.PUBLIC_BASE_URL || 'https://cloudflow-app.onrender.com').replace(/\/$/, '');
const REDIRECT_URI = process.env.META_REDIRECT_URI || `${PUBLIC_BASE_URL}/api/auth/instagram/callback`;
>>>>>>> e09eed7732a3a7bc51e4a6425bd15d8eb90697b4
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

<<<<<<< HEAD
// --- HELPERS ---
const safeParse = (val) => {
  if (!val) return null;
  if (typeof val === 'object') return val;
  try { return JSON.parse(val); } catch (e) { return null; }
};

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
=======
function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : (req.query.token || null);
  if (!token || token === 'undefined') return res.status(401).json({ error: 'Authentication required' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired session' });
>>>>>>> e09eed7732a3a7bc51e4a6425bd15d8eb90697b4
    req.user = user;
    next();
  });
};

<<<<<<< HEAD
// --- HEALTH CHECK FOR RENDER ---
app.get('/health', (req, res) => res.status(200).send('OK'));

// --- ADMIN & AUTH ---
app.get('/api/admin/master-reset', async (req, res) => {
  try {
    await redis.flushall();
    res.send('<h1>✅ Database Wiped Successfully!</h1>');
  } catch (err) {
    res.status(500).send('<h1>❌ Wipe Failed: ' + err.message + '</h1>');
  }
});

app.get('/api/debug/status', async (req, res) => {
  try {
    const fallbackUser = await redis.get('fallback_user_id');
    const rules = fallbackUser ? await redis.hgetall(`post_rules:${fallbackUser}`) : {};
    const tokens = await redis.hgetall('page_tokens');
    res.json({ 
      status: 'Online',
      appId: process.env.META_APP_ID,
      fallbackUser, 
      rulesCount: Object.keys(rules || {}).length, 
      tokenKeys: Object.keys(tokens || {}) 
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
=======
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
>>>>>>> e09eed7732a3a7bc51e4a6425bd15d8eb90697b4
  }
  res.sendStatus(403);
});

<<<<<<< HEAD
app.post('/api/signup', async (req, res) => {
  const { email, password } = req.body;
  const userId = Date.now().toString();
  const hashedPassword = await bcrypt.hash(password, 10);
  await redis.hset('users', { [email]: JSON.stringify({ id: userId, password: hashedPassword }) });
  res.json({ success: true });
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const userStr = await redis.hget('users', email);
  if (!userStr) return res.status(400).json({ error: 'User not found' });
  const user = JSON.parse(userStr);
  if (await bcrypt.compare(password, user.password)) {
    const token = jwt.sign({ id: user.id, email }, JWT_SECRET);
    res.json({ token });
  } else res.status(400).json({ error: 'Wrong password' });
});

// --- META OAUTH ---
app.get('/api/auth/instagram', (req, res) => {
  const { token } = req.query;
  const user = jwt.verify(token, JWT_SECRET);
  const state = Buffer.from(JSON.stringify({ userId: user.id, token })).toString('base64');
  const scope = 'instagram_basic,instagram_manage_messages,instagram_manage_comments,pages_show_list,pages_read_engagement,pages_messaging';
  const url = `https://www.facebook.com/v19.0/dialog/oauth?client_id=${process.env.META_APP_ID}&redirect_uri=${encodeURIComponent(`https://${req.get('host')}/api/auth/instagram/callback`)}&scope=${scope}&state=${state}`;
  res.redirect(url);
=======
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
>>>>>>> e09eed7732a3a7bc51e4a6425bd15d8eb90697b4
});

app.get('/api/auth/instagram/callback', async (req, res) => {
  try {
    const { code, state } = req.query;
<<<<<<< HEAD
    const { userId, token: userJwtToken } = JSON.parse(Buffer.from(state, 'base64').toString('utf-8'));
    const appId = process.env.META_APP_ID;
    const appSecret = process.env.META_APP_SECRET;
    const redirectUri = `https://${req.get('host')}/api/auth/instagram/callback`;

    const tokenRes = await fetch(`https://graph.facebook.com/v19.0/oauth/access_token?client_id=${appId}&redirect_uri=${encodeURIComponent(redirectUri)}&client_secret=${appSecret}&code=${code}`);
    const tokenData = await tokenRes.json();
    if (!tokenData.access_token) throw new Error('Token exchange failed: ' + JSON.stringify(tokenData));

    const pagesRes = await fetch(`https://graph.facebook.com/v19.0/me/accounts?access_token=${tokenData.access_token}`);
    const pagesData = await pagesRes.json();

    if (pagesData.data) {
      for (const page of pagesData.data) {
        const igRes = await fetch(`https://graph.facebook.com/v19.0/${page.id}?fields=instagram_business_account&access_token=${page.access_token}`);
        const igData = await igRes.json();
        const igId = igData.instagram_business_account?.id;

        await redis.hset('page_tokens', { [page.id]: page.access_token });
        await redis.hset(`user_pages:${userId}`, { [page.id]: page.name });
        await redis.set(`page_owner:${page.id}`, userId);

        if (igId) {
          await redis.hset('page_tokens', { [igId]: page.access_token });
          await redis.set(`page_owner:${igId}`, userId);
          console.log(`🔗 Linked IG ID: ${igId}`);
        }
        
        await redis.set('fallback_user_id', userId);
        await redis.set('fallback_token', page.access_token);
        await fetch(`https://graph.facebook.com/v19.0/${page.id}/subscribed_apps?subscribed_fields=messages,messaging_postbacks,feed&access_token=${page.access_token}`, { method: 'POST' });
      }
    }
    res.redirect(`/?meta_connect=success&token=${userJwtToken}`);
  } catch (err) {
    console.error('OAuth Error:', err);
    res.redirect('/?error=oauth_failed');
  }
});

// --- DATA API ---
app.get('/api/instagram/accounts', authenticateToken, async (req, res) => {
  const accountsMap = await redis.hgetall(`user_pages:${req.user.id}`);
  res.json({ accounts: Object.entries(accountsMap || {}).map(([pageId, name]) => ({ pageId, name })) });
});

app.get('/api/instagram/posts', authenticateToken, async (req, res) => {
  const { pageId } = req.query;
  const token = await redis.hget('page_tokens', pageId);
  const igRes = await fetch(`https://graph.facebook.com/v19.0/${pageId}?fields=instagram_business_account&access_token=${token}`);
  const igData = await igRes.json();
  const igId = igData.instagram_business_account?.id;
  if (!igId) return res.json({ posts: [] });
  const postsRes = await fetch(`https://graph.facebook.com/v19.0/${igId}/media?fields=id,caption,media_url,media_type,thumbnail_url&access_token=${token}`);
  const postsData = await postsRes.json();
  res.json({ posts: postsData.data || [] });
});

app.post('/api/rules/post', authenticateToken, async (req, res) => {
  const { mediaId, keyword, responseText, caption, thumbnail } = req.body;
  await redis.hset(`post_rules:${req.user.id}`, { [mediaId]: JSON.stringify({ keyword, responseText, caption, thumbnail, mediaId }) });
  res.json({ success: true });
});

// --- WEBHOOKS & WORKER ---
app.get('/webhook', (req, res) => {
  if (req.query['hub.verify_token'] === VERIFY_TOKEN) res.status(200).send(req.query['hub.challenge']);
  else res.sendStatus(403);
});

app.post('/webhook', async (req, res) => {
  console.log('📬 WEBHOOK HIT!');
  console.log('📦 FULL BODY:', JSON.stringify(req.body, null, 2));
  await redis.lpush('meta_webhook_queue', JSON.stringify(req.body));
  res.status(200).send('EVENT_RECEIVED');
});

async function worker() {
  console.log('👷 Worker Active...');
  while (true) {
    try {
      const raw = await redis.rpop('meta_webhook_queue');
      if (!raw) { 
        await new Promise(r => setTimeout(r, 2000)); 
        continue; 
      }
      
      const payload = typeof raw === 'string' ? JSON.parse(raw) : raw;
      
      for (const entry of payload.entry || []) {
        const igId = entry.id;
        const userId = await redis.get(`page_owner:${igId}`) || await redis.get('fallback_user_id');
        const token = await redis.hget('page_tokens', igId) || await redis.get('fallback_token');
        
        if (!userId || !token) continue;

        const rules = await redis.hgetall(`post_rules:${userId}`);
        const items = [...(entry.messaging || []), ...(entry.changes || [])];
        
        for (const item of items) {
          // Skip edits
          if (item.message_edit) continue;

          const val = item.message || item.value || item;
          const text = (val.text || val.message || '').toUpperCase();
          const senderId = val.from?.id || item.sender?.id;
          const commentId = val.id;
          
          if (!text || !senderId) continue;
          console.log(`💬 Processing: "${text}" from ${senderId}`);

          for (const rStr of Object.values(rules)) {
            const rule = typeof rStr === 'string' ? JSON.parse(rStr) : rStr;
            
            if (text.includes(rule.keyword.toUpperCase())) {
              console.log(`🎯 MATCH! Preparing reply...`);

              // Endpoint logic: Private Reply for comments, Message for DMs
              let endpoint = `https://graph.facebook.com/v19.0/${igId}/messages`;
              let body = { recipient: { id: senderId }, message: { text: rule.responseText } };

              if (commentId && !item.messaging) {
                console.log(`💬 Sending Private Reply to comment: ${commentId}`);
                // recipient should contain comment_id for private replies
                body = { recipient: { comment_id: commentId }, message: { text: rule.responseText } };
              }

              const res = await fetch(endpoint, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
                body: JSON.stringify(body)
              });
              
              const result = await res.json();
              if (res.ok) {
                console.log(`✅ DM DELIVERED SUCCESSFULLY!`);
              } else {
                console.error(`❌ DM FAILED: ${JSON.stringify(result.error)}`);
              }
            }
          }
        }
      }
    } catch (err) { 
      console.error('Worker Critical Error:', err.message); 
      await new Promise(r => setTimeout(r, 5000));
    }
  }
}

// Start Server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server listening on 0.0.0.0:${PORT}`);
  worker();
});
=======
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
>>>>>>> e09eed7732a3a7bc51e4a6425bd15d8eb90697b4
