require('dotenv').config();
const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Redis } = require('@upstash/redis');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// --- SERVICE CLIENTS ---
const redis = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL,
  token: process.env.UPSTASH_REDIS_REST_TOKEN,
});

const PORT = process.env.PORT || 10000;
const VERIFY_TOKEN = (process.env.VERIFY_TOKEN || 'my_secret_token_123');
const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_jwt_key_99';

console.log(`🔑 Configured Meta App ID: ${process.env.META_APP_ID || 'MISSING'}`);

// --- MIDDLEWARE ---
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  let token = authHeader && authHeader.split(' ')[1];
  if (!token && req.query.token) token = req.query.token;
  if (!token) return res.status(401).json({ error: 'Access denied.' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Session expired.' });
    req.user = user;
    next();
  });
}

// -------------------------------------------------------------
// 0. ADMIN & DIAGNOSTICS
// -------------------------------------------------------------
app.get('/api/admin/master-reset', async (req, res) => {
  try {
    await redis.flushall();
    console.log('🧹 MASTER RESET: Redis database wiped successfully.');
    res.send('<h1>✅ Database Wiped Successfully! You can now reconnect your account.</h1>');
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
  }
});

app.get('/api/help/diagnose', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const lastError = await redis.get(`last_error:${userId}`) || 'No errors recorded.';
    const accounts = await redis.hgetall(`user_pages:${userId}`);
    const rules = await redis.hgetall(`post_rules:${userId}`);
    
    let diagnosis = "Everything looks healthy! If DMs aren't working, check your tester account settings.";
    if (lastError.includes('Code #3')) diagnosis = "Meta Error #3: Capability issue. Try reconnecting your account.";
    else if (Object.keys(accounts || {}).length === 0) diagnosis = "No Instagram account linked. Please connect your account.";

    res.json({ diagnosis, lastError, connectedAccountsCount: Object.keys(accounts || {}).length });
  } catch (err) {
    res.status(500).json({ error: 'Diagnosis failed' });
  }
});

// -------------------------------------------------------------
// 1. AUTHENTICATION
// -------------------------------------------------------------
app.post('/api/signup', async (req, res) => {
  try {
    const { email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const userId = Date.now().toString();
    await redis.set(`user:${email}`, JSON.stringify({ id: userId, email, password: hashedPassword }));
    const token = jwt.sign({ id: userId, email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: userId, email } });
  } catch (err) { res.status(500).json({ error: 'Signup failed' }); }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const userData = await redis.get(`user:${email}`);
    if (!userData) return res.status(401).json({ error: 'Invalid credentials' });
    const user = typeof userData === 'string' ? JSON.parse(userData) : userData;
    if (await bcrypt.compare(password, user.password)) {
      const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
      res.json({ token, user: { id: user.id, email: user.email } });
    } else res.status(401).json({ error: 'Invalid credentials' });
  } catch (err) { res.status(500).json({ error: 'Login failed' }); }
});

// -------------------------------------------------------------
// 2. OAUTH & ACCOUNT CONNECTION
// -------------------------------------------------------------
app.get('/api/auth/instagram', (req, res) => {
  const { token } = req.query;
  const decoded = jwt.verify(token, JWT_SECRET);
  const state = Buffer.from(JSON.stringify({ userId: decoded.id, token })).toString('base64');
  const appId = process.env.META_APP_ID;
  const redirectUri = `https://${req.get('host')}/api/auth/instagram/callback`;
  const scope = ['instagram_basic','instagram_manage_comments','instagram_manage_messages','pages_show_list','pages_read_engagement','pages_manage_metadata','business_management'].join(',');
  res.redirect(`https://www.facebook.com/v19.0/dialog/oauth?client_id=${appId}&redirect_uri=${encodeURIComponent(redirectUri)}&scope=${scope}&state=${state}`);
});

app.get('/api/auth/instagram/callback', async (req, res) => {
  try {
    const { code, state } = req.query;
    const { userId, token: userJwtToken } = JSON.parse(Buffer.from(state, 'base64').toString('utf-8'));
    const appId = process.env.META_APP_ID;
    const appSecret = process.env.META_APP_SECRET;
    const redirectUri = `https://${req.get('host')}/api/auth/instagram/callback`;

    const tokenRes = await fetch(`https://graph.facebook.com/v19.0/oauth/access_token?client_id=${appId}&redirect_uri=${encodeURIComponent(redirectUri)}&client_secret=${appSecret}&code=${code}`);
    const tokenData = await tokenRes.json();
    const userToken = tokenData.access_token;

    const pagesRes = await fetch(`https://graph.facebook.com/v19.0/me/accounts?access_token=${userToken}`);
    const pagesData = await pagesRes.json();

    console.log(`📄 Pages Found by Meta: ${pagesData.data?.length || 0}`);

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

// -------------------------------------------------------------
// 3. DATA API
// -------------------------------------------------------------
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

app.get('/api/dashboard-data', authenticateToken, async (req, res) => {
  const rules = await redis.hgetall(`post_rules:${req.user.id}`);
  const parsed = {};
  for (const [k, v] of Object.entries(rules || {})) parsed[k] = JSON.parse(v);
  res.json({ postRules: parsed });
});

app.post('/api/rules/post', authenticateToken, async (req, res) => {
  const { mediaId, keyword, responseText, caption, thumbnail } = req.body;
  await redis.hset(`post_rules:${req.user.id}`, { [mediaId]: JSON.stringify({ keyword, responseText, caption, thumbnail, mediaId }) });
  res.json({ success: true });
});

// -------------------------------------------------------------
// 4. WEBHOOKS & WORKER
// -------------------------------------------------------------
app.get('/webhook', (req, res) => {
  if (req.query['hub.verify_token'] === VERIFY_TOKEN) res.status(200).send(req.query['hub.challenge']);
  else res.sendStatus(403);
});

app.post('/webhook', async (req, res) => {
  console.log('📬 WEBHOOK HIT!');
  await redis.lpush('meta_webhook_queue', JSON.stringify(req.body));
  res.status(200).send('EVENT_RECEIVED');
});

async function worker() {
  console.log('👷 Worker Active...');
  while (true) {
    try {
      const raw = await redis.rpop('meta_webhook_queue');
      if (!raw) { await new Promise(r => setTimeout(r, 2000)); continue; }
      const payload = JSON.parse(raw);
      for (const entry of payload.entry || []) {
        const igId = entry.id;
        const userId = await redis.get(`page_owner:${igId}`) || await redis.get('fallback_user_id');
        const token = await redis.hget('page_tokens', igId) || await redis.get('fallback_token');
        if (!userId || !token) continue;

        const rules = await redis.hgetall(`post_rules:${userId}`);
        const items = [...(entry.messaging || []), ...(entry.changes || [])];
        for (const item of items) {
          const val = item.message || item.value || item;
          const text = (val.text || val.message || '').toUpperCase();
          const senderId = val.from?.id || item.sender?.id;
          if (!text || !senderId) continue;

          for (const rStr of Object.values(rules)) {
            const rule = JSON.parse(rStr);
            if (text.includes(rule.keyword.toUpperCase())) {
              console.log(`🎯 MATCH! Replying to ${senderId}`);
              const res = await fetch(`https://graph.facebook.com/v19.0/me/messages`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
                body: JSON.stringify({ recipient: { id: senderId }, message: { text: rule.responseText } })
              });
              const result = await res.json();
              if (result.error) await redis.set(`last_error:${userId}`, result.error.message);
            }
          }
        }
      }
    } catch (err) { console.error('Worker Error:', err.message); }
  }
}

app.listen(PORT, () => { console.log(`🚀 Server on ${PORT}`); worker(); });
