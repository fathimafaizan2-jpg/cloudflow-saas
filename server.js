require('dotenv').config();
const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Stripe = require('stripe');
const { Redis } = require('@upstash/redis');
const { GoogleGenAI } = require('@google/genai');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// --- SERVICE CLIENTS ---
const stripe = Stripe(process.env.STRIPE_SECRET_KEY || 'sk_test_mock_key');
const redis = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL,
  token: process.env.UPSTASH_REDIS_REST_TOKEN,
});
const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });

const PORT = process.env.PORT || 3000;
const VERIFY_TOKEN = process.env.VERIFY_TOKEN || 'my_secret_token_123';
const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_jwt_key_99';

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
// 0. AUTHENTICATION (Login & Signup) - RESTORED
// -------------------------------------------------------------
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    const existingUser = await redis.get(`user:${email}`);
    if (existingUser) return res.status(400).json({ error: 'User already exists' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const userId = Date.now().toString();
    
    const newUser = { id: userId, email, password: hashedPassword };
    await redis.set(`user:${email}`, JSON.stringify(newUser));
    
    const token = jwt.sign({ id: userId, email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: userId, email } });
  } catch (err) {
    console.error('Signup Error:', err.message);
    res.status(500).json({ error: 'Signup failed' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const userData = await redis.get(`user:${email}`);
    if (!userData) return res.status(401).json({ error: 'Invalid credentials' });

    const user = typeof userData === 'string' ? JSON.parse(userData) : userData;
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, email: user.email } });
  } catch (err) {
    console.error('Login Error:', err.message);
    res.status(500).json({ error: 'Login failed' });
  }
});

// -------------------------------------------------------------
// 1. OAUTH & ACCOUNT CONNECTION
// -------------------------------------------------------------
app.get('/api/auth/instagram', (req, res) => {
  try {
    const { token } = req.query;
    if (!token) return res.status(401).send('No token provided');
    const decoded = jwt.verify(token, JWT_SECRET);
    const userId = decoded.id || decoded.userId || decoded._id || decoded.sub;
    
    const state = Buffer.from(JSON.stringify({ userId, token })).toString('base64');
    const appId = process.env.META_APP_ID;
    const redirectUri = `https://${req.get('host')}/api/auth/instagram/callback`;
    
    const scope = [
      'instagram_basic',
      'instagram_manage_comments',
      'instagram_manage_messages',
      'pages_show_list',
      'pages_read_engagement',
      'pages_manage_metadata',
      'business_management'
    ].join(',');

    res.redirect(`https://www.facebook.com/v19.0/dialog/oauth?client_id=${appId}&redirect_uri=${encodeURIComponent(redirectUri)}&scope=${scope}&state=${state}`);
  } catch (err) {
    res.status(500).send('Auth failed to start');
  }
});

app.get('/api/auth/instagram/callback', async (req, res) => {
  try {
    const { code, state } = req.query;
    const decodedState = JSON.parse(Buffer.from(state, 'base64').toString('utf-8'));
    const { userId, token: userJwtToken } = decodedState;

    const appId = process.env.META_APP_ID;
    const appSecret = process.env.META_APP_SECRET;
    const redirectUri = `https://${req.get('host')}/api/auth/instagram/callback`;

    const tokenRes = await fetch(`https://graph.facebook.com/v19.0/oauth/access_token?client_id=${appId}&redirect_uri=${encodeURIComponent(redirectUri)}&client_secret=${appSecret}&code=${code}`);
    const tokenData = await tokenRes.json();
    const userToken = tokenData.access_token;

    const pagesRes = await fetch(`https://graph.facebook.com/v19.0/me/accounts?access_token=${userToken}`);
    const pagesData = await pagesRes.json();

    if (pagesData.data) {
      for (const page of pagesData.data) {
        await redis.hset('page_tokens', { [page.id]: page.access_token });
        await redis.hset(`user_pages:${userId}`, { [page.id]: page.name });
        await redis.set(`page_owner:${page.id}`, userId);

        console.log(`🔗 Subscribing to Page: ${page.name}`);
        const subRes = await fetch(`https://graph.facebook.com/v19.0/${page.id}/subscribed_apps?subscribed_fields=messages,messaging_postbacks,feed&access_token=${page.access_token}`, { method: 'POST' });
        const subResult = await subRes.json();
        console.log(`✅ Result:`, subResult);
      }
    }
    res.redirect(`/?meta_connect=success&token=${userJwtToken}`);
  } catch (err) {
    res.redirect('/?error=oauth_failed');
  }
});

// -------------------------------------------------------------
// 2. ACCOUNT MANAGEMENT
// -------------------------------------------------------------
app.delete('/api/accounts/:pageId', authenticateToken, async (req, res) => {
  try {
    const { pageId } = req.params;
    const userId = req.user.id || req.user.userId || req.user._id;

    await redis.hdel(`user_pages:${userId}`, pageId);
    await redis.hdel('page_tokens', pageId);
    await redis.del(`page_owner:${pageId}`);
    
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Delete failed' });
  }
});

app.get('/api/accounts', authenticateToken, async (req, res) => {
  const userId = req.user.id || req.user.userId || req.user._id;
  const accounts = await redis.hgetall(`user_pages:${userId}`);
  res.json(accounts || {});
});

// -------------------------------------------------------------
// 3. WEBHOOKS
// -------------------------------------------------------------
app.get('/webhook', (req, res) => {
  if (req.query['hub.mode'] === 'subscribe' && req.query['hub.verify_token'] === VERIFY_TOKEN) {
    return res.status(200).send(req.query['hub.challenge']);
  }
  res.sendStatus(403);
});

app.post('/webhook', async (req, res) => {
  console.log('📬 RAW WEBHOOK HIT! Object:', req.body.object);
  if (req.body.object === 'instagram' || req.body.object === 'page') {
    await redis.lpush('meta_webhook_queue', JSON.stringify(req.body));
    return res.status(200).send('EVENT_RECEIVED');
  }
  res.sendStatus(404);
});

// -------------------------------------------------------------
// 4. BACKGROUND WORKER
// -------------------------------------------------------------
async function startBackgroundWorker() {
  console.log('👷 Engine Active...');
  while (true) {
    try {
      const rawEvent = await redis.rpop('meta_webhook_queue');
      if (!rawEvent) { await new Promise(r => setTimeout(r, 2000)); continue; }

      const payload = JSON.parse(rawEvent);
      for (const entry of payload.entry || []) {
        const igAccountId = entry.id;
        if (entry.messaging) {
          for (const msg of entry.messaging) {
            if (msg.message?.text) await processAutomation(igAccountId, msg.sender.id, msg.message.text, 'DM');
          }
        }
        if (entry.changes) {
          for (const change of entry.changes) {
            if (change.field === 'comments') await processAutomation(igAccountId, change.value.from.id, change.value.text, 'COMMENT', change.value.media.id);
          }
        }
      }
    } catch (err) { console.error('Worker Error:', err.message); }
  }
}

async function processAutomation(igAccountId, targetId, text, type, mediaId = null) {
  const userId = await redis.get(`page_owner:${igAccountId}`);
  if (!userId) return;

  const rules = await redis.hgetall(`post_rules:${userId}`);
  const pageToken = await redis.hget('page_tokens', igAccountId);
  if (!rules || !pageToken) return;

  const input = text.toUpperCase().trim();
  for (const [id, data] of Object.entries(rules)) {
    const rule = typeof data === 'string' ? JSON.parse(data) : data;
    if (type === 'COMMENT' && rule.mediaId !== mediaId) continue;

    const trigger = rule.keyword?.toUpperCase().trim() || 'ANY';
    if (trigger === 'ANY' || input === trigger || input.includes(trigger)) {
      await fetch(`https://graph.facebook.com/v19.0/me/messages`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${pageToken}` },
        body: JSON.stringify({ recipient: { id: targetId }, message: { text: rule.responseText } })
      });
      console.log(`✅ ${type} Sent!`);
      return;
    }
  }
}

app.listen(PORT, () => {
  console.log(`🚀 Active on Port ${PORT}`);
  startBackgroundWorker();
});
