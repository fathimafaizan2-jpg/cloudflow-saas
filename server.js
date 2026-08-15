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
const VERIFY_TOKEN = process.env.VERIFY_TOKEN || 'my_secret_token_123';
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
// 0. AUTHENTICATION (Login & Signup)
// -------------------------------------------------------------
app.post('/api/signup', async (req, res) => {
  try {
    const { email, password } = req.body;
    const existingUser = await redis.get(`user:${email}`);
    if (existingUser) return res.status(400).json({ error: 'User already exists' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const userId = Date.now().toString();
    await redis.set(`user:${email}`, JSON.stringify({ id: userId, email, password: hashedPassword }));
    
    const token = jwt.sign({ id: userId, email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: userId, email } });
  } catch (err) {
    res.status(500).json({ error: 'Signup failed' });
  }
});

app.post('/api/login', async (req, res) => {
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
    res.status(500).json({ error: 'Login failed' });
  }
});

// -------------------------------------------------------------
// 1. OAUTH & ACCOUNT CONNECTION
// -------------------------------------------------------------
app.get('/api/auth/instagram', (req, res) => {
  try {
    const { token } = req.query;
    const decoded = jwt.verify(token, JWT_SECRET);
    const userId = decoded.id || decoded.userId || decoded.sub;
    
    const state = Buffer.from(JSON.stringify({ userId, token })).toString('base64');
    const appId = process.env.META_APP_ID;
    const redirectUri = `https://${req.get('host')}/api/auth/instagram/callback`;
    const scope = ['instagram_basic','instagram_manage_comments','instagram_manage_messages','pages_show_list','pages_read_engagement','pages_manage_metadata','business_management'].join(',');

    res.redirect(`https://www.facebook.com/v19.0/dialog/oauth?client_id=${appId}&redirect_uri=${encodeURIComponent(redirectUri)}&scope=${scope}&state=${state}`);
  } catch (err) {
    res.status(500).send('Auth failed');
  }
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

    if (pagesData.data) {
      for (const page of pagesData.data) {
        const igRes = await fetch(`https://graph.facebook.com/v19.0/${page.id}?fields=instagram_business_account&access_token=${page.access_token}`);
        const igData = await igRes.json();
        const igBusinessId = igData.instagram_business_account?.id;

        await redis.hset('page_tokens', { [page.id]: page.access_token });
        await redis.hset(`user_pages:${userId}`, { [page.id]: page.name });
        await redis.set(`page_owner:${page.id}`, userId);

        if (igBusinessId) {
          await redis.hset('page_tokens', { [igBusinessId]: page.access_token });
          await redis.set(`page_owner:${igBusinessId}`, userId);
          console.log(`🔗 Mapped IG Business ID ${igBusinessId} to User ${userId}`);
        }
        
        // Also save latest active user as fallback so Test Tool always works
        await redis.set('fallback_user_id', userId);
        await redis.set('fallback_token', page.access_token);

        await fetch(`https://graph.facebook.com/v19.0/${page.id}/subscribed_apps?subscribed_fields=messages,messaging_postbacks,feed&access_token=${page.access_token}`, { method: 'POST' });
      }
    }
    res.redirect(`/?meta_connect=success&token=${userJwtToken}`);
  } catch (err) {
    console.error('OAuth Callback Error:', err);
    res.redirect('/?error=oauth_failed');
  }
});

// -------------------------------------------------------------
// 2. DASHBOARD & DATA
// -------------------------------------------------------------
app.get('/api/instagram/accounts', authenticateToken, async (req, res) => {
  const userId = req.user.id;
  const accountsMap = await redis.hgetall(`user_pages:${userId}`);
  const accounts = Object.entries(accountsMap || {}).map(([pageId, name]) => ({ pageId, name }));
  res.json({ accounts });
});

app.get('/api/instagram/posts', authenticateToken, async (req, res) => {
  try {
    const { pageId } = req.query;
    const pageToken = await redis.hget('page_tokens', pageId);
    
    const igRes = await fetch(`https://graph.facebook.com/v19.0/${pageId}?fields=instagram_business_account&access_token=${pageToken}`);
    const igData = await igRes.json();
    const igId = igData.instagram_business_account?.id;

    if (!igId) return res.json({ posts: [] });

    const postsRes = await fetch(`https://graph.facebook.com/v19.0/${igId}/media?fields=id,caption,media_url,media_type,thumbnail_url&access_token=${pageToken}`);
    const postsData = await postsRes.json();
    res.json({ posts: postsData.data || [] });
  } catch (err) {
    res.status(500).json({ error: 'Failed to load posts' });
  }
});

app.get('/api/dashboard-data', authenticateToken, async (req, res) => {
  const userId = req.user.id;
  const postRules = await redis.hgetall(`post_rules:${userId}`);
  const parsedRules = {};
  for (const [mediaId, rule] of Object.entries(postRules || {})) {
    parsedRules[mediaId] = typeof rule === 'string' ? JSON.parse(rule) : rule;
  }
  res.json({ postRules: parsedRules });
});

app.post('/api/rules/post', authenticateToken, async (req, res) => {
  const userId = req.user.id;
  const { mediaId, keyword, responseText, caption, thumbnail } = req.body;
  await redis.hset(`post_rules:${userId}`, { [mediaId]: JSON.stringify({ keyword, responseText, caption, thumbnail, mediaId }) });
  console.log(`💾 Rule saved for user ${userId} on media ${mediaId}: "${keyword}" -> "${responseText}"`);
  res.json({ success: true });
});

app.delete('/api/rules/post/:mediaId', authenticateToken, async (req, res) => {
  const userId = req.user.id;
  await redis.hdel(`post_rules:${userId}`, req.params.mediaId);
  res.json({ success: true });
});

app.delete('/api/user/account', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const email = req.user.email;
    const accounts = await redis.hgetall(`user_pages:${userId}`);
    for (const pageId of Object.keys(accounts || {})) {
      await redis.hdel('page_tokens', pageId);
      await redis.del(`page_owner:${pageId}`);
    }
    await redis.del(`user_pages:${userId}`);
    await redis.del(`post_rules:${userId}`);
    await redis.del(`user:${email}`);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Delete failed' });
  }
});

// Debug endpoint to inspect Redis state
app.get('/api/debug/status', async (req, res) => {
  try {
    const fallbackUser = await redis.get('fallback_user_id');
    const rules = fallbackUser ? await redis.hgetall(`post_rules:${fallbackUser}`) : {};
    const tokens = await redis.hgetall('page_tokens');
    res.json({ fallbackUser, rules, tokenKeys: Object.keys(tokens || {}) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// -------------------------------------------------------------
// 3. WEBHOOKS
// -------------------------------------------------------------
app.get('/webhook', (req, res) => {
  if (req.query['hub.mode'] === 'subscribe' && req.query['hub.verify_token'] === VERIFY_TOKEN) {
    console.log('✅ Webhook Verified Successfully');
    return res.status(200).send(req.query['hub.challenge']);
  }
  res.sendStatus(403);
});

app.post('/webhook', async (req, res) => {
  console.log('📬 RAW WEBHOOK HIT! Full Payload:', JSON.stringify(req.body));
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

      const payload = typeof rawEvent === 'string' ? JSON.parse(rawEvent) : rawEvent;
      
      for (const entry of payload.entry || []) {
        const igAccountId = entry.id;
        console.log(`🔍 Processing entry ID: ${igAccountId}`);

        if (entry.messaging) {
          for (const msg of entry.messaging) {
            if (msg.message?.text) {
              console.log(`📩 DM Received: "${msg.message.text}" from ${msg.sender.id}`);
              await processAutomation(igAccountId, msg.sender.id, msg.message.text, 'DM');
            }
          }
        }
        if (entry.changes) {
          for (const change of entry.changes) {
            if (change.field === 'comments' || change.field === 'feed') {
              const text = change.value.text || change.value.message;
              const senderId = change.value.from?.id;
              const mediaId = change.value.media?.id || change.value.post_id;
              if (text) {
                console.log(`💬 Comment/Feed Received: "${text}" from ${senderId} on media ${mediaId}`);
                await processAutomation(igAccountId, senderId, text, 'COMMENT', mediaId);
              }
            }
          }
        }
      }
    } catch (err) { console.error('Worker Error:', err.message); }
  }
}

async function processAutomation(igAccountId, targetId, text, type, mediaId = null) {
  let userId = await redis.get(`page_owner:${igAccountId}`);
  let pageToken = await redis.hget('page_tokens', igAccountId);

  // Fallback for Test Tool (ID 0) or unmapped IDs
  if (!userId || !pageToken) {
    console.log(`⚠️ Mapping not found for ${igAccountId}. Using fallback active user...`);
    userId = await redis.get('fallback_user_id');
    pageToken = await redis.get('fallback_token');
  }

  if (!userId || !pageToken) {
    console.error(`❌ Complete failure: No user or token found for automation.`);
    return;
  }

  const rules = await redis.hgetall(`post_rules:${userId}`);
  if (!rules || Object.keys(rules).length === 0) {
    console.error(`❌ No automation rules found for user ${userId}. Please create a rule in the dashboard!`);
    return;
  }

  const input = text.toUpperCase().trim();
  console.log(`🔎 Checking ${Object.keys(rules).length} rules for user ${userId}...`);

  for (const [id, data] of Object.entries(rules)) {
    const rule = typeof data === 'string' ? JSON.parse(data) : data;
    
    // For comments, check mediaId match if it's not a test event
    if (type === 'COMMENT' && mediaId && rule.mediaId && rule.mediaId !== mediaId && igAccountId !== "0") {
        console.log(`   - Skipping rule for media ${rule.mediaId} (event was on ${mediaId})`);
        continue;
    }

    const trigger = rule.keyword?.toUpperCase().trim() || 'ANY';
    console.log(`   - Comparing "${input}" to trigger "${trigger}"`);

    if (trigger === 'ANY' || input === trigger || input.includes(trigger)) {
      console.log(`🎯 Match found! Sending reply to ${targetId}`);
      const res = await fetch(`https://graph.facebook.com/v19.0/me/messages`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${pageToken}` },
        body: JSON.stringify({ recipient: { id: targetId }, message: { text: rule.responseText } })
      });
      const result = await res.json();
      if (result.error) console.error('❌ Meta API Error:', result.error.message);
      else console.log(`✅ ${type} Sent successfully!`);
      return;
    }
  }
  console.log('⚠️ No matching keyword found in any rules.');
}

app.listen(PORT, () => {
  console.log(`🚀 Active on Port ${PORT}`);
  startBackgroundWorker();
});
