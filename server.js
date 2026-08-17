require('dotenv').config();
const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Redis } = require('@upstash/redis');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Initialize Redis
const redis = new Redis({ 
  url: process.env.UPSTASH_REDIS_REST_URL, 
  token: process.env.UPSTASH_REDIS_REST_TOKEN 
});

const PORT = process.env.PORT || 10000;
const VERIFY_TOKEN = (process.env.VERIFY_TOKEN || 'my_secret_token_123').trim();
const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_jwt_key_99';

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
    req.user = user;
    next();
  });
};

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
  }
});

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
  console.log('📦 BODY:', JSON.stringify(req.body, null, 2));
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
      
      console.log('📦 Worker found task!');
      const payload = typeof raw === 'string' ? JSON.parse(raw) : raw;
      
      for (const entry of payload.entry || []) {
        const igId = entry.id;
        const userId = await redis.get(`page_owner:${igId}`) || await redis.get('fallback_user_id');
        const token = await redis.hget('page_tokens', igId) || await redis.get('fallback_token');
        
        console.log(`🔍 Checking rules for IG ID: ${igId}, User: ${userId}`);
        if (!userId || !token) {
          console.log('⚠️ Missing owner or token, skipping...');
          continue;
        }

        const rules = await redis.hgetall(`post_rules:${userId}`);
        const items = [...(entry.messaging || []), ...(entry.changes || [])];
        
        for (const item of items) {
          if (item.message_edit) continue;

          const val = item.message || item.value || item;
          const text = (val.text || val.message || '').toUpperCase();
          const senderId = val.from?.id || item.sender?.id;
          const commentId = val.id;
          
          if (!text || !senderId) continue;
          console.log(`💬 Processing text: "${text}" from ${senderId}`);

          for (const rStr of Object.values(rules)) {
            const rule = typeof rStr === 'string' ? JSON.parse(rStr) : rStr;
            console.log(`   - Comparing to keyword: "${rule.keyword.toUpperCase()}"`);
            
            if (text.includes(rule.keyword.toUpperCase())) {
              console.log(`🎯 MATCH FOUND! Sending reply...`);

              let endpoint = `https://graph.facebook.com/v19.0/me/messages`;
              let body = { recipient: { id: senderId }, message: { text: rule.responseText } };

              if (commentId && !item.messaging) {
                console.log(`💬 Sending Private Reply to comment: ${commentId}`);
                endpoint = `https://graph.facebook.com/v19.0/${commentId}/private_replies`;
                body = { message: rule.responseText };
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

// Start Server with 0.0.0.0 binding for Render
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server listening on 0.0.0.0:${PORT}`);
  worker();
});

// Global error handling to prevent silent crashes
process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});
