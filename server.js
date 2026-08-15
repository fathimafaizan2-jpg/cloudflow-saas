require('dotenv').config();
const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Redis } = require('@upstash/redis');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const APP_ID = (process.env.META_APP_ID || '').trim();
const redis = new Redis({ url: process.env.UPSTASH_REDIS_REST_URL, token: process.env.UPSTASH_REDIS_REST_TOKEN });
const PORT = process.env.PORT || 10000;
const VERIFY_TOKEN = (process.env.VERIFY_TOKEN || 'my_secret_token_123').trim();
const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_jwt_key_99';

// --- AUTH ---
app.post('/api/signup', async (req, res) => {
  const { email, password } = req.body;
  const userId = Date.now().toString();
  await redis.set(`user:${email}`, JSON.stringify({ id: userId, email, password: await bcrypt.hash(password, 10) }));
  res.json({ token: jwt.sign({ id: userId, email }, JWT_SECRET), user: { id: userId, email } });
});

app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;
  const user = JSON.parse(await redis.get(`user:${email}`) || '{}');
  if (user.id && await bcrypt.compare(password, user.password)) {
    res.json({ token: jwt.sign({ id: user.id, email: user.email }, JWT_SECRET), user: { id: user.id, email: user.email } });
  } else res.status(401).json({ error: 'Fail' });
});

// --- OAUTH & FORCE SUBSCRIPTION ---
app.get('/api/auth/instagram', (req, res) => {
  const decoded = jwt.verify(req.query.token, JWT_SECRET);
  const state = Buffer.from(JSON.stringify({ userId: decoded.id, token: req.query.token })).toString('base64');
  const scope = ['instagram_basic','instagram_manage_comments','instagram_manage_messages','pages_show_list','pages_read_engagement','pages_manage_metadata','pages_messaging','business_management'].join(',');
  res.redirect(`https://www.facebook.com/v19.0/dialog/oauth?client_id=${APP_ID}&redirect_uri=${encodeURIComponent(`https://${req.get('host')}/api/auth/instagram/callback`)}&scope=${scope}&state=${state}`);
});

app.get('/api/auth/instagram/callback', async (req, res) => {
  try {
    const { code, state } = req.query;
    const { userId, token: userJwtToken } = JSON.parse(Buffer.from(state, 'base64').toString('utf-8'));
    const tRes = await fetch(`https://graph.facebook.com/v19.0/oauth/access_token?client_id=${APP_ID}&redirect_uri=${encodeURIComponent(`https://${req.get('host')}/api/auth/instagram/callback`)}&client_secret=${process.env.META_APP_SECRET.trim()}&code=${code}`);
    const tData = await tRes.json();
    const pRes = await fetch(`https://graph.facebook.com/v19.0/me/accounts?access_token=${tData.access_token}`);
    const pData = await pRes.json();

    for (const page of pData.data || []) {
      const igRes = await fetch(`https://graph.facebook.com/v19.0/${page.id}?fields=instagram_business_account&access_token=${page.access_token}`);
      const igData = await igRes.json();
      const igId = igData.instagram_business_account?.id;
      
      await redis.hset('page_tokens', { [page.id]: page.access_token });
      await redis.set(`page_owner:${page.id}`, userId);
      await redis.hset(`user_pages:${userId}`, { [page.id]: page.name });
      
      if (igId) {
        await redis.hset('page_tokens', { [igId]: page.access_token });
        await redis.set(`page_owner:${igId}`, userId);
        console.log(`🔗 Linked IG: ${igId} to User: ${userId}`);
      }
      
      // --- FIXED SUBSCRIPTION LINE: ADDED messages and messaging_postbacks ---
      const subRes = await fetch(`https://graph.facebook.com/v19.0/${page.id}/subscribed_apps?subscribed_fields=feed,messages,messaging_postbacks&access_token=${page.access_token}`, { method: 'POST' });
      const subData = await subRes.json();
      console.log(`📡 Subscription for ${page.name}:`, subData);
    }
    res.redirect(`/?meta_connect=success&token=${userJwtToken}`);
  } catch (err) { res.redirect('/?error=oauth_failed'); }
});

// --- DASHBOARD DATA ---
app.get('/api/dashboard-data', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    const rules = await redis.hgetall(`post_rules:${decoded.id}`);
    const parsed = {};
    for (const [k, v] of Object.entries(rules || {})) { parsed[k] = typeof v === 'string' ? JSON.parse(v) : v; }
    res.json({ postRules: parsed });
  } catch (err) { res.status(500).json({ error: 'Failed' }); }
});

app.post('/api/rules/post', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    await redis.hset(`post_rules:${decoded.id}`, { [req.body.mediaId]: JSON.stringify(req.body) });
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: 'Failed' }); }
});

app.get('/api/instagram/accounts', async (req, res) => {
  try {
    const token = req.headers.authorization?.split(' ')[1];
    const decoded = jwt.verify(token, JWT_SECRET);
    const accounts = await redis.hgetall(`user_pages:${decoded.id}`);
    res.json({ accounts: Object.entries(accounts || {}).map(([pageId, name]) => ({ pageId, name })) });
  } catch (err) { res.status(500).json({ error: 'Failed' }); }
});

app.get('/api/instagram/posts', async (req, res) => {
  try {
    const { pageId } = req.query;
    const token = await redis.hget('page_tokens', pageId);
    const igRes = await fetch(`https://graph.facebook.com/v19.0/${pageId}?fields=instagram_business_account&access_token=${token}`);
    const igData = await igRes.json();
    const igId = igData.instagram_business_account?.id;
    if (!igId) return res.json({ posts: [] });
    const postsRes = await fetch(`https://graph.facebook.com/v19.0/${igId}/media?fields=id,caption,media_url,media_type,thumbnail_url&access_token=${token}`);
    const postsData = await postsRes.json();
    res.json({ posts: postsData.data || [] });
  } catch (err) { res.status(500).json({ error: 'Failed' }); }
});

// --- WEBHOOK & WORKER ---
app.post('/webhook', async (req, res) => {
  console.log('📬 WEBHOOK HIT:', JSON.stringify(req.body));
  await redis.lpush('webhook_queue', JSON.stringify(req.body));
  res.status(200).send('EVENT_RECEIVED');
});

app.get('/webhook', (req, res) => {
  if (req.query['hub.verify_token'] === VERIFY_TOKEN) res.send(req.query['hub.challenge']);
  else res.sendStatus(403);
});

async function worker() {
  while (true) {
    try {
      const raw = await redis.rpop('webhook_queue');
      if (!raw) { await new Promise(r => setTimeout(r, 2000)); continue; }
      const data = JSON.parse(raw);
      for (const entry of data.entry || []) {
        const userId = await redis.get(`page_owner:${entry.id}`);
        const token = await redis.hget('page_tokens', entry.id);
        if (!userId || !token) continue;
        const rules = await redis.hgetall(`post_rules:${userId}`);
        const items = [...(entry.changes || []), ...(entry.messaging || [])];
        for (const item of items) {
          const val = item.value || item.message || item;
          const text = val.text || val.message;
          const senderId = val.from?.id || item.sender?.id;
          if (!text || !senderId) continue;
          for (const rStr of Object.values(rules)) {
            const rule = JSON.parse(rStr);
            if (text.toUpperCase().includes(rule.keyword.toUpperCase())) {
              await fetch(`https://graph.facebook.com/v19.0/me/messages`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
                body: JSON.stringify({ recipient: { id: senderId }, message: { text: rule.responseText } })
              });
              console.log('✅ DM Sent Successfully!');
            }
          }
        }
      }
    } catch (err) { console.error('Worker Error:', err.message); }
  }
}

app.listen(PORT, () => { console.log(`🚀 Server on ${PORT}`); worker(); });
