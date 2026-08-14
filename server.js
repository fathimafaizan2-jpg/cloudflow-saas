require('dotenv').config();
const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Redis } = require('@upstash/redis');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const redis = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL,
  token: process.env.UPSTASH_REDIS_REST_TOKEN,
});

const PORT = process.env.PORT || 10000;
const VERIFY_TOKEN = process.env.VERIFY_TOKEN || 'my_secret_token_123';
const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_jwt_key_99';

// --- AUTH ROUTES ---
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
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: user.id, email: user.email } });
  } catch (err) { res.status(500).json({ error: 'Login failed' }); }
});

// --- OAUTH ROUTES ---
app.get('/api/auth/instagram', (req, res) => {
  const { token } = req.query;
  const decoded = jwt.verify(token, JWT_SECRET);
  const state = Buffer.from(JSON.stringify({ userId: decoded.id, token })).toString('base64');
  const scope = ['instagram_basic','instagram_manage_comments','instagram_manage_messages','pages_show_list','pages_read_engagement','pages_manage_metadata','business_management'].join(',');
  res.redirect(`https://www.facebook.com/v19.0/dialog/oauth?client_id=${process.env.META_APP_ID}&redirect_uri=${encodeURIComponent(`https://${req.get('host')}/api/auth/instagram/callback`)}&scope=${scope}&state=${state}`);
});

app.get('/api/auth/instagram/callback', async (req, res) => {
  try {
    const { code, state } = req.query;
    const { userId, token: userJwtToken } = JSON.parse(Buffer.from(state, 'base64').toString('utf-8'));
    const tokenRes = await fetch(`https://graph.facebook.com/v19.0/oauth/access_token?client_id=${process.env.META_APP_ID}&redirect_uri=${encodeURIComponent(`https://${req.get('host')}/api/auth/instagram/callback`)}&client_secret=${process.env.META_APP_SECRET}&code=${code}`);
    const tokenData = await tokenRes.json();
    const pagesRes = await fetch(`https://graph.facebook.com/v19.0/me/accounts?access_token=${tokenData.access_token}`);
    const pagesData = await pagesRes.json();

    for (const page of pagesData.data || []) {
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
      // Set fallback for Test Tool
      await redis.set('fallback_user', userId);
      await redis.set('fallback_token', page.access_token);
      
      await fetch(`https://graph.facebook.com/v19.0/${page.id}/subscribed_apps?subscribed_fields=messages,messaging_postbacks,feed&access_token=${page.access_token}`, { method: 'POST' });
    }
    res.redirect(`/?meta_connect=success&token=${userJwtToken}`);
  } catch (err) { res.redirect('/?error=oauth_failed'); }
});

// --- DASHBOARD ROUTES ---
app.get('/api/dashboard-data', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  const decoded = jwt.verify(token, JWT_SECRET);
  const rules = await redis.hgetall(`post_rules:${decoded.id}`);
  res.json({ postRules: rules || {} });
});

app.post('/api/rules/post', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  const decoded = jwt.verify(token, JWT_SECRET);
  const { mediaId, keyword, responseText } = req.body;
  await redis.hset(`post_rules:${decoded.id}`, { [mediaId]: JSON.stringify(req.body) });
  res.json({ success: true });
});

app.get('/api/instagram/accounts', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  const decoded = jwt.verify(token, JWT_SECRET);
  const accounts = await redis.hgetall(`user_pages:${decoded.id}`);
  res.json({ accounts: Object.entries(accounts || {}).map(([pageId, name]) => ({ pageId, name })) });
});

app.delete('/api/user/account', async (req, res) => {
  const token = req.headers.authorization?.split(' ')[1];
  const decoded = jwt.verify(token, JWT_SECRET);
  await redis.del(`user_pages:${decoded.id}`);
  await redis.del(`post_rules:${decoded.id}`);
  res.json({ success: true });
});

// --- WEBHOOK & WORKER ---
app.post('/webhook', async (req, res) => {
  console.log('📬 WEBHOOK RECEIVED');
  await redis.lpush('webhook_queue', JSON.stringify(req.body));
  res.status(200).send('EVENT_RECEIVED');
});

app.get('/webhook', (req, res) => {
  if (req.query['hub.verify_token'] === VERIFY_TOKEN) res.send(req.query['hub.challenge']);
  else res.sendStatus(403);
});

async function worker() {
  while (true) {
    const raw = await redis.rpop('webhook_queue');
    if (!raw) { await new Promise(r => setTimeout(r, 2000)); continue; }
    const data = JSON.parse(raw);
    for (const entry of data.entry || []) {
      const igId = entry.id;
      const userId = await redis.get(`page_owner:${igId}`) || await redis.get('fallback_user');
      const token = await redis.hget('page_tokens', igId) || await redis.get('fallback_token');
      const rules = await redis.hgetall(`post_rules:${userId}`);
      
      const changes = entry.changes || [];
      const messaging = entry.messaging || [];
      
      for (const item of [...changes, ...messaging]) {
        const text = item.value?.text || item.message?.text;
        const senderId = item.value?.from?.id || item.sender?.id;
        if (!text || !senderId) continue;

        console.log(`🔎 Checking text: "${text}"`);
        for (const ruleStr of Object.values(rules)) {
          const rule = JSON.parse(ruleStr);
          if (text.toUpperCase().includes(rule.keyword.toUpperCase())) {
            console.log(`🎯 MATCH! Sending DM to ${senderId}`);
            await fetch(`https://graph.facebook.com/v19.0/me/messages`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
              body: JSON.stringify({ recipient: { id: senderId }, message: { text: rule.responseText } })
            });
          }
        }
      }
    }
  }
}

app.listen(PORT, () => { console.log(`🚀 Server on ${PORT}`); worker(); });
