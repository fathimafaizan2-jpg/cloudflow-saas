require('dotenv').config();
const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Redis } = require('@upstash/redis');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const redis = new Redis({ url: process.env.UPSTASH_REDIS_REST_URL, token: process.env.UPSTASH_REDIS_REST_TOKEN });
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

app.get('/api/debug/conversations', async (req, res) => {
  try {
    const fallbackUser = await redis.get('fallback_user_id');
    if (!fallbackUser) return res.json({ error: 'No user connected yet.' });
    const accounts = await redis.hgetall(`user_pages:${fallbackUser}`);
    const results = {};
    for (const pageId of Object.keys(accounts || {})) {
      const token = await redis.hget('page_tokens', pageId);
      const igRes = await fetch(`https://graph.facebook.com/v19.0/${pageId}?fields=instagram_business_account&access_token=${token}`);
      const igData = await igRes.json();
      const igId = igData.instagram_business_account?.id;
      if (igId) {
        const convRes = await fetch(`https://graph.facebook.com/v20.0/${igId}/conversations?fields=participants&access_token=${token}`);
        results[igId] = await convRes.json();
      }
    }
    res.json({ info: "Showing data for latest connected user", results });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/help/diagnose', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const lastError = await redis.get(`last_error:${userId}`);
    const tokens = await redis.hgetall('page_tokens');
    const accounts = await redis.hgetall(`user_pages:${userId}`);
    
    let advice = "Everything looks healthy! Try sending a manual DM from your tester to your business account to 'open the door' for Meta.";
    if (lastError) {
      if (lastError.includes('capability')) advice = "Meta says your app is missing a permission. Go to 'App Review > Permissions and Features' and ensure 'instagram_manage_messages' has Standard Access.";
      if (lastError.includes('client secret')) advice = "Your App Secret is incorrect. Please re-copy it from the Meta Dashboard and update it in your Render Environment settings.";
      if (lastError.includes('100')) advice = "Error 100: Scoped ID mismatch. Please have your tester send a manual DM to your business account first to link their ID.";
    }

    res.json({ 
      error: lastError || "None",
      advice,
      connectedAccounts: Object.keys(accounts || {}).length,
      hasTokens: Object.keys(tokens || {}).length > 0
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

app.post('/api/account/update', authenticateToken, async (req, res) => {
  try {
    const { password, twoFactorEnabled } = req.body;
    const userStr = await redis.hget('users', req.user.email);
    const user = JSON.parse(userStr);
    if (password) user.password = await bcrypt.hash(password, 10);
    user.twoFactorEnabled = twoFactorEnabled;
    await redis.hset('users', { [req.user.email]: JSON.stringify(user) });
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/account', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    await redis.hdel('users', req.user.email);
    await redis.del(`user_pages:${userId}`);
    await redis.del(`post_rules:${userId}`);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
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
      await redis.del(`last_error:${userId}`);
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

app.get('/api/dashboard-data', authenticateToken, async (req, res) => {
  const rules = await redis.hgetall(`post_rules:${req.user.id}`);
  const parsed = {};
  for (const [k, v] of Object.entries(rules || {})) parsed[k] = typeof v === 'string' ? JSON.parse(v) : v;
  res.json({ postRules: parsed });
});

app.post('/api/rules/post', authenticateToken, async (req, res) => {
  const { mediaId, keyword, responseText, caption, thumbnail } = req.body;
  await redis.hset(`post_rules:${req.user.id}`, { [mediaId]: JSON.stringify({ keyword, responseText, caption, thumbnail, mediaId }) });
  res.json({ success: true });
});

app.delete('/api/rules/post/:mediaId', authenticateToken, async (req, res) => {
  try {
    await redis.hdel(`post_rules:${req.user.id}`, req.params.mediaId);
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: 'Failed to delete rule' }); }
});

// --- WEBHOOKS & WORKER ---
app.get('/webhook', (req, res) => {
  if (req.query['hub.verify_token'] === VERIFY_TOKEN) res.status(200).send(req.query['hub.challenge']);
  else res.sendStatus(403);
});

app.post('/webhook', async (req, res) => {
  console.log('📬 WEBHOOK HIT!');
  console.log('📦 FULL WEBHOOK BODY:', JSON.stringify(req.body, null, 2));
  await redis.lpush('meta_webhook_queue', JSON.stringify(req.body));
  res.status(200).send('EVENT_RECEIVED');
});

async function worker() {
  console.log('👷 Worker Active...');
  while (true) {
    try {
      const raw = await redis.rpop('meta_webhook_queue');
      if (!raw) { await new Promise(r => setTimeout(r, 2000)); continue; }
      const payload = typeof raw === 'string' ? JSON.parse(raw) : raw;
      
      for (const entry of payload.entry || []) {
        const igId = entry.id;
        const userId = await redis.get(`page_owner:${igId}`) || await redis.get('fallback_user_id');
        const token = await redis.hget('page_tokens', igId) || await redis.get('fallback_token');
        if (!userId || !token) continue;

        const rules = await redis.hgetall(`post_rules:${userId}`);
        const items = [...(entry.messaging || []), ...(entry.changes || [])];
        
        for (const item of items) {
          // Ignore message edits, focus on new messages or comment changes
          if (item.message_edit) continue;

          const val = item.message || item.value || item;
          const text = (val.text || val.message || '').toUpperCase();
          const senderId = val.from?.id || item.sender?.id;
          const commentId = val.id; // For comments
          
          if (!text || !senderId) continue;

          for (const rStr of Object.values(rules)) {
            const rule = typeof rStr === 'string' ? JSON.parse(rStr) : rStr;
            if (text.includes(rule.keyword.toUpperCase())) {
              console.log(`🎯 MATCH! Keyword "${rule.keyword}" found in text "${text}"`);

              let endpoint = `https://graph.facebook.com/v19.0/me/messages`;
              let body = { recipient: { id: senderId }, message: { text: rule.responseText } };

              // If it's a comment, use the Private Reply endpoint
              if (commentId && !item.messaging) {
                console.log(`💬 Sending Private Reply to comment ID: ${commentId}`);
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
                await redis.set(`last_error:${userId}`, result.error.message);
              }
            }
          }
        }
      }
    } catch (err) { console.error('Worker Error:', err.message); }
  }
}

app.listen(PORT, () => { console.log(`🚀 Server on ${PORT}`); worker(); });
