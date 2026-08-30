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
  const token = (authHeader && authHeader.split(' ')[1]) || req.query.token;
  if (!token || token === 'undefined') return res.sendStatus(401);
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
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
    
    const lowerEmail = email.toLowerCase().trim();
    const existing = await redis.hget('users', lowerEmail);
    if (existing) return res.status(400).json({ error: 'Account already exists.' });

    const userId = Date.now().toString();
    const hashedPassword = await bcrypt.hash(password, 10);
    const userData = { id: userId, email: lowerEmail, password: hashedPassword };

    await redis.hset('users', { [lowerEmail]: JSON.stringify(userData) });
    const token = jwt.sign({ id: userId, email: lowerEmail }, JWT_SECRET, { expiresIn: '7d' });

    res.json({ success: true, token, user: { id: userId, email: lowerEmail } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    const lowerEmail = email.toLowerCase().trim();
    const userRaw = await redis.hget('users', lowerEmail);
    if (!userRaw) return res.status(400).json({ error: 'Invalid email or password.' });

    const user = safeParse(userRaw);
    if (!user || !user.password) return res.status(400).json({ error: 'Invalid user data structure.' });

    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) return res.status(400).json({ error: 'Invalid email or password.' });

    const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ success: true, token, user: { id: user.id, email: user.email } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PERMANENT ACCOUNT DELETION
app.delete('/api/user/account', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const lowerEmail = req.user.email ? req.user.email.toLowerCase() : null;

    if (lowerEmail) {
      await redis.hdel('users', lowerEmail);
    }
    
    await redis.del(`user_pages:${userId}`);
    await redis.del(`post_rules:${userId}`);

    console.log(`🗑️ Permanently deleted account data for user ${userId}`);
    res.json({ success: true, message: 'Account deleted successfully.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- META OAUTH ---
app.get('/api/auth/instagram', (req, res) => {
  try {
    const { token } = req.query;
    if (!token || token === 'undefined') {
      return res.redirect('/?error=login_required');
    }

    let user;
    try {
      user = jwt.verify(token, JWT_SECRET);
    } catch (e) {
      return res.redirect('/?error=session_expired');
    }

    const state = Buffer.from(JSON.stringify({ userId: user.id, token })).toString('base64');
    const scope = 'instagram_basic,instagram_manage_messages,instagram_manage_comments,pages_show_list,pages_read_engagement,pages_messaging,business_management';
    const redirectUri = `https://${req.get('host')}/api/auth/instagram/callback`;
    const url = `https://www.facebook.com/v19.0/dialog/oauth?client_id=${process.env.META_APP_ID}&redirect_uri=${encodeURIComponent(redirectUri)}&scope=${encodeURIComponent(scope)}&state=${state}`;
    res.redirect(url);
  } catch (err) {
    console.error('OAuth Init Error:', err.message);
    res.redirect('/?error=oauth_init_failed');
  }
});

app.get('/api/auth/instagram/callback', async (req, res) => {
  try {
    const { code, state } = req.query;
    if (!code) return res.redirect('/?error=missing_code');

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
  try {
    const accountsMap = await redis.hgetall(`user_pages:${req.user.id}`);
    res.json({ accounts: Object.entries(accountsMap || {}).map(([pageId, name]) => ({ pageId, name })) });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/instagram/posts', authenticateToken, async (req, res) => {
  try {
    const { pageId } = req.query;
    if (!pageId) return res.status(400).json({ error: 'Page ID required' });

    const token = await redis.hget('page_tokens', pageId);
    if (!token) return res.status(400).json({ error: 'Page access token not found.' });

    const igRes = await fetch(`https://graph.facebook.com/v19.0/${pageId}?fields=instagram_business_account&access_token=${token}`);
    const igData = await igRes.json();
    const igId = igData.instagram_business_account?.id;
    if (!igId) return res.json({ posts: [] });

    const postsRes = await fetch(`https://graph.facebook.com/v19.0/${igId}/media?fields=id,caption,media_url,media_type,thumbnail_url&access_token=${token}`);
    const postsData = await postsRes.json();
    res.json({ posts: postsData.data || [] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/rules/post', authenticateToken, async (req, res) => {
  try {
    const { mediaId, keyword, responseText, caption, thumbnail } = req.body;
    await redis.hset(`post_rules:${req.user.id}`, { [mediaId]: JSON.stringify({ keyword, responseText, caption, thumbnail, mediaId }) });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/dashboard-data', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const postRules = (await redis.hgetall(`post_rules:${userId}`)) || {};
    const userPages = (await redis.hgetall(`user_pages:${userId}`)) || {};

    const parsedRules = {};
    for (const [key, val] of Object.entries(postRules)) {
      parsedRules[key] = safeParse(val);
    }

    res.json({ postRules: parsedRules, connectedPagesCount: Object.keys(userPages).length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/rules/post/:mediaId', authenticateToken, async (req, res) => {
  try {
    await redis.hdel(`post_rules:${req.user.id}`, req.params.mediaId);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// --- WEBHOOKS & WORKER ---
app.get('/webhook', (req, res) => {
  if (req.query['hub.verify_token'] === VERIFY_TOKEN) res.status(200).send(req.query['hub.challenge']);
  else res.sendStatus(403);
});

app.post('/webhook', async (req, res) => {
  try {
    if (req.body.object === 'instagram' || req.body.object === 'page') {
      console.log('📬 WEBHOOK HIT!');
      await redis.lpush('meta_webhook_queue', JSON.stringify(req.body));
      return res.status(200).send('EVENT_RECEIVED');
    }
    res.sendStatus(404);
  } catch (err) {
    res.sendStatus(500);
  }
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
          if (item.message_edit) continue;

          const val = item.message || item.value || item;
          const text = (val.text || val.message || '').toUpperCase();
          const senderId = val.from?.id || item.sender?.id;
          const commentId = val.id;
          
          if (!text || !senderId) continue;
          console.log(`💬 Processing: "${text}" from ${senderId}`);

          for (const rStr of Object.values(rules)) {
            const rule = safeParse(rStr);
            if (!rule || !rule.keyword) continue;
            
            if (text.includes(rule.keyword.toUpperCase())) {
              console.log(`🎯 MATCH! Preparing reply...`);

              let endpoint = `https://graph.facebook.com/v19.0/me/messages`;
              let body = { recipient: { id: senderId }, message: { text: rule.responseText } };

              if (commentId && !item.messaging) {
                console.log(`💬 Sending Private Reply to comment: ${commentId}`);
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
