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

// Service Clients
const stripe = Stripe(process.env.STRIPE_SECRET_KEY || 'sk_test_mock_key');
const redis = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL,
  token: process.env.UPSTASH_REDIS_REST_TOKEN,
});
const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });

const PORT = process.env.PORT || 3000;
const VERIFY_TOKEN = process.env.VERIFY_TOKEN || 'my_secret_token_123';
const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_jwt_key_99';

// AUTHENTICATION MIDDLEWARE
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  let token = authHeader && authHeader.split(' ')[1];

  if (!token && req.query.token) token = req.query.token;
  if (!token) return res.status(401).json({ error: 'Access denied. Please log in.' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Session expired. Log in again.' });
    req.user = user;
    next();
  });
}

// 1. PUBLIC COMPLIANCE ROUTES
app.get('/privacy.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'privacy.html')));
app.get('/terms.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'terms.html')));

// 2. AUTH & USER ACCOUNTS
app.post('/api/signup', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    const lowerEmail = email.toLowerCase().trim();
    const existing = await redis.hget('cloudflow_users', lowerEmail);
    if (existing) return res.status(400).json({ error: 'Account already exists.' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const userId = 'usr_' + Date.now();
    const userData = { userId, email: lowerEmail, password: hashedPassword, tier: 'Starter', maxAccounts: 1 };

    await redis.hset('cloudflow_users', { [lowerEmail]: JSON.stringify(userData) });
    const token = jwt.sign({ userId, email: lowerEmail }, JWT_SECRET, { expiresIn: '7d' });

    res.json({ success: true, token, user: { userId, email: lowerEmail, tier: 'Starter', maxAccounts: 1 } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const lowerEmail = email.toLowerCase().trim();
    const rawUser = await redis.hget('cloudflow_users', lowerEmail);
    if (!rawUser) return res.status(400).json({ error: 'Invalid email or password.' });

    const user = typeof rawUser === 'string' ? JSON.parse(rawUser) : rawUser;
    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) return res.status(400).json({ error: 'Invalid email or password.' });

    const token = jwt.sign({ userId: user.userId, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ success: true, token, user: { userId: user.userId, email: user.email, tier: user.tier || 'Starter' } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 3. MULTI-ACCOUNT & POST-LEVEL AUTOMATIONS
app.get('/api/instagram/accounts', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const userPages = (await redis.hgetall(`user_pages:${userId}`)) || {};
    
    const accounts = Object.entries(userPages).map(([pageId, name]) => ({
      pageId,
      name: typeof name === 'string' ? name : JSON.parse(name)
    }));

    res.json({ accounts });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/instagram/posts', authenticateToken, async (req, res) => {
  try {
    const { pageId } = req.query;
    if (!pageId) return res.status(400).json({ error: 'Page ID required' });

    const pageToken = await redis.hget('page_tokens', pageId);
    if (!pageToken) return res.status(400).json({ error: 'Page access token not found.' });

    // Fetch Media
    let mediaUrl = `https://graph.facebook.com/v19.0/${pageId}/media?fields=id,caption,media_type,media_url,thumbnail_url,permalink,timestamp&access_token=${pageToken}`;
    
    // Check if pageId is a Facebook Page or direct Instagram User
    const igRes = await fetch(`https://graph.facebook.com/v19.0/${pageId}?fields=instagram_business_account&access_token=${pageToken}`);
    const igData = await igRes.json();
    if (igData.instagram_business_account?.id) {
      const igUserId = igData.instagram_business_account.id;
      mediaUrl = `https://graph.facebook.com/v19.0/${igUserId}/media?fields=id,caption,media_type,media_url,thumbnail_url,permalink,timestamp&access_token=${pageToken}`;
    }

    const mediaRes = await fetch(mediaUrl);
    const mediaData = await mediaRes.json();

    if (mediaData.error) return res.status(400).json({ error: mediaData.error.message });

    res.json({ posts: mediaData.data || [] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/rules/post', authenticateToken, async (req, res) => {
  try {
    const { mediaId, responseText, keyword } = req.body;
    if (!mediaId || !responseText) return res.status(400).json({ error: 'Media ID and response text required.' });

    const userId = req.user.userId;
    const ruleData = {
      mediaId,
      keyword: keyword ? keyword.trim().toUpperCase() : 'ANY',
      responseText: responseText.trim(),
      updatedAt: Date.now()
    };

    await redis.hset(`post_rules:${userId}`, { [mediaId]: JSON.stringify(ruleData) });
    res.json({ success: true, message: 'Automation active for post!' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/dashboard-data', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const postRules = (await redis.hgetall(`post_rules:${userId}`)) || {};
    const userPages = (await redis.hgetall(`user_pages:${userId}`)) || {};

    const parsedRules = {};
    for (const [key, val] of Object.entries(postRules)) {
      parsedRules[key] = typeof val === 'string' ? JSON.parse(val) : val;
    }

    res.json({ postRules: parsedRules, connectedPagesCount: Object.keys(userPages).length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/rules/post/:mediaId', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    await redis.hdel(`post_rules:${userId}`, req.params.mediaId);
    res.json({ success: true, message: 'Automation deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// 4. DIRECT INSTAGRAM & FACEBOOK OAUTH
app.get('/api/auth/instagram', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const authHeader = req.headers['authorization'];
    const clientJwtToken = (authHeader && authHeader.split(' ')[1]) || req.query.token;

    const appId = process.env.META_APP_ID;
    const redirectUri = `https://${req.get('host')}/api/auth/instagram/callback`;
    const state = Buffer.from(JSON.stringify({ userId, token: clientJwtToken })).toString('base64');
    
    // Comprehensive scope covering both Direct Instagram & Facebook Pages
    const scope = 'instagram_basic,instagram_manage_messages,instagram_manage_comments,pages_manage_metadata,pages_show_list,business_management';

    const authUrl = `https://www.facebook.com/v19.0/dialog/oauth?client_id=${appId}&redirect_uri=${encodeURIComponent(redirectUri)}&scope=${encodeURIComponent(scope)}&state=${state}`;
    res.redirect(authUrl);
  } catch (err) {
    res.status(500).send('OAuth Initialization Error');
  }
});

app.get('/api/auth/instagram/callback', async (req, res) => {
  try {
    const { code, state } = req.query;
    if (!code) return res.status(400).send('Authorization code missing from Meta.');

    const decodedState = JSON.parse(Buffer.from(state, 'base64').toString('utf-8'));
    const userId = decodedState.userId;
    const userJwtToken = decodedState.token;

    const appId = process.env.META_APP_ID;
    const appSecret = process.env.META_APP_SECRET || '';
    const redirectUri = `https://${req.get('host')}/api/auth/instagram/callback`;

    // 1. Exchange OAuth code for User Access Token
    const tokenUrl = `https://graph.facebook.com/v19.0/oauth/access_token?client_id=${appId}&redirect_uri=${encodeURIComponent(redirectUri)}&client_secret=${appSecret}&code=${code}`;
    const tokenRes = await fetch(tokenUrl);
    const tokenData = await tokenRes.json();

    if (tokenData.error) {
      console.error('❌ Token Exchange Error:', tokenData.error);
      return res.redirect(`/?error=token_exchange_failed&token=${userJwtToken}`);
    }

    const shortLivedUserToken = tokenData.access_token;

    // 2. Exchange for Long-Lived Token
    const longLivedUrl = `https://graph.facebook.com/v19.0/oauth/access_token?grant_type=fb_exchange_token&client_id=${appId}&client_secret=${appSecret}&fb_exchange_token=${shortLivedUserToken}`;
    const longLivedRes = await fetch(longLivedUrl);
    const longLivedData = await longLivedRes.json();
    const userToken = longLivedData.access_token || shortLivedUserToken;

    let accountsLinked = 0;

    // A. Check Facebook Pages Endpoint
    const pagesUrl = `https://graph.facebook.com/v19.0/me/accounts?access_token=${userToken}`;
    const pagesRes = await fetch(pagesUrl);
    const pagesData = await pagesRes.json();

    if (pagesData.data && pagesData.data.length > 0) {
      for (const page of pagesData.data) {
        await redis.hset('page_tokens', { [page.id]: page.access_token });
        await redis.hset(`user_pages:${userId}`, { [page.id]: page.name });
        console.log(`✅ Linked Page "${page.name}" (#${page.id}) to User ${userId}`);
        accountsLinked++;
      }
    }

    // B. Direct Fallback: Fetch User's Direct Instagram Account info if Pages list was empty
    if (accountsLinked === 0) {
      const meRes = await fetch(`https://graph.facebook.com/v19.0/me?fields=id,name,username&access_token=${userToken}`);
      const meData = await meRes.json();
      if (meData.id) {
        const accountName = meData.username || meData.name || 'Instagram Account';
        await redis.hset('page_tokens', { [meData.id]: userToken });
        await redis.hset(`user_pages:${userId}`, { [meData.id]: accountName });
        console.log(`✅ Linked Direct Instagram Account "${accountName}" (#${meData.id}) to User ${userId}`);
      }
    }

    res.redirect(`/?meta_connect=success&token=${userJwtToken}`);
  } catch (err) {
    console.error('❌ OAuth Callback Failed:', err.message);
    res.redirect('/?error=oauth_processing_error');
  }
});

// 5. WEBHOOK LISTENER & QUEUE WORKER
app.get('/webhook', (req, res) => {
  if (req.query['hub.mode'] === 'subscribe' && req.query['hub.verify_token'] === VERIFY_TOKEN) {
    return res.status(200).send(req.query['hub.challenge']);
  }
  return res.status(403).send('Verification failed');
});

app.post('/webhook', async (req, res) => {
  try {
    if (req.body.object) {
      await redis.lpush('meta_webhook_queue', JSON.stringify(req.body));
      return res.status(200).send('EVENT_RECEIVED');
    }
    res.sendStatus(404);
  } catch (error) {
    res.sendStatus(500);
  }
});

async function startBackgroundWorker() {
  console.log('👷 CloudFlow Engine Active...');
  while (true) {
    try {
      const rawEvent = await redis.rpop('meta_webhook_queue');
      if (rawEvent) {
        const payload = typeof rawEvent === 'string' ? JSON.parse(rawEvent) : rawEvent;
        for (const entry of payload.entry || []) {
          for (const change of entry.changes || []) {
            if (change.field === 'comments') {
              console.log(`💬 Comment Event Received on Media #${change.value.media?.id}`);
            }
          }
        }
      } else {
        await new Promise((res) => setTimeout(res, 2000));
      }
    } catch (error) {
      await new Promise((res) => setTimeout(res, 3000));
    }
  }
}

app.listen(PORT, () => {
  console.log(`🚀 CloudFlow Active on Port ${PORT}`);
  startBackgroundWorker();
});