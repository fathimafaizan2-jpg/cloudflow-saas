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

// -------------------------------------------------------------
// AUTHENTICATION MIDDLEWARE
// -------------------------------------------------------------
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

// -------------------------------------------------------------
// 1. PUBLIC COMPLIANCE ROUTES
// -------------------------------------------------------------
app.get('/privacy.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'privacy.html')));
app.get('/terms.html', (req, res) => res.sendFile(path.join(__dirname, 'public', 'terms.html')));

// -------------------------------------------------------------
// 2. AUTH & USER ACCOUNTS
// -------------------------------------------------------------
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

// -------------------------------------------------------------
// 3. MULTI-ACCOUNT ($N$) & POST-LEVEL AUTOMATIONS
// -------------------------------------------------------------

// Fetch all connected pages for user
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

// Fetch posts for a specific connected Instagram Page
app.get('/api/instagram/posts', authenticateToken, async (req, res) => {
  try {
    const { pageId } = req.query;
    if (!pageId) return res.status(400).json({ error: 'Page ID required' });

    const pageToken = await redis.hget('page_tokens', pageId);
    if (!pageToken) return res.status(400).json({ error: 'Page access token not found.' });

    // Get Linked Instagram Business Account ID
    const igRes = await fetch(`https://graph.facebook.com/v19.0/${pageId}?fields=instagram_business_account&access_token=${pageToken}`);
    const igData = await igRes.json();
    const igUserId = igData.instagram_business_account?.id;

    if (!igUserId) return res.status(400).json({ error: 'No Instagram Business Account linked to this Facebook page.' });

    // Fetch Recent Posts/Reels
    const mediaRes = await fetch(
      `https://graph.facebook.com/v19.0/${igUserId}/media?fields=id,caption,media_type,media_url,thumbnail_url,permalink,timestamp&access_token=${pageToken}`
    );
    const mediaData = await mediaRes.json();

    if (mediaData.error) return res.status(400).json({ error: mediaData.error.message });

    res.json({ posts: mediaData.data || [] });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Save Post Automation Rule
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

    console.log(`📌 Post Automation Saved: User ${userId} | Post #${mediaId} ➔ "${responseText}"`);
    res.json({ success: true, message: 'Automation active for post!' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Get User Dashboard Data
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

// Delete Post Automation
app.delete('/api/rules/post/:mediaId', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    await redis.hdel(`post_rules:${userId}`, req.params.mediaId);
    res.json({ success: true, message: 'Automation deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// -------------------------------------------------------------
// 4. INSTAGRAM OAUTH & MULTI-ACCOUNT CAP ENFORCEMENT
// -------------------------------------------------------------
app.get('/api/auth/instagram', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const rawUser = await redis.hget('cloudflow_users', req.user.email);
    const user = typeof rawUser === 'string' ? JSON.parse(rawUser) : rawUser;

    const userPages = (await redis.hgetall(`user_pages:${userId}`)) || {};
    const connectedCount = Object.keys(userPages).length;
    const maxAccounts = user?.maxAccounts || 1;

    // Enforce Tier Account Limit
    if (connectedCount >= maxAccounts) {
      return res.redirect(`/?error=account_limit_reached&limit=${maxAccounts}`);
    }

    const appId = process.env.META_APP_ID;
    const redirectUri = `https://${req.get('host')}/api/auth/instagram/callback`;
    const state = Buffer.from(JSON.stringify({ userId })).toString('base64');
    
    // RESTORED FULL INSTAGRAM SCOPES
    const scope = 'instagram_basic,instagram_manage_messages,pages_manage_metadata,pages_show_list';

    const authUrl = `https://www.facebook.com/v19.0/dialog/oauth?client_id=${appId}&redirect_uri=${encodeURIComponent(redirectUri)}&scope=${encodeURIComponent(scope)}&state=${state}`;
    res.redirect(authUrl);
  } catch (err) {
    res.status(500).send('OAuth Initialization Error');
  }
});

app.get('/api/auth/instagram/callback', async (req, res) => {
  res.redirect('/?meta_connect=success');
});

// -------------------------------------------------------------
// 5. WEBHOOK LISTENER & QUEUE WORKER
// -------------------------------------------------------------
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

// Background queue processor for incoming comments
async function startBackgroundWorker() {
  console.log('👷 CloudFlow Post & Multi-Tenant Worker Running...');
  while (true) {
    try {
      const rawEvent = await redis.rpop('meta_webhook_queue');
      if (rawEvent) {
        const payload = typeof rawEvent === 'string' ? JSON.parse(rawEvent) : rawEvent;

        for (const entry of payload.entry || []) {
          for (const change of entry.changes || []) {
            if (change.field === 'comments') {
              const mediaId = change.value.media?.id;
              const commentText = change.value.text;
              const commentId = change.value.id;

              console.log(`💬 Comment Received on Media #${mediaId}: "${commentText}"`);
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
  console.log(`🚀 CloudFlow Multi-Account Engine Active on Port ${PORT}`);
  startBackgroundWorker();
});