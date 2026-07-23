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
// 2. AUTH, USER ACCOUNTS & ACCOUNT DELETION
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
    const userData = { userId, email: lowerEmail, password: hashedPassword, tier: 'Starter', maxAccounts: 1, phone: null, twoFactorEnabled: false };

    await redis.hset('cloudflow_users', { [lowerEmail]: JSON.stringify(userData) });
    const token = jwt.sign({ userId, email: lowerEmail }, JWT_SECRET, { expiresIn: '7d' });

    res.json({ success: true, token, user: { userId, email: lowerEmail, tier: 'Starter' } });
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
    res.json({ success: true, token, user: { userId: user.userId, email: user.email, tier: user.tier || 'Starter', twoFactorEnabled: !!user.twoFactorEnabled } });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// OPTIONAL 2FA / OTP ENDPOINTS
app.post('/api/otp/request', authenticateToken, async (req, res) => {
  try {
    const { phone } = req.body;
    if (!phone) return res.status(400).json({ error: 'Phone number required' });

    const mockOtp = Math.floor(100000 + Math.random() * 900000).toString();
    await redis.hset(`otp_codes:${req.user.userId}`, { code: mockOtp, phone, createdAt: Date.now() });

    console.log(`📱 [OPTIONAL OTP] Mock Verification Code for User ${req.user.userId} (${phone}): ${mockOtp}`);
    res.json({ success: true, message: 'OTP sent successfully! (Demo code logged to server output)', demoCode: mockOtp });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/otp/verify', authenticateToken, async (req, res) => {
  try {
    const { code } = req.body;
    const otpData = await redis.hgetall(`otp_codes:${req.user.userId}`);
    if (!otpData || otpData.code !== code) {
      return res.status(400).json({ error: 'Invalid or expired OTP code.' });
    }

    const lowerEmail = req.user.email.toLowerCase();
    const rawUser = await redis.hget('cloudflow_users', lowerEmail);
    if (rawUser) {
      const user = typeof rawUser === 'string' ? JSON.parse(rawUser) : rawUser;
      user.phone = otpData.phone;
      user.twoFactorEnabled = true;
      await redis.hset('cloudflow_users', { [lowerEmail]: JSON.stringify(user) });
    }

    await redis.del(`otp_codes:${req.user.userId}`);
    res.json({ success: true, message: 'Phone 2FA verified and enabled successfully!' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// PERMANENT ACCOUNT DELETION
app.delete('/api/user/account', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const lowerEmail = req.user.email.toLowerCase();

    await redis.hdel('cloudflow_users', lowerEmail);
    await redis.del(`user_pages:${userId}`);
    await redis.del(`post_rules:${userId}`);

    console.log(`🗑️ Permanently deleted all data for user ${userId} (${lowerEmail})`);
    res.json({ success: true, message: 'Account and associated data deleted permanently.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// -------------------------------------------------------------
// 3. MULTI-ACCOUNT & POST-LEVEL AUTOMATIONS
// -------------------------------------------------------------
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

    let mediaUrl = `https://graph.facebook.com/v19.0/${pageId}/media?fields=id,caption,media_type,media_url,thumbnail_url,permalink,timestamp&access_token=${pageToken}`;
    
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
    const { mediaId, responseText, keyword, caption, thumbnail } = req.body;
    if (!mediaId || !responseText) return res.status(400).json({ error: 'Media ID and response text required.' });

    const userId = req.user.userId;
    const ruleData = {
      mediaId,
      keyword: keyword ? keyword.trim().toUpperCase() : 'ANY',
      responseText: responseText.trim(),
      caption: caption || 'Instagram Post',
      thumbnail: thumbnail || '',
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

// -------------------------------------------------------------
// 4. DIRECT INSTAGRAM & FACEBOOK OAUTH
// -------------------------------------------------------------
app.get('/api/auth/instagram', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const authHeader = req.headers['authorization'];
    const clientJwtToken = (authHeader && authHeader.split(' ')[1]) || req.query.token;

    const appId = process.env.META_APP_ID;
    const redirectUri = `https://${req.get('host')}/api/auth/instagram/callback`;
    const state = Buffer.from(JSON.stringify({ userId, token: clientJwtToken })).toString('base64');
    
    // Cleaned scope strictly matching active permissions:
    const scope = 'instagram_basic,instagram_manage_messages,pages_manage_metadata,pages_show_list';

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

    const tokenUrl = `https://graph.facebook.com/v19.0/oauth/access_token?client_id=${appId}&redirect_uri=${encodeURIComponent(redirectUri)}&client_secret=${appSecret}&code=${code}`;
    const tokenRes = await fetch(tokenUrl);
    const tokenData = await tokenRes.json();

    if (tokenData.error) {
      console.error('❌ Token Exchange Error:', tokenData.error);
      return res.redirect(`/?error=token_exchange_failed&token=${userJwtToken}`);
    }

    const shortLivedUserToken = tokenData.access_token;

    const longLivedUrl = `https://graph.facebook.com/v19.0/oauth/access_token?grant_type=fb_exchange_token&client_id=${appId}&client_secret=${appSecret}&fb_exchange_token=${shortLivedUserToken}`;
    const longLivedRes = await fetch(longLivedUrl);
    const longLivedData = await longLivedRes.json();
    const userToken = longLivedData.access_token || shortLivedUserToken;

    let accountsLinked = 0;

    const pagesUrl = `https://graph.facebook.com/v19.0/me/accounts?access_token=${userToken}`;
    const pagesRes = await fetch(pagesUrl);
    const pagesData = await pagesRes.json();

    if (pagesData.data && pagesData.data.length > 0) {
      for (const page of pagesData.data) {
        await redis.hset('page_tokens', { [page.id]: page.access_token });
        await redis.hset(`user_pages:${userId}`, { [page.id]: page.name });

        try {
          await fetch(`https://graph.facebook.com/v19.0/${page.id}/subscribed_apps?subscribed_fields=feed,comments,messages&access_token=${page.access_token}`, {
            method: 'POST'
          });
        } catch (subErr) {
          console.warn(`⚠️ Subscribed apps call warning:`, subErr.message);
        }

        accountsLinked++;
      }
    }

    if (accountsLinked === 0) {
      const meRes = await fetch(`https://graph.facebook.com/v19.0/me?fields=id,name,username&access_token=${userToken}`);
      const meData = await meRes.json();
      if (meData.id) {
        const accountName = meData.username || meData.name || 'Instagram Account';
        await redis.hset('page_tokens', { [meData.id]: userToken });
        await redis.hset(`user_pages:${userId}`, { [meData.id]: accountName });

        try {
          await fetch(`https://graph.facebook.com/v19.0/${meData.id}/subscribed_apps?subscribed_fields=feed,comments,messages&access_token=${userToken}`, {
            method: 'POST'
          });
        } catch (subErr) {
          console.warn(`⚠️ Subscribed apps call warning:`, subErr.message);
        }
      }
    }

    res.redirect(`/?meta_connect=success&token=${userJwtToken}`);
  } catch (err) {
    console.error('❌ OAuth Callback Failed:', err.message);
    res.redirect('/?error=oauth_processing_error');
  }
});

// -------------------------------------------------------------
// 5. WEBHOOK LISTENER & AUTOMATED DM WORKER
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
              const mediaId = change.value.media?.id;
              const commentText = change.value.text || '';
              const commenterId = change.value.from?.id;
              const recipientId = entry.id;

              console.log(`💬 Comment Received on Media #${mediaId}: "${commentText}"`);

              if (mediaId && commenterId) {
                const allKeys = await redis.keys('post_rules:*');
                for (const key of allKeys) {
                  const rawRule = await redis.hget(key, mediaId);
                  if (rawRule) {
                    const rule = typeof rawRule === 'string' ? JSON.parse(rawRule) : rawRule;
                    const triggerKeyword = rule.keyword ? rule.keyword.toUpperCase() : 'ANY';
                    
                    if (triggerKeyword === 'ANY' || commentText.toUpperCase().includes(triggerKeyword)) {
                      const pageToken = await redis.hget('page_tokens', recipientId);

                      if (pageToken) {
                        const sendDmRes = await fetch(`https://graph.facebook.com/v19.0/${recipientId}/messages`, {
                          method: 'POST',
                          headers: {
                            'Content-Type': 'application/json',
                            'Authorization': `Bearer ${pageToken}`
                          },
                          body: JSON.stringify({
                            recipient: { id: commenterId },
                            message: { text: rule.responseText }
                          })
                        });

                        const sendDmData = await sendDmRes.json();
                        if (sendDmData.message_id) {
                          console.log(`✅ DM Sent Successfully!`);
                        } else {
                          console.error(`❌ Meta DM Error:`, sendDmData.error?.message || sendDmData);
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      } else {
        await new Promise((res) => setTimeout(res, 2000));
      }
    } catch (error) {
      console.error('Worker Error:', error.message);
      await new Promise((res) => setTimeout(res, 3000));
    }
  }
}

app.listen(PORT, () => {
  console.log(`🚀 CloudFlow Active on Port ${PORT}`);
  startBackgroundWorker();
});