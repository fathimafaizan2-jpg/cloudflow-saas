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
// 1. OAUTH & ACCOUNT CONNECTION (With Force Takeover)
// -------------------------------------------------------------
app.get('/api/auth/instagram/callback', async (req, res) => {
  try {
    const { code, state } = req.query;
    const decodedState = JSON.parse(Buffer.from(state, 'base64').toString('utf-8'));
    const userId = decodedState.userId;
    const userJwtToken = decodedState.token;

    const appId = process.env.META_APP_ID;
    const appSecret = process.env.META_APP_SECRET || '';
    const redirectUri = `https://${req.get('host')}/api/auth/instagram/callback`;

    // 1. Exchange code for User Access Token
    const tokenUrl = `https://graph.facebook.com/v19.0/oauth/access_token?client_id=${appId}&redirect_uri=${encodeURIComponent(redirectUri)}&client_secret=${appSecret}&code=${code}`;
    const tokenRes = await fetch(tokenUrl);
    const tokenData = await tokenRes.json();
    const userToken = tokenData.access_token;

    // 2. Get the Pages linked to this User
    const pagesUrl = `https://graph.facebook.com/v19.0/me/accounts?access_token=${userToken}`;
    const pagesRes = await fetch(pagesUrl);
    const pagesData = await pagesRes.json();

    if (pagesData.data) {
      for (const page of pagesData.data) {
        // Save Page Token and Owner Mapping
        await redis.hset('page_tokens', { [page.id]: page.access_token });
        await redis.hset(`user_pages:${userId}`, { [page.id]: page.name });
        await redis.set(`page_owner:${page.id}`, userId);

        // 3. FORCE TAKEOVER: Tell Meta this app is the Primary Receiver for messages and comments
        console.log(`🔗 Subscribing App to Page: ${page.name} (${page.id})`);
        const subUrl = `https://graph.facebook.com/v19.0/${page.id}/subscribed_apps?subscribed_fields=messages,messaging_postbacks,comments&access_token=${page.access_token}`;
        const subRes = await fetch(subUrl, { method: 'POST' });
        const subResult = await subRes.json();
        console.log(`✅ Subscription Result for ${page.name}:`, subResult);
      }
    }
    res.redirect(`/?meta_connect=success&token=${userJwtToken}`);
  } catch (err) {
    console.error('OAuth Error:', err.message);
    res.redirect('/?error=oauth_failed');
  }
});

// -------------------------------------------------------------
// 2. WEBHOOK ENDPOINTS (The "Ear" of your App)
// -------------------------------------------------------------
app.get('/webhook', (req, res) => {
  if (req.query['hub.mode'] === 'subscribe' && req.query['hub.verify_token'] === VERIFY_TOKEN) {
    console.log('✅ Webhook Verified Successfully');
    return res.status(200).send(req.query['hub.challenge']);
  }
  res.sendStatus(403);
});

app.post('/webhook', async (req, res) => {
  // DIAGNOSTIC LOG: See if Meta is even touching your server
  console.log('📬 RAW WEBHOOK HIT! Object:', req.body.object);

  if (req.body.object === 'instagram' || req.body.object === 'page') {
    try {
      await redis.lpush('meta_webhook_queue', JSON.stringify(req.body));
      return res.status(200).send('EVENT_RECEIVED');
    } catch (err) {
      console.error('Queue Error:', err.message);
      return res.sendStatus(500);
    }
  }
  res.sendStatus(404);
});

// -------------------------------------------------------------
// 3. BACKGROUND WORKER (The "Brain" that processes events)
// -------------------------------------------------------------
async function startBackgroundWorker() {
  console.log('👷 CloudFlow Automation Engine Active...');
  while (true) {
    try {
      const rawEvent = await redis.rpop('meta_webhook_queue');
      if (!rawEvent) {
        await new Promise(r => setTimeout(r, 2000)); // Wait 2 seconds if queue is empty
        continue;
      }

      const payload = JSON.parse(rawEvent);
      for (const entry of payload.entry || []) {
        const igAccountId = entry.id; // This is the ID of the Page or IG account receiving the event

        // --- PRIORITY 1: DIRECT MESSAGES (DMs) ---
        if (entry.messaging) {
          for (const msgEvent of entry.messaging) {
            const senderId = msgEvent.sender?.id;
            const text = msgEvent.message?.text || '';
            if (senderId && text) {
              console.log(`📩 DM Received from ${senderId}: "${text}"`);
              await runAutomationLogic(igAccountId, senderId, text, 'DM');
            }
          }
        }

        // --- PRIORITY 2: COMMENTS ---
        if (entry.changes) {
          for (const change of entry.changes) {
            if (change.field === 'comments') {
              const senderId = change.value.from?.id;
              const text = change.value.text || '';
              const mediaId = change.value.media?.id;
              if (senderId && text) {
                console.log(`💬 Comment Received on Media ${mediaId}: "${text}"`);
                await runAutomationLogic(igAccountId, senderId, text, 'COMMENT', mediaId);
              }
            }
          }
        }
      }
    } catch (err) {
      console.error('Worker Processing Error:', err.message);
    }
  }
}

// -------------------------------------------------------------
// 4. AUTOMATION LOGIC (Keyword Matching & Replying)
// -------------------------------------------------------------
async function runAutomationLogic(igAccountId, targetUserId, incomingText, type, mediaId = null) {
  try {
    // 1. Find which user owns this Page/IG Account
    const userId = await redis.get(`page_owner:${igAccountId}`);
    if (!userId) {
      console.log(`⚠️ No owner found for Account ID: ${igAccountId}`);
      return;
    }

    // 2. Fetch all automation rules for this user
    const rules = await redis.hgetall(`post_rules:${userId}`);
    if (!rules) return;

    const pageToken = await redis.hget('page_tokens', igAccountId);
    if (!pageToken) return;

    const cleanInput = incomingText.toUpperCase().trim();

    for (const [ruleId, ruleDataRaw] of Object.entries(rules)) {
      const rule = typeof ruleDataRaw === 'string' ? JSON.parse(ruleDataRaw) : ruleDataRaw;
      const trigger = rule.keyword ? rule.keyword.toUpperCase().trim() : 'ANY';

      // --- CONDITION MATCHING ---
      
      // A. If it's a comment, it MUST match the specific Post (mediaId)
      if (type === 'COMMENT' && rule.mediaId !== mediaId) continue;

      // B. Keyword Match Check
      const isMatch = (trigger === 'ANY') || 
                      (cleanInput === trigger) || 
                      (cleanInput.includes(trigger));

      if (isMatch) {
        console.log(`🎯 Match! Trigger: "${trigger}" -> Sending ${type} Response.`);
        
        // 3. Send the DM Response via Meta API
        const response = await fetch(`https://graph.facebook.com/v19.0/me/messages`, {
          method: 'POST',
          headers: { 
            'Content-Type': 'application/json', 
            'Authorization': `Bearer ${pageToken}` 
          },
          body: JSON.stringify({
            recipient: { id: targetUserId },
            message: { text: rule.responseText }
          })
        });

        const result = await response.json();
        if (result.message_id) {
          console.log(`✅ Auto-Reply Sent to ${targetUserId}`);
        } else {
          console.error(`❌ Meta API Error:`, result.error?.message || result);
        }
        
        return; // Stop after first match
      }
    }
  } catch (err) {
    console.error('Automation Logic Error:', err.message);
  }
}

// --- START SERVER ---
app.listen(PORT, () => {
  console.log(`🚀 CloudFlow Active on Port ${PORT}`);
  startBackgroundWorker();
});
