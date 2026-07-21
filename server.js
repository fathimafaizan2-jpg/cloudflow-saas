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

// Environment & Service Clients
const stripe = Stripe(process.env.STRIPE_SECRET_KEY || 'sk_test_mock_key');
const redis = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL,
  token: process.env.UPSTASH_REDIS_REST_TOKEN,
});
const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });

const PORT = process.env.PORT || 3000;
const VERIFY_TOKEN = process.env.VERIFY_TOKEN || 'my_secret_token_123';
const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_jwt_key_99';
const STARTER_AI_LIMIT = 50; // 50 Free AI Replies included with $3 Starter Pass

// -------------------------------------------------------------
// AUTHENTICATION MIDDLEWARE
// -------------------------------------------------------------
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'Access denied. Please log in.' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Session expired. Log in again.' });
    req.user = user;
    next();
  });
}

// -------------------------------------------------------------
// 1. AUTHENTICATION & USER MANAGEMENT
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
    const userData = { userId, email: lowerEmail, password: hashedPassword, plan: 'unpaid' };

    await redis.hset('cloudflow_users', { [lowerEmail]: JSON.stringify(userData) });
    const token = jwt.sign({ userId, email: lowerEmail }, JWT_SECRET, { expiresIn: '7d' });

    console.log(`👤 New User Signed Up: ${lowerEmail}`);
    res.json({ success: true, token, user: { userId, email: lowerEmail, plan: 'unpaid' } });
  } catch (err) {
    console.error('❌ Signup Error:', err.message);
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
    console.log(`🔑 User Logged In: ${lowerEmail}`);
    res.json({ success: true, token, user: { userId: user.userId, email: user.email, plan: user.plan || 'unpaid' } });
  } catch (err) {
    console.error('❌ Login Error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// -------------------------------------------------------------
// 2. DASHBOARD & DATA API
// -------------------------------------------------------------
app.get('/api/dashboard-data', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    const rules = (await redis.hgetall(`rules:${userId}`)) || {};
    const usageCount = parseInt((await redis.get(`usage:${userId}`)) || '0', 10);
    
    const rawUser = await redis.hget('cloudflow_users', req.user.email);
    const user = typeof rawUser === 'string' ? JSON.parse(rawUser) : rawUser;

    res.json({
      rules,
      usageCount,
      aiLimit: STARTER_AI_LIMIT,
      plan: user?.plan || 'starter',
      isLimitReached: usageCount >= STARTER_AI_LIMIT && user?.plan !== 'pro',
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/rules', authenticateToken, async (req, res) => {
  try {
    const { keyword, responseText } = req.body;
    if (!keyword || !responseText) return res.status(400).json({ error: 'All fields required' });

    const userId = req.user.userId;
    const cleanKey = keyword.trim().toUpperCase();
    await redis.hset(`rules:${userId}`, { [cleanKey]: responseText.trim() });

    console.log(`📝 Rule Saved for User ${userId}: ${cleanKey} ➔ ${responseText}`);
    res.json({ success: true, message: 'Rule saved!' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/rules/:keyword', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.userId;
    await redis.hdel(`rules:${userId}`, req.params.keyword.trim().toUpperCase());
    console.log(`🗑️ Rule Deleted for User ${userId}: ${req.params.keyword}`);
    res.json({ success: true, message: 'Rule deleted' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// -------------------------------------------------------------
// 3. STRIPE PAYMENT SESSIONS ($3 Starter Pass & $19 Pro)
// -------------------------------------------------------------
app.post('/api/checkout/starter-pass', authenticateToken, async (req, res) => {
  try {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: [
        {
          price_data: {
            currency: 'usd',
            product_data: {
              name: 'CloudFlow $3 Starter Pass',
              description: 'Unlimited Keyword Rules + 50 Smart AI DMs',
            },
            unit_amount: 300, // $3.00 USD
          },
          quantity: 1,
        },
      ],
      mode: 'payment',
      success_url: `${req.protocol}://${req.get('host')}/?payment=starter_success`,
      cancel_url: `${req.protocol}://${req.get('host')}/?payment=cancel`,
      client_reference_id: req.user.userId,
    });

    console.log(`💳 Created $3 Starter Checkout Session for ${req.user.email}`);
    res.json({ url: session.url });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/checkout/pro-plan', authenticateToken, async (req, res) => {
  try {
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: [
        {
          price_data: {
            currency: 'usd',
            product_data: {
              name: 'CloudFlow Pro Unlimited Plan',
              description: 'Unlimited Keywords + Unlimited Smart AI Replies',
            },
            unit_amount: 1900, // $19.00 USD / Month
            recurring: { interval: 'month' },
          },
          quantity: 1,
        },
      ],
      mode: 'subscription',
      success_url: `${req.protocol}://${req.get('host')}/?payment=pro_success`,
      cancel_url: `${req.protocol}://${req.get('host')}/?payment=cancel`,
      client_reference_id: req.user.userId,
    });

    console.log(`⚡ Created $19/mo Pro Checkout Session for ${req.user.email}`);
    res.json({ url: session.url });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// -------------------------------------------------------------
// 4. META WEBHOOK & EMBEDDED WORKER (WITH LIVE LOGGING)
// -------------------------------------------------------------
app.get('/webhook', (req, res) => {
  console.log('🔍 GET Webhook Handshake Received from Meta');
  if (req.query['hub.mode'] === 'subscribe' && req.query['hub.verify_token'] === VERIFY_TOKEN) {
    console.log('✅ Meta Webhook handshake verified successfully!');
    return res.status(200).send(req.query['hub.challenge']);
  }
  console.log('❌ Handshake failed: Token mismatch');
  return res.status(403).send('Verification failed');
});

app.post('/webhook', async (req, res) => {
  try {
    console.log('📩 INCOMING WEBHOOK EVENT:', JSON.stringify(req.body));
    if (req.body.object) {
      await redis.lpush('meta_webhook_queue', JSON.stringify(req.body));
      console.log('📥 Message successfully pushed to Redis processing queue');
      return res.status(200).send('EVENT_RECEIVED');
    }
    res.sendStatus(404);
  } catch (error) {
    console.error('❌ Webhook Error:', error.message);
    res.sendStatus(500);
  }
});

async function startBackgroundWorker() {
  console.log('👷 Embedded CloudFlow Queue Worker active & watching queue...');
  while (true) {
    try {
      const rawEvent = await redis.rpop('meta_webhook_queue');
      if (rawEvent) {
        const parsedEvent = typeof rawEvent === 'string' ? JSON.parse(rawEvent) : rawEvent;
        console.log('⚡ WORKER PROCESSING EVENT:', JSON.stringify(parsedEvent));
        // Automation logic handles message dispatch here
      } else {
        await new Promise((res) => setTimeout(res, 2000));
      }
    } catch (error) {
      if (!error.message.includes('fetch failed')) console.error('❌ WORKER ERROR:', error.message);
      await new Promise((res) => setTimeout(res, 3000));
    }
  }
}

app.listen(PORT, () => {
  console.log(`🚀 CloudFlow SaaS active on port ${PORT}`);
  startBackgroundWorker();
});