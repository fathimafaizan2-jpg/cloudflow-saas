require('dotenv').config();
const express = require('express');
const path = require('path');
const { Redis } = require('@upstash/redis');
const { GoogleGenAI } = require('@google/genai');

const app = express();
app.use(express.json());

// Serve static frontend dashboard from the /public folder
app.use(express.static(path.join(__dirname, 'public')));

// Initialize Upstash Redis Client
const redis = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL,
  token: process.env.UPSTASH_REDIS_REST_TOKEN,
});

// Initialize Gemini AI Client
const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });

const PORT = process.env.PORT || 3000;
const VERIFY_TOKEN = process.env.VERIFY_TOKEN || 'my_secret_token_123';
const DB_KEY = 'cloudflow_rules_v1';

// -------------------------------------------------------------
// 1. API ROUTES FOR DASHBOARD RULE MANAGEMENT
// -------------------------------------------------------------

// Fetch all rules stored in Redis
app.get('/api/rules', async (req, res) => {
  try {
    const rules = await redis.hgetall(DB_KEY);
    res.json({ rules: rules || {} });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Save a new keyword rule
app.post('/api/rules', async (req, res) => {
  try {
    const { keyword, responseText } = req.body;
    if (!keyword || !responseText) {
      return res.status(400).json({ error: 'Keyword and Response required' });
    }

    const cleanKey = keyword.trim().toUpperCase();
    const cleanValue = responseText.trim();

    await redis.hset(DB_KEY, { [cleanKey]: cleanValue });
    console.log(`📌 SAVED TO REDIS: "${cleanKey}" ➔ "${cleanValue}"`);

    res.json({ success: true, message: 'Rule saved successfully!' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Delete a single rule
app.delete('/api/rules/:keyword', async (req, res) => {
  try {
    const { keyword } = req.params;
    await redis.hdel(DB_KEY, keyword.trim().toUpperCase());
    res.json({ success: true, message: 'Rule deleted successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Clear all rules
app.delete('/api/rules-clear-all', async (req, res) => {
  try {
    await redis.del(DB_KEY);
    console.log('🧹 REDIS RULES WIPED CLEAN!');
    res.json({ success: true, message: 'All rules wiped' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// -------------------------------------------------------------
// 2. META WEBHOOK ENDPOINTS
// -------------------------------------------------------------

// Verification endpoint for Meta / Instagram Developer setup
app.get('/webhook', (req, res) => {
  const mode = req.query['hub.mode'];
  const token = req.query['hub.verify_token'];
  const challenge = req.query['hub.challenge'];

  if (mode === 'subscribe' && token === VERIFY_TOKEN) {
    console.log('✅ META WEBHOOK VERIFIED!');
    return res.status(200).send(challenge);
  }
  return res.status(403).send('Verification failed');
});

// Webhook listener - Queues incoming messages into Redis
app.post('/webhook', async (req, res) => {
  try {
    const body = req.body;
    console.log('📩 RECEIVED WEBHOOK PAYLOAD:', JSON.stringify(body));

    if (body.object) {
      await redis.lpush('meta_webhook_queue', JSON.stringify(body));
      console.log('⚡ EVENT QUEUED IN REDIS REAL-TIME!');
      return res.status(200).send('EVENT_RECEIVED');
    }
    res.sendStatus(404);
  } catch (error) {
    console.error('❌ REDIS QUEUE ERROR:', error.message);
    res.sendStatus(500);
  }
});

// -------------------------------------------------------------
// 3. BACKGROUND QUEUE WORKER (Embedded Process)
// -------------------------------------------------------------

// Fallback AI generation using Gemini AI
async function generateAIReply(userMessage) {
  try {
    const response = await ai.models.generateContent({
      model: 'gemini-2.0-flash',
      contents: `You are a helpful customer support bot for CloudFlow SaaS. Keep replies under 2 sentences, friendly, and concise. User text: "${userMessage}"`,
    });
    return response.text;
  } catch (err) {
    console.error('❌ AI Generation Error:', err.message);
    return 'Thanks for reaching out! We will get back to you shortly.';
  }
}

// Process popped events from the Redis queue
async function processEvent(event) {
  console.log('\n⚙️ PROCESSING QUEUED EVENT:');

  if (event.entry && event.entry.length > 0) {
    for (const entry of event.entry) {
      if (entry.messaging) {
        for (const messageObj of entry.messaging) {
          const senderId = messageObj.sender?.id;
          const rawText = messageObj.message?.text?.trim();

          if (!rawText) continue;

          const cleanKeyword = rawText.toUpperCase();
          console.log(`💬 Message from [${senderId}]: "${rawText}"`);

          const allRules = (await redis.hgetall(DB_KEY)) || {};
          let matchedResponse = allRules[cleanKeyword];

          // Substring matching fallback
          if (!matchedResponse) {
            for (const key of Object.keys(allRules)) {
              if (cleanKeyword.includes(key)) {
                matchedResponse = allRules[key];
                break;
              }
            }
          }

          if (matchedResponse) {
            console.log(`⚡ INSTANT RULE MATCHED FOR "${cleanKeyword}"!`);
            console.log(`📄 Auto-Response Delivered: "${matchedResponse}"\n`);
          } else {
            console.log(`🔍 No keyword match in Redis. Forwarding to Gemini AI...`);
            const aiReply = await generateAIReply(rawText);
            console.log(`🤖 AI Generated Reply: "${aiReply}"\n`);
          }
        }
      }
    }
  }
}

// Continuous worker loop with silent network reconnection
async function startBackgroundWorker() {
  console.log('👷 Embedded CloudFlow Queue Worker started...');

  while (true) {
    try {
      const rawEvent = await redis.rpop('meta_webhook_queue');

      if (rawEvent) {
        const parsedEvent = typeof rawEvent === 'string' ? JSON.parse(rawEvent) : rawEvent;
        await processEvent(parsedEvent);
      } else {
        await new Promise((resolve) => setTimeout(resolve, 2000));
      }
    } catch (error) {
      // Suppress noisy network fetch timeout logs from spamming terminal output
      if (!error.message.includes('fetch failed')) {
        console.error('❌ WORKER ERROR:', error.message);
      }
      await new Promise((resolve) => setTimeout(resolve, 3000));
    }
  }
}

// -------------------------------------------------------------
// 4. PROCESS SAFETY & SERVER STARTUP
// -------------------------------------------------------------

process.on('uncaughtException', (err) => {
  console.error('💥 UNCAUGHT EXCEPTION:', err);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('💥 UNHANDLED REJECTION:', reason);
});

app.listen(PORT, () => {
  console.log(`🚀 CloudFlow Server active on http://localhost:${PORT}`);
  // Launch the background queue processing loop on boot
  startBackgroundWorker();
});
