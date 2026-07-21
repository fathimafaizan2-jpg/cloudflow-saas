require('dotenv').config();
const express = require('express');
const path = require('path');
const { Redis } = require('@upstash/redis');
const { GoogleGenAI } = require('@google/genai');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Initialize DB & AI Clients
const redis = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL,
  token: process.env.UPSTASH_REDIS_REST_TOKEN,
});
const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });

const PORT = process.env.PORT || 3000;
const VERIFY_TOKEN = process.env.VERIFY_TOKEN || 'my_secret_token_123';
const DB_KEY = 'cloudflow_rules_v1';

// -------------------------------------------------------------
// 1. FRONTEND RULES API ENDPOINTS
// -------------------------------------------------------------
app.get('/api/rules', async (req, res) => {
  try {
    const rules = await redis.hgetall(DB_KEY);
    res.json({ rules: rules || {} });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/rules', async (req, res) => {
  try {
    const { keyword, responseText } = req.body;
    if (!keyword || !responseText) return res.status(400).json({ error: 'Missing fields' });

    const cleanKey = keyword.trim().toUpperCase();
    const cleanValue = responseText.trim();
    await redis.hset(DB_KEY, { [cleanKey]: cleanValue });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/rules/:keyword', async (req, res) => {
  try {
    await redis.hdel(DB_KEY, req.params.keyword.trim().toUpperCase());
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/rules-clear-all', async (req, res) => {
  try {
    await redis.del(DB_KEY);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// -------------------------------------------------------------
// 2. META WEBHOOK ENDPOINTS
// -------------------------------------------------------------
app.get('/webhook', (req, res) => {
  const mode = req.query['hub.mode'];
  const token = req.query['hub.verify_token'];
  const challenge = req.query['hub.challenge'];

  if (mode === 'subscribe' && token === VERIFY_TOKEN) {
    return res.status(200).send(challenge);
  }
  return res.status(403).send('Verification failed');
});

app.post('/webhook', async (req, res) => {
  try {
    const body = req.body;
    if (body.object) {
      await redis.lpush('meta_webhook_queue', JSON.stringify(body));
      return res.status(200).send('EVENT_RECEIVED');
    }
    res.sendStatus(404);
  } catch (error) {
    res.sendStatus(500);
  }
});

// -------------------------------------------------------------
// 3. BACKGROUND QUEUE WORKER (Runs inside process)
// -------------------------------------------------------------
async function generateAIReply(userMessage) {
  try {
    const response = await ai.models.generateContent({
      model: 'gemini-2.0-flash',
      contents: `You are a helpful support bot. Reply in under 2 sentences. User: "${userMessage}"`,
    });
    return response.text;
  } catch (err) {
    return 'Thanks for reaching out! We will get back to you shortly.';
  }
}

async function processEvent(event) {
  if (event.entry && event.entry.length > 0) {
    for (const entry of event.entry) {
      if (entry.messaging) {
        for (const messageObj of entry.messaging) {
          const senderId = messageObj.sender?.id;
          const rawText = messageObj.message?.text?.trim();
          if (!rawText) continue;

          const cleanKeyword = rawText.toUpperCase();
          const allRules = (await redis.hgetall(DB_KEY)) || {};
          let matchedResponse = allRules[cleanKeyword];

          if (!matchedResponse) {
            for (const key of Object.keys(allRules)) {
              if (cleanKeyword.includes(key)) {
                matchedResponse = allRules[key];
                break;
              }
            }
          }

          if (matchedResponse) {
            console.log(`⚡ INSTANT RULE MATCHED FOR "${cleanKeyword}" to [${senderId}]`);
            // HERE: Send Meta API DM Request
          } else {
            const aiReply = await generateAIReply(rawText);
            console.log(`🤖 AI Reply Generated: "${aiReply}"`);
            // HERE: Send Meta API DM Request
          }
        }
      }
    }
  }
}

async function startWorker() {
  console.log('👷 Background queue worker active...');
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
      await new Promise((resolve) => setTimeout(resolve, 3000));
    }
  }
}

// Start Web Server & Worker
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  startWorker();
});