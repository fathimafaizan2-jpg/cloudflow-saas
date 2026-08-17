require('dotenv').config();
const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { Redis } = require('@upstash/redis');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// --- SERVICE CLIENTS ---
const redis = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL,
  token: process.env.UPSTASH_REDIS_REST_TOKEN,
});

const PORT = process.env.PORT || 10000;
const VERIFY_TOKEN = (process.env.VERIFY_TOKEN || 'my_secret_token_123');
const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_jwt_key_99';

console.log(`🔑 Configured Meta App ID: ${process.env.META_APP_ID || 'MISSING'}`);

// --- MIDDLEWARE ---
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  let token = authHeader && authHeader.split(' ')[1];
  if (!token && req.query.token) token = req.query.token;
  if (!token) return res.status(401).json({ error: 'Access denied.' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Session expired.' });
    if (user.pending2fa) return res.status(403).json({ error: 'Two-factor verification required.' });
    req.user = user;
    next();
  });
}

function issueSession(user) {
  return jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
}

function base32Decode(value) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const clean = String(value || '').toUpperCase().replace(/[^A-Z2-7]/g, '');
  let bits = '';
  for (const char of clean) {
    const index = alphabet.indexOf(char);
    if (index < 0) continue;
    bits += index.toString(2).padStart(5, '0');
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(bytes);
}

function totpCode(secret, timestamp = Date.now()) {
  const counter = Math.floor(timestamp / 30000);
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeBigUInt64BE(BigInt(counter));
  const digest = crypto.createHmac('sha1', base32Decode(secret)).update(counterBuffer).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const binary = ((digest[offset] & 0x7f) << 24) | (digest[offset + 1] << 16) | (digest[offset + 2] << 8) | digest[offset + 3];
  return String(binary % 1000000).padStart(6, '0');
}

function verifyTotp(secret, code) {
  const normalized = String(code || '').replace(/\s/g, '');
  if (!/^\d{6}$/.test(normalized)) return false;
  for (const drift of [-30000, 0, 30000]) {
    if (totpCode(secret, Date.now() + drift) === normalized) return true;
  }
  return false;
}

function makeTotpSecret() {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const bytes = crypto.randomBytes(20);
  let bits = '';
  for (const byte of bytes) bits += byte.toString(2).padStart(8, '0');
  let secret = '';
  for (let i = 0; i + 5 <= bits.length; i += 5) secret += alphabet[parseInt(bits.slice(i, i + 5), 2)];
  return secret;
}

async function deleteUserResources(userId, email) {
  const accounts = await redis.hgetall(`user_pages:${userId}`);
  const ownedIds = new Set(Object.keys(accounts || {}));
  const pageTokens = await redis.hgetall('page_tokens');
  for (const id of Object.keys(pageTokens || {})) {
    if (await redis.get(`page_owner:${id}`) === userId) ownedIds.add(id);
  }
  for (const id of ownedIds) {
    await redis.hdel('page_tokens', id);
    await redis.del(`page_owner:${id}`);
  }
  if (await redis.get('fallback_user_id') === userId) {
    await redis.del('fallback_user_id');
    await redis.del('fallback_token');
  }
  await redis.del(`user_pages:${userId}`);
  await redis.del(`post_rules:${userId}`);
  await redis.del(`last_error:${userId}`);
  await redis.del(`user:${email}`);
  await redis.del(`userid:${userId}`);
}

// -------------------------------------------------------------
// 0. ADMIN & DIAGNOSTICS
// -------------------------------------------------------------
app.get('/api/admin/master-reset', async (req, res) => {
  try {
    await redis.flushall();
    console.log('🧹 MASTER RESET: Redis database wiped successfully.');
    res.send('<h1>✅ Database Wiped Successfully! You can now reconnect your account.</h1>');
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
    // Make this public for debugging
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
    const lastError = await redis.get(`last_error:${userId}`) || 'No errors recorded.';
    const accounts = await redis.hgetall(`user_pages:${userId}`);
    const rules = await redis.hgetall(`post_rules:${userId}`);
    
    let diagnosis = "Everything looks healthy! If DMs aren't working, check your tester account settings.";
    if (lastError.includes('Code #3')) {
      diagnosis = "Meta Error #3: Capability issue. Ensure 'instagram_manage_messages' has Standard Access and try reconnecting.";
    } else if (lastError.includes('refused to list your pages')) {
      diagnosis = "Meta is blocking your page list. This usually means 'business_management' or 'pages_show_list' permissions are missing in your Meta Dashboard.";
    } else if (lastError.includes('Token exchange failed') || lastError.includes('client secret')) {
      diagnosis = "There was a problem with your App Secret. Please re-check your Render Environment variables and then click 'Connect Instagram' again.";
    } else if (Object.keys(accounts || {}).length === 0) {
      diagnosis = "No Instagram account linked. Please click 'Connect Instagram' and ensure you check ALL boxes in the Facebook popup.";
    }

    res.json({ diagnosis, lastError, connectedAccountsCount: Object.keys(accounts || {}).length });
  } catch (err) {
    res.status(500).json({ error: 'Diagnosis failed' });
  }
});

// -------------------------------------------------------------
// 1. AUTHENTICATION & ACCOUNT MANAGEMENT
// -------------------------------------------------------------
app.post('/api/signup', async (req, res) => {
  try {
    const { email, password } = req.body;
    const existing = await redis.get(`user:${email}`);
    if (existing) return res.status(400).json({ error: 'User already exists' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const userId = Date.now().toString();
    const userData = { id: userId, email, password: hashedPassword, tfaEnabled: false };
    await redis.set(`user:${email}`, JSON.stringify(userData));
    await redis.set(`userid:${userId}`, email);

    const token = jwt.sign({ id: userId, email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: userId, email, tfaEnabled: false } });
  } catch (err) { res.status(500).json({ error: 'Signup failed' }); }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const userData = await redis.get(`user:${email}`);
    if (!userData) return res.status(401).json({ error: 'Invalid credentials' });
    const user = typeof userData === 'string' ? JSON.parse(userData) : userData;
    if (!(await bcrypt.compare(password, user.password))) return res.status(401).json({ error: 'Invalid credentials' });

    if (user.tfaEnabled && user.tfaSecret) {
      const pendingToken = jwt.sign({ id: user.id, email: user.email, pending2fa: true }, JWT_SECRET, { expiresIn: '10m' });
      return res.json({ requires2fa: true, pendingToken, user: { id: user.id, email: user.email, tfaEnabled: true } });
    }

    const token = issueSession(user);
    res.json({ token, user: { id: user.id, email: user.email, tfaEnabled: false } });
  } catch (err) { res.status(500).json({ error: 'Login failed' }); }
});

app.post('/api/login/2fa', async (req, res) => {
  try {
    const { pendingToken, code } = req.body;
    const pending = jwt.verify(pendingToken, JWT_SECRET);
    if (!pending.pending2fa) return res.status(400).json({ error: 'Invalid 2FA session.' });
    const userData = await redis.get(`user:${pending.email}`);
    if (!userData) return res.status(401).json({ error: 'Invalid credentials' });
    const user = typeof userData === 'string' ? JSON.parse(userData) : userData;
    if (!user.tfaEnabled || !verifyTotp(user.tfaSecret, code)) return res.status(401).json({ error: 'Invalid authenticator code.' });
    const token = issueSession(user);
    res.json({ token, user: { id: user.id, email: user.email, tfaEnabled: true } });
  } catch (err) { res.status(401).json({ error: '2FA verification failed.' }); }
});

app.get('/api/user/settings', authenticateToken, async (req, res) => {
  const userData = await redis.get(`user:${req.user.email}`);
  const user = typeof userData === 'string' ? JSON.parse(userData) : userData;
  res.json({ user: { id: user.id, email: user.email, tfaEnabled: Boolean(user.tfaEnabled) } });
});

app.post('/api/user/2fa/setup', authenticateToken, async (req, res) => {
  try {
    const email = req.user.email;
    const userData = await redis.get(`user:${email}`);
    const user = typeof userData === 'string' ? JSON.parse(userData) : userData;
    const secret = makeTotpSecret();
    user.tfaSetupSecret = secret;
    await redis.set(`user:${email}`, JSON.stringify(user));
    const issuer = 'Cloudflow';
    const label = `${issuer}:${encodeURIComponent(email)}`;
    const otpauthUri = `otpauth://totp/${label}?secret=${secret}&issuer=${issuer}&algorithm=SHA1&digits=6&period=30`;
    res.json({ secret, otpauthUri });
  } catch (err) { res.status(500).json({ error: '2FA setup failed' }); }
});

app.post('/api/user/2fa/verify', authenticateToken, async (req, res) => {
  try {
    const email = req.user.email;
    const userData = await redis.get(`user:${email}`);
    const user = typeof userData === 'string' ? JSON.parse(userData) : userData;
    if (!user.tfaSetupSecret || !verifyTotp(user.tfaSetupSecret, req.body.code)) return res.status(400).json({ error: 'Invalid authenticator code.' });
    user.tfaSecret = user.tfaSetupSecret;
    delete user.tfaSetupSecret;
    user.tfaEnabled = true;
    await redis.set(`user:${email}`, JSON.stringify(user));
    res.json({ success: true, tfaEnabled: true });
  } catch (err) { res.status(500).json({ error: '2FA verification failed' }); }
});

app.post('/api/user/2fa/disable', authenticateToken, async (req, res) => {
  try {
    const email = req.user.email;
    const userData = await redis.get(`user:${email}`);
    const user = typeof userData === 'string' ? JSON.parse(userData) : userData;
    if (user.tfaEnabled && !verifyTotp(user.tfaSecret, req.body.code)) return res.status(400).json({ error: 'Valid authenticator code required.' });
    delete user.tfaSecret;
    delete user.tfaSetupSecret;
    user.tfaEnabled = false;
    await redis.set(`user:${email}`, JSON.stringify(user));
    res.json({ success: true, tfaEnabled: false });
  } catch (err) { res.status(500).json({ error: '2FA disable failed' }); }
});

app.post('/api/user/settings', authenticateToken, async (req, res) => {
  try {
    const email = req.user.email;
    const { newPassword } = req.body;
    const userData = await redis.get(`user:${email}`);
    const user = typeof userData === 'string' ? JSON.parse(userData) : userData;
    if (newPassword) {
      if (String(newPassword).length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });
      user.password = await bcrypt.hash(newPassword, 12);
    }
    await redis.set(`user:${email}`, JSON.stringify(user));
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: 'Settings update failed' }); }
});

app.delete('/api/user/account', authenticateToken, async (req, res) => {
  try {
    await deleteUserResources(req.user.id, req.user.email);
    res.json({ success: true });
  } catch (err) {
    console.error('Account deletion failed:', err);
    res.status(500).json({ error: 'Account deletion failed' });
  }
});

// -------------------------------------------------------------
// 2. OAUTH & ACCOUNT CONNECTION
// -------------------------------------------------------------
app.get('/api/auth/instagram', (req, res) => {
  const { token } = req.query;
  const decoded = jwt.verify(token, JWT_SECRET);
  const state = Buffer.from(JSON.stringify({ userId: decoded.id, token })).toString('base64');
  const appId = process.env.META_APP_ID;
  const redirectUri = `https://${req.get('host')}/api/auth/instagram/callback`;
  const scope = ['instagram_basic','instagram_manage_comments','instagram_manage_messages','pages_show_list','pages_read_engagement','pages_manage_metadata','business_management'].join(',');
  res.redirect(`https://www.facebook.com/v19.0/dialog/oauth?client_id=${appId}&redirect_uri=${encodeURIComponent(redirectUri)}&scope=${scope}&state=${state}`);
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
    
    if (!tokenRes.ok) {
      console.error(`❌ Meta Token Exchange Error: ${JSON.stringify(tokenData)}`);
      await redis.set(`last_error:${userId}`, `Token exchange failed: ${tokenData.error?.message || 'Unknown error'}`);
      return res.redirect(`/?error=oauth_failed&msg=${encodeURIComponent(tokenData.error?.message || '')}`);
    }

    const userToken = tokenData.access_token;
    const pagesRes = await fetch(`https://graph.facebook.com/v19.0/me/accounts?access_token=${userToken}`);
    const pagesData = await pagesRes.json();

    if (pagesData.error) {
      console.error(`❌ Meta API Error (Pages): ${JSON.stringify(pagesData.error)}`);
      await redis.set(`last_error:${userId}`, `Meta refused to list your pages: ${pagesData.error.message} (Error Code: ${pagesData.error.code})`);
    }

    console.log(`📄 Pages Found by Meta: ${pagesData.data?.length || 0}`);

    if (pagesData.data && pagesData.data.length > 0) {
      // ✅ SUCCESS: Clear any old error messages from the database
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

// -------------------------------------------------------------
// 3. DATA API & RULE MANAGEMENT
// -------------------------------------------------------------
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
    const userId = req.user.id;
    const mediaId = req.params.mediaId;
    await redis.hdel(`post_rules:${userId}`, mediaId);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete rule' });
  }
});

// -------------------------------------------------------------
// 4. WEBHOOKS & WORKER
// -------------------------------------------------------------
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
          const val = item.message || item.value || item;
          const text = (val.text || val.message || '').toUpperCase();
          const senderId = val.from?.id || item.sender?.id;
          if (!text || !senderId) continue;

          for (const rStr of Object.values(rules)) {
            const rule = typeof rStr === 'string' ? JSON.parse(rStr) : rStr;
            if (text.includes(rule.keyword.toUpperCase())) {
              console.log(`🎯 MATCH! Replying to ${senderId}`);
              // --- SMART ID RESOLUTION ---
              let targetId = senderId;
              
              // If we suspect this is a comment ID (longer) and we need a scoped ID,
              // we will try to send. If it fails with Error 100, we check the conversations cache.
              const sendDm = async (id) => {
                const endpoint = `https://graph.facebook.com/v19.0/me/messages`;
                const r = await fetch(endpoint, {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
                  body: JSON.stringify({ recipient: { id }, message: { text: rule.responseText } })
                });
                return { ok: r.ok, status: r.status, data: await r.json() };
              };

              let result = await sendDm(targetId);
              
              // Error 100 often means the ID is not scoped for DMs (common with comment triggers)
              if (!result.ok && result.data.error?.code === 100) {
                console.log(`⚠️ Direct DM failed (Error 100). Attempting conversation discovery...`);
                // Try to find a conversation with this user to get their scoped ID
                try {
                  const convRes = await fetch(`https://graph.facebook.com/v20.0/${igId}/conversations?fields=participants&access_token=${token}`);
                  const convData = await convRes.json();
                  if (convData.data) {
                    for (const conv of convData.data) {
                      for (const part of conv.participants.data) {
                        // If we find a participant that matches or looks like our sender
                        if (part.id !== igId) { 
                          console.log(`🔎 Found potential scoped ID: ${part.id}. Retrying...`);
                          const retry = await sendDm(part.id);
                          if (retry.ok) {
                            result = retry;
                            break;
                          }
                        }
                      }
                      if (result.ok) break;
                    }
                  }
                } catch (e) { console.error('Discovery Error:', e.message); }
              }

              if (result.ok) {
                console.log(`✅ DM DELIVERED SUCCESSFULLY to ${targetId}!`);
              } else {
                console.error(`❌ DM FAILED: ${JSON.stringify(result.data.error)}`);
                await redis.set(`last_error:${userId}`, result.data.error.message);
              }
            }
          }
        }
      }
    } catch (err) { console.error('Worker Error:', err.message); }
  }
}

app.listen(PORT, () => { console.log(`🚀 Server on ${PORT}`); worker(); });
