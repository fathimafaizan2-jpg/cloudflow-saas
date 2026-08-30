require('dotenv').config();

const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { Redis } = require('@upstash/redis');

const app = express();
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

const redis = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL,
  token: process.env.UPSTASH_REDIS_REST_TOKEN
});

const PORT = process.env.PORT || 10000;
const GRAPH_VERSION = process.env.META_GRAPH_VERSION || 'v19.0';
const PUBLIC_BASE_URL = (process.env.PUBLIC_BASE_URL || 'https://cloudflow-app.onrender.com').replace(/\/$/, '');
const REDIRECT_URI =
  process.env.META_REDIRECT_URI ||
  `${PUBLIC_BASE_URL}/api/auth/instagram/callback`;

const VERIFY_TOKEN = (process.env.VERIFY_TOKEN || 'my_secret_token_123').trim();
const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_jwt_key_99';
const META_APP_ID = process.env.META_APP_ID;
const META_APP_SECRET = process.env.META_APP_SECRET;

const GRAPH_BASE = `https://graph.facebook.com/${GRAPH_VERSION}`;

const safeParse = (val) => {
  if (!val) return null;
  if (typeof val === 'object') return val;
  try { return JSON.parse(val); } catch { return null; }
};

function requireEnv(name, value) {
  if (!value) throw new Error(`${name} is not configured`);
}

function graphUrl(pathname, params = {}) {
  const url = new URL(`${GRAPH_BASE}${pathname.startsWith('/') ? pathname : `/${pathname}`}`);
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== '') {
      url.searchParams.set(key, value);
    }
  }
  return url;
}

async function graphFetch(pathname, { method = 'GET', token, params = {}, body } = {}) {
  const url = graphUrl(pathname, params);
  const headers = { Accept: 'application/json' };

  if (body !== undefined) headers['Content-Type'] = 'application/json';
  if (token) headers.Authorization = `Bearer ${token}`;

  const response = await fetch(url, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body)
  });

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    const message = data?.error?.message || `Meta API returned HTTP ${response.status}`;
    const error = new Error(message);
    error.status = response.status;
    error.meta = data?.error || data;
    throw error;
  }

  return data;
}

function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : (req.query.token || null);

  if (!token || token === 'undefined') return res.status(401).json({ error: 'Authentication required' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired session' });
    req.user = user;
    next();
  });
}

// -----------------------------------------------------------------------------
// HEALTH / DEBUG
// -----------------------------------------------------------------------------

app.get('/health', (req, res) => res.status(200).send('OK'));

app.get('/api/debug/status', async (req, res) => {
  try {
    const fallbackUser = await redis.get('fallback_user_id');
    const rules = fallbackUser ? await redis.hgetall(`post_rules:${fallbackUser}`) : {};
    res.json({
      status: 'Online',
      graphVersion: GRAPH_VERSION,
      appIdConfigured: Boolean(META_APP_ID),
      appSecretConfigured: Boolean(META_APP_SECRET),
      redirectUri: REDIRECT_URI,
      webhookConfigured: Boolean(VERIFY_TOKEN),
      fallbackUser,
      rulesCount: Object.keys(rules || {}).length
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// -----------------------------------------------------------------------------
// AUTH & ACCOUNT CONTROL
// -----------------------------------------------------------------------------

app.post('/api/signup', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const normalizedEmail = String(email || '').trim().toLowerCase();

    if (!normalizedEmail || !/^\S+@\S+\.\S+$/.test(normalizedEmail)) {
      return res.status(400).json({ error: 'Enter a valid email address.' });
    }
    if (!password || String(password).length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters.' });
    }

    const existing = await redis.hget('users', normalizedEmail);
    if (existing) return res.status(409).json({ error: 'An account with that email already exists.' });

    const userId = crypto.randomUUID();
    const hashedPassword = await bcrypt.hash(password, 10);

    await redis.hset('users', {
      [normalizedEmail]: JSON.stringify({
        id: userId,
        email: normalizedEmail,
        password: hashedPassword
      })
    });

    const token = jwt.sign({ id: userId, email: normalizedEmail }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ success: true, token, user: { id: userId, email: normalizedEmail } });
  } catch (err) {
    console.error('Signup error:', err);
    res.status(500).json({ error: 'Unable to create account.' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    const normalizedEmail = String(email || '').trim().toLowerCase();
    const userStr = await redis.hget('users', normalizedEmail);

    if (!userStr) return res.status(400).json({ error: 'User not found' });

    const user = safeParse(userStr);
    if (!user || !(await bcrypt.compare(String(password || ''), user.password))) {
      return res.status(400).json({ error: 'Wrong password' });
    }

    const token = jwt.sign(
      { id: user.id, email: normalizedEmail },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      token,
      user: { id: user.id, email: normalizedEmail }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed.' });
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

    console.log(`🗑️ Account deleted permanently for user: ${userId}`);
    res.json({ success: true, message: 'Account deleted successfully.' });
  } catch (err) {
    res.status(500).json({ error: 'Unable to delete account.' });
  }
});

// -----------------------------------------------------------------------------
// META / INSTAGRAM OAUTH
// -----------------------------------------------------------------------------

app.get('/api/auth/instagram', async (req, res) => {
  try {
    requireEnv('META_APP_ID', META_APP_ID);
    requireEnv('JWT_SECRET', JWT_SECRET);

    const sessionToken = String(req.query.token || '');
    const user = jwt.verify(sessionToken, JWT_SECRET);

    const state = crypto.randomBytes(32).toString('hex');

    await redis.set(
      `oauth_state:${state}`,
      JSON.stringify({ userId: user.id, email: user.email }),
      { ex: 600 }
    );

    const scopes = [
      'instagram_basic',
      'instagram_manage_comments',
      'instagram_manage_messages',
      'pages_show_list',
      'pages_read_engagement',
      'pages_messaging',
      'business_management'
    ].join(',');

    const url = new URL(`https://www.facebook.com/${GRAPH_VERSION}/dialog/oauth`);
    url.searchParams.set('client_id', META_APP_ID);
    url.searchParams.set('redirect_uri', REDIRECT_URI);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('scope', scopes);
    url.searchParams.set('state', state);

    console.log('🔐 Starting Meta OAuth:', {
      redirectUri: REDIRECT_URI,
      graphVersion: GRAPH_VERSION,
      scopes
    });

    res.redirect(url.toString());
  } catch (err) {
    console.error('OAuth start error:', err);
    res.redirect(`/?error=${encodeURIComponent(err.message)}`);
  }
});

async function subscribePage(pageId, pageAccessToken) {
  try {
    const result = await graphFetch(`/${pageId}/subscribed_apps`, {
      method: 'POST',
      token: pageAccessToken,
      params: { subscribed_fields: 'messages,messaging_postbacks,feed' }
    });
    console.log(`✅ Page webhook subscribed: ${pageId}`, result);
    return result;
  } catch (err) {
    console.error(`⚠️ Page webhook subscription failed for ${pageId}:`, err.meta || err.message);
    return null;
  }
}

async function subscribeInstagram(igId, pageAccessToken) {
  try {
    const result = await graphFetch(`/${igId}/subscribed_apps`, {
      method: 'POST',
      token: pageAccessToken,
      params: { subscribed_fields: 'comments,messages' }
    });
    console.log(`✅ Instagram webhook subscribed: ${igId}`, result);
    return result;
  } catch (firstErr) {
    console.error(`⚠️ Instagram subscription via graph.facebook.com failed for ${igId}:`, firstErr.meta || firstErr.message);

    try {
      const url = new URL(`https://graph.instagram.com/${GRAPH_VERSION}/${igId}/subscribed_apps`);
      url.searchParams.set('subscribed_fields', 'comments,messages');
      url.searchParams.set('access_token', pageAccessToken);

      const response = await fetch(url, { method: 'POST' });
      const data = await response.json().catch(() => ({}));

      if (!response.ok || data.success === false) {
        throw new Error(data?.error?.message || `HTTP ${response.status}`);
      }

      console.log(`✅ Instagram webhook subscribed via graph.instagram.com: ${igId}`, data);
      return data;
    } catch (secondErr) {
      console.error(`❌ Instagram webhook subscription failed for ${igId}:`, secondErr.message);
      return null;
    }
  }
}

app.get('/api/auth/instagram/callback', async (req, res) => {
  try {
    requireEnv('META_APP_ID', META_APP_ID);
    requireEnv('META_APP_SECRET', META_APP_SECRET);

    const { code, state, error, error_description } = req.query;

    if (error) {
      throw new Error(error_description || error);
    }
    if (!code || !state) throw new Error('Meta did not return an authorization code/state.');

    const stateKey = `oauth_state:${String(state)}`;
    const stateData = safeParse(await redis.get(stateKey));
    await redis.del(stateKey);

    if (!stateData?.userId) {
      throw new Error('OAuth state expired or is invalid. Please try Connect Instagram again.');
    }

    const tokenData = await graphFetch('/oauth/access_token', {
      params: {
        client_id: META_APP_ID,
        redirect_uri: REDIRECT_URI,
        client_secret: META_APP_SECRET,
        code
      }
    });

    const userAccessToken = tokenData.access_token;
    if (!userAccessToken) throw new Error('Meta did not return a user access token.');

    const pagesData = await graphFetch('/me/accounts', {
      token: userAccessToken,
      params: {
        fields: 'id,name,access_token,tasks,instagram_business_account'
      }
    });

    if (!Array.isArray(pagesData.data) || pagesData.data.length === 0) {
      throw new Error(
        'Meta login succeeded, but no Facebook Pages were returned. Make sure the Instagram account is Professional and linked to a Facebook Page.'
      );
    }

    let connected = 0;

    for (const page of pagesData.data) {
      const pageId = page.id;
      const pageToken = page.access_token;

      if (!pageId || !pageToken) continue;

      let igId = page.instagram_business_account?.id;

      if (!igId) {
        try {
          const pageData = await graphFetch(`/${pageId}`, {
            token: userAccessToken,
            params: {
              fields: 'id,name,access_token,instagram_business_account,tasks'
            }
          });
          igId = pageData.instagram_business_account?.id;
        } catch (err) {
          console.error(`Page lookup failed for ${pageId}:`, err.meta || err.message);
        }
      }

      if (!igId) {
        console.log(`ℹ️ Page has no linked Instagram Professional account: ${page.name} (${pageId})`);
        continue;
      }

      const igProfile = await graphFetch(`/${igId}`, {
        token: pageToken,
        params: { fields: 'id,username,name,profile_picture_url' }
      }).catch(err => {
        console.error(`Instagram profile lookup failed for ${igId}:`, err.meta || err.message);
        return {};
      });

      await redis.hset('page_tokens', { [pageId]: pageToken });
      await redis.hset('page_tokens', { [igId]: pageToken });

      await redis.hset(`user_pages:${stateData.userId}`, {
        [pageId]: JSON.stringify({
          pageId,
          pageName: page.name || 'Facebook Page',
          igId,
          igUsername: igProfile.username || '',
          igName: igProfile.name || ''
        })
      });

      await redis.set(`page_owner:${pageId}`, stateData.userId);
      await redis.set(`page_owner:${igId}`, stateData.userId);
      await redis.set(`page_for_ig:${igId}`, pageId);

      console.log(`🔗 Linked Instagram: ${igId} (${igProfile.username || 'unknown'}) → Page ${pageId}`);

      await subscribePage(pageId, pageToken);
      await subscribeInstagram(igId, pageToken);

      connected++;
    }

    if (!connected) {
      throw new Error(
        'Facebook login completed, but no Instagram Professional account was found on the Pages you selected.'
      );
    }

    await redis.set('fallback_user_id', stateData.userId);
    const firstConnectedPage = pagesData.data.find(p => p.instagram_business_account?.id);
    if (firstConnectedPage?.access_token) {
      await redis.set('fallback_token', firstConnectedPage.access_token);
    }

    res.redirect('/?meta_connect=success');
  } catch (err) {
    console.error('❌ OAuth callback error:', {
      message: err.message,
      meta: err.meta || null
    });

    const detail = err.meta?.message || err.message || 'Meta connection failed.';
    res.redirect(`/?error=${encodeURIComponent(detail)}`);
  }
});

// -----------------------------------------------------------------------------
// INSTAGRAM DATA API
// -----------------------------------------------------------------------------

app.get('/api/instagram/accounts', authenticateToken, async (req, res) => {
  try {
    const accountsMap = await redis.hgetall(`user_pages:${req.user.id}`);

    const accounts = Object.entries(accountsMap || {}).map(([pageId, value]) => {
      const parsed = safeParse(value);

      if (parsed) {
        return {
          pageId: parsed.pageId || pageId,
          name: parsed.igUsername
            ? `${parsed.igUsername} · ${parsed.pageName || 'Facebook Page'}`
            : (parsed.pageName || 'Instagram account'),
          igId: parsed.igId || '',
          igUsername: parsed.igUsername || ''
        };
      }

      return {
        pageId,
        name: String(value || 'Instagram account'),
        igId: '',
        igUsername: ''
      };
    });

    res.json({ accounts });
  } catch (err) {
    console.error('Load accounts error:', err);
    res.status(500).json({ error: 'Unable to load connected accounts.' });
  }
});

app.get('/api/instagram/posts', authenticateToken, async (req, res) => {
  try {
    const { pageId } = req.query;
    if (!pageId) return res.status(400).json({ error: 'pageId is required.' });

    const connectionRaw = await redis.hget(`user_pages:${req.user.id}`, pageId);
    const connection = safeParse(connectionRaw);

    const igId = connection?.igId || pageId;
    const token = await redis.hget('page_tokens', pageId);

    if (!token) return res.status(404).json({ error: 'Instagram connection token not found. Reconnect Instagram.' });

    const postsData = await graphFetch(`/${igId}/media`, {
      token,
      params: {
        fields: 'id,caption,media_url,media_type,thumbnail_url,permalink,timestamp',
        limit: 50
      }
    });

    res.json({ posts: postsData.data || [] });
  } catch (err) {
    console.error('Load posts error:', err.meta || err);
    res.status(err.status || 500).json({
      error: err.meta?.message || err.message || 'Unable to load Instagram posts.'
    });
  }
});

// -----------------------------------------------------------------------------
// RULES & AUTOMATIONS
// -----------------------------------------------------------------------------

app.post('/api/rules/post', authenticateToken, async (req, res) => {
  try {
    const { mediaId, keyword, responseText, caption, thumbnail } = req.body || {};

    if (!mediaId || !keyword || !responseText) {
      return res.status(400).json({ error: 'mediaId, keyword and responseText are required.' });
    }

    await redis.hset(`post_rules:${req.user.id}`, {
      [mediaId]: JSON.stringify({
        mediaId,
        keyword: String(keyword).trim(),
        responseText: String(responseText).trim(),
        caption: caption || '',
        thumbnail: thumbnail || ''
      })
    });

    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Unable to save automation.' });
  }
});

app.get('/api/dashboard-data', authenticateToken, async (req, res) => {
  try {
    const postRules = await redis.hgetall(`post_rules:${req.user.id}`);
    const parsedRules = {};

    for (const [key, value] of Object.entries(postRules || {})) {
      const rule = safeParse(value);
      if (rule) parsedRules[key] = rule;
    }

    res.json({ postRules: parsedRules });
  } catch (err) {
    res.status(500).json({ error: 'Unable to load automations.' });
  }
});

app.delete('/api/rules/post/:mediaId', authenticateToken, async (req, res) => {
  try {
    await redis.hdel(`post_rules:${req.user.id}`, req.params.mediaId);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Unable to delete automation.' });
  }
});

// -----------------------------------------------------------------------------
// WEBHOOKS
// -----------------------------------------------------------------------------

app.get('/webhook', (req, res) => {
  const mode = req.query['hub.mode'];
  const token = req.query['hub.verify_token'];
  const challenge = req.query['hub.challenge'];

  if (mode === 'subscribe' && token === VERIFY_TOKEN && challenge) {
    console.log('✅ Meta webhook verification successful');
    return res.status(200).type('text/plain').send(challenge);
  }

  console.error('❌ Meta webhook verification failed');
  return res.sendStatus(403);
});

app.post('/webhook', async (req, res) => {
  res.status(200).send('EVENT_RECEIVED');

  try {
    if (req.body?.object === 'instagram' || req.body?.object === 'page') {
      console.log('📬 WEBHOOK HIT:', req.body?.object);
      await redis.lpush('meta_webhook_queue', JSON.stringify(req.body));
    }
  } catch (err) {
    console.error('Webhook queue error:', err);
  }
});

// -----------------------------------------------------------------------------
// BACKGROUND WORKER
// -----------------------------------------------------------------------------

async function sendInstagramMessage({ igId, token, senderId, commentId, text }) {
  const body = commentId
    ? {
        recipient: { comment_id: commentId },
        message: { text }
      }
    : {
        recipient: { id: senderId },
        message: { text }
      };

  return graphFetch(`/me/messages`, {
    method: 'POST',
    token,
    body
  });
}

function normalizeWebhookEvent(entry, item) {
  if (item.read || item.delivery || item.message_edit) return null;
  
  const msg = item.message || item.value || {};
  if (msg.is_echo) return null;

  if (item.field === 'comments' || item.field === 'live_comments') {
    const value = item.value || {};
    return {
      type: 'comment',
      commentId: value.id,
      text: value.text || '',
      mediaId: value.media?.id || null,
      senderId: value.from?.id || null,
      senderUsername: value.from?.username || null
    };
  }

  if (item.sender && item.message) {
    return {
      type: 'message',
      senderId: item.sender.id,
      text: item.message.text || '',
      messageId: item.message.mid || item.message.id || null
    };
  }

  return null;
}

async function processWebhookPayload(payload) {
  if (!payload || !Array.isArray(payload.entry)) return;

  for (const entry of payload.entry) {
    const igId = entry.id;
    if (!igId) continue;

    const userId =
      await redis.get(`page_owner:${igId}`) ||
      await redis.get('fallback_user_id');

    const token =
      await redis.hget('page_tokens', igId) ||
      await redis.get('fallback_token');

    if (!userId || !token) {
      console.warn('⚠️ No Cloudflow owner/token for webhook entry:', igId);
      continue;
    }

    const rulesMap = await redis.hgetall(`post_rules:${userId}`);
    const rules = Object.values(rulesMap || {})
      .map(safeParse)
      .filter(Boolean);

    const events = [];

    for (const item of entry.messaging || []) {
      const event = normalizeWebhookEvent(entry, item);
      if (event) events.push(event);
    }

    for (const item of entry.changes || []) {
      const event = normalizeWebhookEvent(event, item);
      if (event) events.push(event);
    }

    for (const event of events) {
      const text = String(event.text || '').trim();
      if (!text) continue;

      console.log(
        `💬 ${event.type.toUpperCase()} | IG=${igId} | ` +
        `media=${event.mediaId || '-'} | comment=${event.commentId || '-'} | ` +
        `sender=${event.senderId || event.senderUsername || '-'} | text="${text}"`
      );

      const upperText = text.toUpperCase();

      for (const rule of rules) {
        const keyword = String(rule.keyword || '').trim().toUpperCase();
        if (!keyword) continue;

        if (event.type === 'comment' && rule.mediaId !== event.mediaId) {
          continue;
        }

        if (!upperText.includes(keyword)) continue;

        console.log(`🎯 MATCH | rule=${rule.mediaId} | keyword=${keyword}`);

        try {
          const result = await sendInstagramMessage({
            igId,
            token,
            senderId: event.senderId,
            commentId: event.type === 'comment' ? event.commentId : null,
            text: rule.responseText
          });

          console.log(`✅ META SEND SUCCESS: ${JSON.stringify(result)}`);
        } catch (err) {
          console.error('❌ META SEND FAILED:', {
            message: err.message,
            meta: err.meta || null,
            event
          });
        }
      }
    }
  }
}

async function worker() {
  console.log('👷 Cloudflow Meta worker active...');

  while (true) {
    try {
      const raw = await redis.rpop('meta_webhook_queue');

      if (!raw) {
        await new Promise(resolve => setTimeout(resolve, 1000));
        continue;
      }

      const payload = typeof raw === 'string' ? JSON.parse(raw) : raw;
      await processWebhookPayload(payload);
    } catch (err) {
      console.error('Worker critical error:', err);
      await new Promise(resolve => setTimeout(resolve, 3000));
    }
  }
}

// -----------------------------------------------------------------------------
// START
// -----------------------------------------------------------------------------

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Cloudflow listening on 0.0.0.0:${PORT}`);
  console.log(`🌐 Public base URL: ${PUBLIC_BASE_URL}`);
  console.log(`🔗 Meta redirect URI: ${REDIRECT_URI}`);
  console.log(`📡 Graph API version: ${GRAPH_VERSION}`);
  worker();
});
