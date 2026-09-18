
Server fixed v2 · TXT

require('dotenv').config();

const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const cors = require('cors');
const { Redis } = require('@upstash/redis');

const app = express();

app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// =============================================================================
// REDIS
// =============================================================================

const redis = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL,
  token: process.env.UPSTASH_REDIS_REST_TOKEN
});

// =============================================================================
// CONFIG
// =============================================================================

const PORT = process.env.PORT || 10000;

const GRAPH_VERSION = process.env.META_GRAPH_VERSION || 'v26.0';

const PUBLIC_BASE_URL = (
  process.env.PUBLIC_BASE_URL || 'https://cloudflow-app.onrender.com'
).replace(/\/$/, '');

const REDIRECT_URI =
  process.env.META_REDIRECT_URI || `${PUBLIC_BASE_URL}/api/auth/instagram/callback`;

const VERIFY_TOKEN = (process.env.VERIFY_TOKEN || 'my_secret_token_123').trim();

const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_jwt_key_99';

if (!process.env.VERIFY_TOKEN || !process.env.JWT_SECRET) {
  console.warn(
    '⚠️ SECURITY: VERIFY_TOKEN and/or JWT_SECRET are not set in the environment — ' +
    'using hardcoded fallback values. Set both as real env vars on Render before going live; ' +
    'anyone who reads this repo can currently forge webhook verification and login sessions.'
  );
}

const META_APP_ID = process.env.META_APP_ID;
const META_APP_SECRET = process.env.META_APP_SECRET;

const FALLBACK_PAGE_TOKEN = process.env.FACEBOOK_PAGE_ACCESS_TOKEN;

const GRAPH_BASE = `https://graph.facebook.com/${GRAPH_VERSION}`;

// =============================================================================
// HELPERS
// =============================================================================

const safeParse = (val) => {
  if (!val) return null;
  if (typeof val === 'object') return val;
  try {
    return JSON.parse(val);
  } catch {
    return null;
  }
};

function requireEnv(name, value) {
  if (!value) {
    throw new Error(`${name} is not configured`);
  }
}

function graphUrl(pathname, params = {}) {
  const pathValue = pathname.startsWith('/') ? pathname : `/${pathname}`;
  const url = new URL(`${GRAPH_BASE}${pathValue}`);

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

  if (body !== undefined) {
    headers['Content-Type'] = 'application/json';
  }

  if (token) {
    headers.Authorization = `Bearer ${token}`;
  }

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

// =============================================================================
// AUTH MIDDLEWARE
// =============================================================================

function authenticateToken(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ')
    ? authHeader.slice(7)
    : (req.query.token || null);

  if (!token || token === 'undefined') {
    return res.status(401).json({ error: 'Authentication required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired session' });
    }
    req.user = user;
    next();
  });
}

// =============================================================================
// HEALTH / DEBUG
// =============================================================================

app.get('/health', (req, res) => {
  res.status(200).send('OK');
});

app.get('/api/debug/status', async (req, res) => {
  try {
    const fallbackUser = await redis.get('fallback_user_id');
    const rules = fallbackUser
      ? await redis.hgetall(`post_rules:${fallbackUser}`)
      : {};

    res.json({
      status: 'Online',
      graphVersion: GRAPH_VERSION,
      appIdConfigured: Boolean(META_APP_ID),
      appSecretConfigured: Boolean(META_APP_SECRET),
      redirectUri: REDIRECT_URI,
      webhookConfigured: Boolean(VERIFY_TOKEN),
      envPageTokenConfigured: Boolean(FALLBACK_PAGE_TOKEN),
      fallbackUser,
      rulesCount: Object.keys(rules || {}).length
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// =============================================================================
// SIGNUP & LOGIN & ACCOUNT MANAGEMENT
// =============================================================================

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
    if (existing) {
      return res.status(409).json({ error: 'An account with that email already exists.' });
    }

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

    res.json({
      success: true,
      token,
      user: { id: userId, email: normalizedEmail }
    });
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
    if (!userStr) {
      return res.status(400).json({ error: 'User not found' });
    }

    const user = safeParse(userStr);
    if (!user || !(await bcrypt.compare(String(password || ''), user.password))) {
      return res.status(400).json({ error: 'Wrong password' });
    }

    const token = jwt.sign({ id: user.id, email: normalizedEmail }, JWT_SECRET, { expiresIn: '7d' });

    res.json({
      token,
      user: { id: user.id, email: normalizedEmail }
    });
  } catch (err) {
    console.error('Login error:', err);
    res.status(500).json({ error: 'Login failed.' });
  }
});

// ✅ FIX #4: MISSING PASSWORD UPDATE ENDPOINT
app.post('/api/user/settings', authenticateToken, async (req, res) => {
  try {
    const { newPassword } = req.body || {};

    if (!newPassword || String(newPassword).length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters.' });
    }

    const lowerEmail = req.user.email ? req.user.email.toLowerCase() : null;
    if (!lowerEmail) {
      return res.status(400).json({ error: 'User email not found in session.' });
    }

    const userStr = await redis.hget('users', lowerEmail);
    const user = safeParse(userStr);
    if (!user) {
      return res.status(404).json({ error: 'User not found.' });
    }

    user.password = await bcrypt.hash(String(newPassword), 10);
    await redis.hset('users', { [lowerEmail]: JSON.stringify(user) });

    res.json({ success: true, message: 'Password updated.' });
  } catch (err) {
    console.error('Update password error:', err);
    res.status(500).json({ error: 'Unable to update password.' });
  }
});

app.delete('/api/user/account', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const lowerEmail = req.user.email ? req.user.email.toLowerCase() : null;

    if (lowerEmail) {
      await redis.hdel('users', lowerEmail);
    }

    await redis.del(`user_pages:${userId}`);
    await redis.del(`post_rules:${userId}`);

    console.log(`🗑️ Account deleted: ${userId}`);
    res.json({ success: true, message: 'Account deleted successfully.' });
  } catch (err) {
    res.status(500).json({ error: 'Unable to delete account.' });
  }
});

// =============================================================================
// META OAUTH
// =============================================================================

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

    console.log('🔐 Starting Meta OAuth:', { redirectUri: REDIRECT_URI, graphVersion: GRAPH_VERSION, scopes });

    res.redirect(url.toString());
  } catch (err) {
    console.error('OAuth start error:', err);
    res.redirect(`/?error=${encodeURIComponent(err.message)}`);
  }
});

// ✅ FIX #3: SEND subscribed_fields IN POST BODY (was query param — could silently fail)
// ✅ FIX #6 (CRITICAL): 'comments' was missing from subscribed_fields.
// This was the actual cause of "DM works, comment doesn't": Meta was never told to
// deliver comment webhooks for this page/IG account, regardless of tester status or
// token scopes — subscribed_fields controls what Meta actually sends per connected
// account, on top of (not instead of) the app-level Webhooks product config in the
// App Dashboard, which must ALSO have 'comments' enabled under the Instagram object.
async function subscribePage(pageId, pageAccessToken) {
  try {
    const result = await graphFetch(`/${pageId}/subscribed_apps`, {
      method: 'POST',
      token: pageAccessToken,
      body: {
        subscribed_fields: 'messages,messaging_postbacks,messaging_optins,comments'
      }
    });
    console.log(`✅ Page webhook subscribed: ${pageId}`, result);
    return result;
  } catch (err) {
    console.error(`⚠️ Page webhook subscription failed for ${pageId}:`, err.meta || err.message);
    return null;
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

    if (!code || !state) {
      throw new Error('Meta did not return an authorization code/state.');
    }

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
    if (!userAccessToken) {
      throw new Error('Meta did not return a user access token.');
    }

    const pagesData = await graphFetch('/me/accounts', {
      token: userAccessToken,
      params: { fields: 'id,name,access_token,instagram_business_account' }
    });

    if (!Array.isArray(pagesData.data) || pagesData.data.length === 0) {
      throw new Error(
        'Meta login succeeded, but no Facebook Pages were returned. Make sure the Instagram account is Professional and linked to a Facebook Page.'
      );
    }

    let connected = 0;
    let firstPageToken = null;

    for (const page of pagesData.data) {
      const pageId = page.id;
      const pageToken = page.access_token;

      if (!pageId || !pageToken) continue;

      let igId = page.instagram_business_account?.id;

      if (!igId) {
        try {
          const pageData = await graphFetch(`/${pageId}`, {
            token: userAccessToken,
            params: { fields: 'id,name,access_token,instagram_business_account' }
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

      console.log(`🔗 Linked Instagram: ${igId} (${igProfile.username || 'unknown'}) → Page ${pageId}`);

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
      await redis.set(`ig_for_page:${pageId}`, igId);

      await subscribePage(pageId, pageToken);

      if (!firstPageToken) firstPageToken = pageToken;
      connected++;
    }

    if (!connected) {
      throw new Error(
        'Facebook login completed, but no Instagram Professional account was found on the Pages you selected.'
      );
    }

    await redis.set('fallback_user_id', stateData.userId);
    if (firstPageToken) {
      await redis.set('fallback_token', firstPageToken);
    }

    console.log(`✅ Meta connection completed. Instagram accounts connected: ${connected}`);
    res.redirect('/?meta_connect=success');

  } catch (err) {
    console.error('❌ OAuth callback error:', { message: err.message, meta: err.meta || null });
    const detail = err.meta?.message || err.message || 'Meta connection failed.';
    res.redirect(`/?error=${encodeURIComponent(detail)}`);
  }
});

// =============================================================================
// INSTAGRAM ACCOUNTS & POSTS
// =============================================================================

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

// ✅ FIX #6: Re-subscribe already-connected pages to the corrected field list
// (including 'comments') WITHOUT forcing a full Instagram disconnect/reconnect.
// subscribePage() only ever ran once, at the moment of the original OAuth callback —
// any account connected before this fix has a stale subscription on Meta's side.
// Hit this once per connected account after deploying the fix.
app.post('/api/debug/resubscribe', authenticateToken, async (req, res) => {
  try {
    const accountsMap = await redis.hgetall(`user_pages:${req.user.id}`);
    const results = [];

    for (const [pageId, value] of Object.entries(accountsMap || {})) {
      const parsed = safeParse(value);
      const token = (await redis.hget('page_tokens', pageId)) || FALLBACK_PAGE_TOKEN;

      if (!token) {
        results.push({ pageId, igId: parsed?.igId, ok: false, error: 'No stored page token' });
        continue;
      }

      const result = await subscribePage(pageId, token);
      results.push({ pageId, igId: parsed?.igId, ok: Boolean(result), meta: result || null });
    }

    res.json({ results });
  } catch (err) {
    console.error('Resubscribe error:', err);
    res.status(500).json({ error: err.message });
  }
});

// ✅ FIX #1: STORE MEDIA OWNER MAPPING WHEN LOADING POSTS
app.get('/api/instagram/posts', authenticateToken, async (req, res) => {
  try {
    const { pageId } = req.query;
    if (!pageId) return res.status(400).json({ error: 'pageId is required.' });

    const connectionRaw = await redis.hget(`user_pages:${req.user.id}`, pageId);
    const connection = safeParse(connectionRaw);

    const igId = connection?.igId || pageId;
    const token = (await redis.hget('page_tokens', pageId)) || FALLBACK_PAGE_TOKEN;

    if (!token) {
      return res.status(404).json({ error: 'Instagram connection token not found. Reconnect Instagram.' });
    }

    const postsData = await graphFetch(`/${igId}/media`, {
      token,
      params: {
        fields: 'id,caption,media_url,media_type,thumbnail_url,permalink,timestamp',
        limit: 50
      }
    });

    // ✅ NEW: Store mapping so we know which IG account owns each media ID
    for (const post of postsData.data || []) {
      await redis.set(`media_owner:${post.id}`, igId, { ex: 86400 * 30 });
    }

    res.json({ posts: postsData.data || [] });
  } catch (err) {
    console.error('Load posts error:', err.meta || err);
    res.status(err.status || 500).json({
      error: err.meta?.message || err.message || 'Unable to load Instagram posts.'
    });
  }
});

// =============================================================================
// RULES & AUTOMATIONS
// =============================================================================

app.post('/api/rules/post', authenticateToken, async (req, res) => {
  try {
    const { mediaId, keyword, responseText, caption, thumbnail } = req.body || {};

    if (!mediaId || !keyword || !responseText) {
      return res.status(400).json({ error: 'mediaId, keyword and responseText are required.' });
    }

    const rule = {
      mediaId: String(mediaId),
      keyword: String(keyword).trim(),
      responseText: String(responseText).trim(),
      caption: caption || '',
      thumbnail: thumbnail || ''
    };

    await redis.hset(`post_rules:${req.user.id}`, {
      [String(mediaId)]: JSON.stringify(rule)
    });

    console.log(`✅ Automation saved | user=${req.user.id} | media=${mediaId} | keyword=${keyword}`);
    res.json({ success: true });
  } catch (err) {
    console.error('Save rule error:', err);
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

// =============================================================================
// WEBHOOK VERIFICATION & RECEIVER
// =============================================================================

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
    console.log('\n==============================================');
    console.log('📬 WEBHOOK HIT:', req.body?.object);
    console.log('📦 FULL WEBHOOK BODY:');
    console.log(JSON.stringify(req.body, null, 2));
    console.log('==============================================\n');

    if (req.body?.object === 'instagram' || req.body?.object === 'page') {
      await redis.lpush('meta_webhook_queue', JSON.stringify(req.body));
    }
  } catch (err) {
    console.error('Webhook queue error:', err);
  }
});

// =============================================================================
// SEND INSTAGRAM MESSAGE / PRIVATE REPLY
// =============================================================================

async function sendInstagramMessage({ igId, token, senderId, commentId, text }) {
  let body;

  if (commentId) {
    body = {
      recipient: { comment_id: String(commentId) },
      message: { text: String(text) }
    };
    console.log(`📨 Sending PRIVATE REPLY | IG=${igId} | comment=${commentId}`);
  } else {
    if (!senderId) {
      throw new Error('Cannot send normal Instagram DM because senderId is missing.');
    }
    body = {
      recipient: { id: String(senderId) },
      message: { text: String(text) }
    };
    console.log(`📨 Sending normal Instagram DM | IG=${igId} | recipient=${senderId}`);
  }

  return graphFetch(`/${igId}/messages`, {
    method: 'POST',
    token,
    body
  });
}

// =============================================================================
// ✅ FIX #2: RESOLVE FACEBOOK POST ID → INSTAGRAM MEDIA ID
// =============================================================================

async function resolveMediaId(fbPostId, token) {
  if (!fbPostId) return null;

  // No underscore = likely already an IG media ID
  if (!fbPostId.includes('_')) return fbPostId;

  // Check Redis cache first
  const cached = await redis.get(`fb_to_ig:${fbPostId}`);
  if (cached) {
    console.log(`📎 Cache hit: FB ${fbPostId} → IG ${cached}`);
    return cached;
  }

  // Try Graph API lookup
  try {
    const data = await graphFetch(`/${fbPostId}`, {
      token,
      params: { fields: 'instagram_media_id' }
    });

    if (data.instagram_media_id) {
      await redis.set(`fb_to_ig:${fbPostId}`, data.instagram_media_id, { ex: 86400 * 30 });
      console.log(`🔄 Resolved: FB ${fbPostId} → IG ${data.instagram_media_id}`);
      return data.instagram_media_id;
    }
  } catch (err) {
    console.warn(`⚠️ Could not resolve FB post ${fbPostId}:`, err.message);
  }

  return null;
}

// =============================================================================
// NORMALIZE WEBHOOK EVENTS
// =============================================================================

function normalizeWebhookEvent(entry, item) {
  if (!item) return null;

  if (item.read || item.delivery || item.message_edit) return null;

  // 1. INSTAGRAM COMMENT (entry.changes with field=comments)
  if (item.field === 'comments' || item.field === 'live_comments') {
    const value = item.value || {};
    return {
      type: 'comment',
      commentId: value.id || value.comment_id || null,
      text: value.text || value.message || '',
      mediaId: value.media?.id || value.media_id || null,
      fbPostId: null,
      senderId: value.from?.id || null,
      senderUsername: value.from?.username || null
    };
  }

  // ✅ FIX #2: PAGE FEED COMMENT
  // BEFORE: mediaId used value.post_id as fallback — this is a Facebook-format ID
  //         (e.g. "123456_789012") that NEVER matches IG media IDs in your rules.
  // AFTER:  Store fbPostId separately, resolve it to IG media ID in processWebhookPayload.
  if (item.field === 'feed') {
    const value = item.value || {};
    if (value.item && value.item !== 'comment') return null;

    return {
      type: 'comment',
      commentId: value.comment_id || value.id || null,
      text: value.message || value.text || '',
      mediaId: value.media?.id || null,
      fbPostId: value.post_id || null,
      senderId: value.from?.id || value.sender_id || null,
      senderUsername: value.from?.username || null
    };
  }

  // 3. MESSAGING OPT-INS
  if (item.optin || item.messaging_optins) {
    const optin = item.optin || item.messaging_optins || {};
    return {
      type: 'message',
      senderId: item.sender?.id || null,
      text: optin.payload || optin.ref || optin.user_ref || 'POST_TRIGGER',
      messageId: null,
      mediaId: null,
      fbPostId: null,
      commentId: null
    };
  }

  // 4. POSTBACK BUTTON CLICKS
  if (item.postback) {
    return {
      type: 'message',
      senderId: item.sender?.id || null,
      text: item.postback.payload || item.postback.title || '',
      messageId: null,
      mediaId: null,
      fbPostId: null,
      commentId: null
    };
  }

  // 5. STANDARD INSTAGRAM DM
  if (item.sender && item.message) {
    if (item.message.is_echo) return null;

    return {
      type: 'message',
      senderId: item.sender.id,
      text: item.message.text || '',
      messageId: item.message.mid || item.message.id || null,
      mediaId: null,
      fbPostId: null,
      commentId: null
    };
  }

  return null;
}

// =============================================================================
// PROCESS WEBHOOK PAYLOAD
// =============================================================================

async function processWebhookPayload(payload) {
  if (!payload || !Array.isArray(payload.entry)) return;

  for (const entry of payload.entry) {
    const entryId = String(entry.id || '');
    if (!entryId) continue;

    const mappedInstagramId = await redis.get(`ig_for_page:${entryId}`);
    const igId = mappedInstagramId || entryId;

    console.log(`🔎 Processing webhook entry | entryId=${entryId} | resolvedIG=${igId}`);

    const userId =
      (await redis.get(`page_owner:${igId}`)) ||
      (await redis.get(`page_owner:${entryId}`)) ||
      (await redis.get('fallback_user_id'));

    const token =
      (await redis.hget('page_tokens', igId)) ||
      (await redis.hget('page_tokens', entryId)) ||
      (await redis.get('fallback_token')) ||
      FALLBACK_PAGE_TOKEN;

    if (!userId || !token) {
      console.warn(`⚠️ No Cloudflow owner/token for webhook entry=${entryId}, ig=${igId}`);
      continue;
    }

    const rulesMap = await redis.hgetall(`post_rules:${userId}`);
    const rules = Object.values(rulesMap || {})
      .map(safeParse)
      .filter(Boolean);

    console.log(`📋 Loaded ${rules.length} automation rule(s) for user ${userId}`);

    const events = [];

    // Note: removed a dead check here that looked for `entry.field` — real Meta
    // payloads never put `field` on entry itself, only inside entry.changes[].field
    // (handled by the loop below). The old check could never match anything.

    for (const item of entry.messaging || []) {
      const event = normalizeWebhookEvent(entry, item);
      if (event) events.push(event);
    }

    for (const item of entry.changes || []) {
      const event = normalizeWebhookEvent(entry, item);
      if (event) events.push(event);
    }

    console.log(`📥 Normalized events: ${events.length}`);

    for (const event of events) {
      const text = String(event.text || '').trim();

      if (!text) {
        console.log('ℹ️ Event ignored because it contains no text.');
        continue;
      }

      // ✅ FIX #5: DEDUPLICATION — Prevent duplicate DMs on webhook retries
      const dedupKey = event.commentId
        ? `dedup:comment:${event.commentId}`
        : (event.messageId ? `dedup:msg:${event.messageId}` : null);

      if (dedupKey) {
        const alreadyProcessed = await redis.get(dedupKey);
        if (alreadyProcessed) {
          console.log(`♻️ Skipping duplicate event: ${dedupKey}`);
          continue;
        }
      }

      // ✅ FIX #2: RESOLVE FB POST ID → IG MEDIA ID BEFORE RULE MATCHING
      if (event.type === 'comment' && !event.mediaId && event.fbPostId) {
        const resolved = await resolveMediaId(event.fbPostId, token);
        if (resolved) {
          event.mediaId = resolved;
          console.log(`🔄 Resolved media ID for comment: ${event.fbPostId} → ${resolved}`);
        } else {
          console.warn(`⚠️ Could not resolve media ID for FB post: ${event.fbPostId}`);
        }
      }

      console.log(
        `💬 ${event.type.toUpperCase()} | ` +
        `IG=${igId} | ` +
        `media=${event.mediaId || '-'} | ` +
        `fbPost=${event.fbPostId || '-'} | ` +
        `comment=${event.commentId || '-'} | ` +
        `sender=${event.senderId || event.senderUsername || '-'} | ` +
        `text="${text}"`
      );

      const upperText = text.toUpperCase();

      for (const rule of rules) {
        const keyword = String(rule.keyword || '').trim().toUpperCase();
        if (!keyword) continue;

        // Media ID matching for comments
        if (event.type === 'comment' && rule.mediaId && event.mediaId) {
          if (String(rule.mediaId) !== String(event.mediaId)) {
            console.log(`⏭️ Post mismatch | rule media=${rule.mediaId} | event media=${event.mediaId}`);
            continue;
          }
        }

        // If media ID couldn't be resolved, allow keyword-only match with warning
        if (event.type === 'comment' && rule.mediaId && !event.mediaId) {
          console.warn(`⚠️ No media ID on event — matching by keyword only for rule ${rule.mediaId}`);
        }

        if (!upperText.includes(keyword)) continue;

        console.log(`🎯 MATCH | type=${event.type} | media=${rule.mediaId} | keyword=${keyword}`);

        if (event.type === 'comment' && !event.commentId) {
          console.error('❌ Comment matched, but Meta webhook did not contain a comment ID.');
          continue;
        }

        try {
          const result = await sendInstagramMessage({
            igId,
            token,
            senderId: event.senderId,
            commentId: event.type === 'comment' ? event.commentId : null,
            text: rule.responseText
          });

          console.log('✅ META SEND SUCCESS:', JSON.stringify(result));

          // ✅ FIX #5: Mark as processed (24hr TTL)
          if (dedupKey) {
            await redis.set(dedupKey, '1', { ex: 86400 });
          }
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

// =============================================================================
// WORKER LOOP
// =============================================================================

async function worker() {
  console.log('👷 Cloudflow Meta worker active...');

  while (true) {
    try {
      const raw = await redis.rpop('meta_webhook_queue');

      if (!raw) {
        await new Promise((resolve) => setTimeout(resolve, 1000));
        continue;
      }

      const payload = typeof raw === 'string' ? JSON.parse(raw) : raw;
      await processWebhookPayload(payload);
    } catch (err) {
      console.error('Worker critical error:', err);
      await new Promise((resolve) => setTimeout(resolve, 3000));
    }
  }
}

// =============================================================================
// START SERVER
// =============================================================================

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Cloudflow listening on 0.0.0.0:${PORT}`);
  console.log(`🌐 Public base URL: ${PUBLIC_BASE_URL}`);
  console.log(`🔗 Meta redirect URI: ${REDIRECT_URI}`);
  console.log(`📡 Graph API version: ${GRAPH_VERSION}`);

  worker();
});
 
