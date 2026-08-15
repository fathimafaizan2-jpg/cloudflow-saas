require('dotenv').config();
const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Redis } = require('@upstash/redis');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const APP_ID = (process.env.META_APP_ID || '').trim();
const redis = new Redis({
  url: process.env.UPSTASH_REDIS_REST_URL,
  token: process.env.UPSTASH_REDIS_REST_TOKEN,
});

const PORT = process.env.PORT || 10000;
const VERIFY_TOKEN = (process.env.VERIFY_TOKEN || 'my_secret_token_123').trim();
const JWT_SECRET = process.env.JWT_SECRET || 'super_secret_jwt_key_99';

// --- OAUTH & SUBSCRIPTION ---
app.get('/api/auth/instagram', (req, res) => {
  const { token } = req.query;
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const state = Buffer.from(JSON.stringify({ userId: decoded.id, token })).toString('base64');
    
    // --- ADDED pages_messaging TO THE SCOPE ---
    const scope = [
      'instagram_basic',
      'instagram_manage_comments',
      'instagram_manage_messages',
      'pages_show_list',
      'pages_read_engagement',
      'pages_manage_metadata',
      'pages_messaging', // <--- THIS IS THE FIX
      'business_management'
    ].join(',');
    
    const oauthUrl = `https://www.facebook.com/v19.0/dialog/oauth?client_id=${APP_ID}&redirect_uri=${encodeURIComponent(`https://${req.get('host')}/api/auth/instagram/callback`)}&scope=${scope}&state=${state}`;
    res.redirect(oauthUrl);
  } catch (err) { res.redirect('/?error=auth_init_failed'); }
});

app.get('/api/auth/instagram/callback', async (req, res) => {
  try {
    const { code, state } = req.query;
    const { userId, token: userJwtToken } = JSON.parse(Buffer.from(state, 'base64').toString('utf-8'));
    
    const tokenUrl = `https://graph.facebook.com/v19.0/oauth/access_token?client_id=${APP_ID}&redirect_uri=${encodeURIComponent(`https://${req.get('host')}/api/auth/instagram/callback`)}&client_secret=${process.env.META_APP_SECRET.trim()}&code=${code}`;
    
    const tokenRes = await fetch(tokenUrl);
    const tokenData = await tokenRes.json();
    
    if (tokenData.error) throw new Error(tokenData.error.message);

    const pagesRes = await fetch(`https://graph.facebook.com/v19.0/me/accounts?access_token=${tokenData.access_token}`);
    const pagesData = await pagesRes.json();

    for (const page of pagesData.data || []) {
      const igRes = await fetch(`https://graph.facebook.com/v19.0/${page.id}?fields=instagram_business_account&access_token=${page.access_token}`);
      const igData = await igRes.json();
      const igId = igData.instagram_business_account?.id;
      
      await redis.hset('page_tokens', { [page.id]: page.access_token });
      await redis.set(`page_owner:${page.id}`, userId);
      await redis.hset(`user_pages:${userId}`, { [page.id]: page.name });
      
      if (igId) {
        await redis.hset('page_tokens', { [igId]: page.access_token });
        await redis.set(`page_owner:${igId}`, userId);
        console.log(`🔗 Linked IG: ${igId} to User: ${userId}`);
      }
      
      // --- SIMPLIFIED SUBSCRIPTION TO AVOID ERROR ---
      const subRes = await fetch(`https://graph.facebook.com/v19.0/${page.id}/subscribed_apps?subscribed_fields=feed&access_token=${page.access_token}`, { method: 'POST' });
      const subData = await subRes.json();
      console.log(`📡 Subscription Result for Page ${page.name}:`, subData);
    }
    res.redirect(`/?meta_connect=success&token=${userJwtToken}`);
  } catch (err) { 
    console.error('OAuth Callback Error:', err.message);
    res.redirect('/?error=oauth_failed'); 
  }
});

// ... (Rest of your code remains the same)
app.listen(PORT, () => { console.log(`🚀 Server on ${PORT}`); });
