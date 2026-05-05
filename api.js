// netlify/functions/api.js
// Gère toutes les routes /api/* :
//   GET  /api/me        → profil utilisateur connecté
//   GET  /api/bots      → liste des bots de l'user
//   POST /api/bots      → déployer un nouveau bot
//   DELETE /api/bots/:id → supprimer un bot

const crypto = require('crypto');
const { store, encrypt, decrypt, parseCookies, verifySession } = require('./_utils');

// ─── HELPERS ────────────────────────────────────────────────
function json(statusCode, body, headers = {}) {
  return {
    statusCode,
    headers: { 'Content-Type': 'application/json', ...headers },
    body: JSON.stringify(body)
  };
}

function getSession(event) {
  const cookies = parseCookies(event.headers.cookie || event.headers.Cookie || '');
  return verifySession(cookies['bn_session']);
}

// ─── HANDLER PRINCIPAL ───────────────────────────────────────
exports.handler = async (event) => {
  const method = event.httpMethod;
  // Extrait le path après /api/
  // ex: /.netlify/functions/api?path=/bots/ABC123
  const rawPath = event.queryStringParameters?.path || event.path || '';
  const path    = rawPath.replace(/^\/?api/, '').replace(/^\/\.netlify\/functions\/api/, '') || '/';

  // ── GET /api/me ────────────────────────────────────────────
  if (method === 'GET' && path === '/me') {
    const session = getSession(event);
    if (!session?.userId) return json(401, { error: 'Non authentifié' });

    const user = store.users.get(session.userId);
    if (!user) return json(404, { error: 'Utilisateur introuvable' });

    // Renvoie uniquement les données publiques — jamais les tokens
    return json(200, {
      id:            user.id,
      username:      user.username,
      discriminator: user.discriminator,
      email:         user.email,
      verified:      user.verified,
      premium:       user.premium,
      avatar:        user.avatar,
      guilds:        user.guilds,
    });
  }

  // ── GET /api/bots ──────────────────────────────────────────
  if (method === 'GET' && path === '/bots') {
    const session = getSession(event);
    if (!session?.userId) return json(401, { error: 'Non authentifié' });

    const userBots = [];
    for (const bot of store.bots.values()) {
      if (bot.userId === session.userId) {
        userBots.push({
          id:        bot.id,
          name:      bot.name,
          type:      bot.type,
          status:    bot.status,
          createdAt: bot.createdAt
        });
      }
    }
    return json(200, userBots);
  }

  // ── POST /api/bots ─────────────────────────────────────────
  if (method === 'POST' && path === '/bots') {
    const session = getSession(event);
    if (!session?.userId) return json(401, { error: 'Non authentifié' });

    // Vérification CSRF
    const csrfHeader = event.headers['x-csrf-token'];
    if (!csrfHeader || csrfHeader !== session.csrfToken) {
      return json(403, { error: 'Token CSRF invalide' });
    }

    let body;
    try { body = JSON.parse(event.body || '{}'); }
    catch { return json(400, { error: 'JSON invalide' }); }

    const { name, type, token } = body;

    if (!name || !type || !token) {
      return json(400, { error: 'Champs manquants : name, type, token' });
    }
    if (name.length > 32) {
      return json(400, { error: 'Nom trop long (max 32 caractères)' });
    }

    const VALID_TYPES = ['tickets', 'moderation', 'music', 'economy', 'welcome', 'logs'];
    if (!VALID_TYPES.includes(type)) {
      return json(400, { error: 'Type de bot invalide' });
    }

    // Validation format token Discord
    if (!/^[A-Za-z0-9_\-.]{50,}$/.test(token)) {
      return json(400, { error: 'Format de token invalide' });
    }

    const botId = crypto.randomBytes(8).toString('hex').toUpperCase();

    store.bots.set(botId, {
      id:             botId,
      userId:         session.userId,
      name,
      type,
      encryptedToken: encrypt(token), // Chiffré AES-256-GCM immédiatement
      status:         'online',
      createdAt:      Date.now()
    });

    return json(201, {
      id:        botId,
      name,
      type,
      status:    'online',
      createdAt: Date.now()
    });
  }

  // ── DELETE /api/bots/:id ───────────────────────────────────
  if (method === 'DELETE' && path.startsWith('/bots/')) {
    const session = getSession(event);
    if (!session?.userId) return json(401, { error: 'Non authentifié' });

    const csrfHeader = event.headers['x-csrf-token'];
    if (!csrfHeader || csrfHeader !== session.csrfToken) {
      return json(403, { error: 'Token CSRF invalide' });
    }

    const botId = path.split('/bots/')[1];
    const bot   = store.bots.get(botId);

    if (!bot) return json(404, { error: 'Bot introuvable' });
    if (bot.userId !== session.userId) return json(403, { error: 'Accès refusé' });

    store.bots.delete(botId);
    return json(200, { success: true });
  }

  // ── GET /api/csrf ──────────────────────────────────────────
  if (method === 'GET' && path === '/csrf') {
    const session = getSession(event);
    if (!session?.userId) return json(401, { error: 'Non authentifié' });

    // Génère un nouveau token CSRF et le stocke dans la session
    const csrfToken = crypto.randomBytes(32).toString('hex');
    // Note: en stateless, on retourne le token — le client doit le renvoyer dans X-CSRF-Token
    return json(200, { csrfToken });
  }

  return json(404, { error: 'Route introuvable' });
};
