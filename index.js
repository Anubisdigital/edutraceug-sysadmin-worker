/**
 * Worker: edutraceug-sysadmin-worker
 * Base URL: https://edutraceug-sysadmin-worker.anubisdigital114-9df.workers.dev
 *
 * Auth: email + password checked against two Cloudflare secrets.
 *   ADMIN_LOGIN_EMAIL
 *   ADMIN_LOGIN_PASSWORD
 *
 * Session: signed JWT (HMAC-SHA256) with an expiry, issued by /auth/login.
 *   SESSION_SECRET must also be set as a secret.
 *
 * Other env vars:
 *   ACCOUNT-SERVICE-FIREBASE
 *   RESEND_API_KEY
 */

const SESSION_TTL_HOURS = 24 * 7; // 7 days

/* ================================================================== *
 * HELPERS & UTILS
 * ================================================================== */

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    },
  });
}

function handleOptions() {
  return new Response(null, {
    status: 204,
    headers: {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    },
  });
}

const esc = (s) =>
  String(s ?? '').replace(
    /[&<>"']/g,
    (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])
  );

async function safeFetchJson(url, options = {}) {
  const res = await fetch(url, options);
  const contentType = res.headers.get('content-type') || '';
  const bodyText = await res.text();

  if (
    contentType.includes('text/html') ||
    bodyText.trim().startsWith('<!DOCTYPE') ||
    bodyText.trim().startsWith('<html')
  ) {
    throw new Error(`Upstream returned HTML response (${res.status}) instead of JSON from ${url}`);
  }

  let data;
  try {
    data = JSON.parse(bodyText);
  } catch (err) {
    throw new Error(`Failed to parse JSON response (${res.status}): ${bodyText.slice(0, 100)}`);
  }

  return { status: res.status, ok: res.ok, data };
}

function base64UrlDecode(str) {
  let base64 = str.replace(/-/g, '+').replace(/_/g, '/');
  while (base64.length % 4) base64 += '=';
  const raw = atob(base64);
  const bytes = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
  return bytes;
}

function base64UrlEncodeBytes(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
  return btoa(binary).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function base64UrlEncodeString(str) {
  return base64UrlEncodeBytes(new TextEncoder().encode(str));
}

function base64UrlDecodeToString(str) {
  return new TextDecoder().decode(base64UrlDecode(str));
}

/* ================================================================== *
 * CONSTANT-TIME STRING COMPARE
 * ================================================================== */

function constantTimeEqual(a, b) {
  const aBytes = new TextEncoder().encode(String(a));
  const bBytes = new TextEncoder().encode(String(b));
  const len = Math.max(aBytes.length, bBytes.length);
  let diff = aBytes.length ^ bBytes.length;
  for (let i = 0; i < len; i++) {
    diff |= (aBytes[i] || 0) ^ (bBytes[i] || 0);
  }
  return diff === 0;
}

/* ================================================================== *
 * SESSION JWT (HMAC-SHA256)
 * ================================================================== */

async function getHmacKey(secret) {
  const keyMaterial = new TextEncoder().encode(secret);
  return crypto.subtle.importKey(
    'raw',
    keyMaterial,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign', 'verify']
  );
}

async function signSession(env) {
  const secret = env.SESSION_SECRET;
  if (!secret) throw new Error('SESSION_SECRET is not configured');

  const now = Math.floor(Date.now() / 1000);
  const header = { alg: 'HS256', typ: 'JWT' };
  const payload = {
    sub: 'sysadmin',
    role: 'sysAdmin',
    iat: now,
    exp: now + SESSION_TTL_HOURS * 3600,
  };

  const headerB64 = base64UrlEncodeString(JSON.stringify(header));
  const payloadB64 = base64UrlEncodeString(JSON.stringify(payload));
  const unsigned = `${headerB64}.${payloadB64}`;

  const key = await getHmacKey(secret);
  const sigBuffer = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(unsigned));
  const sigB64 = base64UrlEncodeBytes(new Uint8Array(sigBuffer));

  return `${unsigned}.${sigB64}`;
}

async function verifySession(env, token) {
  const secret = env.SESSION_SECRET;
  if (!secret) throw new Error('SESSION_SECRET is not configured');

  const parts = String(token || '').split('.');
  if (parts.length !== 3) throw new Error('Malformed session token');
  const [headerB64, payloadB64, sigB64] = parts;

  const key = await getHmacKey(secret);
  const valid = await crypto.subtle.verify(
    'HMAC',
    key,
    base64UrlDecode(sigB64),
    new TextEncoder().encode(`${headerB64}.${payloadB64}`)
  );
  if (!valid) throw new Error('Invalid session signature');

  const payload = JSON.parse(base64UrlDecodeToString(payloadB64));
  const now = Math.floor(Date.now() / 1000);
  if (payload.exp && payload.exp < now) throw new Error('Session expired');

  return payload;
}

/* ================================================================== *
 * GOOGLE OAUTH2 ACCESS TOKEN FOR FIREBASE ADMIN
 * ================================================================== */

async function getServiceAccountToken(saJson) {
  const sa = typeof saJson === 'string' ? JSON.parse(saJson) : saJson;
  const now = Math.floor(Date.now() / 1000);

  const header = { alg: 'RS256', typ: 'JWT' };
  const payload = {
    iss: sa.client_email,
    sub: sa.client_email,
    aud: sa.token_uri || 'https://oauth2.googleapis.com/token',
    iat: now,
    exp: now + 3600,
    scope:
      'https://www.googleapis.com/auth/identitytoolkit https://www.googleapis.com/auth/datastore',
  };

  const encHeader = base64UrlEncodeString(JSON.stringify(header));
  const encPayload = base64UrlEncodeString(JSON.stringify(payload));

  const pemContents = sa.private_key
    .replace('-----BEGIN PRIVATE KEY-----', '')
    .replace('-----END PRIVATE KEY-----', '')
    .replace(/\s/g, '');
  const binaryKey = base64UrlDecode(pemContents);

  const cryptoKey = await crypto.subtle.importKey(
    'pkcs8',
    binaryKey,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const dataToSign = new TextEncoder().encode(`${encHeader}.${encPayload}`);
  const sigBuffer = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', cryptoKey, dataToSign);
  const sigB64 = base64UrlEncodeBytes(new Uint8Array(sigBuffer));

  const jwt = `${encHeader}.${encPayload}.${sigB64}`;

  const tokenUri = sa.token_uri || 'https://oauth2.googleapis.com/token';
  const { ok, data } = await safeFetchJson(tokenUri, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: jwt,
    }),
  });

  if (!ok || !data.access_token) {
    throw new Error(`Failed to retrieve OAuth2 access token: ${JSON.stringify(data)}`);
  }

  return { token: data.access_token, projectId: sa.project_id };
}

/* ================================================================== *
 * FIRESTORE REST API HELPERS
 * ================================================================== */

function formatFirestoreValue(val) {
  if (val === null || val === undefined) return { nullValue: null };
  if (typeof val === 'boolean') return { booleanValue: val };
  if (typeof val === 'number') {
    return Number.isInteger(val) ? { integerValue: String(val) } : { doubleValue: val };
  }
  if (typeof val === 'string') return { stringValue: val };
  if (Array.isArray(val)) return { arrayValue: { values: val.map(formatFirestoreValue) } };
  if (typeof val === 'object') {
    const fields = {};
    for (const [k, v] of Object.entries(val)) fields[k] = formatFirestoreValue(v);
    return { mapValue: { fields } };
  }
  return { stringValue: String(val) };
}

function parseFirestoreValue(field) {
  if (!field) return null;
  if ('stringValue' in field) return field.stringValue;
  if ('integerValue' in field) return parseInt(field.integerValue, 10);
  if ('doubleValue' in field) return parseFloat(field.doubleValue);
  if ('booleanValue' in field) return field.booleanValue;
  if ('timestampValue' in field) return field.timestampValue;
  if ('nullValue' in field) return null;
  if ('arrayValue' in field) return (field.arrayValue.values || []).map(parseFirestoreValue);
  if ('mapValue' in field) {
    const res = {};
    const fields = field.mapValue.fields || {};
    for (const [k, v] of Object.entries(fields)) res[k] = parseFirestoreValue(v);
    return res;
  }
  return null;
}

function parseDoc(doc) {
  if (!doc || !doc.name) return null;
  const id = doc.name.split('/').pop();
  const fields = doc.fields || {};
  const data = { id };
  for (const [k, v] of Object.entries(fields)) data[k] = parseFirestoreValue(v);
  return data;
}

async function getDoc(token, projectId, collection, docId) {
  const url = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/${collection}/${docId}`;
  const res = await fetch(url, { headers: { Authorization: `Bearer ${token}` } });
  if (res.status === 404) return null;
  const contentType = res.headers.get('content-type') || '';
  const bodyText = await res.text();
  if (contentType.includes('text/html') || bodyText.trim().startsWith('<!DOCTYPE')) {
    throw new Error(`Upstream returned HTML response fetching document ${collection}/${docId}`);
  }
  const doc = JSON.parse(bodyText);
  if (!res.ok) throw new Error(doc.error?.message || `Firestore error ${res.status}`);
  return parseDoc(doc);
}

async function createDoc(token, projectId, collection, docId, data) {
  const url = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/${collection}?documentId=${encodeURIComponent(
    docId
  )}`;
  const fields = {};
  for (const [k, v] of Object.entries(data)) fields[k] = formatFirestoreValue(v);
  const { ok, data: resData } = await safeFetchJson(url, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ fields }),
  });
  if (!ok) throw new Error(resData.error?.message || 'Failed to create document');
  return parseDoc(resData);
}

async function updateDocFields(token, projectId, collection, docId, updateFieldsMap) {
  const fieldPaths = Object.keys(updateFieldsMap);
  const queryParams = fieldPaths
    .map((f) => `updateMask.fieldPaths=${encodeURIComponent(f)}`)
    .join('&');
  const url = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/${collection}/${docId}?${queryParams}`;

  const fields = {};
  for (const [k, v] of Object.entries(updateFieldsMap)) fields[k] = formatFirestoreValue(v);

  const { ok, data } = await safeFetchJson(url, {
    method: 'PATCH',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ fields }),
  });

  if (!ok) throw new Error(data.error?.message || 'Failed to update document');
  return parseDoc(data);
}

async function listAllCollectionDocs(token, projectId, collection) {
  let documents = [];
  let pageToken = '';

  do {
    let url = `https://firestore.googleapis.com/v1/projects/${projectId}/databases/(default)/documents/${collection}?pageSize=300`;
    if (pageToken) url += `&pageToken=${encodeURIComponent(pageToken)}`;

    const { ok, data } = await safeFetchJson(url, {
      headers: { Authorization: `Bearer ${token}` },
    });

    if (!ok) throw new Error(data.error?.message || `Failed to list collection ${collection}`);

    if (data.documents) documents = documents.concat(data.documents.map(parseDoc));
    pageToken = data.nextPageToken || '';
  } while (pageToken);

  return documents;
}

/* ================================================================== *
 * FIREBASE IDENTITY TOOLKIT HELPERS
 * ================================================================== */

async function lookupUserByEmail(token, projectId, email) {
  const url = `https://identitytoolkit.googleapis.com/v1/projects/${projectId}/accounts:lookup`;
  const { ok, data } = await safeFetchJson(url, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: [email] }),
  });
  if (ok && data.users && data.users.length > 0) return data.users[0];
  return null;
}

async function createFirebaseUser(token, projectId, email, password) {
  const url = 'https://identitytoolkit.googleapis.com/v1/accounts';
  const { ok, data } = await safeFetchJson(url, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password, returnSecureToken: false }),
  });

  if (!ok) {
    const errCode = data.error?.message || '';
    if (errCode.includes('EMAIL_EXISTS')) {
      const existing = await lookupUserByEmail(token, projectId, email);
      if (existing) return { user: existing, isExisting: true };
      throw new Error(`Email '${email}' already exists but could not be looked up`);
    }
    throw new Error(`Firebase Auth user creation failed: ${errCode}`);
  }
  return { user: data, isExisting: false };
}

async function setCustomUserClaims(token, projectId, uid, customClaims) {
  const url = 'https://identitytoolkit.googleapis.com/v1/accounts:update';
  const { ok, data } = await safeFetchJson(url, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ localId: uid, customAttributes: JSON.stringify(customClaims) }),
  });
  if (!ok) throw new Error(`Failed to set custom claims: ${data.error?.message || 'Unknown error'}`);
  return data;
}

/* ================================================================== *
 * EMAIL NOTIFICATIONS (RESEND)
 * ================================================================== */

async function sendEmail(apiKey, to, subject, html) {
  if (!apiKey) return;
  try {
    await safeFetchJson('https://api.resend.com/emails', {
      method: 'POST',
      headers: {
        Authorization: `Bearer ${apiKey}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        from: 'Edutrace <notifications@edutraceug.com>',
        to: Array.isArray(to) ? to : [to],
        subject,
        html,
      }),
    });
  } catch (err) {
    console.error('Failed to send email via Resend:', err);
  }
}

/* ================================================================== *
 * AUTH MIDDLEWARE
 * ================================================================== */

async function requireSession(request, env) {
  const authHeader = request.headers.get('Authorization') || '';
  if (!authHeader.startsWith('Bearer ')) {
    throw new Error('Missing or malformed Authorization header');
  }
  const token = authHeader.substring(7).trim();
  const payload = await verifySession(env, token);
  if (payload.role !== 'sysAdmin') throw new Error('Not a system admin session');
  return payload;
}

/* ================================================================== *
 * MAIN ROUTER
 * ================================================================== */

export default {
  async fetch(request, env, ctx) {
    if (request.method === 'OPTIONS') return handleOptions();

    const url = new URL(request.url);
    const path = url.pathname;

    try {
      /* ---------- Unprotected: health ---------- */
      if (path === '/health' && request.method === 'GET') {
        return jsonResponse({ status: 'ok', service: 'edutraceug-sysadmin-worker' });
      }

      /* ---------- Unprotected: login ---------- */
      if (path === '/auth/login' && request.method === 'POST') {
        const body = await request.json().catch(() => ({}));
        const email = String(body.email || '').trim().toLowerCase();
        const password = String(body.password || '');

        const expectedEmail = String(env.ADMIN_LOGIN_EMAIL || '').trim().toLowerCase();
        const expectedPassword = String(env.ADMIN_LOGIN_PASSWORD || '');

        if (!expectedEmail || !expectedPassword) {
          return jsonResponse({ error: 'Server misconfigured: login credentials not set' }, 500);
        }

        const emailOk = constantTimeEqual(email, expectedEmail);
        const passOk = constantTimeEqual(password, expectedPassword);

        if (!emailOk || !passOk) {
          return jsonResponse({ error: 'Invalid email or password' }, 401);
        }

        const token = await signSession(env);
        return jsonResponse({
          status: 'ok',
          token,
          expiresInSeconds: SESSION_TTL_HOURS * 3600,
          email: expectedEmail,
        });
      }

      /* ---------- All routes below require a valid session ---------- */
      let session;
      try {
        session = await requireSession(request, env);
      } catch (err) {
        return jsonResponse({ error: `Unauthorized — ${err.message}` }, 401);
      }

      /* ---------- /me ---------- */
      if (path === '/me' && request.method === 'GET') {
        return jsonResponse({ email: env.ADMIN_LOGIN_EMAIL || 'admin', role: 'sysAdmin' });
      }

      /* ---------- Firebase admin context ---------- */
      const saRaw = env['ACCOUNT-SERVICE-FIREBASE'];
      if (!saRaw) throw new Error('Environment variable ACCOUNT-SERVICE-FIREBASE is not configured');
      const { token: fbToken, projectId } = await getServiceAccountToken(saRaw);

      /* ---------- /stats ---------- */
      if (path === '/stats' && request.method === 'GET') {
        const [requests, schools, members] = await Promise.all([
          listAllCollectionDocs(fbToken, projectId, 'schoolRequests'),
          listAllCollectionDocs(fbToken, projectId, 'schools'),
          listAllCollectionDocs(fbToken, projectId, 'members'),
        ]);

        const pending = requests.filter((r) => r.status === 'pending').length;
        const approved = requests.filter((r) => r.status === 'approved').length;
        const rejected = requests.filter((r) => r.status === 'rejected').length;
        const schoolAdmins = members.filter((m) => m.role === 'schoolAdmin').length;

        return jsonResponse({
          pending,
          approved,
          rejected,
          totalRequests: requests.length,
          schools: schools.length,
          admins: schoolAdmins,
        });
      }

      /* ---------- GET /requests?status=... ---------- */
      if (path === '/requests' && request.method === 'GET') {
        const reqStatus = url.searchParams.get('status') || 'all';
        const allRequests = await listAllCollectionDocs(fbToken, projectId, 'schoolRequests');

        let filtered = allRequests;
        if (reqStatus !== 'all') filtered = allRequests.filter((r) => r.status === reqStatus);

        const requests = filtered.map((r) => {
          const photoUrls = Array.isArray(r.photoUrls) ? r.photoUrls : [];
          return {
            id: r.id,
            schoolName: r.schoolName || '',
            location: r.location || '',
            studentCount: r.studentCount || 0,
            registrarName: r.registrarName || '',
            registrarRole: r.registrarRole || '',
            contactEmail: r.contactEmail || '',
            contactPhone: r.contactPhone || '',
            status: r.status || 'pending',
            slug: r.slug || '',
            schoolId: r.schoolId || '',
            photoCount: photoUrls.length,
            createdAt: r.createdAt || '',
          };
        });

        requests.sort((a, b) => String(b.createdAt).localeCompare(String(a.createdAt)));
        return jsonResponse({ requests, total: requests.length });
      }

      /* ---------- GET /requests/:id ---------- */
      const matchRequestDetail = path.match(/^\/requests\/([^\/]+)$/);
      if (matchRequestDetail && request.method === 'GET') {
        const reqId = decodeURIComponent(matchRequestDetail[1]);
        const reqDoc = await getDoc(fbToken, projectId, 'schoolRequests', reqId);
        if (!reqDoc) return jsonResponse({ error: 'School request doc not found' }, 404);
        return jsonResponse(reqDoc);
      }

      /* ---------- POST /requests/:id/approve ---------- */
      const matchApprove = path.match(/^\/requests\/([^\/]+)\/approve$/);
      if (matchApprove && request.method === 'POST') {
        const reqId = decodeURIComponent(matchApprove[1]);
        const body = await request.json().catch(() => ({}));
        const { schoolName, slug, adminEmail, adminPassword } = body;

        if (!schoolName || !slug || !adminEmail || !adminPassword) {
          return jsonResponse(
            { error: 'Missing required fields: schoolName, slug, adminEmail, adminPassword' },
            400
          );
        }

        if (!/^[a-z0-9](?:[a-z0-9-]{1,30}[a-z0-9])?$/.test(slug)) {
          return jsonResponse(
            { error: 'Invalid slug. Use lowercase letters, numbers, hyphens (3–32 chars).' },
            400
          );
        }

        const requestDoc = await getDoc(fbToken, projectId, 'schoolRequests', reqId);
        if (!requestDoc) return jsonResponse({ error: 'School request not found' }, 404);
        if (requestDoc.status === 'approved') {
          return jsonResponse({ error: 'This request has already been approved' }, 409);
        }

        // Check slug availability (don't reserve yet — reserve at the end)
        const existingSlugDoc = await getDoc(fbToken, projectId, 'slugs', slug);
        if (
          existingSlugDoc &&
          existingSlugDoc.schoolId &&
          String(existingSlugDoc.schoolId).trim() !== ''
        ) {
          return jsonResponse(
            { error: `Slug '${slug}' is already in use by another school.` },
            409
          );
        }

        let schoolId =
          existingSlugDoc && existingSlugDoc.schoolId ? String(existingSlugDoc.schoolId).trim() : '';
        if (!schoolId) {
          schoolId = 'sch_' + crypto.randomUUID().replace(/-/g, '').slice(0, 12);
        }

        // Create or reuse Firebase user
        const { user: fbUser, isExisting } = await createFirebaseUser(
          fbToken,
          projectId,
          adminEmail,
          adminPassword
        );
        const adminUid = fbUser.localId || fbUser.uid;

        await setCustomUserClaims(fbToken, projectId, adminUid, {
          role: 'schoolAdmin',
          schoolId,
        });

        const nowIso = new Date().toISOString();

        // Create school doc
        await createDoc(fbToken, projectId, 'schools', schoolId, {
          id: schoolId,
          name: schoolName,
          nameLower: schoolName.toLowerCase(),
          slug,
          location: requestDoc.location || '',
          email: adminEmail,
          phone: requestDoc.contactPhone || '',
          themeColor: '#3570BC',
          logoUrl: '',
          heroImages: [],
          sections: [],
          createdAt: nowIso,
          createdBy: env.ADMIN_LOGIN_EMAIL || 'sysadmin',
          createdVia: 'registration-request',
        });

        // Upsert member doc (idempotent — safe if the Firebase user already existed)
        const memberData = {
          uid: adminUid,
          email: adminEmail,
          name: requestDoc.registrarName || schoolName + ' Admin',
          role: 'schoolAdmin',
          schoolId,
          schoolName,
          schoolSlug: slug,
          createdAt: nowIso,
        };
        const existingMember = await getDoc(fbToken, projectId, 'members', adminUid);
        if (existingMember) {
          await updateDocFields(fbToken, projectId, 'members', adminUid, memberData);
        } else {
          await createDoc(fbToken, projectId, 'members', adminUid, memberData);
        }

        // Reserve slug LAST — only after user + school + member exist
        if (!existingSlugDoc) {
          await createDoc(fbToken, projectId, 'slugs', slug, {
            schoolId,
            createdAt: nowIso,
          });
        } else {
          await updateDocFields(fbToken, projectId, 'slugs', slug, { schoolId });
        }

        // Flip request status
        await updateDocFields(fbToken, projectId, 'schoolRequests', reqId, {
          status: 'approved',
          approvedAt: nowIso,
          approvedBy: env.ADMIN_LOGIN_EMAIL || 'sysadmin',
          schoolId,
          slug,
          adminUid,
          adminEmail,
        });

        // Emails
        if (env.RESEND_API_KEY) {
          const safeSchoolName = esc(schoolName);
          const safeSlug = esc(slug);
          const safeAdminEmail = esc(adminEmail);
          const safeAdminPassword = esc(adminPassword);
          const safeRegistrarName = esc(requestDoc.registrarName || 'there');
          const safeRequestSchoolName = esc(requestDoc.schoolName || 'your school');
          const safeReason = esc(reasonSafe());

          const welcomeHtml = `
            <div style="font-family:Arial,sans-serif;max-width:600px;color:#1A1A1A;line-height:1.6">
              <div style="background:#3570BC;color:#fff;padding:18px 22px;font-weight:800;font-size:18px">Welcome to Edutrace</div>
              <div style="padding:22px;border:1px solid #E5E5E5;border-top:none">
                <p>Your school <b>${safeSchoolName}</b> has been approved and activated on Edutrace.</p>
                <h3 style="color:#3570BC;font-size:13px;text-transform:uppercase;letter-spacing:1px;margin:20px 0 8px">Your school page</h3>
                <p><a href="https://${safeSlug}.edutraceug.com" style="color:#3570BC;font-weight:700">https://${safeSlug}.edutraceug.com</a></p>
                <h3 style="color:#3570BC;font-size:13px;text-transform:uppercase;letter-spacing:1px;margin:20px 0 8px">Your admin login</h3>
                <p><b>Email:</b> ${safeAdminEmail}</p>
                ${
                  isExisting
                    ? '<p>Your existing Edutrace account has been granted school admin access.</p>'
                    : `<p><b>Password:</b> <code style="background:#F8F9FA;padding:3px 8px;border:1px solid #E5E5E5">${safeAdminPassword}</code></p>
                       <p style="margin-top:12px;padding:12px;background:#FEF4E5;border-left:3px solid #F9B515;font-size:13px">Please change your password after your first login.</p>`
                }
                <p style="margin-top:16px">Need help? Email <a href="mailto:support@edutraceug.com">support@edutraceug.com</a>.</p>
              </div>
            </div>`;

          const applicantHtml = `
            <div style="font-family:Arial,sans-serif;max-width:600px;color:#1A1A1A;line-height:1.6">
              <div style="background:#008E34;color:#fff;padding:18px 22px;font-weight:800;font-size:18px">Your school is approved</div>
              <div style="padding:22px;border:1px solid #E5E5E5;border-top:none">
                <p>Hello ${safeRegistrarName},</p>
                <p>Great news — your registration request for <b>${safeSchoolName}</b> has been approved.</p>
                <p>An admin account has been created and login details sent to <b>${safeAdminEmail}</b>.</p>
              </div>
            </div>`;

          const emailTasks = [
            sendEmail(env.RESEND_API_KEY, adminEmail, `Welcome to Edutrace — ${schoolName}`, welcomeHtml),
          ];
          if (requestDoc.contactEmail && requestDoc.contactEmail !== adminEmail) {
            emailTasks.push(
              sendEmail(
                env.RESEND_API_KEY,
                requestDoc.contactEmail,
                `Your school is approved — ${schoolName}`,
                applicantHtml
              )
            );
          }
          ctx.waitUntil(Promise.all(emailTasks));

          function reasonSafe() {
            return '';
          }
        }

        return jsonResponse({
          status: 'ok',
          schoolId,
          slug,
          adminUid,
          adminEmail,
          existingUser: isExisting,
        });
      }

      /* ---------- POST /requests/:id/reject ---------- */
      const matchReject = path.match(/^\/requests\/([^\/]+)\/reject$/);
      if (matchReject && request.method === 'POST') {
        const reqId = decodeURIComponent(matchReject[1]);
        const body = await request.json().catch(() => ({}));
        const reason = String(body.reason || '');

        const requestDoc = await getDoc(fbToken, projectId, 'schoolRequests', reqId);
        if (!requestDoc) return jsonResponse({ error: 'School request not found' }, 404);
        if (requestDoc.status === 'approved') {
          return jsonResponse({ error: 'Already approved. Cannot reject.' }, 409);
        }

        const nowIso = new Date().toISOString();
        await updateDocFields(fbToken, projectId, 'schoolRequests', reqId, {
          status: 'rejected',
          rejectedAt: nowIso,
          rejectedBy: env.ADMIN_LOGIN_EMAIL || 'sysadmin',
          rejectionReason: reason,
        });

        if (env.RESEND_API_KEY && requestDoc.contactEmail) {
          const safeRegistrarName = esc(requestDoc.registrarName || 'there');
          const safeRequestSchoolName = esc(requestDoc.schoolName || 'your school');
          const safeReason = esc(reason);

          const rejectionHtml = `
            <div style="font-family:Arial,sans-serif;max-width:600px;color:#1A1A1A;line-height:1.6">
              <div style="background:#D7040A;color:#fff;padding:18px 22px;font-weight:800;font-size:18px">Registration update</div>
              <div style="padding:22px;border:1px solid #E5E5E5;border-top:none">
                <p>Hello ${safeRegistrarName},</p>
                <p>Thank you for your interest in Edutrace for <b>${safeRequestSchoolName}</b>.</p>
                <p>After review, we're unable to proceed with this registration at this time.</p>
                ${safeReason ? `<p><b>Reason:</b> ${safeReason}</p>` : ''}
                <p>You're welcome to apply again later or reach us at <a href="mailto:support@edutraceug.com">support@edutraceug.com</a>.</p>
              </div>
            </div>`;

          ctx.waitUntil(
            sendEmail(
              env.RESEND_API_KEY,
              requestDoc.contactEmail,
              `Registration update — ${requestDoc.schoolName || 'Edutrace'}`,
              rejectionHtml
            )
          );
        }

        return jsonResponse({ status: 'ok' });
      }

      /* ---------- GET /schools ---------- */
      if (path === '/schools' && request.method === 'GET') {
        const rawSchools = await listAllCollectionDocs(fbToken, projectId, 'schools');
        const schools = rawSchools.map((s) => ({
          id: s.id,
          name: s.name || '',
          nameLower: s.nameLower || (s.name || '').toLowerCase(),
          slug: s.slug || '',
          location: s.location || '',
          email: s.email || '',
          phone: s.phone || '',
          themeColor: s.themeColor || '#3570BC',
          logoUrl: s.logoUrl || '',
          createdAt: s.createdAt || '',
        }));
        schools.sort((a, b) => a.nameLower.localeCompare(b.nameLower));
        return jsonResponse({ schools });
      }

      /* ---------- GET /admins ---------- */
      if (path === '/admins' && request.method === 'GET') {
        const rawMembers = await listAllCollectionDocs(fbToken, projectId, 'members');
        const schoolAdmins = rawMembers.filter((m) => m.role === 'schoolAdmin');

        const admins = schoolAdmins.map((a) => ({
          uid: a.uid || a.id,
          email: a.email || '',
          name: a.name || '',
          schoolId: a.schoolId || '',
          schoolName: a.schoolName || '',
          schoolSlug: a.schoolSlug || '',
          createdAt: a.createdAt || '',
        }));
        admins.sort((a, b) => a.email.localeCompare(b.email));
        return jsonResponse({ admins });
      }

      return jsonResponse({ error: 'Endpoint not found' }, 404);
    } catch (err) {
      console.error('Worker error:', err);
      return jsonResponse(
        { error: `Internal server error — ${err.message || String(err)}` },
        500
      );
    }
  },
};
