/**
 * Worker: edutraceug-sysadmin-worker
 * Base URL: https://edutraceug-sysadmin-worker.anubisdigital114-9df.workers.dev
 */

const GOOGLE_JWKS_URL = 'https://www.googleapis.com/oauth2/v3/certs';
let jwksCache = { keys: null, fetchedAt: 0 };

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
  while (base64.length % 4) {
    base64 += '=';
  }
  const raw = atob(base64);
  const bytes = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) {
    bytes[i] = raw.charCodeAt(i);
  }
  return bytes;
}

function base64UrlEncode(str) {
  return btoa(str).replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}

function parseJwt(token) {
  const parts = token.split('.');
  if (parts.length !== 3) throw new Error('Invalid JWT format');

  const header = JSON.parse(new TextDecoder().decode(base64UrlDecode(parts[0])));
  const payload = JSON.parse(new TextDecoder().decode(base64UrlDecode(parts[1])));

  return { header, payload, signature: parts[2], rawHeader: parts[0], rawPayload: parts[1] };
}

/* ================================================================== *
 * GOOGLE JWKS VERIFICATION
 * ================================================================== */

async function getGoogleJwks() {
  const now = Date.now();
  if (jwksCache.keys && now - jwksCache.fetchedAt < 3600000) {
    return jwksCache.keys;
  }
  const { ok, data } = await safeFetchJson(GOOGLE_JWKS_URL);
  if (!ok || !data.keys) {
    throw new Error('Failed to fetch Google JWKS public keys');
  }
  jwksCache = { keys: data.keys, fetchedAt: now };
  return data.keys;
}

async function verifyGoogleIdToken(token) {
  const { header, payload, rawHeader, rawPayload, signature } = parseJwt(token);

  if (header.alg !== 'RS256') throw new Error('Unsupported JWT algorithm');

  const now = Math.floor(Date.now() / 1000);
  if (payload.exp && payload.exp < now) throw new Error('Token has expired');

  const keys = await getGoogleJwks();
  const matchingKey = keys.find((k) => k.kid === header.kid);
  if (!matchingKey) throw new Error('Matching Google public key not found');

  const cryptoKey = await crypto.subtle.importKey(
    'jwk',
    matchingKey,
    { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' },
    false,
    ['verify']
  );

  const dataToVerify = new TextEncoder().encode(`${rawHeader}.${rawPayload}`);
  const sigBytes = base64UrlDecode(signature);

  const isValid = await crypto.subtle.verify('RSASSA-PKCS1-v1_5', cryptoKey, sigBytes, dataToVerify);
  if (!isValid) throw new Error('Invalid JWT signature');

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

  const encHeader = base64UrlEncode(JSON.stringify(header));
  const encPayload = base64UrlEncode(JSON.stringify(payload));

  const pemHeader = '-----BEGIN PRIVATE KEY-----';
  const pemFooter = '-----END PRIVATE KEY-----';
  const pemContents = sa.private_key
    .replace(pemHeader, '')
    .replace(pemFooter, '')
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

  let sigBase64 = btoa(String.fromCharCode(...new Uint8Array(sigBuffer)));
  sigBase64 = sigBase64.replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');

  const jwt = `${encHeader}.${encPayload}.${sigBase64}`;

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
  if (Array.isArray(val)) {
    return { arrayValue: { values: val.map(formatFirestoreValue) } };
  }
  if (typeof val === 'object') {
    const fields = {};
    for (const [k, v] of Object.entries(val)) {
      fields[k] = formatFirestoreValue(v);
    }
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
    for (const [k, v] of Object.entries(fields)) {
      res[k] = parseFirestoreValue(v);
    }
    return res;
  }
  return null;
}

function parseDoc(doc) {
  if (!doc || !doc.name) return null;
  const id = doc.name.split('/').pop();
  const fields = doc.fields || {};
  const data = { id };
  for (const [k, v] of Object.entries(fields)) {
    data[k] = parseFirestoreValue(v);
  }
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
  for (const [k, v] of Object.entries(data)) {
    fields[k] = formatFirestoreValue(v);
  }
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
  for (const [k, v] of Object.entries(updateFieldsMap)) {
    fields[k] = formatFirestoreValue(v);
  }

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

    if (data.documents) {
      documents = documents.concat(data.documents.map(parseDoc));
    }
    pageToken = data.nextPageToken || '';
  } while (pageToken);

  return documents;
}

/* ================================================================== *
 * FIREBASE IDENTITY TOOLKIT REST API HELPERS
 * ================================================================== */

async function lookupUserByEmail(token, projectId, email) {
  const url = `https://identitytoolkit.googleapis.com/v1/projects/${projectId}/accounts:lookup`;
  const { ok, data } = await safeFetchJson(url, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ email: [email] }),
  });

  if (ok && data.users && data.users.length > 0) {
    return data.users[0];
  }
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

  if (!ok) {
    throw new Error(`Failed to set custom claims: ${data.error?.message || 'Unknown error'}`);
  }
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
 * MAIN ROUTER & HANDLER
 * ================================================================== */

export default {
  async fetch(request, env, ctx) {
    if (request.method === 'OPTIONS') return handleOptions();

    const url = new URL(request.url);
    const path = url.pathname;

    try {
      if (path === '/health' && request.method === 'GET') {
        return jsonResponse({ status: 'ok', service: 'edutraceug-sysadmin-worker' });
      }

      const authHeader = request.headers.get('Authorization') || '';
      if (!authHeader.startsWith('Bearer ')) {
        return jsonResponse({ error: 'Missing or malformed Authorization header' }, 401);
      }

      const token = authHeader.substring(7).trim();
      let claims;
      try {
        claims = await verifyGoogleIdToken(token);
      } catch (err) {
        return jsonResponse({ error: `Unauthorized — ${err.message}` }, 401);
      }

      const userEmail = (claims.email || '').toLowerCase().trim();
      const whitelist = (env.SYSTEM_ADMIN_EMAILS || '')
        .split(',')
        .map((e) => e.trim().toLowerCase())
        .filter(Boolean);

      if (!userEmail || !whitelist.includes(userEmail)) {
        return jsonResponse(
          { error: 'Forbidden — Account email not in system admin whitelist' },
          403
        );
      }

      const saRaw = env['ACCOUNT-SERVICE-FIREBASE'];
      if (!saRaw) throw new Error('Environment variable ACCOUNT-SERVICE-FIREBASE is not configured');
      const { token: fbToken, projectId } = await getServiceAccountToken(saRaw);

      if (path === '/me' && request.method === 'GET') {
        return jsonResponse({ email: userEmail, role: 'sysAdmin' });
      }

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

      if (path === '/requests' && request.method === 'GET') {
        const reqStatus = url.searchParams.get('status') || 'all';
        const allRequests = await listAllCollectionDocs(fbToken, projectId, 'schoolRequests');

        let filtered = allRequests;
        if (reqStatus !== 'all') {
          filtered = allRequests.filter((r) => r.status === reqStatus);
        }

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

      const matchRequestDetail = path.match(/^\/requests\/([^\/]+)$/);
      if (matchRequestDetail && request.method === 'GET') {
        const reqId = decodeURIComponent(matchRequestDetail[1]);
        const reqDoc = await getDoc(fbToken, projectId, 'schoolRequests', reqId);
        if (!reqDoc) return jsonResponse({ error: 'School request doc not found' }, 404);
        return jsonResponse(reqDoc);
      }

      const matchApprove = path.match(/^\/requests\/([^\/]+)\/approve$/);
      if (matchApprove && request.method === 'POST') {
        const reqId = decodeURIComponent(matchApprove[1]);
        const body = await request.json();
        const { schoolName, slug, adminEmail, adminPassword } = body;

        if (!schoolName || !slug || !adminEmail || !adminPassword) {
          return jsonResponse(
            { error: 'Missing required fields: schoolName, slug, adminEmail, adminPassword' },
            400
          );
        }

        const requestDoc = await getDoc(fbToken, projectId, 'schoolRequests', reqId);
        if (!requestDoc) return jsonResponse({ error: 'School request not found' }, 404);
        if (requestDoc.status === 'approved') {
          return jsonResponse({ error: 'This request has already been approved' }, 409);
        }

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

        if (!existingSlugDoc) {
          await createDoc(fbToken, projectId, 'slugs', slug, {
            schoolId,
            createdAt: new Date().toISOString(),
          });
        } else {
          await updateDocFields(fbToken, projectId, 'slugs', slug, { schoolId });
        }

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
          createdBy: userEmail,
          createdVia: 'registration-request',
        });

        await createDoc(fbToken, projectId, 'members', adminUid, {
          uid: adminUid,
          email: adminEmail,
          name: requestDoc.registrarName || schoolName + ' Admin',
          role: 'schoolAdmin',
          schoolId,
          schoolName,
          schoolSlug: slug,
          createdAt: nowIso,
        });

        await updateDocFields(fbToken, projectId, 'schoolRequests', reqId, {
          status: 'approved',
          approvedAt: nowIso,
          approvedBy: userEmail,
          schoolId,
          slug,
          adminUid,
          adminEmail,
        });

        if (env.RESEND_API_KEY) {
          const welcomeHtml = `
            <div style="font-family:Arial,sans-serif;max-width:600px;color:#1A1A1A;line-height:1.6">
              <div style="background:#3570BC;color:#fff;padding:18px 22px;font-weight:800;font-size:18px">
                Welcome to Edutrace
              </div>
              <div style="padding:22px;border:1px solid #E5E5E5;border-top:none">
                <p>Your school <b>${schoolName}</b> has been approved and activated on Edutrace.</p>
                <h3 style="color:#3570BC;font-size:13px;text-transform:uppercase;letter-spacing:1px;margin:20px 0 8px">Your school page</h3>
                <p><a href="https://${slug}.edutraceug.com" style="color:#3570BC;font-weight:700">https://${slug}.edutraceug.com</a></p>
                <h3 style="color:#3570BC;font-size:13px;text-transform:uppercase;letter-spacing:1px;margin:20px 0 8px">Your admin login</h3>
                <p><b>Email:</b> ${adminEmail}</p>
                ${
                  isExisting
                    ? '<p>Your existing Edutrace account has been granted school admin access.</p>'
                    : `<p><b>Password:</b> <code style="background:#F8F9FA;padding:3px 8px;border:1px solid #E5E5E5">${adminPassword}</code></p>
                       <p style="margin-top:12px;padding:12px;background:#FEF4E5;border-left:3px solid #F9B515;font-size:13px">Please change your password after your first login.</p>`
                }
                <p style="margin-top:16px">Need help? Email <a href="mailto:support@edutraceug.com">support@edutraceug.com</a>.</p>
              </div>
            </div>`;

          const applicantHtml = `
            <div style="font-family:Arial,sans-serif;max-width:600px;color:#1A1A1A;line-height:1.6">
              <div style="background:#008E34;color:#fff;padding:18px 22px;font-weight:800;font-size:18px">
                Your school is approved
              </div>
              <div style="padding:22px;border:1px solid #E5E5E5;border-top:none">
                <p>Hello ${requestDoc.registrarName || 'there'},</p>
                <p>Great news — your registration request for <b>${schoolName}</b> has been approved.</p>
                <p>An admin account has been created and login details sent to <b>${adminEmail}</b>.</p>
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

      const matchReject = path.match(/^\/requests\/([^\/]+)\/reject$/);
      if (matchReject && request.method === 'POST') {
        const reqId = decodeURIComponent(matchReject[1]);
        const body = await request.json().catch(() => ({}));
        const reason = body.reason || '';

        const requestDoc = await getDoc(fbToken, projectId, 'schoolRequests', reqId);
        if (!requestDoc) return jsonResponse({ error: 'School request not found' }, 404);
        if (requestDoc.status === 'approved') {
          return jsonResponse({ error: 'Already approved. Cannot reject.' }, 409);
        }

        const nowIso = new Date().toISOString();
        await updateDocFields(fbToken, projectId, 'schoolRequests', reqId, {
          status: 'rejected',
          rejectedAt: nowIso,
          rejectedBy: userEmail,
          rejectionReason: reason,
        });

        if (env.RESEND_API_KEY && requestDoc.contactEmail) {
          const rejectionHtml = `
            <div style="font-family:Arial,sans-serif;max-width:600px;color:#1A1A1A;line-height:1.6">
              <div style="background:#D7040A;color:#fff;padding:18px 22px;font-weight:800;font-size:18px">
                Registration update
              </div>
              <div style="padding:22px;border:1px solid #E5E5E5;border-top:none">
                <p>Hello ${requestDoc.registrarName || 'there'},</p>
                <p>Thank you for your interest in Edutrace for <b>${requestDoc.schoolName || 'your school'}</b>.</p>
                <p>After review, we're unable to proceed with this registration at this time.</p>
                ${reason ? `<p><b>Reason:</b> ${reason}</p>` : ''}
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
