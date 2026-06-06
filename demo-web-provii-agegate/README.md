# Provii Demo

Reference implementation demonstrating the **correct way** to integrate Provii age verification with server-side proxying.

**Live Demo:** https://demo.provii.app

## 🎯 Purpose

This demo showcases production-ready integration patterns:

- ✅ **Server-side proxying** - All verifier API calls go through your backend
- ✅ **HMAC authentication** - API secrets never exposed to the client
- ✅ **Session management** - Secure cookies set after successful verification
- ✅ **Zero personal data leakage** - Only proof of age, not date of birth

## 🚀 Quick Start

### 1. Install Dependencies

```bash
npm install
```

### 2. Development

```bash
npm run dev
```

Visit `http://localhost:8787` to see the demo in action.

### 3. Deploy

```bash
npm run deploy
```

The worker will be deployed to `https://demo.provii.app`

## 📁 Structure

```
demo-worker/
├── src/
│ └── index.ts # Worker backend with proxy routes
├── public/
│ ├── index.html # Age gate UI
│ ├── styles.css # Styling
│ └── app.js # Frontend logic (uses proxy API)
├── wrangler.toml # Worker configuration
├── package.json # Dependencies and scripts
└── README.md # This file
```

## 🔧 Architecture

### Frontend Flow

```
1. User lands on site
2. Age gate overlay appears
3. JavaScript calls /v1/verify/create-challenge
 → Backend creates challenge with HMAC
 → QR code displayed to user
4. User scans QR with Provii Wallet
5. Frontend polls /v1/verify/poll
 → Backend checks verification status
6. On verification:
 → Frontend calls /v1/verify/redeem
 → Backend sets session cookie
 → User granted access
```

### API Routes

#### `POST /v1/verify/create-challenge`

Creates a new age verification challenge.

**Request:**
```json
{
 "minimumAge": 21
}
```

**Response:**
```json
{
 "challenge_id": "550e8400-e29b-41d4-a716-446655440000",
 "verify_url": "provii://verify?d=...",
 "status_url": "https://sandbox-verify.provii.app/v1/challenge/550e8400...",
 "expires_at": 1704067620
}
```

#### `POST /v1/verify/poll`

Polls the status of a verification challenge.

**Request:**
```json
{
 "challengeId": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Response:**
```json
{
 "challenge_id": "550e8400-e29b-41d4-a716-446655440000",
 "status": "verified",
 "policies": [
 {
 "attribute": "age",
 "comparator": "gte",
 "threshold": 21,
 "satisfied": true
 }
 ]
}
```

#### `POST /v1/verify/redeem`

Redeems a verified challenge and sets session cookie.

**Request:**
```json
{
 "challengeId": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Response:**
```json
{
 "success": true,
 "session": "demo-session-token",
 "message": "In production, this would set a secure session cookie"
}
```

Sets HTTP-only cookie: `age_verified=true; Secure; SameSite=Strict`

## 🔐 Security Best Practices

### Never Expose Secrets to Client

❌ **Wrong:**
```javascript
// Client-side code
const hmac = createHmac('sha256', 'my-secret').update(message).digest('hex');
```

✅ **Right:**
```javascript
// Client calls your backend
const response = await fetch('/v1/verify/create-challenge', {
 method: 'POST',
 body: JSON.stringify({ minimumAge: 21 })
});
// Backend handles HMAC internally
```

### Set Secure Session Cookies

After successful verification, set a secure HTTP-only cookie:

```typescript
return new Response(JSON.stringify(data), {
 headers: {
 'Set-Cookie': 'age_verified=true; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=3600'
 }
});
```

### Validate on Every Request

```typescript
// Middleware to check age verification
async function requireAgeVerification(request: Request) {
 const cookie = request.headers.get('Cookie');
 if (!cookie?.includes('age_verified=true')) {
 return new Response('Age verification required', { status: 403 });
 }
 // Continue to protected content
}
```

## 🎨 Customization

### Change Minimum Age

Edit `public/app.js`:
```javascript
const MINIMUM_AGE = 18; // Change from 21 to 18
```

### Update Styling

Edit `public/styles.css` to match your brand:
```css
:root {
 --primary: #007AFF; /* Your brand color */
 --bg-overlay: rgba(0, 0, 0, 0.95);
}
```

### Add Session Database

Uncomment KV namespace in `wrangler.toml`:
```toml
[[kv_namespaces]]
binding = "DEMO_SESSIONS"
id = "your-kv-namespace-id"
```

Then use in `src/index.ts`:
```typescript
// Store session after verification
await env.DEMO_SESSIONS.put(sessionId, JSON.stringify({
 verified: true,
 age: 21,
 timestamp: Date.now
}), { expirationTtl: 3600 });
```

## 📚 Integration Guide

To integrate this pattern into your production site:

1. **Copy the backend proxy pattern** from `src/index.ts`
2. **Adapt the frontend** from `public/app.js` to your framework
3. **Store HMAC secrets securely** in Workers Secrets or KV
4. **Implement session management** with your auth system
5. **Add rate limiting** on poll endpoints
6. **Monitor** verification success/failure rates

## 🐛 Troubleshooting

### QR Code Not Appearing

Check browser console for errors. Ensure the backend is responding:
```bash
curl -X POST http://localhost:8787/v1/verify/create-challenge \
 -H "Content-Type: application/json" \
 -d '{"minimumAge": 21}'
```

### CORS Errors

The demo allows all origins for testing. In production, restrict CORS:
```typescript
const corsHeaders = {
 'Access-Control-Allow-Origin': 'https://your-domain.com',
 'Access-Control-Allow-Methods': 'POST',
 'Access-Control-Allow-Headers': 'Content-Type',
};
```

### Polling Timeout

Default timeout is 5 minutes (150 attempts × 2 seconds). Adjust in `public/app.js`:
```javascript
const MAX_POLL_ATTEMPTS = 150; // Increase if needed
```

## 📖 Additional Resources

- [Verifier Integration Guide](https://docs.provii.app/guides/verifier-integration)
- [API Reference](https://docs.provii.app/api-reference/verifier)
- [Sandbox Overview](https://docs.provii.app/guides/sandbox-overview)
- [HMAC Canonical Message](https://docs.provii.app/reference/hmac-canonical-message)

## 📝 License

This demo is part of the Provii sandbox environment and is provided for reference and testing purposes.
