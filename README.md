# Salesforce OAuth Cheat Sheet

Complete reference for all Salesforce OAuth 2.0 flows with authorization and token exchange calls.

---

## Table of Contents

1. [Web Server Flow (Authorization Code)](#1-web-server-flow-authorization-code)
2. [JWT Bearer Token Flow](#2-jwt-bearer-token-flow)
3. [Username-Password Flow](#3-username-password-flow)
4. [Refresh Token Flow](#4-refresh-token-flow)
5. [SAML Bearer Assertion Flow](#5-saml-bearer-assertion-flow)
6. [Client Credentials Flow](#6-client-credentials-flow)

---

## Common Endpoints

**Production/Developer Orgs:**
- Authorization: `https://login.salesforce.com/services/oauth2/authorize`
- Token: `https://login.salesforce.com/services/oauth2/token`

**Sandbox Orgs:**
- Authorization: `https://test.salesforce.com/services/oauth2/authorize`
- Token: `https://test.salesforce.com/services/oauth2/token`

**Custom Domains:**
- Replace `login.salesforce.com` or `test.salesforce.com` with your My Domain URL

---

<details>
<summary>

## 1. Web Server Flow (Authorization Code)

</summary>

The most common OAuth flow for web applications. Two-step process: authorization then token exchange.

### Conceptual Overview

The Web Server Flow (also called Authorization Code Flow) is the **standard OAuth 2.0 flow for user-facing web applications**. It provides secure user authentication with consent, delegating authorization without exposing user credentials to your application.

**Think of it as a valet key system:**
1. **User Requests Access**: User wants to grant your app access to their Salesforce data
2. **Authorization Request**: Your app redirects user to Salesforce login
3. **User Consents**: User authenticates and approves permissions
4. **Code Exchange**: Salesforce returns authorization code, your server exchanges it for tokens
5. **Secure Access**: Your app uses access token to make API calls on user's behalf

**Key Characteristics:**
- ✅ User-initiated authentication with consent screen
- ✅ Most secure flow for web applications
- ✅ Refresh tokens provided for long-term access
- ✅ Client secret kept secure on backend server
- ✅ Supports PKCE for enhanced security (mobile/SPA apps)

### How It Works (Step-by-Step)

```
┌─────────┐                                  ┌──────────────┐
│ Browser │                                  │  Salesforce  │
│  User   │                                  │              │
└────┬────┘                                  └──────┬───────┘
     │                                              │
     │ 1. Click "Login with Salesforce"            │
     ├──────────────────────────────────────────►  │
     │                                              │
     │ 2. Redirect to /oauth2/authorize            │
     │    (with client_id, redirect_uri, scope)    │
     │                                              │
     │ 3. User sees Salesforce login page      ◄───┤
     │                                              │
     │ 4. User authenticates & approves            │
     ├──────────────────────────────────────────►  │
     │                                              │
     │ 5. Redirect back with authorization code◄───┤
     │    https://your-app.com/callback?code=ABC   │
     │                                              │
┌────▼────┐                                  ┌──────▼───────┐
│  Your   │                                  │  Salesforce  │
│ Backend │ 6. Exchange code for tokens      │   Token      │
│ Server  ├──────────────────────────────────►   Endpoint   │
│         │    (code, client_secret)         │              │
│         │ 7. Receive access + refresh token│              │
│         │ ◄────────────────────────────────┤              │
└─────────┘                                  └──────────────┘
```

### When to Use This Flow

✅ **Ideal for:**
- Web applications with a backend server
- Customer-facing portals requiring user login
- SaaS applications integrating with Salesforce
- Apps requiring delegated user permissions
- Long-running sessions with refresh tokens
- Multi-tenant applications

❌ **Not suitable for:**
- Server-to-server integrations (use JWT Bearer Flow)
- Native mobile apps without PKCE (security risk)
- Applications that can't secure client_secret (use PKCE)
- Automated background processes (use JWT or Client Credentials)

### Step 1: Authorization Request

**Method:** `GET`  
**Endpoint:** `/services/oauth2/authorize`

#### Required Parameters (Query String)

| Parameter | Description |
|-----------|-------------|
| `response_type` | Must be `code` |
| `client_id` | Consumer Key from Connected App |
| `redirect_uri` | Callback URL (must match Connected App) |

#### Optional Parameters

| Parameter | Description |
|-----------|-------------|
| `scope` | Space-separated list (e.g., `api refresh_token`) |
| `state` | CSRF protection token |
| `prompt` | `login` forces re-authentication, `consent` forces approval |
| `code_challenge` | PKCE code challenge (Base64-URL encoded SHA256 hash) |
| `code_challenge_method` | Must be `S256` when using PKCE |

#### cURL Example

```bash
# This opens in browser - redirect user to this URL
https://login.salesforce.com/services/oauth2/authorize?response_type=code&client_id=YOUR_CLIENT_ID&redirect_uri=https://your-app.com/callback&scope=api%20refresh_token&state=mystate123
```

#### JavaScript Example

```javascript
// Redirect user to authorization URL
const authUrl = new URL('https://login.salesforce.com/services/oauth2/authorize');
authUrl.searchParams.append('response_type', 'code');
authUrl.searchParams.append('client_id', 'YOUR_CLIENT_ID');
authUrl.searchParams.append('redirect_uri', 'https://your-app.com/callback');
authUrl.searchParams.append('scope', 'api refresh_token');
authUrl.searchParams.append('state', 'mystate123');

window.location.href = authUrl.toString();
```

### Step 2: Token Exchange

**Method:** `POST`  
**Endpoint:** `/services/oauth2/token`

#### Required Headers

```
Content-Type: application/x-www-form-urlencoded
```

#### Required Parameters (Body)

| Parameter | Description |
|-----------|-------------|
| `grant_type` | Must be `authorization_code` |
| `code` | Authorization code from Step 1 |
| `client_id` | Consumer Key |
| `client_secret` | Consumer Secret |
| `redirect_uri` | Same URI from authorization request |

#### Optional Parameters

| Parameter | Description |
|-----------|-------------|
| `code_verifier` | PKCE code verifier (if using PKCE) |

#### cURL Example

```bash
curl -X POST https://login.salesforce.com/services/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "code=AUTHORIZATION_CODE" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "client_secret=YOUR_CLIENT_SECRET" \
  -d "redirect_uri=https://your-app.com/callback"
```

#### JavaScript Example

```javascript
const response = await fetch('https://login.salesforce.com/services/oauth2/token', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/x-www-form-urlencoded'
  },
  body: new URLSearchParams({
    grant_type: 'authorization_code',
    code: 'AUTHORIZATION_CODE',
    client_id: 'YOUR_CLIENT_ID',
    client_secret: 'YOUR_CLIENT_SECRET',
    redirect_uri: 'https://your-app.com/callback'
  })
});

const data = await response.json();
// data.access_token, data.refresh_token, data.instance_url
```

#### Response

```json
{
  "access_token": "00D...",
  "refresh_token": "5Aep...",
  "signature": "...",
  "scope": "api refresh_token",
  "id_token": "eyJ...",
  "instance_url": "https://yourInstance.salesforce.com",
  "id": "https://login.salesforce.com/id/00D.../005...",
  "token_type": "Bearer",
  "issued_at": "1234567890"
}
```

### Security Considerations

**Critical Security Requirements:**
- **🔒 CSRF Protection**: Always use `state` parameter to prevent cross-site request forgery attacks
- **🔐 Client Secret Security**: Never expose `client_secret` in client-side code (browser, mobile)
- **✅ Redirect URI Validation**: Must exactly match URI registered in Connected App
- **🛡️ PKCE for Public Clients**: Mandatory for SPAs and mobile apps (use `code_challenge`)
- **🔄 Authorization Code Single Use**: Codes expire after ~15 minutes and can only be used once

**PKCE (Proof Key for Code Exchange):**
```javascript
// Step 1: Generate code verifier (random string)
const codeVerifier = generateRandomString(128);

// Step 2: Create SHA256 hash and base64-url encode
const codeChallenge = base64UrlEncode(sha256(codeVerifier));

// Step 3: Include in authorization request
authUrl.searchParams.append('code_challenge', codeChallenge);
authUrl.searchParams.append('code_challenge_method', 'S256');

// Step 4: Include verifier in token exchange
tokenParams.append('code_verifier', codeVerifier);
```

**Why PKCE is Critical:**
- Protects against authorization code interception attacks
- Required for mobile apps and Single Page Applications (SPAs)
- Recommended even for confidential clients (defense in depth)

### Architectural Considerations

**Token Lifecycle Management:**
```
Authorization Code Lifecycle:
├─ Issued: After user authorization
├─ Lifetime: ~15 minutes
├─ Usage: Single-use only
└─ Exchange: For access + refresh tokens

Access Token Lifecycle:
├─ Lifetime: ~2 hours (org configurable)
├─ Storage: Secure, HTTP-only cookies or session storage
├─ Renewal: Use refresh token when expired
└─ Revocation: User can revoke via Salesforce settings

Refresh Token Lifecycle:
├─ Lifetime: Indefinite or policy-based
├─ Storage: Encrypted database (never client-side)
├─ Rotation: Consider rotating on each use (security best practice)
└─ Revocation: Revoked if inactive for extended period
```

**Session Management Best Practices:**
- Store `refresh_token` server-side only (database, encrypted)
- Use HTTP-only, Secure cookies for `access_token` in browser
- Implement token refresh logic before expiration
- Handle token revocation gracefully (redirect to login)
- Log out users when refresh token fails

**Common Errors:**

| Error | Meaning | Solution |
|-------|---------|----------|
| `redirect_uri_mismatch` | Redirect URI doesn't match Connected App | Verify exact match including protocol and path |
| `invalid_client_id` | Client ID incorrect | Check Consumer Key from Connected App |
| `invalid_grant` | Authorization code expired/used | Restart authorization flow |
| `unauthorized_client` | Client not authorized for flow | Enable OAuth in Connected App settings |
| `access_denied` | User denied authorization | Handle gracefully, allow retry |

**Multi-Tenant Architecture:**
```javascript
// Store tokens per user/organization
const tokenStore = {
  userId: {
    accessToken: "00D...",
    refreshToken: "5Aep...",
    instanceUrl: "https://org.salesforce.com",
    expiresAt: timestamp
  }
};

// Automatic refresh before API calls
async function apiCall(userId, endpoint) {
  let tokens = tokenStore[userId];
  
  if (Date.now() > tokens.expiresAt - 300000) { // 5 min buffer
    tokens = await refreshAccessToken(tokens.refreshToken);
    tokenStore[userId] = tokens;
  }
  
  return fetch(tokens.instanceUrl + endpoint, {
    headers: { 'Authorization': `Bearer ${tokens.accessToken}` }
  });
}
```

**CORS Configuration:**
- Configure allowed origins in Connected App settings
- Required for browser-based token exchanges
- Use wildcards carefully (security risk)

**Governor Limits:**
- Authorization requests don't count toward API limits
- Token exchanges count as API calls (1 per exchange)
- Refresh token requests count as API calls
- Monitor Connected App usage in Setup → Connected Apps OAuth Usage

</details>

---

<details>
<summary>

## 2. JWT Bearer Token Flow

</summary>

Server-to-server authentication using a digitally signed JWT. No user interaction required.

### Conceptual Overview

The JWT Bearer Token Flow is a **certificate-based, server-to-server authentication mechanism** that allows applications to obtain Salesforce access tokens without user interaction or storing user credentials. It uses a digitally signed JSON Web Token (JWT) as proof of identity.

**Think of it as a diplomatic passport system:**
1. **Pre-established Trust**: You register a digital certificate with Salesforce (like registering with an embassy)
2. **Self-Issued Credential**: Your application creates and signs a JWT using its private key
3. **Verification & Access**: Salesforce verifies the JWT signature and grants access

**Key Advantages:**
- ✅ No user login prompt - completely autonomous
- ✅ No refresh tokens needed - generate new access tokens on demand
- ✅ No client secret exposure - security based on private key possession
- ✅ User context preserved - tokens issued for a specific Salesforce user

### How It Works (Step-by-Step)

#### Phase 1: One-Time Setup

```
1. Generate RSA Key Pair (2048-bit minimum)
   ├─ private.key (kept secret on your server)
   └─ certificate.crt (uploaded to Salesforce)

2. Configure Connected App in Salesforce
   ├─ Enable OAuth Settings
   ├─ Upload certificate.crt
   ├─ Enable "Use Digital Signatures"
   ├─ Authorize specific users/profiles
   └─ Note the Consumer Key (client_id)
```

#### Phase 2: Runtime Authentication

```
Step 1: Create JWT
┌─────────────────────────────────────┐
│ Header: { "alg": "RS256" }          │
│ Payload:                            │
│ {                                   │
│   "iss": "Consumer Key",            │
│   "sub": "user@org.com",            │
│   "aud": "https://login.salesforce.com" │
│   "exp": Unix timestamp (5 min max) │
│ }                                   │
└─────────────────────────────────────┘
         ↓ Sign with private key
         
Step 2: Exchange JWT for Access Token
POST /services/oauth2/token
         ↓ Salesforce validates signature
         
Step 3: Receive Access Token
Use for all subsequent API calls
```

### When to Use This Flow

✅ **Ideal for:**
- Scheduled batch jobs (nightly data sync, ETL processes)
- Microservices architecture (service-to-service calls)
- CI/CD pipelines (automated deployments)
- Integration middleware (MuleSoft, Dell Boomi)
- IoT backend services

❌ **Not suitable for:**
- User-facing applications (use Web Server Flow)
- Public clients (can't secure private key)
- Applications requiring user consent
- Mobile apps (use Web Server Flow with PKCE)

### Token Request

**Method:** `POST`  
**Endpoint:** `/services/oauth2/token`

#### Required Headers

```
Content-Type: application/x-www-form-urlencoded
```

#### Required Parameters (Body)

| Parameter | Description |
|-----------|-------------|
| `grant_type` | Must be `urn:ietf:params:oauth:grant-type:jwt-bearer` |
| `assertion` | Base64-URL encoded JWT |

#### JWT Header

```json
{
  "alg": "RS256"
}
```

#### JWT Claims (Payload)

| Claim | Description |
|-------|-------------|
| `iss` | Consumer Key (client_id) |
| `sub` | Salesforce username (e.g., user@example.com) |
| `aud` | `https://login.salesforce.com` or `https://test.salesforce.com` |
| `exp` | Expiration time (Unix timestamp, max 5 minutes from now) |

#### cURL Example

```bash
# First, create and sign the JWT (using a library or tool)
# JWT must be signed with private key matching certificate in Connected App

curl -X POST https://login.salesforce.com/services/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer" \
  -d "assertion=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
```

#### JavaScript Example

```javascript
// Using a JWT library like 'jsonwebtoken'
const jwt = require('jsonwebtoken');
const fs = require('fs');

// Create JWT
const privateKey = fs.readFileSync('private.key');
const token = jwt.sign(
  {
    iss: 'YOUR_CLIENT_ID',
    sub: 'user@example.com',
    aud: 'https://login.salesforce.com',
    exp: Math.floor(Date.now() / 1000) + 300 // 5 minutes
  },
  privateKey,
  { algorithm: 'RS256' }
);

// Exchange JWT for access token
const response = await fetch('https://login.salesforce.com/services/oauth2/token', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/x-www-form-urlencoded'
  },
  body: new URLSearchParams({
    grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
    assertion: token
  })
});

const data = await response.json();
// data.access_token, data.instance_url
```

#### Response

```json
{
  "access_token": "00D...",
  "scope": "api web",
  "instance_url": "https://yourInstance.salesforce.com",
  "id": "https://login.salesforce.com/id/00D.../005...",
  "token_type": "Bearer",
  "issued_at": "1234567890"
}
```

### Security Considerations

**Critical Security Requirements:**
- **🔐 Private Key Protection**: Store in HSM, key vault, or encrypted at rest - never commit to version control
- **👤 User Authorization**: The `sub` user must be pre-authorized in Connected App policies
- **📅 Certificate Rotation**: Monitor expiration dates and implement rotation procedures
- **🌍 Environment Isolation**: Use different certificates for sandbox vs production
- **⏱️ Short-Lived JWTs**: 5-minute maximum expiration prevents token replay attacks

**Why RS256 (RSA Signature)?**
- **Asymmetric cryptography**: Private key signs, public key (certificate) verifies
- **No shared secrets**: Salesforce never sees your private key
- **Non-repudiation**: Only holder of private key can create valid JWTs

### Architectural Considerations

**Performance & Scalability:**
```
Token Caching Strategy:
├─ Generate JWT → Exchange for access token (1 API call)
├─ Cache access token for ~1.5 hours
├─ Reuse cached token for all API calls
└─ Generate new JWT only when token expires

Result: Reduces auth overhead from 1000s to ~16 calls per day
```

**Governor Limits:**
- JWT creation is **local** - no Salesforce API call consumed
- Token exchange counts as **1 API call** per access token
- Access tokens typically valid for 2 hours (org configurable)
- Suitable for high-volume integrations (1000s of requests/hour)

**Common Errors:**

| Error | Meaning | Solution |
|-------|---------|----------|
| `invalid_grant` | User not authorized or JWT invalid | Check Connected App user authorization |
| `expired_token` | JWT exp claim exceeded 5 minutes | Regenerate JWT with fresh timestamp |
| `invalid_client` | Consumer Key (iss) incorrect | Verify Connected App Consumer Key |
| `invalid_signature` | Private/public key mismatch | Ensure certificate in SF matches key pair |

**Retry Logic Best Practice:**
```javascript
async function getAccessToken(maxRetries = 3) {
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    const jwt = createJWT(); // Fresh JWT each attempt
    try {
      return await exchangeJWT(jwt);
    } catch (error) {
      if (error.code === 'expired_token' || error.code === 'invalid_grant') {
        throw error; // Don't retry - fix JWT claims
      }
      if (attempt === maxRetries) throw error;
      await sleep(2 ** attempt * 1000); // Exponential backoff
    }
  }
}
```

</details>

---

<details>
<summary>

## 3. Username-Password Flow

</summary>

Direct authentication with username and password. Use only for trusted applications.

### Conceptual Overview

The Username-Password Flow (also called Resource Owner Password Credentials) is a **legacy OAuth flow** that exchanges user credentials directly for access tokens. While simple, it's considered **less secure** than modern flows and should only be used in highly trusted scenarios.

**Think of it as handing over your house keys:**
- Unlike Web Server Flow (valet key), this gives direct credential access
- No user consent screen or redirect flow
- Application receives and handles raw credentials
- Should only be used when other flows aren't feasible

**Key Characteristics:**
- ⚠️ **Security Risk**: Application handles raw user credentials
- ⚠️ **No Consent Screen**: User doesn't see what permissions are granted
- ⚠️ **Security Token Required**: Must append security token to password
- ✅ **Simple Implementation**: Single API call to get tokens
- ⚠️ **Limited Use Cases**: Being phased out in favor of more secure flows

### How It Works (Step-by-Step)

```
┌──────────────┐                          ┌──────────────┐
│ Your App     │                          │  Salesforce  │
│              │                          │   Token      │
│              │                          │  Endpoint    │
└──────┬───────┘                          └──────┬───────┘
       │                                         │
       │ 1. User enters credentials              │
       │    (username + password + token)        │
       │                                         │
       │ 2. POST /oauth2/token                   │
       │    grant_type=password                  │
       │    username=user@example.com            │
       │    password=myPass123SECURITYTOKEN      │
       │    client_id=XXX                        │
       │    client_secret=YYY                    │
       ├─────────────────────────────────────────►
       │                                         │
       │                                         │ 3. Validate
       │                                         │    credentials
       │                                         │
       │ 4. Return access + refresh tokens       │
       │◄─────────────────────────────────────────
       │                                         │
       │ 5. Use access token for API calls       │
       │                                         │
```

**Critical Requirement - Security Token:**
```
Password Format: actualPassword + securityToken

Example:
├─ Password: "MyP@ssw0rd"
├─ Security Token: "ABC123xyz789"
└─ Combined: "MyP@ssw0rd ABC123xyz789"

Get Security Token:
1. Login to Salesforce
2. Settings → My Personal Information → Reset My Security Token
3. Token emailed to registered email address
```

### When to Use This Flow

✅ **Use ONLY for:**
- Legacy applications being migrated (temporary measure)
- Internal IT tools with strict access controls
- Trusted scripts running in secure environments
- Testing/development (not production user authentication)
- Migration scenarios where other flows aren't immediately available

❌ **NEVER use for:**
- Customer-facing applications (use Web Server Flow)
- Mobile applications (use Web Server Flow with PKCE)
- SaaS products (use Web Server Flow)
- Third-party integrations (use JWT Bearer Flow)
- Any scenario where credentials could be intercepted

⚠️ **Security Warning:**
This flow is **deprecated** by OAuth 2.1 specification and discouraged by Salesforce. It should be replaced with Web Server Flow or JWT Bearer Flow whenever possible.

### Token Request

**Method:** `POST`  
**Endpoint:** `/services/oauth2/token`

#### Required Headers

```
Content-Type: application/x-www-form-urlencoded
```

#### Required Parameters (Body)

| Parameter | Description |
|-----------|-------------|
| `grant_type` | Must be `password` |
| `client_id` | Consumer Key |
| `client_secret` | Consumer Secret |
| `username` | Salesforce username |
| `password` | Password + Security Token concatenated |

#### cURL Example

```bash
curl -X POST https://login.salesforce.com/services/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "client_secret=YOUR_CLIENT_SECRET" \
  -d "username=user@example.com" \
  -d "password=password123SECURITYTOKEN"
```

#### JavaScript Example

```javascript
const response = await fetch('https://login.salesforce.com/services/oauth2/token', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/x-www-form-urlencoded'
  },
  body: new URLSearchParams({
    grant_type: 'password',
    client_id: 'YOUR_CLIENT_ID',
    client_secret: 'YOUR_CLIENT_SECRET',
    username: 'user@example.com',
    password: 'password123SECURITYTOKEN'
  })
});

const data = await response.json();
// data.access_token, data.refresh_token, data.instance_url
```

#### Response

```json
{
  "access_token": "00D...",
  "refresh_token": "5Aep...",
  "signature": "...",
  "scope": "api web",
  "instance_url": "https://yourInstance.salesforce.com",
  "id": "https://login.salesforce.com/id/00D.../005...",
  "token_type": "Bearer",
  "issued_at": "1234567890"
}
```

### Security Considerations

**Critical Security Risks:**
- **🚨 Credential Exposure**: Application handles plaintext passwords
- **🚨 Credential Storage**: Never store passwords - only tokens after authentication
- **🚨 Man-in-the-Middle**: Credentials sent over network (use HTTPS only)
- **🚨 Logging Risk**: Never log password parameters
- **🔒 Security Token Complexity**: Users must understand and manage security tokens

**Mitigation Strategies:**
```javascript
// NEVER do this - storing credentials
const NEVER_DO_THIS = {
  username: "user@example.com",
  password: "MyPassword123Token" // ❌ NEVER store passwords
};

// DO THIS - store only tokens after authentication
const tokenCache = {
  accessToken: "00D...",
  refreshToken: "5Aep...",
  expiresAt: timestamp
};

// Use refresh token for subsequent authentications
async function authenticate() {
  if (tokenCache.refreshToken) {
    return await refreshAccessToken(tokenCache.refreshToken);
  }
  // Only prompt for credentials if no refresh token
  return await usernamePasswordAuth();
}
```

**IP Restrictions:**
- Salesforce tracks login locations
- Untrusted IP addresses trigger verification emails
- Configure trusted IP ranges in Profile/Permission Set settings
- Consider using Named Credentials for automated processes

### Architectural Considerations

**Common Errors:**

| Error | Meaning | Solution |
|-------|---------|----------|
| `invalid_grant` | Invalid credentials or security token | Verify password + security token concatenation |
| `authentication_failure` | Wrong username/password | Check credentials, account may be locked |
| `inactive_user` | User account inactive | Activate user in Salesforce |
| `unsupported_grant_type` | Flow not enabled | Enable OAuth in Connected App |
| `invalid_client` | Client credentials wrong | Verify client_id and client_secret |

**Security Token Management:**
```
When Security Token Resets:
├─ Password change (token automatically resets)
├─ Manual reset via user settings
├─ Admin-initiated password reset
└─ Login from new IP (may trigger reset)

Token Management:
├─ Email delivery can be delayed (check spam folder)
├─ Only one token active per user at a time
├─ Resetting invalidates previous token
└─ Impacts all applications using Username-Password Flow
```

**Migration Strategy (Away from this Flow):**

```
Step 1: Assess Current Usage
├─ Identify all applications using Username-Password Flow
├─ Categorize by use case (user-facing, automated, etc.)
└─ Prioritize migration based on risk

Step 2: Choose Replacement Flow
├─ User-facing apps → Web Server Flow (Authorization Code + PKCE)
├─ Server integrations → JWT Bearer Flow
├─ Service accounts → Client Credentials Flow
└─ SSO scenarios → SAML Bearer Assertion Flow

Step 3: Implement & Test
├─ Create new Connected Apps with appropriate flows
├─ Test in sandbox environment
├─ Migrate users in phases
└─ Decommission Username-Password Connected Apps

Step 4: Monitor & Verify
├─ Track Connected Apps OAuth Usage
├─ Monitor for authentication failures
└─ Provide user support/documentation
```

**Alternative Patterns:**
```javascript
// Instead of Username-Password Flow, use:

// Pattern 1: Web Server Flow for user authentication
window.location.href = authUrl; // Redirect to Salesforce login

// Pattern 2: JWT Bearer for automated processes
const jwt = createJWT(privateKey, username);
const tokens = await exchangeJWT(jwt);

// Pattern 3: Client Credentials for service accounts
const tokens = await clientCredentialsAuth(clientId, clientSecret);
```

**Governor Limits:**
- Authentication failures count toward login rate limits
- Too many failed attempts can lock user accounts
- Monitor API usage - each authentication is 1 API call
- Refresh tokens preferred over repeated credential authentication

</details>

---

<details>
<summary>

## 4. Refresh Token Flow

</summary>

Exchange a refresh token for a new access token when the access token expires.

### Conceptual Overview

The Refresh Token Flow is **not a standalone authentication flow**, but rather a **token renewal mechanism** used with other flows (Web Server, Username-Password, etc.). It allows applications to obtain new access tokens without requiring user re-authentication.

**Think of it as a keycard renewal system:**
- Your access keycard (access token) expires after 2 hours
- Instead of going back through security (login again)
- You use your master card (refresh token) to get a new keycard
- No user interaction required

**Key Characteristics:**
- ✅ **Seamless UX**: Renew tokens without interrupting user experience
- ✅ **Long-Lived**: Refresh tokens can be indefinite or policy-controlled
- ✅ **Security**: Can be revoked by user or admin at any time
- ✅ **Efficient**: Avoids repeated authorization flows
- ⚠️ **Must Request**: Need `refresh_token` scope in initial authorization

### How It Works (Step-by-Step)

```
Initial Authentication (Web Server Flow Example):
┌──────────┐                              ┌──────────────┐
│ Your App │                              │  Salesforce  │
└────┬─────┘                              └──────┬───────┘
     │                                           │
     │ 1. Authorization Code Flow                │
     ├───────────────────────────────────────────►
     │                                           │
     │ 2. Receive access + refresh tokens    ◄───┤
     │    {                                      │
     │      "access_token": "...",               │
     │      "refresh_token": "..."               │
     │    }                                      │
     │                                           │
     ▼                                           │
  Store both tokens securely                     │

Access Token Expires (~2 hours later):
     │                                           │
     │ 3. Access token expired during API call   │
     │    → 401 Unauthorized                     │
     │                                           │
     │ 4. POST /oauth2/token                     │
     │    grant_type=refresh_token               │
     │    refresh_token=5Aep...                  │
     ├───────────────────────────────────────────►
     │                                           │
     │ 5. Receive new access token           ◄───┤
     │    {                                      │
     │      "access_token": "...",               │
     │      "instance_url": "..."                │
     │    }                                      │
     │                                           │
     │ 6. Retry API call with new token          │
     └───────────────────────────────────────────►
```

### When to Use This Flow

✅ **Always use when:**
- Building applications with long-lived sessions
- Users shouldn't be logged out every 2 hours
- Background processes need continuous access
- Mobile applications (combined with Web Server + PKCE)
- SaaS applications with persistent user sessions

⚠️ **Requirements:**
- Must request `refresh_token` scope during initial authorization
- Only works with flows that provide refresh tokens:
  - ✅ Web Server Flow (Authorization Code)
  - ✅ Username-Password Flow
  - ❌ JWT Bearer Flow (generates new tokens on demand instead)
  - ❌ SAML Bearer Flow (doesn't provide refresh tokens)

### Token Request

**Method:** `POST`  
**Endpoint:** `/services/oauth2/token`

#### Required Headers

```
Content-Type: application/x-www-form-urlencoded
```

#### Required Parameters (Body)

| Parameter | Description |
|-----------|-------------|
| `grant_type` | Must be `refresh_token` |
| `client_id` | Consumer Key |
| `client_secret` | Consumer Secret |
| `refresh_token` | Refresh token from previous authorization |

#### cURL Example

```bash
curl -X POST https://login.salesforce.com/services/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "client_secret=YOUR_CLIENT_SECRET" \
  -d "refresh_token=5Aep..."
```

#### JavaScript Example

```javascript
const response = await fetch('https://login.salesforce.com/services/oauth2/token', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/x-www-form-urlencoded'
  },
  body: new URLSearchParams({
    grant_type: 'refresh_token',
    client_id: 'YOUR_CLIENT_ID',
    client_secret: 'YOUR_CLIENT_SECRET',
    refresh_token: '5Aep...'
  })
});

const data = await response.json();
// data.access_token (new token)
// Note: refresh_token may or may not be returned
```

#### Response

```json
{
  "access_token": "00D...",
  "signature": "...",
  "scope": "api refresh_token",
  "instance_url": "https://yourInstance.salesforce.com",
  "id": "https://login.salesforce.com/id/00D.../005...",
  "token_type": "Bearer",
  "issued_at": "1234567890"
}
```

### Security Considerations

**Critical Security Requirements:**
- **🔐 Secure Storage**: Refresh tokens are long-lived - store encrypted at rest
- **🚫 Never Client-Side**: Never store refresh tokens in browser localStorage/sessionStorage
- **📱 Mobile Security**: Use platform-secure storage (iOS Keychain, Android KeyStore)
- **🔄 Token Rotation**: Consider rotating refresh tokens on each use (best practice)
- **⏱️ Expiration Policies**: Configure refresh token lifetime in Connected App policies

**Refresh Token Storage Best Practices:**
```javascript
// ❌ NEVER do this - client-side storage
localStorage.setItem('refresh_token', token); // Vulnerable to XSS

// ✅ DO THIS - server-side encrypted storage
// Backend API endpoint
app.post('/auth/store-tokens', async (req, res) => {
  const { userId, refreshToken, accessToken } = req.body;
  
  // Encrypt refresh token before storing
  const encrypted = await encrypt(refreshToken, ENCRYPTION_KEY);
  
  await database.tokens.upsert({
    userId,
    refreshToken: encrypted,
    accessToken: accessToken, // Can be less secure - short-lived
    expiresAt: Date.now() + 7200000 // 2 hours
  });
});

// Mobile secure storage (React Native example)
import * as SecureStore from 'expo-secure-store';
await SecureStore.setItemAsync('refresh_token', token);
```

**Revocation Scenarios:**
```
Refresh Tokens Are Revoked When:
├─ User changes password
├─ User explicitly revokes access (Connected Apps settings)
├─ Admin revokes Connected App access
├─ Org policy: inactive for X days (configurable)
├─ Security violation detected
└─ Manual revocation via Salesforce API
```

### Architectural Considerations

**Automatic Token Refresh Pattern:**
```javascript
class SalesforceClient {
  constructor(accessToken, refreshToken, expiresAt) {
    this.accessToken = accessToken;
    this.refreshToken = refreshToken;
    this.expiresAt = expiresAt;
  }

  async apiCall(endpoint, options = {}) {
    // Proactively refresh if expiring soon (5 min buffer)
    if (Date.now() > this.expiresAt - 300000) {
      await this.refresh();
    }

    try {
      return await this._makeRequest(endpoint, options);
    } catch (error) {
      // Reactive refresh on 401
      if (error.status === 401) {
        await this.refresh();
        return await this._makeRequest(endpoint, options);
      }
      throw error;
    }
  }

  async refresh() {
    const response = await fetch('https://login.salesforce.com/services/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        client_id: this.clientId,
        client_secret: this.clientSecret,
        refresh_token: this.refreshToken
      })
    });

    const data = await response.json();
    
    if (!response.ok) {
      if (data.error === 'invalid_grant') {
        // Refresh token revoked - require re-authentication
        throw new Error('REFRESH_TOKEN_REVOKED');
      }
      throw new Error(data.error);
    }

    this.accessToken = data.access_token;
    this.expiresAt = Date.now() + 7200000;
    
    // Note: refresh_token may or may not be returned
    // If returned, it's a rotated token - update storage
    if (data.refresh_token) {
      this.refreshToken = data.refresh_token;
    }
  }

  async _makeRequest(endpoint, options) {
    return fetch(endpoint, {
      ...options,
      headers: {
        ...options.headers,
        'Authorization': `Bearer ${this.accessToken}`
      }
    });
  }
}
```

**Refresh Token Rotation:**
```
Traditional (Non-Rotating):
├─ Refresh token issued once
├─ Same token used repeatedly
├─ Valid until revoked or expired
└─ Security risk: stolen token valid indefinitely

Modern (Rotating):
├─ Each refresh returns NEW refresh token
├─ Previous refresh token immediately invalidated
├─ Limits window for token theft
└─ Configure in Connected App: "Refresh Token Rotation"
```

**Common Errors:**

| Error | Meaning | Solution |
|-------|---------|----------|
| `invalid_grant` | Refresh token revoked or invalid | Re-authenticate user via full OAuth flow |
| `inactive_user` | User deactivated | Check user status in Salesforce |
| `inactive_org` | Org expired or suspended | Contact Salesforce support |
| `invalid_client` | Client credentials wrong | Verify client_id and client_secret |

**Multi-Device Session Management:**
```javascript
// Track refresh tokens per device
const userSessions = {
  userId123: {
    devices: {
      web_chrome: { refreshToken: "xxx", lastUsed: timestamp },
      mobile_ios: { refreshToken: "yyy", lastUsed: timestamp },
      mobile_android: { refreshToken: "zzz", lastUsed: timestamp }
    }
  }
};

// Logout from specific device
async function logoutDevice(userId, deviceId) {
  const session = userSessions[userId].devices[deviceId];
  await revokeRefreshToken(session.refreshToken);
  delete userSessions[userId].devices[deviceId];
}

// Logout from all devices
async function logoutAllDevices(userId) {
  const devices = Object.values(userSessions[userId].devices);
  await Promise.all(devices.map(d => revokeRefreshToken(d.refreshToken)));
  delete userSessions[userId];
}
```

**Governor Limits:**
- Refresh token requests count as API calls (1 per refresh)
- Typical: 15-20 refreshes per user per day (2-hour access tokens)
- Plan for peak concurrent users refreshing simultaneously
- Monitor Connected Apps OAuth Usage

</details>

---

<details>
<summary>

## 5. SAML Bearer Assertion Flow

</summary>

Exchange a SAML assertion for an access token. Used for SSO integrations.

### Conceptual Overview

The SAML Bearer Assertion Flow enables **Single Sign-On (SSO) integration** between Salesforce and enterprise Identity Providers (IdPs). It exchanges a SAML 2.0 assertion for an OAuth access token, allowing users authenticated by an external IdP to access Salesforce APIs without separate login.

**Think of it as a passport stamp system:**
- Your company's IdP (Okta, Azure AD, etc.) is the passport issuer
- SAML assertion is the stamped passport proving authentication
- Salesforce accepts the stamp and grants API access
- No separate Salesforce login required

**Key Characteristics:**
- ✅ **Enterprise SSO**: Integrates with corporate identity systems
- ✅ **No Password Exposure**: Users never enter Salesforce credentials
- ✅ **Centralized Identity**: IdP manages authentication and MFA
- ✅ **API Access**: Converts SSO session into API tokens
- ⚠️ **Complex Setup**: Requires SAML configuration and certificate trust

### How It Works (Step-by-Step)

```
┌─────────┐          ┌──────────┐          ┌──────────────┐
│  User   │          │   IdP    │          │  Salesforce  │
│ Browser │          │  (Okta)  │          │              │
└────┬────┘          └────┬─────┘          └──────┬───────┘
     │                    │                       │
     │ 1. Access app      │                       │
     ├───────────►        │                       │
     │                    │                       │
     │ 2. Redirect to IdP │                       │
     │◄───────────        │                       │
     │                    │                       │
     │ 3. Authenticate    │                       │
     ├────────────────────►                       │
     │                    │                       │
     │ 4. SAML Response   │                       │
     │    (with assertion)│                       │
     │◄────────────────────                       │
     │                    │                       │

┌────▼────┐                                ┌──────▼───────┐
│ Your    │                                │  Salesforce  │
│ Backend │ 5. POST /oauth2/token          │   OAuth      │
│         │    grant_type=saml2-bearer     │  Endpoint    │
│         │    assertion=<SAML>            │              │
│         ├────────────────────────────────►              │
│         │                                │              │
│         │ 6. Validate SAML assertion     │              │
│         │    - Signature valid?          │              │
│         │    - Not expired?              │              │
│         │    - User exists in SF?        │              │
│         │                                │              │
│         │ 7. Return access token         │              │
│         │◄────────────────────────────────              │
└─────────┘                                └──────────────┘
```

### When to Use This Flow

✅ **Ideal for:**
- Enterprise customers with existing IdP infrastructure
- Organizations requiring centralized identity management
- Compliance scenarios needing audit trails from IdP
- Apps integrating with corporate SSO (Okta, Azure AD, Ping, etc.)
- API access following browser-based SAML SSO

❌ **Not suitable for:**
- Simple user authentication (use Web Server Flow)
- No existing IdP infrastructure (use Web Server Flow)
- Server-to-server automation (use JWT Bearer Flow)
- Consumer applications (complexity not warranted)

### Token Request

**Method:** `POST`  
**Endpoint:** `/services/oauth2/token`

#### Required Headers

```
Content-Type: application/x-www-form-urlencoded
```

#### Required Parameters (Body)

| Parameter | Description |
|-----------|-------------|
| `grant_type` | Must be `urn:ietf:params:oauth:grant-type:saml2-bearer` |
| `assertion` | Base64-encoded SAML assertion |

#### SAML Assertion Requirements

- Must be signed by IdP
- Subject must match Salesforce user (by username or Federation ID)
- Audience: `https://login.salesforce.com` or `https://test.salesforce.com`
- Recipient: Token endpoint URL
- Valid time window (NotBefore/NotOnOrAfter)

#### cURL Example

```bash
curl -X POST https://login.salesforce.com/services/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:saml2-bearer" \
  -d "assertion=PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4..."
```

#### JavaScript Example

```javascript
// SAML assertion must be Base64-encoded
const samlAssertion = btoa(samlXmlString);

const response = await fetch('https://login.salesforce.com/services/oauth2/token', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/x-www-form-urlencoded'
  },
  body: new URLSearchParams({
    grant_type: 'urn:ietf:params:oauth:grant-type:saml2-bearer',
    assertion: samlAssertion
  })
});

const data = await response.json();
// data.access_token, data.instance_url
```

#### Response

```json
{
  "access_token": "00D...",
  "signature": "...",
  "scope": "api web",
  "instance_url": "https://yourInstance.salesforce.com",
  "id": "https://login.salesforce.com/id/00D.../005...",
  "token_type": "Bearer",
  "issued_at": "1234567890"
}
```

### Security & Architectural Considerations

**SAML Configuration Requirements:**
- **Certificate Trust**: IdP certificate must be uploaded to Salesforce (Setup → Certificate and Key Management)
- **User Matching**: SAML Subject must match either Salesforce Username or Federation ID
- **Signature Validation**: SAML assertion must be digitally signed by trusted IdP
- **Time Validation**: NotBefore/NotOnOrAfter timestamps must be valid (clock synchronization critical)

**Common Errors:**

| Error | Meaning | Solution |
|-------|---------|----------|
| `invalid_grant` | SAML assertion invalid or expired | Check signature, timestamps, and user matching |
| `user_not_found` | Subject doesn't match SF user | Verify Federation ID or username mapping |
| `expired_assertion` | Assertion expired | Sync clocks between IdP and Salesforce |

**Integration Pattern:**
```javascript
// Typical SSO + API Access Pattern
// 1. User logs in via browser SAML SSO
// 2. Browser receives SAML assertion
// 3. Backend exchanges assertion for OAuth token
async function handleSAMLResponse(samlAssertion) {
  const tokens = await fetch('https://login.salesforce.com/services/oauth2/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'urn:ietf:params:oauth:grant-type:saml2-bearer',
      assertion: btoa(samlAssertion) // Base64 encode
    })
  });
  return tokens.access_token;
}
```

</details>

---

<details>
<summary>

## 6. Client Credentials Flow

</summary>

Server-to-server authentication using client credentials. Used for accessing Salesforce APIs without user context, commonly for CDP, Marketing Cloud, and other asset-based integrations.

### Conceptual Overview

The Client Credentials Flow is a **service-to-service authentication mechanism** where the application itself is the resource owner (not a user). It's ideal for automated processes that access resources owned by the application, not specific users.

**Think of it as a service account with API keys:**
- No user login or interaction required
- Application authenticates with its own credentials (client_id + client_secret)
- All operations run as a designated "Run As" user
- Commonly used for data integration pipelines

**Key Characteristics:**
- ✅ **No User Context**: Operates without specific user authentication
- ✅ **Simple Authentication**: Single API call with client credentials
- ⚠️ **Execution User Required**: Must configure "Run As" user in Salesforce
- ✅ **Asset-Based Access**: Designed for CDP, Marketing Cloud, external objects
- ⚠️ **Limited Salesforce Use**: Not for standard SOAP/REST API operations

> **⚠️ Important Configuration Requirement:**  
> Before using this flow, you must configure your Connected App:
> 1. Navigate to Setup → App Manager → Your Connected App → Manage
> 2. Click "Edit Policies"
> 3. Enable "Client Credentials Flow"
> 4. Select a "Run As" user (execution user) who has the necessary permissions
> 5. The API calls will run with the permissions of this execution user

### How It Works (Step-by-Step)

```
┌──────────────┐                          ┌──────────────┐
│ Your Service │                          │  Salesforce  │
│ (Automated)  │                          │   OAuth      │
│              │                          │  Endpoint    │
└──────┬───────┘                          └──────┬───────┘
       │                                         │
       │ 1. POST /oauth2/token                   │
       │    grant_type=client_credentials        │
       │    client_id=YOUR_CLIENT_ID             │
       │    client_secret=YOUR_CLIENT_SECRET     │
       │    scope=cdp_ingest_api                 │
       ├─────────────────────────────────────────►
       │                                         │
       │                                         │ 2. Validate
       │                                         │    client
       │                                         │    credentials
       │                                         │
       │ 3. Return access token                  │
       │    (runs as configured execution user)  │
       │◄─────────────────────────────────────────
       │                                         │
       │ 4. Use access token for API calls       │
       │    (all operations run as "Run As" user)│
       ├─────────────────────────────────────────►
       │                                         │
```

**Execution User is Critical:**
- All API calls execute with the "Run As" user's permissions and profile
- Execution user must have appropriate licenses and permissions
- Record ownership, sharing rules, and field-level security apply
- Changes in execution user permissions affect all applications using this flow

### When to Use This Flow

✅ **Ideal for:**
- Salesforce CDP data ingestion pipelines
- Marketing Cloud API integrations
- External object data synchronization
- Automated data imports/exports (non-user-specific)
- Service-to-service integrations without user context

❌ **Not suitable for:**
- Standard Salesforce CRUD operations (use JWT Bearer Flow with user context)
- User-specific data access (use Web Server Flow or JWT Bearer)
- Applications requiring per-user permissions
- When you need user-specific audit trails

### Token Request

**Method:** `POST`  
**Endpoint:** `/services/oauth2/token`

#### Required Headers

```
Content-Type: application/x-www-form-urlencoded
```

#### Required Parameters (Body)

| Parameter | Description |
|-----------|-------------|
| `grant_type` | Must be `client_credentials` |
| `client_id` | Consumer Key |
| `client_secret` | Consumer Secret |

#### Optional Parameters

| Parameter | Description |
|-----------|-------------|
| `scope` | Requested scopes (e.g., `cdp_ingest_api`) |

#### cURL Example

```bash
curl -X POST https://login.salesforce.com/services/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "client_secret=YOUR_CLIENT_SECRET" \
  -d "scope=cdp_ingest_api"
```

#### JavaScript Example

```javascript
const response = await fetch('https://login.salesforce.com/services/oauth2/token', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/x-www-form-urlencoded'
  },
  body: new URLSearchParams({
    grant_type: 'client_credentials',
    client_id: 'YOUR_CLIENT_ID',
    client_secret: 'YOUR_CLIENT_SECRET',
    scope: 'cdp_ingest_api'
  })
});

const data = await response.json();
// data.access_token
```

#### Response

```json
{
  "access_token": "00D...",
  "signature": "...",
  "scope": "cdp_ingest_api",
  "instance_url": "https://yourInstance.salesforce.com",
  "id": "https://login.salesforce.com/id/00D.../005...",
  "token_type": "Bearer",
  "issued_at": "1234567890"
}
```

### Security & Architectural Considerations

**Critical Security Requirements:**
- **🔐 Client Secret Protection**: Store securely - equivalent to a password for your service
- **👤 Execution User Management**: Changes to "Run As" user permissions affect all consumers
- **📊 Audit Trail**: All operations attributed to execution user, not individual users
- **🔒 Scope Limitation**: Request minimum necessary scopes (principle of least privilege)

**Execution User Best Practices:**
```
Configuration:
├─ Create dedicated "Integration User" for execution
├─ Assign minimal permissions (profile/permission sets)
├─ Monitor user's API usage and operations
└─ Document which applications use this user

Security:
├─ Do NOT use admin users as execution users
├─ Separate execution users per application/use case
├─ Regular permission audits
└─ Deactivate unused execution users
```

**Common Errors:**

| Error | Meaning | Solution |
|-------|---------|----------|
| `invalid_grant` | Client credentials invalid | Verify client_id and client_secret |
| `invalid_client` | Client Credentials Flow not enabled | Enable in Connected App policies |
| `unsupported_grant_type` | Flow not configured | Select execution user in Connected App |
| `insufficient_access` | Execution user lacks permissions | Grant necessary permissions to "Run As" user |

**Token Caching Strategy:**
```javascript
// Cache access tokens - they're reusable until expiration
class ClientCredentialsManager {
  constructor(clientId, clientSecret) {
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.tokenCache = null;
  }

  async getAccessToken() {
    // Return cached token if still valid
    if (this.tokenCache && Date.now() < this.tokenCache.expiresAt) {
      return this.tokenCache.accessToken;
    }

    // Request new token
    const response = await fetch('https://login.salesforce.com/services/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: this.clientId,
        client_secret: this.clientSecret,
        scope: 'cdp_ingest_api'
      })
    });

    const data = await response.json();
    this.tokenCache = {
      accessToken: data.access_token,
      expiresAt: Date.now() + 7200000 // 2 hours
    };

    return data.access_token;
  }
}
```

</details>

---

## Using Access Tokens

Once you have an access token, include it in API requests:

### Header Format

```
Authorization: Bearer YOUR_ACCESS_TOKEN
```

### cURL Example

```bash
curl https://yourInstance.salesforce.com/services/data/v59.0/sobjects/Account \
  -H "Authorization: Bearer 00D..."
```

### JavaScript Example

```javascript
const response = await fetch('https://yourInstance.salesforce.com/services/data/v59.0/sobjects/Account', {
  headers: {
    'Authorization': 'Bearer 00D...'
  }
});
```

---

## Common Scopes

| Scope | Description |
|-------|-------------|
| `api` | Access to REST/SOAP APIs |
| `web` | Access to current logged-in user info |
| `full` | Full access (equivalent to user's permissions) |
| `refresh_token` | Request refresh token |
| `openid` | OpenID Connect authentication |
| `profile` | Access to user's profile info |
| `email` | Access to user's email |
| `address` | Access to user's address |
| `phone` | Access to user's phone |
| `offline_access` | Refresh token without user presence |
| `cdp_ingest_api` | CDP Ingest API access |
| `cdp_query_api` | CDP Query API access |
| `cdp_profile_api` | CDP Profile API access |

---

## Notes

- **Access Token Lifetime**: Typically 2 hours (customizable in Connected App or Session Settings)
- **Refresh Token Lifetime**: Can be indefinite or time-limited based on org policies
- **Security**: Never expose client secrets in client-side code
- **Rate Limits**: OAuth requests are subject to Salesforce API limits
- **Custom Domains**: Always use My Domain for production applications
- **CORS**: Web Server Flow requires CORS configuration for browser-based apps

---

## Verification Notes

### ✅ Verified OAuth Flows

The following flows are **officially supported** by Salesforce OAuth 2.0:
1. **Web Server Flow (Authorization Code)** - Standard web application authentication
2. **JWT Bearer Token Flow** - Server-to-server with digital certificate
3. **Username-Password Flow** - Direct credential authentication (trusted apps only)
4. **Refresh Token Flow** - Token renewal without re-authentication
5. **SAML Bearer Assertion Flow** - SSO integration with SAML 2.0
6. **Client Credentials Flow** - Server-to-server without user context (requires execution user)

### ⚠️ Removed Unsupported Flows

The following flows were **removed from this documentation** as they are **NOT supported** by Salesforce:
- **Device Flow** - Not implemented in Salesforce OAuth
- **Token Exchange Flow (RFC 8693)** - Not implemented in Salesforce OAuth

### Architectural Considerations

**Security Best Practices:**
- Never expose `client_secret` in client-side code (mobile apps, SPAs)
- Use PKCE (Proof Key for Code Exchange) for public clients
- Implement proper refresh token rotation policies
- Use My Domain for all production implementations
- Configure session timeout policies at org level

**Governor Limits:**
- OAuth token requests count toward API limits
- Default: 5,000 API calls per user per 24 hours (varies by license)
- Connected App rate limiting applies separately

**Enterprise Architecture:**
- JWT Bearer Flow recommended for system integrations (no user interaction)
- Client Credentials Flow for CDP, Marketing Cloud integrations
- Web Server Flow for end-user authentication
- Implement token caching to minimize auth requests
- Use Named Credentials for declarative authentication management

### Sources

This documentation has been verified against official Salesforce resources:
- Salesforce Developer Documentation: OAuth 2.0 Flows
- Salesforce Help: Connected Apps and OAuth
- Salesforce API Reference (Winter '25, Spring '25 releases)

---

## Disclaimer

**⚠️ Important:** OAuth implementation details, endpoints, and parameters may change between Salesforce releases. Always confirm:
- Current API version compatibility
- Connected App configuration requirements
- Org-level OAuth policies and session settings
- Latest Salesforce release notes for OAuth changes

For the most current information, consult the official Salesforce Developer Documentation at https://developer.salesforce.com/docs/

---

*Last Updated: October 2024 | Verified for Winter '25 & Spring '25 Releases*

