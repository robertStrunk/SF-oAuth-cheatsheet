# Salesforce OAuth Guide

Complete reference for all Salesforce OAuth 2.0 flows with authorization and token exchange calls.

---

## Table of Contents

1. [Web Server Flow (Authorization Code)](#1-web-server-flow-authorization-code)
2. [JWT Bearer Token Flow](#2-jwt-bearer-token-flow)
3. [Username-Password Flow](#3-username-password-flow)
4. [Device Flow](#4-device-flow)
5. [Refresh Token Flow](#5-refresh-token-flow)
6. [SAML Bearer Assertion Flow](#6-saml-bearer-assertion-flow)
7. [Token Exchange Flow](#7-token-exchange-flow)
8. [Asset Token Flow](#8-asset-token-flow)

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

## 1. Web Server Flow (Authorization Code)

The most common OAuth flow for web applications. Two-step process: authorization then token exchange.

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

---

## 2. JWT Bearer Token Flow

Server-to-server authentication using a digitally signed JWT. No user interaction required.

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

---

## 3. Username-Password Flow

Direct authentication with username and password. Use only for trusted applications.

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

---

## 4. Device Flow

OAuth flow for devices with limited input capabilities (IoT, CLI tools, smart TVs).

### Step 1: Device Authorization Request

**Method:** `POST`  
**Endpoint:** `/services/oauth2/token`

#### Required Headers

```
Content-Type: application/x-www-form-urlencoded
```

#### Required Parameters (Body)

| Parameter | Description |
|-----------|-------------|
| `response_type` | Must be `device_code` |
| `client_id` | Consumer Key |
| `scope` | Space-separated scopes (e.g., `api refresh_token`) |

#### cURL Example

```bash
curl -X POST https://login.salesforce.com/services/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "response_type=device_code" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "scope=api refresh_token"
```

#### JavaScript Example

```javascript
const response = await fetch('https://login.salesforce.com/services/oauth2/token', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/x-www-form-urlencoded'
  },
  body: new URLSearchParams({
    response_type: 'device_code',
    client_id: 'YOUR_CLIENT_ID',
    scope: 'api refresh_token'
  })
});

const data = await response.json();
// Show data.user_code to user
// Direct user to data.verification_uri
// Poll using data.device_code
```

#### Response

```json
{
  "device_code": "9e0c1e14...",
  "user_code": "ABC-DEF-GHI",
  "verification_uri": "https://login.salesforce.com/setup/connect",
  "interval": 5
}
```

### Step 2: Poll for Token

**Method:** `POST`  
**Endpoint:** `/services/oauth2/token`

#### Required Headers

```
Content-Type: application/x-www-form-urlencoded
```

#### Required Parameters (Body)

| Parameter | Description |
|-----------|-------------|
| `grant_type` | Must be `urn:ietf:params:oauth:grant-type:device_code` |
| `client_id` | Consumer Key |
| `code` | Device code from Step 1 |

#### cURL Example

```bash
# Poll every 5 seconds (or interval from Step 1)
curl -X POST https://login.salesforce.com/services/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:device_code" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "code=9e0c1e14..."
```

#### JavaScript Example

```javascript
// Poll until authorized or timeout
async function pollForToken(deviceCode, clientId, interval = 5000) {
  while (true) {
    const response = await fetch('https://login.salesforce.com/services/oauth2/token', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: new URLSearchParams({
        grant_type: 'urn:ietf:params:oauth:grant-type:device_code',
        client_id: clientId,
        code: deviceCode
      })
    });

    const data = await response.json();
    
    if (response.ok) {
      return data; // Success - has access_token
    }
    
    if (data.error === 'authorization_pending') {
      await new Promise(resolve => setTimeout(resolve, interval));
      continue;
    }
    
    throw new Error(data.error);
  }
}
```

#### Success Response

```json
{
  "access_token": "00D...",
  "refresh_token": "5Aep...",
  "signature": "...",
  "scope": "api refresh_token",
  "instance_url": "https://yourInstance.salesforce.com",
  "id": "https://login.salesforce.com/id/00D.../005...",
  "token_type": "Bearer",
  "issued_at": "1234567890"
}
```

---

## 5. Refresh Token Flow

Exchange a refresh token for a new access token when the access token expires.

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

---

## 6. SAML Bearer Assertion Flow

Exchange a SAML assertion for an access token. Used for SSO integrations.

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

---

## 7. Token Exchange Flow

Exchange one token for another (e.g., actor token for subject token). Enables delegation and impersonation scenarios.

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
| `grant_type` | Must be `urn:ietf:params:oauth:grant-type:token-exchange` |
| `subject_token` | Token being exchanged |
| `subject_token_type` | `urn:ietf:params:oauth:token-type:access_token` |
| `client_id` | Consumer Key |
| `client_secret` | Consumer Secret |

#### Optional Parameters

| Parameter | Description |
|-----------|-------------|
| `actor_token` | Token representing the party on behalf of which exchange is requested |
| `actor_token_type` | Type of actor token |
| `scope` | Requested scope for new token |
| `resource` | Target service/resource where token will be used |
| `audience` | Intended audience for new token |

#### cURL Example

```bash
curl -X POST https://login.salesforce.com/services/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "subject_token=00D..." \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
  -d "client_id=YOUR_CLIENT_ID" \
  -d "client_secret=YOUR_CLIENT_SECRET" \
  -d "scope=api"
```

#### JavaScript Example

```javascript
const response = await fetch('https://login.salesforce.com/services/oauth2/token', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/x-www-form-urlencoded'
  },
  body: new URLSearchParams({
    grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
    subject_token: '00D...',
    subject_token_type: 'urn:ietf:params:oauth:token-type:access_token',
    client_id: 'YOUR_CLIENT_ID',
    client_secret: 'YOUR_CLIENT_SECRET',
    scope: 'api'
  })
});

const data = await response.json();
// data.access_token (new exchanged token)
```

#### Response

```json
{
  "access_token": "00D...",
  "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "api"
}
```

---

## 8. Asset Token Flow

Exchange client credentials for an access token to access protected assets. Used for accessing Salesforce CDP and other asset-based resources.

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

*Last Updated: October 2024*

