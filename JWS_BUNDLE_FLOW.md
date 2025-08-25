# JWS Bundle Flow - SDK Implementation Guide

## 📋 Overview

The D2 Cloud policy system uses **JSON Web Signatures (JWS)** to securely deliver policy bundles to SDKs. This ensures bundle integrity and authenticity.

## 🔄 Complete Flow

### 1. **SDK Requests Policy Bundle**
```http
GET /v1/policy/bundle
Authorization: Bearer <token>
```

### 2. **Backend Response**
```json
{
  "jws": "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJtZXRhZGF0YSI6eyJuYW1lIjoiTXlBcHAiLCJleHBpcmVzIjoiMjAyNS0wOS0xNVQxMDowMzo0My4yNjM0NDYrMDA6MDAifSwicG9saWNpZXMiOlt7InJvbGUiOiJhZG1pbiIsInBlcm1pc3Npb25zIjpbIioiXX0seyJyb2xlIjoiZGV2ZWxvcGVyIiwicGVybWlzc2lvbnMiOlsiZGF0YWJhc2U6cXVlcnkiLCJub3RpZmljYXRpb25zOnNlbmQiXX1dfQ.signature_here",
  "version": 42,
  "etag": "abc123def456"
}
```

### 3. **SDK Decodes JWS**
The `jws` field contains a **signed policy bundle**. When decoded, it reveals:

```json
{
  "metadata": {
    "name": "MyApp",
    "expires": "2025-09-15T10:03:43.263446+00:00"
  },
  "policies": [
    {
      "role": "admin",
      "permissions": ["*"]
    },
    {
      "role": "developer", 
      "permissions": ["database:query", "notifications:send"]
    }
  ]
}
```

## 🔧 SDK Implementation Steps

### Step 1: Verify JWS Signature
```javascript
// Get public key from /v1/keys endpoint first
const publicKey = await getPublicKey(accountId);

// Verify and decode JWS
try {
  const decodedBundle = jwt.verify(response.jws, publicKey, { 
    algorithms: ['RS256'] 
  });
} catch (error) {
  // Invalid signature - reject bundle
  throw new Error('Bundle signature verification failed');
}
```

### Step 2: Extract Policy Data
```javascript
// Now decodedBundle contains the actual policy data
const policies = decodedBundle.policies;
const metadata = decodedBundle.metadata;
const expires = new Date(metadata.expires);

// Use policies for authorization decisions
function hasPermission(userRole, requiredPermission) {
  const rolePolicy = policies.find(p => p.role === userRole);
  if (!rolePolicy) return false;
  
  return rolePolicy.permissions.includes(requiredPermission) || 
         rolePolicy.permissions.includes('*');
}
```

### Step 3: Handle Caching & Updates
```javascript
// Use ETag for efficient caching
const currentETag = localStorage.getItem('policy_etag');

const headers = {};
if (currentETag) {
  headers['If-None-Match'] = currentETag;
}

const response = await fetch('/v1/policy/bundle', { headers });

if (response.status === 304) {
  // Policy unchanged, use cached version
  return getCachedPolicy();
}

// Store new ETag for next request
localStorage.setItem('policy_etag', response.etag);
```

## 🔒 Security Benefits

1. **Integrity**: JWS signature prevents bundle tampering
2. **Authenticity**: Proves bundle came from trusted D2 Cloud backend  
3. **Non-repudiation**: Signed bundles provide audit trail
4. **Immutability**: Any modification breaks the signature

## ⚠️ Important Notes

- **Always verify signatures** before using policy data
- **Cache decoded bundles** with ETag to reduce API calls
- **Handle signature failures** gracefully (fail open per your default-deny model)
- **Public keys rotate** - refresh them periodically from `/v1/keys`

## 🔄 Error Handling

```javascript
try {
  const bundle = await fetchAndVerifyBundle();
  return extractPermissions(bundle);
} catch (signatureError) {
  // Log error but fail open
  console.warn('Policy verification failed, falling back to default permissions');
  return getDefaultPermissions();
}
```

## 🎯 Key Takeaway

The JWS is **not metadata** - it **IS the policy bundle**, just cryptographically signed for security. Always decode it to get your actual permission rules!

