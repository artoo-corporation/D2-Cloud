# D2 Policy Schema Integration

## 📋 **Updated System Behavior**

The backend now fully supports the D2 policy schema with automatic expiry detection and validation.

## 🎯 **D2 Policy Bundle Example**

### **Input Policy Bundle:**
```json
{
  "metadata": {
    "name": "MyApp Authorization Policy",
    "description": "Role-based access control for MyApp service",
    "expires": "2025-09-15T10:03:43.263446+00:00"
  },
  "policies": [
    {
      "role": "admin",
      "description": "Full system access",
      "permissions": ["*"]
    },
    {
      "role": "developer", 
      "description": "Limited development access",
      "permissions": [
        "database:query",
        "notifications:send",
        "!admin:delete"
      ]
    },
    {
      "role": "readonly",
      "permissions": [
        "database:read",
        "!database:write",
        "!admin:*"
      ]
    }
  ]
}
```

## 🔄 **Backend Processing**

### **1. Draft Upload**
```bash
PUT /v1/policy/draft
Content-Type: application/json

{
  "bundle": { /* D2 policy above */ }
}
```

**Backend Actions:**
- ✅ **Validates** D2 schema (metadata.name, policies structure)
- ✅ **Extracts expiry** from `metadata.expires`
- ✅ **Auto-versions** the draft
- ✅ **Logs policy summary**:
  ```
  Policy summary: {
    "name": "MyApp Authorization Policy",
    "expires": "2025-09-15T10:03:43.263446+00:00",
    "role_count": 3,
    "permission_stats": {
      "total": 6,
      "allow": 3,
      "deny": 3,
      "wildcard": 1
    }
  }
  ```

### **2. Policy Publish**
```bash
POST /v1/policy/publish
```

**Backend Actions:**
- ✅ **Re-extracts expiry** from bundle
- ✅ **Signs bundle** with JWS
- ✅ **Sets expires field** in database
- ✅ **Activates policy**

### **3. Bundle Retrieval**
```bash
GET /v1/policy/bundle
```

**Response Headers:**
```http
ETag: "abc123..."
X-D2-Poll-Seconds: 60
X-D2-Policy-Expires: 2025-09-15T10:03:43Z
X-D2-Policy-Expired: false
X-D2-Policy-Expiring-Soon: true
X-D2-Days-Until-Expiry: 5
```

**Response Body:**
```json
{
  "jws": "eyJ0eXAiOiJKV1MiLCJhbGciOiJSUzI1NiJ9...",
  "version": 3,
  "etag": "abc123..."
}
```

## 📊 **Policy Version History**
```bash
GET /v1/policy/versions
```

```json
[
  {
    "id": "uuid-v3",
    "version": 3,
    "active": true,
    "published_at": "2025-08-18T18:00:00Z",
    "expires": "2025-09-15T10:03:43Z",
    "revocation_time": null
  },
  {
    "id": "uuid-v2",
    "version": 2,
    "active": false,
    "published_at": "2025-08-17T15:30:00Z",
    "expires": "2025-08-25T10:00:00Z",
    "revocation_time": null
  }
]
```

## 🎯 **Schema Validation Features**

### **Required Fields Checked:**
- ✅ `metadata` object exists
- ✅ `metadata.name` is a string
- ✅ `metadata.expires` is ISO-8601 string
- ✅ `policies` array exists with ≥1 entry
- ✅ Each policy has `role` string
- ✅ Each policy has `permissions` array with ≥1 entry

### **Optional Fields Supported:**
- ✅ `metadata.description`
- ✅ `policy.description`
- ✅ Future-proof extra fields preserved

### **Permission Format Recognition:**
- ✅ **Allow rules**: `"database:query"`
- ✅ **Deny rules**: `"!admin:delete"`  
- ✅ **Wildcards**: `"*"`

## 🚀 **Benefits**

### **For Policy Authors:**
- ✅ **Schema validation** catches errors early
- ✅ **Automatic expiry** handling from metadata
- ✅ **Rich logging** shows policy statistics

### **For Operations:**
- ✅ **Expiry warnings** prevent policy lapses
- ✅ **Version history** with expiry tracking
- ✅ **Structured validation** ensures consistency

### **For SDKs/Clients:**
- ✅ **Clear headers** about policy expiry status
- ✅ **Standard D2 format** for interoperability
- ✅ **Automatic versioning** simplifies workflow

## 🔧 **Error Handling**

### **Validation Warnings (Non-blocking):**
```
Policy validation warnings: [
  "Missing 'metadata.expires' field (recommended)",
  "policies[1].permissions must contain at least one entry"
]
```

### **Expiry Warnings:**
```
Policy expired for account abc123: 2025-08-15T10:00:00Z
```

The system is **permissive** - validation warnings don't block uploads, but provide helpful feedback for policy quality.

Your D2 policy system now has **enterprise-grade validation and expiry management** while maintaining **developer-friendly workflows**! 🎉

