# Multi-App Policy System - Implementation Guide

## 🎯 Overview

The D2 Cloud policy system now supports **multiple applications per account** using the `metadata.name` field from policy bundles. Each app has independent policy versioning, drafting, publishing, and revocation.

## 🔄 New Data Model

### **Enhanced Schema:**
```sql
-- Added app_name field extracted from bundle.metadata.name
ALTER TABLE public.policies ADD COLUMN app_name text NOT NULL;

-- New constraints for app-specific versioning
UNIQUE (account_id, app_name, version)
UNIQUE (account_id, app_name, version, is_draft)

-- Indexes for efficient app-specific queries
INDEX (account_id, app_name)
INDEX (account_id, app_name, version DESC) 
INDEX (account_id, app_name, active) WHERE active = true AND is_draft = false
```

### **App Name Extraction:**
- **Source:** `bundle.metadata.name` field (REQUIRED in D2 schema)
- **Sanitization:** Non-alphanumeric characters → underscores, max 100 chars
- **Default:** `"default"` if metadata.name is missing
- **Examples:** 
  - `"my-service"` → `"my-service"`
  - `"My App!"` → `"My_App_"`
  - `""` → `"default"`

## 🚀 Updated API Endpoints

### **1. Policy Bundle Retrieval**
```http
GET /v1/policy/bundle?app_name=my-service
```

**Changes:**
- ✅ **New `app_name` query parameter** (defaults to `"default"`)
- ✅ **App-specific policy lookup** 
- ✅ **Backward compatible** - existing calls get `"default"` app

**Example:**
```bash
# Get policy for specific app
curl "/v1/policy/bundle?app_name=user-service"

# Get default app policy (backward compatible)
curl "/v1/policy/bundle"
```

### **2. Draft Upload**
```http
PUT /v1/policy/draft
Content-Type: application/json

{
  "bundle": {
    "metadata": {
      "name": "user-service",    // Extracted as app_name
      "expires": "2025-12-01T00:00:00Z"
    },
    "policies": [...]
  }
}
```

**Changes:**
- ✅ **Automatic app_name extraction** from `metadata.name`
- ✅ **App-specific versioning** - each app has independent version sequence
- ✅ **App-specific draft management** - one draft per app

### **3. Policy Publishing**
```http
POST /v1/policy/publish
```

**Changes:**
- ✅ **App-specific publish** - only affects the app from the draft
- ✅ **App-specific activation** - other apps remain unaffected
- ✅ **Independent lifecycle** - each app can be published/reverted separately

### **4. Policy Revocation**
```http
POST /v1/policy/revoke?app_name=user-service
```

**Changes:**
- ✅ **Required `app_name` parameter** for granular revocation
- ✅ **App-specific revocation** - only affects specified app
- ✅ **Other apps unaffected** - surgical policy control

**Examples:**
```bash
# Revoke specific app policy
curl -X POST "/v1/policy/revoke?app_name=user-service"

# Each app must be revoked separately
curl -X POST "/v1/policy/revoke?app_name=billing-service"
curl -X POST "/v1/policy/revoke?app_name=notification-service"
```

## 🔄 Migration Process

### **Step 1: Run Schema Migration**
```sql
-- Run inside transaction
\i migrations/add_app_name_field.sql
```

### **Step 2: Create Indexes**
```sql  
-- Run outside transaction (concurrent)
\i migrations/add_app_name_indexes.sql
```

### **Step 3: Update Existing Policies**
Existing policies will be automatically backfilled:
- **If `metadata.name` exists** → Use as `app_name`
- **If missing** → Set to `"default"`

## 📋 Policy Bundle Requirements

### **Updated D2 Schema:**
```yaml
metadata:
  name: "user-service"           # REQUIRED - becomes app_name in DB
  description: "User management" # OPTIONAL  
  expires: "2025-12-01T00:00:00Z" # REQUIRED

policies:
  - role: admin
    permissions: ["*"]
  - role: user  
    permissions: ["user:read", "user:update"]
```

### **Validation:**
- ✅ **`metadata.name` is required** for multi-app support
- ✅ **Automatic sanitization** of app names
- ✅ **Clear error messages** if name is missing

## 🎯 Benefits

### **🔧 Granular Control:**
- **Independent versioning** per app
- **App-specific revocation** for emergency control
- **Separate draft/publish cycles** per app

### **🚀 Operational Flexibility:**
- **Deploy apps independently** without affecting others
- **Rollback specific apps** without global impact  
- **Test policies per app** in isolation

### **📊 Clear Separation:**
- **Logical app boundaries** in policy management
- **Audit trails per app** for compliance
- **Simplified permission debugging** per service

## 🔄 Backward Compatibility

### **Existing APIs:**
- ✅ **`GET /bundle`** → Returns `"default"` app policy
- ✅ **`PUT /draft`** → Creates draft for extracted app name
- ✅ **`POST /publish`** → Publishes the app from draft

### **SDK Changes Required:**
- ✅ **Add `app_name` parameter** to bundle requests
- ✅ **Update revocation handling** to specify app
- ✅ **Handle app-specific 404s** gracefully

## 🚨 Important Notes

1. **Migration Required:** Run the schema migration before deploying
2. **Breaking Change:** Revocation now requires `app_name` parameter  
3. **SDK Updates:** Client libraries need app-aware functionality
4. **Monitoring:** Update alerts for app-specific policy failures

## 🎉 Example Multi-App Setup

```bash
# Upload policies for different apps
curl -X PUT "/v1/policy/draft" -d '{
  "bundle": {
    "metadata": {"name": "user-service", "expires": "2025-12-01T00:00:00Z"},
    "policies": [{"role": "admin", "permissions": ["user:*"]}]
  }
}'

curl -X PUT "/v1/policy/draft" -d '{
  "bundle": {
    "metadata": {"name": "billing-service", "expires": "2025-12-01T00:00:00Z"}, 
    "policies": [{"role": "admin", "permissions": ["billing:*"]}]
  }
}'

# Publish each app independently
curl -X POST "/v1/policy/publish"  # Publishes whatever app is in draft

# Retrieve app-specific policies
curl "/v1/policy/bundle?app_name=user-service"
curl "/v1/policy/bundle?app_name=billing-service"

# Revoke specific app if needed
curl -X POST "/v1/policy/revoke?app_name=user-service"
# billing-service remains active!
```

Your policy system now supports **true multi-tenancy at the application level**! 🚀

