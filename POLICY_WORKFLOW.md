# Policy Draft to Publish Workflow

## 🔄 **Complete Policy Lifecycle**

### **1. Draft Creation/Update**
```bash
PUT /v1/policy/draft
```
**What happens:**
- ✅ Backend auto-generates next version number
- ✅ Replaces any existing draft (only one draft per account)
- ✅ Version = `max(latest_published, latest_draft) + 1`

**Examples:**
```
Scenario A: No policies exist
→ Creates draft v1

Scenario B: Published v3 exists  
→ Creates draft v4

Scenario C: Published v2, Draft v5 exists
→ Replaces draft v5 with new draft v6
```

### **2. Policy Publishing**
```bash
POST /v1/policy/publish
```
**What happens:**
- ✅ Takes the current draft (only one exists)
- ✅ Signs it with JWS (creates tamper-proof bundle)
- ✅ Converts `is_draft: true` → `is_draft: false`
- ✅ Sets `active: true` (for serving)
- ✅ Deactivates previous active policy (`active: false`)
- ✅ Draft is consumed (becomes published)

### **3. Active Policy Serving**
```bash
GET /v1/policy/bundle
```
**What happens:**
- ✅ Returns the policy where `active = true` 
- ✅ Falls back to latest draft if no published policy
- ✅ Applies security/quota checks

## 📊 **State Transitions**

```
[No Policy] 
    ↓ upload draft
[Draft v1] 
    ↓ publish
[Published v1 (active)] 
    ↓ upload draft  
[Published v1 (active) + Draft v2]
    ↓ publish
[Published v1 (inactive) + Published v2 (active)]
    ↓ upload draft
[Published v1 (inactive) + Published v2 (active) + Draft v3]
```

## 🔄 **Revision Workflow (New Policy from Existing)**

**Question:** *"What happens when we want to draft a separate version of the published policy?"*

**Answer:** The workflow naturally handles this:

### **Scenario: Revise Published Policy**
```
Current State: Published v5 (active)
```

1. **Upload new draft:**
   ```bash
   PUT /v1/policy/draft
   Body: { "bundle": { "new policy content" } }
   ```
   **Result:** Creates Draft v6 (auto-versioned)

2. **Published policy keeps serving:**
   ```bash
   GET /v1/policy/bundle  
   ```
   **Result:** Still returns Published v5 (active)

3. **Publish when ready:**
   ```bash
   POST /v1/policy/publish
   ```
   **Result:** 
   - Draft v6 → Published v6 (active)
   - Published v5 → Published v5 (inactive, retained for rollback)

## 🎯 **Key Benefits**

### **For Developers:**
- ✅ **No version management** - backend handles it automatically
- ✅ **One draft at a time** - no confusion about which draft to publish
- ✅ **Safe iterations** - can keep updating draft without affecting production

### **For Operations:**  
- ✅ **Full version history** - all published versions retained
- ✅ **Instant rollbacks** - can revert to any previous version
- ✅ **Atomic deployments** - publish is all-or-nothing

### **For Security:**
- ✅ **Signed bundles** - JWS prevents tampering
- ✅ **Audit trail** - track who published what when
- ✅ **Policy validation** - checks before publishing

## 🔧 **Backend Implementation Details**

### **Version Calculation:**
```python
latest_draft_version = max_draft_version || 0
latest_published_version = max_published_version || 0  
next_version = max(latest_draft_version, latest_published_version) + 1
```

### **Draft Replacement:**
- Only **one draft** exists per account
- New draft upload **replaces** existing draft
- Version number **always increments**

### **Publishing Process:**
- Draft gets **converted** to published (not copied)
- JWS signature **added** during publish
- Previous active policy **deactivated**
- New policy becomes **active**

This workflow provides a clean, predictable path from draft to production with full version control and rollback capabilities.

