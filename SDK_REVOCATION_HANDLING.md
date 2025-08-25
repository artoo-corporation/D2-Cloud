# SDK Policy Revocation Handling - Implementation Guide

## 🚨 Overview

The D2 Cloud policy system supports **emergency policy revocation**. When a policy is revoked, the SDK must handle this gracefully to maintain system stability.

## 🔄 Revocation Flow

### 1. **Admin Revokes Policy**
```bash
POST /v1/policy/revoke
# Revokes the currently active published policy
```

### 2. **SDK Requests Bundle**
```javascript
const response = await fetch('/v1/policy/bundle', {
  headers: { 'Authorization': `Bearer ${token}` }
});
```

### 3. **Backend Returns HTTP 410 Gone**
```http
HTTP/1.1 410 Gone
Content-Type: application/json

{
  "detail": "Policy revoked"
}
```

## ✅ Required SDK Behavior

### **CRITICAL: Fail Open on Revocation**

When you receive a `410 Gone` response, the SDK **MUST** fail open:

```javascript
async function fetchPolicyBundle() {
  try {
    const response = await fetch('/v1/policy/bundle');
    
    if (response.status === 410) {
      // POLICY REVOKED - FAIL OPEN
      console.warn('Policy revoked, falling back to default permissions');
      return getDefaultPermissions(); // Returns empty permissions object
    }
    
    if (!response.ok) {
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }
    
    return await response.json();
    
  } catch (error) {
    // Network errors, parsing errors, etc. - also fail open
    console.warn('Policy fetch failed, falling back to default permissions:', error);
    return getDefaultPermissions();
  }
}

function getDefaultPermissions() {
  // Return empty permissions - default-deny engine will handle this
  return {
    permissions: {},
    roles: {},
    metadata: { name: "fallback", revoked: true }
  };
}
```

## 🎯 Why Fail Open?

1. **System Stability** - Revocation shouldn't break running services
2. **Emergency Safety** - Admins can revoke without causing outages  
3. **Default-Deny Architecture** - Empty permissions = everything denied (secure)
4. **Graceful Degradation** - Services continue with minimal permissions

## 🔧 Implementation Checklist

- [ ] **Detect 410 status** and handle specifically (not as generic error)
- [ ] **Log revocation events** for monitoring/alerting
- [ ] **Return empty permissions** (not cached/stale data)
- [ ] **Clear any cached policies** when revocation detected
- [ ] **Implement retry logic** with backoff for recovery
- [ ] **Test revocation scenarios** in your test suite

## 📝 Example Complete Implementation

```javascript
class PolicyClient {
  async getPermissions(userRole) {
    try {
      const bundle = await this.fetchWithRetry();
      
      if (bundle.metadata?.revoked) {
        return this.getDefaultPermissions();
      }
      
      return this.extractPermissions(bundle, userRole);
      
    } catch (error) {
      if (error.status === 410) {
        console.warn('Policy revoked - using default permissions');
        this.clearCache();
        return this.getDefaultPermissions();
      }
      
      // Other errors - also fail open
      console.error('Policy fetch failed:', error);
      return this.getDefaultPermissions();
    }
  }
  
  getDefaultPermissions() {
    return {
      permissions: [],
      wildcard: false,
      revoked: true
    };
  }
  
  clearCache() {
    localStorage.removeItem('policy_bundle');
    localStorage.removeItem('policy_etag');
  }
}
```

## 🚨 Important Notes

1. **Never cache revoked policies** - always fetch fresh after revocation
2. **Don't retry 410 errors** immediately - they're intentional  
3. **Monitor revocation events** - they should be rare and logged
4. **Document the behavior** for your application teams
5. **Test emergency scenarios** regularly

## 🔄 Recovery Flow

After revocation, normal flow resumes when a new policy is published:

1. **Admin publishes new policy** → New active policy available
2. **SDK next request** → Gets new policy bundle (200 OK)
3. **Normal operations resume** → Full permissions restored

## 🎯 Key Takeaway

**Policy revocation is an emergency brake** - your SDK should handle it gracefully by failing open, which works perfectly with the default-deny policy engine architecture!

