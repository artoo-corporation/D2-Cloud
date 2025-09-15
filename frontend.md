# D2 Cloud Platform - Frontend Guide

*Last updated: 2025-09-08*

## 🌟 Welcome to D2 Cloud

D2 Cloud is a comprehensive policy management platform that helps you control access and permissions across your applications. This guide explains everything you need to know as a customer using our web interface.

## 📋 Table of Contents

- [Getting Started](#getting-started)
- [Subscription Plans & Quotas](#subscription-plans--quotas)
- [User Roles & Permissions](#user-roles--permissions)
- [Policy Management](#policy-management)
- [Team Collaboration](#team-collaboration)
- [API Tokens](#api-tokens)
- [Monitoring & Analytics](#monitoring--analytics)
- [Common Workflows](#common-workflows)
- [Troubleshooting](#troubleshooting)

---

## 🚀 Getting Started

### What is D2 Cloud?

D2 Cloud helps you:
- **Define policies** that control who can access what in your applications
- **Manage multiple apps** from a single dashboard
- **Collaborate with your team** on policy development
- **Monitor access patterns** and security events
- **Integrate with your existing systems** via SDKs and APIs

### First Steps

1. **Sign up** with OAuth (Google, GitHub, etc.)
2. **Create your organization** - you'll automatically become the owner
3. **Choose your subscription plan** based on your needs
4. **Invite team members** to collaborate
5. **Create your first policy** for an application

---

## 💰 Subscription Plans & Quotas

### Available Plans

| Feature | Free | Essentials | Pro | Enterprise |
|---------|------|------------|-----|------------|
| **Price** | $0/month | $99/month | $250/month | Custom |
| **Published Apps** | 1 | 5 | 25 | 1000 |
| **Draft Policies** | Unlimited | Unlimited | Unlimited | Unlimited |
| **Team Members** | 3 | 10 | 50 | Unlimited |
| **Policy Refresh Rate** | 5 minutes | 1 minute | 30 seconds | 10 seconds |
| **Event Storage** | 7 days | 30 days | 90 days | 1 year |
| **Support** | Community | Email | Priority | Dedicated |

### Understanding Quotas

#### **App Limits**
- **What counts**: Only **published** policies count toward your app limit
- **What doesn't count**: Draft policies are unlimited on all plans
- **Example**: On the Free plan, you can create drafts for 100 different apps, but only publish policies for 1 app

#### **Policy Refresh Rate**
- **What it means**: How often your applications check for policy updates
- **Impact**: Lower refresh rates mean faster response to policy changes
- **Override**: Enterprise customers can set custom refresh rates per application

#### **Event Storage**
- **What it tracks**: Access attempts, policy decisions, security events
- **Retention**: How long we keep your audit logs and analytics data
- **Usage**: Longer retention helps with compliance and security analysis

### Quota Management

When you reach a limit:
- **Apps**: You'll get a clear error message when trying to publish beyond your limit
- **Storage**: Older events are automatically purged based on your plan
- **Team**: Invitation links will be disabled when you reach your member limit

**Upgrading**: You can upgrade your plan anytime - changes take effect immediately.

---

## 👥 User Roles & Permissions

### Role Hierarchy

#### **Owner** 👑
- **One per organization** - cannot be changed via the interface
- **Full control**: All admin privileges plus billing and plan management
- **Account management**: Can delete the organization
- **Automatic assignment**: The first person to create the organization

#### **Admin** 🛡️
- **Team management**: Invite users, change roles (except owner)
- **Full policy control**: Create, edit, publish, and revoke policies
- **Token management**: Create and manage API tokens
- **Settings access**: Configure organization settings and integrations

#### **Dev** 💻
- **Policy development**: Create and edit draft policies
- **Publishing**: Publish policies to production
- **Key management**: Upload and manage signing keys
- **Limited access**: Cannot manage users or organization settings

#### **Member** 📖
- **Read-only access**: View policies and analytics
- **No editing**: Cannot create or modify policies
- **Basic monitoring**: Access to basic usage statistics

### Role Management

**Changing Roles**:
- Admins and owners can promote/demote users
- Cannot assign or remove the owner role
- Role changes take effect immediately

**Best Practices**:
- Give developers `dev` role for day-to-day policy work
- Limit `admin` role to team leads and senior developers
- Use `member` role for stakeholders who need visibility but not editing access

---

## 📝 Policy Management

### What Are Policies?

Policies define **who can do what** in your applications. They consist of:
- **App Name**: Which application this policy applies to
- **Roles**: Different user types (e.g., "user", "admin", "guest")
- **Permissions**: What each role can do (e.g., "read", "write", "delete")

### Policy Structure

```json
{
  "metadata": {
    "name": "my-web-app",
    "description": "Main web application policies"
  },
  "policies": [
    {
      "role": "user",
      "permissions": ["read", "comment"]
    },
    {
      "role": "admin", 
      "permissions": ["read", "write", "delete", "manage_users"]
    }
  ]
}
```

### Policy Lifecycle

#### **1. Draft Phase** ✏️
- **Unlimited drafts**: Create as many draft policies as needed
- **No impact**: Draft policies don't affect your live applications
- **Collaboration**: Team members can review and edit drafts
- **Validation**: System ensures all required fields are present

#### **2. Publishing** 🚀
- **Goes live**: Published policies are immediately available to your applications
- **Quota enforcement**: Publishing counts toward your app limit
- **Automatic expiry**: Policies automatically expire and refresh every week
- **Version control**: Each publish creates a new version

#### **3. Active Monitoring** 📊
- **Real-time updates**: Applications poll for policy changes
- **Auto-refresh**: Expired policies are automatically extended
- **Event tracking**: All policy decisions are logged for analysis

### Policy Editor Features

**Smart Validation**:
- Real-time validation as you type
- Clear error messages for missing or invalid fields
- Suggestions for common permission patterns

**Version History**:
- See all previous versions of your policies
- Compare changes between versions
- Revert to previous versions if needed

**Collaboration Tools**:
- Comments and annotations on policies
- Review workflows for team approval
- Change notifications via email/Slack

### Required Fields

Every policy must include:
- ✅ **App name** (`metadata.name`) - cannot be empty
- ✅ **At least one role** - each policy needs roles defined
- ✅ **At least one permission per role** - roles must have permissions
- ✅ **Valid JSON structure** - properly formatted policy document

**Server-Managed Fields**:
- **Expiry date**: Always set to 1 week from submission (client values ignored)
- **Version number**: Automatically incremented on each publish
- **Timestamps**: Creation and modification times tracked automatically

---

## 🤝 Team Collaboration

### Inviting Team Members

1. **Navigate to Team Settings**
2. **Click "Invite Member"**
3. **Enter email address**
4. **Select role** (Admin or Dev)
5. **Send invitation**

The invitee receives a secure link to join your organization.

### Invitation Management

**Pending Invitations**:
- View all sent invitations
- Cancel invitations before they're accepted
- Resend invitations if needed

**Active Members**:
- See all team members and their roles
- Change member roles (Admin/Owner only)
- Remove team members from the organization

### Collaboration Features

**Policy Reviews**:
- Request reviews before publishing critical policies
- Add comments and suggestions on policy drafts
- Track who made what changes and when

**Activity Feed**:
- See recent policy changes across all apps
- Monitor team member activity
- Get notified of important changes

**Shared Workspaces**:
- Organize policies by project or team
- Set up role-based access to different policy groups
- Create templates for common policy patterns

---

## 🔑 API Tokens

### Token Types

#### **Development Tokens** 🛠️
- **Purpose**: Local development and testing
- **Scope**: `dev` - can create drafts and publish policies
- **Usage**: CLI tools, local development environments
- **Security**: Keep secure, rotate regularly

#### **Server Tokens** 🖥️
- **Purpose**: Production applications fetching policies
- **Scope**: `server` - can read policies and send events
- **Usage**: Your live applications use these to get policy updates
- **Security**: Tied to specific apps, automatically rotated

#### **Admin Tokens** 👑
- **Purpose**: Administrative automation and integrations
- **Scope**: `admin` - full access to all resources
- **Usage**: CI/CD pipelines, administrative scripts
- **Security**: Highest privilege level, use sparingly

### Token Management

**Creating Tokens**:
1. Go to **API Tokens** section
2. Click **"Create New Token"**
3. Choose token type and scope
4. Assign to specific app (for server tokens)
5. Copy token immediately (shown only once)

**Security Best Practices**:
- Store tokens securely (environment variables, secret managers)
- Rotate tokens regularly (every 90 days recommended)
- Use least-privilege principle (don't use admin tokens for server access)
- Monitor token usage in the activity logs

**Token Rotation**:
- Generate new token value while keeping same permissions
- Update your applications with new token
- Old token is immediately revoked

---

## 📊 Monitoring & Analytics

### Dashboard Overview

**Key Metrics**:
- Total policies across all apps
- Policy refresh rate and performance
- Team activity and collaboration stats
- Quota usage across all plan limits

**Real-time Status**:
- Which apps are currently active
- Recent policy changes and their impact
- System health and performance indicators

### Event Tracking

**What We Track**:
- Every access decision made by your applications
- Policy refresh events and timing
- User actions in the dashboard
- System errors and performance issues

**Event Types**:
- `policy_decision`: When your app allows/denies access
- `policy_refresh`: When apps fetch updated policies
- `user_action`: Dashboard interactions and changes
- `system_event`: Background processes and maintenance

### Analytics & Reporting

**Usage Reports**:
- Which policies are most/least used
- Peak usage times and patterns
- Geographic distribution of access requests
- Performance metrics and response times

**Security Insights**:
- Unusual access patterns
- Failed authorization attempts
- Policy changes that might affect security
- Compliance and audit trail reports

**Custom Dashboards**:
- Create custom views for your specific needs
- Set up alerts for important events
- Export data for external analysis
- Share reports with stakeholders

---

## 🔄 Common Workflows

### Setting Up Your First App

1. **Create Draft Policy**
   - Navigate to Policies → New Policy
   - Enter your app name (e.g., "web-app")
   - Define roles (user, admin, etc.)
   - Add permissions for each role

2. **Test and Validate**
   - Use the policy validator to check syntax
   - Preview how the policy will work
   - Get feedback from team members

3. **Publish to Production**
   - Click "Publish Policy"
   - Policy becomes immediately available
   - Your app can start using it via SDK

4. **Monitor Usage**
   - Check dashboard for policy decisions
   - Monitor performance and errors
   - Adjust policies based on usage patterns

### Adding Team Members

1. **Send Invitations**
   - Team Settings → Invite Member
   - Choose appropriate role for each person
   - Include personal message explaining their role

2. **Onboard New Members**
   - Walk through policy structure
   - Show them how to create drafts
   - Explain review and approval process

3. **Set Up Workflows**
   - Define who can publish to production
   - Create review processes for sensitive changes
   - Set up notifications for important events

### Managing Multiple Apps

1. **Organize by Environment**
   - Use clear naming: "web-app-prod", "web-app-staging"
   - Keep development and production policies separate
   - Use consistent role names across apps

2. **Template Creation**
   - Create policy templates for common patterns
   - Share templates across apps and teams
   - Version control your templates

3. **Bulk Operations**
   - Update multiple apps with similar changes
   - Monitor all apps from single dashboard
   - Set up alerts for cross-app issues

### Handling Emergencies

1. **Policy Rollback**
   - View version history for affected app
   - Identify last known good version
   - Revert to previous version immediately

2. **Emergency Access**
   - Use admin override capabilities
   - Temporarily expand permissions if needed
   - Document emergency actions for audit

3. **Communication**
   - Notify affected team members
   - Update status page if customer-facing
   - Schedule post-incident review

---

## 🔧 Troubleshooting

### Common Issues

#### **"Policy Validation Failed"**
**Cause**: Missing required fields in your policy
**Solution**: 
- Check that `metadata.name` is present and not empty
- Ensure each policy has at least one role
- Verify each role has at least one permission

#### **"Quota Apps Exceeded"**
**Cause**: Trying to publish more apps than your plan allows
**Solution**:
- Upgrade your plan for more apps
- Delete unused published policies
- Use drafts for development (they don't count toward quota)

#### **"Policy Not Found"**
**Cause**: Your application can't find the policy it's looking for
**Solution**:
- Verify the app name matches exactly
- Check that policy is published (not just draft)
- Ensure your server token has correct permissions

#### **"Token Invalid or Expired"**
**Cause**: API token is no longer valid
**Solution**:
- Generate new token in dashboard
- Update your application configuration
- Check token scopes match your usage

### Getting Help

**Documentation**:
- Check this guide for common questions
- Review API documentation for technical details
- Browse example policies and templates

**Support Channels**:
- **Free Plan**: Community forums and documentation
- **Paid Plans**: Email support with response SLA
- **Enterprise**: Dedicated support team and phone support

**Best Practices**:
- Always test policy changes in development first
- Keep backups of critical policies
- Monitor your applications after policy changes
- Set up alerts for unusual patterns

### Performance Optimization

**Policy Design**:
- Keep policies simple and focused
- Avoid overly complex permission structures
- Use clear, descriptive role and permission names

**Application Integration**:
- Cache policy decisions when appropriate
- Use efficient polling intervals
- Monitor SDK performance metrics

**Team Workflows**:
- Establish clear review processes
- Use staging environments for testing
- Document policy decisions and rationales

---

## 🎯 Next Steps

### Getting the Most from D2 Cloud

1. **Start Small**: Begin with one application and simple policies
2. **Expand Gradually**: Add more apps and team members over time
3. **Monitor Actively**: Use analytics to understand usage patterns
4. **Iterate Often**: Refine policies based on real-world usage
5. **Engage Support**: Don't hesitate to ask questions and get help

### Advanced Features

As you grow more comfortable with D2 Cloud:
- Set up automated policy testing
- Integrate with your CI/CD pipelines
- Create custom dashboards and reports
- Explore enterprise features like SSO and compliance tools

### Stay Updated

- Subscribe to our changelog for new features
- Join our community for tips and best practices
- Follow our blog for policy management insights
- Attend webinars and training sessions

---

## 📞 Support & Resources

- **Documentation**: [docs.d2cloud.com](https://docs.d2cloud.com)
- **Community Forum**: [community.d2cloud.com](https://community.d2cloud.com)
- **Status Page**: [status.d2cloud.com](https://status.d2cloud.com)
- **Support Email**: support@d2cloud.com
- **Sales**: sales@d2cloud.com

---

*This guide is regularly updated. Last revision: September 8, 2025*
