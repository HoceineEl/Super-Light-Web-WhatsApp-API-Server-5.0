# WhatsApp Groups API Documentation

## Overview

This document describes the WhatsApp Groups API endpoints that allow you to interact with WhatsApp groups through your connected Baileys REST API sessions. These endpoints provide comprehensive group management functionality including listing groups, managing participants, generating invite links, and sending messages.

## Authentication

All group endpoints require authentication using Bearer token that corresponds to your session:

```
Authorization: Bearer YOUR_SESSION_TOKEN
```

You can get your session token when creating a session via `POST /api/v1/sessions`.

## Prerequisites

- Session must be in `CONNECTED` state
- WhatsApp account must be linked to the session
- For admin operations (like generating invite links), the account must have admin privileges in the target group

## Group Endpoints

### Group Information Endpoints

#### 1. Get All Groups

Retrieve all WhatsApp groups that the session account is part of with caching support.

**Endpoint:** `GET /api/v1/sessions/:sessionId/groups`

**Response:**

```json
{
  "status": "success",
  "groups": [
    {
      "id": "120363123456789@g.us",
      "name": "Family Group",
      "description": "Family chat group",
      "createdAt": 1234567890,
      "owner": "1234567890@s.whatsapp.net",
      "participants": 25,
      "isAnnounce": false,
      "isRestricted": false,
      "isCommunity": false,
      "isCommunityAnnounce": false,
      "joinApprovalMode": false,
      "memberAddMode": "all_member_add",
      "size": 25
    }
  ],
  "count": 1,
  "cached": false
}
```

#### 2. Get Specific Group Details

Get detailed information about a specific group with caching.

**Endpoint:** `GET /api/v1/sessions/:sessionId/groups/:groupId`

**Parameters:**

- `groupId`: Can be either the full JID (120363123456789@g.us) or just the ID (120363123456789)

**Response:**

```json
{
  "status": "success",
  "group": {
    "id": "120363123456789@g.us",
    "name": "Family Group",
    "description": "Family chat group",
    "descriptionId": "123456",
    "createdAt": 1234567890,
    "owner": "1234567890@s.whatsapp.net",
    "subjectOwner": "1234567890@s.whatsapp.net",
    "subjectTime": 1234567890,
    "descOwner": "1234567890@s.whatsapp.net",
    "descTime": 1234567890,
    "isAnnounce": false,
    "isRestricted": false,
    "isCommunity": false,
    "isCommunityAnnounce": false,
    "joinApprovalMode": false,
    "memberAddMode": false,
    "participants": [
      {
        "id": "1234567890@s.whatsapp.net",
        "admin": "admin",
        "isAdmin": true,
        "isSuperAdmin": false
      }
    ],
    "ephemeralDuration": null
  }
}
```

#### 3. Get Group Participants

Get the list of all participants in a group.

**Endpoint:** `GET /api/v1/sessions/:sessionId/groups/:groupId/participants`

**Response:**

```json
{
  "status": "success",
  "groupId": "120363123456789@g.us",
  "groupName": "Family Group",
  "participants": [
    {
      "id": "1234567890@s.whatsapp.net",
      "number": "1234567890",
      "admin": "admin",
      "isAdmin": true,
      "isSuperAdmin": false
    },
    {
      "id": "0987654321@s.whatsapp.net",
      "number": "0987654321",
      "admin": null,
      "isAdmin": false,
      "isSuperAdmin": false
    }
  ],
  "count": 2
}
```

#### 4. Get Group Metadata

Get comprehensive metadata about a group including invite link (if available).

**Endpoint:** `GET /api/v1/sessions/:sessionId/groups/:groupId/metadata`

**Response:**

```json
{
  "status": "success",
  "metadata": {
    "id": "120363123456789@g.us",
    "subject": "Family Group",
    "desc": "Family chat group",
    "descId": "123456",
    "creation": 1234567890,
    "owner": "1234567890@s.whatsapp.net",
    "participants": [...],
    "inviteLink": "https://chat.whatsapp.com/AbCdEfGhIjKlMn",
    "participantCount": 25,
    "adminCount": 3,
    "isCurrentUserAdmin": true
  }
}
```

### Group Management Endpoints

#### 5. Create New Group with Advanced Options

Create a new WhatsApp group with participants and advanced settings.

**Endpoint:** `POST /api/v1/sessions/:sessionId/groups`

**Request Body:**

```json
{
  "subject": "My New Group",
  "participants": ["1234567890", "0987654321"],
  "description": "Optional group description",
  "settings": {
    "announcement": false,
    "restricted": true,
    "ephemeralDuration": 604800
  }
}
```

**Settings Options:**

- `announcement`: boolean - Only admins can send messages (default: false)
- `restricted`: boolean - Only admins can edit group info (default: false)
- `ephemeralDuration`: number - Disappearing messages duration in seconds (0 = off, 86400 = 1 day, 604800 = 1 week, 7776000 = 90 days)

**Response:**

```json
{
  "status": "success",
  "message": "Group 'My New Group' created successfully",
  "group": {
    "id": "120363999888777@g.us",
    "name": "My New Group",
    "description": "Optional group description",
    "createdAt": 1640995200,
    "owner": "session_user@s.whatsapp.net",
    "participants": 3,
    "participantDetails": [...],
    "isAnnounce": false,
    "isRestricted": false,
    "isCommunity": false,
    "inviteCode": "AbCdEfGhIjKlMn",
    "created": true
  }
}
```

### Participant Management Endpoints

#### 6. Add Participants to Group

Add new participants to an existing group.

**Endpoint:** `POST /api/v1/sessions/:sessionId/groups/:groupId/participants`

**Request Body:**

```json
{
  "participants": ["1111111111", "2222222222"]
}
```

**Response:**

```json
{
  "status": "success",
  "message": "Added 2 participants to group",
  "results": [
    { "id": "1111111111@s.whatsapp.net", "status": "200" },
    { "id": "2222222222@s.whatsapp.net", "status": "200" }
  ],
  "groupId": "120363123456789@g.us"
}
```

#### 7. Remove Participants from Group

Remove participants from a group.

**Endpoint:** `DELETE /api/v1/sessions/:sessionId/groups/:groupId/participants`

**Request Body:**

```json
{
  "participants": ["1111111111", "2222222222"]
}
```

**Response:**

```json
{
  "status": "success",
  "message": "Removed 2 participants from group",
  "results": [
    { "id": "1111111111@s.whatsapp.net", "status": "200" },
    { "id": "2222222222@s.whatsapp.net", "status": "200" }
  ],
  "groupId": "120363123456789@g.us"
}
```

#### 8. Promote/Demote Participant

Promote a participant to admin or demote from admin.

**Endpoint:** `PUT /api/v1/sessions/:sessionId/groups/:groupId/participants/:participantId`

**Request Body:**

```json
{
  "action": "promote"
}
```

**Response:**

```json
{
  "status": "success",
  "message": "Participant promoted successfully",
  "result": { "id": "1234567890@s.whatsapp.net", "status": "200" },
  "groupId": "120363123456789@g.us",
  "participantId": "1234567890@s.whatsapp.net",
  "action": "promote"
}
```

#### 9. Bulk Add Participants to Group

Add multiple participants to a group in batches with rate limiting.

**Endpoint:** `POST /api/v1/sessions/:sessionId/groups/:groupId/participants/bulk`

**Request Body:**

```json
{
  "participants": ["1111111111", "2222222222", "3333333333", "4444444444"]
}
```

**Response:**

```json
{
  "status": "success",
  "message": "Bulk participant operation completed",
  "groupId": "120363123456789@g.us",
  "totalProcessed": 4,
  "successful": 3,
  "failed": 1,
  "results": [
    {
      "participant": "1111111111@s.whatsapp.net",
      "status": "added",
      "result": {}
    },
    {
      "participant": "2222222222@s.whatsapp.net",
      "status": "added",
      "result": {}
    },
    {
      "participant": "3333333333@s.whatsapp.net",
      "status": "added",
      "result": {}
    }
  ],
  "errors": [{ "participant": "4444444444", "error": "User not found" }]
}
```

#### 10. Bulk Remove Participants from Group

Remove multiple participants from a group in batches.

**Endpoint:** `DELETE /api/v1/sessions/:sessionId/groups/:groupId/participants/bulk`

**Request Body:**

```json
{
  "participants": ["1111111111", "2222222222"]
}
```

**Response:**

```json
{
  "status": "success",
  "message": "Bulk participant removal completed",
  "groupId": "120363123456789@g.us",
  "totalProcessed": 2,
  "successful": 2,
  "failed": 0,
  "results": [
    {
      "participant": "1111111111@s.whatsapp.net",
      "status": "removed",
      "result": {}
    },
    {
      "participant": "2222222222@s.whatsapp.net",
      "status": "removed",
      "result": {}
    }
  ]
}
```

#### 11. Bulk Promote Participants to Admin

Promote multiple participants to admin role.

**Endpoint:** `PUT /api/v1/sessions/:sessionId/groups/:groupId/participants/bulk/promote`

**Request Body:**

```json
{
  "participants": ["1111111111", "2222222222"]
}
```

**Response:**

```json
{
  "status": "success",
  "message": "Bulk participant promotion completed",
  "groupId": "120363123456789@g.us",
  "totalProcessed": 2,
  "successful": 2,
  "failed": 0,
  "results": [
    {
      "participant": "1111111111@s.whatsapp.net",
      "status": "promoted",
      "result": {}
    },
    {
      "participant": "2222222222@s.whatsapp.net",
      "status": "promoted",
      "result": {}
    }
  ]
}
```

#### 12. Bulk Demote Participants from Admin

Demote multiple participants from admin role.

**Endpoint:** `PUT /api/v1/sessions/:sessionId/groups/:groupId/participants/bulk/demote`

**Request Body:**

```json
{
  "participants": ["1111111111", "2222222222"]
}
```

**Response:**

```json
{
  "status": "success",
  "message": "Bulk participant demotion completed",
  "groupId": "120363123456789@g.us",
  "totalProcessed": 2,
  "successful": 2,
  "failed": 0,
  "results": [
    {
      "participant": "1111111111@s.whatsapp.net",
      "status": "demoted",
      "result": {}
    },
    {
      "participant": "2222222222@s.whatsapp.net",
      "status": "demoted",
      "result": {}
    }
  ]
}
```

### Group Settings Endpoints

#### 13. Update Group Settings

Update various group settings like announcement mode, member permissions, etc.

**Endpoint:** `PUT /api/v1/sessions/:sessionId/groups/:groupId/settings`

**Request Body:**

```json
{
  "setting": "announcement",
  "value": "on"
}
```

**Valid Settings:**

- `announcement`: "on" | "off" (admin-only messages)
- `locked`: "on" | "off" (admin-only settings changes)
- `memberAddMode`: "all_member_add" | "admin_add"
- `joinApprovalMode`: "on" | "off"
- `ephemeral`: 0 | 86400 | 604800 | 7776000 (off, 1 day, 1 week, 90 days)

**Response:**

```json
{
  "status": "success",
  "message": "Group announcement updated to on",
  "setting": "announcement",
  "value": "on",
  "groupId": "120363123456789@g.us",
  "result": {}
}
```

#### 14. Update Group Subject (Name)

Change the group's name/subject.

**Endpoint:** `PUT /api/v1/sessions/:sessionId/groups/:groupId/subject`

**Request Body:**

```json
{
  "subject": "New Group Name"
}
```

**Response:**

```json
{
  "status": "success",
  "message": "Group subject updated to 'New Group Name'",
  "groupId": "120363123456789@g.us",
  "newSubject": "New Group Name"
}
```

#### 15. Update Group Description

Change the group's description.

**Endpoint:** `PUT /api/v1/sessions/:sessionId/groups/:groupId/description`

**Request Body:**

```json
{
  "description": "New group description"
}
```

**Response:**

```json
{
  "status": "success",
  "message": "Group description updated successfully",
  "groupId": "120363123456789@g.us",
  "newDescription": "New group description"
}
```

#### 16. Leave Group

Leave a group (removes the current user from the group).

**Endpoint:** `POST /api/v1/sessions/:sessionId/groups/:groupId/leave`

**Response:**

```json
{
  "status": "success",
  "message": "Successfully left the group",
  "groupId": "120363123456789@g.us"
}
```

### Invite System Endpoints

#### 17. Generate Group Invite Link

Generate an invite link for a group (requires admin privileges).

**Endpoint:** `POST /api/v1/sessions/:sessionId/groups/:groupId/invite`

**Response:**

```json
{
  "status": "success",
  "groupId": "120363123456789@g.us",
  "inviteCode": "AbCdEfGhIjKlMn",
  "inviteLink": "https://chat.whatsapp.com/AbCdEfGhIjKlMn"
}
```

#### 18. Revoke and Regenerate Invite Link

Revoke the current invite link and generate a new one.

**Endpoint:** `DELETE /api/v1/sessions/:sessionId/groups/:groupId/invite`

**Response:**

```json
{
  "status": "success",
  "message": "Group invite link revoked and new one generated",
  "groupId": "120363123456789@g.us",
  "newInviteCode": "XyZaBcDeF12345",
  "newInviteLink": "https://chat.whatsapp.com/XyZaBcDeF12345"
}
```

#### 19. Get Group Info from Invite Code

Get information about a group using its invite code without joining.

**Endpoint:** `GET /api/v1/sessions/:sessionId/groups/invite/:inviteCode`

**Response:**

```json
{
  "status": "success",
  "inviteCode": "AbCdEfGhIjKlMn",
  "groupInfo": {
    "id": "120363123456789@g.us",
    "subject": "Family Group",
    "owner": "1234567890@s.whatsapp.net",
    "creation": 1234567890,
    "size": 25,
    "desc": "Family chat group",
    "participants": [],
    "subjectOwner": "1234567890@s.whatsapp.net",
    "subjectTime": 1234567890
  }
}
```

#### 20. Join Group via Invite Code

Join a group using its invite code.

**Endpoint:** `POST /api/v1/sessions/:sessionId/groups/join/:inviteCode`

**Response:**

```json
{
  "status": "success",
  "message": "Successfully joined group",
  "inviteCode": "AbCdEfGhIjKlMn",
  "groupId": "120363123456789@g.us"
}
```

#### 21. Accept V4 Group Invite

Accept a GroupInviteMessage (V4 invite system).

**Endpoint:** `POST /api/v1/sessions/:sessionId/groups/accept-invite-v4`

**Request Body:**

```json
{
  "key": "message_key_object",
  "inviteMessage": "group_invite_message_object"
}
```

**Response:**

```json
{
  "status": "success",
  "message": "Successfully accepted V4 group invite",
  "result": "120363123456789@g.us"
}
```

#### 22. Revoke V4 Invite for Participant

Revoke a V4 invite for a specific participant.

**Endpoint:** `DELETE /api/v1/sessions/:sessionId/groups/:groupId/invite-v4/:participantId`

**Response:**

```json
{
  "status": "success",
  "message": "Successfully revoked V4 invite for participant",
  "groupId": "120363123456789@g.us",
  "participantId": "1234567890@s.whatsapp.net"
}
```

### Join Request Management Endpoints

#### 23. Get Pending Join Requests

Get list of pending join requests for a group.

**Endpoint:** `GET /api/v1/sessions/:sessionId/groups/:groupId/requests`

**Response:**

```json
{
  "status": "success",
  "groupId": "120363123456789@g.us",
  "requests": [
    {
      "jid": "1111111111@s.whatsapp.net",
      "timestamp": 1640995200
    },
    {
      "jid": "2222222222@s.whatsapp.net",
      "timestamp": 1640995300
    }
  ],
  "count": 2
}
```

#### 24. Approve/Reject Join Requests

Approve or reject pending join requests.

**Endpoint:** `PUT /api/v1/sessions/:sessionId/groups/:groupId/requests`

**Request Body:**

```json
{
  "participants": ["1111111111", "2222222222"],
  "action": "approve"
}
```

**Response:**

```json
{
  "status": "success",
  "message": "Approved 2 join requests",
  "groupId": "120363123456789@g.us",
  "action": "approve",
  "results": [
    { "id": "1111111111@s.whatsapp.net", "status": "200" },
    { "id": "2222222222@s.whatsapp.net", "status": "200" }
  ]
}
```

## Sending Messages to Groups

You can send messages to groups using the existing messages endpoint with the group ID:

**Endpoint:** `POST /api/v1/messages?sessionId=YOUR_SESSION`

**Request Body:**

```json
{
  "recipient_type": "group",
  "to": "120363123456789@g.us",
  "type": "text",
  "text": {
    "body": "Hello Group!"
  }
}
```

Or you can use just the group ID without @g.us:

```json
{
  "recipient_type": "group",
  "to": "120363123456789",
  "type": "text",
  "text": {
    "body": "Hello Group!"
  }
}
```

## Error Handling

All endpoints return consistent error responses:

```json
{
  "status": "error",
  "message": "Descriptive error message"
}
```

### Common Error Codes:

- **`401`**: No authentication token provided
- **`403`**: Invalid token or insufficient permissions
- **`404`**: Session not found, not connected, or group not found
- **`400`**: Invalid parameters or malformed request
- **`500`**: Server error or WhatsApp API error
- **`501`**: Group functionality not available in this Baileys version

### Specific Error Scenarios:

- **Session not connected**: Returns 404 when trying to access groups on a disconnected session
- **Invalid group ID**: Returns 500 when group doesn't exist or user isn't a member
- **Admin required**: Returns 403 when trying to generate invite links without admin privileges
- **Rate limiting**: Returns 429 when exceeding 100 requests per minute
- **Baileys compatibility**: Returns 501 if the installed Baileys version doesn't support group operations

## Usage Examples

### Example 1: List all groups and send a message to one

```bash
# Get all groups
curl -X GET \
  http://localhost:3000/api/v1/sessions/mysession/groups \
  -H "Authorization: Bearer YOUR_TOKEN"

# Send message to a specific group
curl -X POST \
  "http://localhost:3000/api/v1/messages?sessionId=mysession" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "recipient_type": "group",
    "to": "120363123456789@g.us",
    "type": "text",
    "text": {
      "body": "Hello everyone!"
    }
  }'
```

### Example 2: Get group details and invite link

```bash
# Get group details
curl -X GET \
  http://localhost:3000/api/v1/sessions/mysession/groups/120363123456789 \
  -H "Authorization: Bearer YOUR_TOKEN"

# Generate invite link (requires admin)
curl -X POST \
  http://localhost:3000/api/v1/sessions/mysession/groups/120363123456789/invite \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Example 3: Complete group workflow

```bash
# Step 1: List all sessions to find a connected one
curl -X GET http://localhost:3000/api/v1/sessions

# Step 2: Get all groups for the connected session
curl -X GET \
  "http://localhost:3000/api/v1/sessions/2/groups" \
  -H "Authorization: Bearer YOUR_TOKEN"

# Step 3: Get detailed info about a specific group
curl -X GET \
  "http://localhost:3000/api/v1/sessions/2/groups/120363123456789" \
  -H "Authorization: Bearer YOUR_TOKEN"

# Step 4: List all participants in the group
curl -X GET \
  "http://localhost:3000/api/v1/sessions/2/groups/120363123456789/participants" \
  -H "Authorization: Bearer YOUR_TOKEN"

# Step 5: Send a message to the group
curl -X POST \
  "http://localhost:3000/api/v1/messages?sessionId=2" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "recipient_type": "group",
    "to": "120363123456789@g.us",
    "type": "text",
    "text": {
      "body": "Hello from the API!"
    }
  }'

# Step 6: Generate invite link (if you're admin)
curl -X POST \
  "http://localhost:3000/api/v1/sessions/2/groups/120363123456789/invite" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Example 4: Working with different message types

```bash
# Send image to group
curl -X POST \
  "http://localhost:3000/api/v1/messages?sessionId=2" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "recipient_type": "group",
    "to": "120363123456789@g.us",
    "type": "image",
    "image": {
      "link": "https://example.com/image.jpg",
      "caption": "Check out this image!"
    }
  }'

# Send document to group
curl -X POST \
  "http://localhost:3000/api/v1/messages?sessionId=2" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "recipient_type": "group",
    "to": "120363123456789@g.us",
    "type": "document",
    "document": {
      "link": "https://example.com/document.pdf",
      "filename": "Important_Document.pdf",
      "mimetype": "application/pdf"
    }
  }'
```

### Example 5: Bulk Participant Operations

```bash
# Bulk add multiple participants to group
curl -X POST \
  "http://localhost:3000/api/v1/sessions/2/groups/120363123456789/participants/bulk" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "participants": ["1111111111", "2222222222", "3333333333", "4444444444"]
  }'

# Bulk promote multiple participants to admin
curl -X PUT \
  "http://localhost:3000/api/v1/sessions/2/groups/120363123456789/participants/bulk/promote" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "participants": ["1111111111", "2222222222"]
  }'

# Bulk remove multiple participants from group
curl -X DELETE \
  "http://localhost:3000/api/v1/sessions/2/groups/120363123456789/participants/bulk" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "participants": ["3333333333", "4444444444"]
  }'
```

### Example 6: Advanced Group Creation

```bash
# Create group with advanced settings
curl -X POST \
  "http://localhost:3000/api/v1/sessions/2/groups" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "subject": "Advanced Group",
    "participants": ["1111111111", "2222222222", "3333333333"],
    "description": "A group with advanced settings",
    "settings": {
      "announcement": false,
      "restricted": true,
      "ephemeralDuration": 604800
    }
  }'
```

## Implementation Notes

### 1. Group ID Format

Group IDs in WhatsApp use the format `xxxxx@g.us`. The API accepts both formats:

- Full format: `120363123456789@g.us`
- Short format: `120363123456789` (automatically converted to full format)

### 2. Permission Requirements

- **Read operations** (listing groups, getting details, participants): Any group member
- **Admin operations** (generating invite links): Requires admin or super admin privileges
- **Message sending**: Any group member (unless group is announcement-only)

### 3. Rate Limiting

- Default: 100 requests per minute per IP
- Authenticated admin users have higher limits
- Rate limits apply to all API endpoints collectively

### 4. Session Management

- All group operations require session to be in `CONNECTED` state
- Sessions auto-disconnect after 24 hours of inactivity
- Maximum 25 concurrent sessions per instance

### 5. Data Freshness

- Group data is fetched in real-time from WhatsApp servers
- No caching is implemented to ensure latest information
- Large groups may take longer to fetch complete participant lists

### 6. Baileys Version Compatibility

The implementation includes fallback methods for different Baileys versions:

- Primary: `groupFetchAllParticipating()` (preferred)
- Fallback 1: `groupsFetchAll()`
- Fallback 2: Manual chat enumeration with `groupMetadata()`

### 7. Error Recovery

- Failed group operations are logged with detailed error messages
- Network timeouts are handled gracefully
- Invalid group IDs return descriptive error messages

### 8. Security Considerations

- All endpoints require valid Bearer token authentication
- Group membership is verified before data access
- Admin privileges are checked for restricted operations
- Input validation prevents injection attacks

### 9. Logging and Monitoring

- All group operations are logged to system logs
- Activity tracking includes user email, session ID, and operation details
- Failed operations include error details for debugging

### 10. Bulk Operations

The API now supports efficient bulk operations for participant management:

- **Batch Processing**: Operations are processed in batches of 10 participants to avoid rate limits
- **Rate Limiting**: Automatic delays between batches (1 second) and individual operations (500ms for promote/demote)
- **Error Handling**: Individual error tracking per participant with detailed success/failure reporting
- **Progress Tracking**: Real-time status reporting with counts of successful and failed operations

### 11. Performance Tips

- Use specific group detail endpoints instead of fetching all groups when possible
- Cache group IDs on client side to reduce API calls
- Use bulk operations for multiple participant changes instead of individual requests
- Monitor the errors array in bulk operation responses for failed participants
