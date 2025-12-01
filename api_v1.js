const express = require("express");
// jidNormalizedUser passed as parameter from index.js (Baileys v7 ESM)
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const { randomUUID } = require("crypto");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const csurf = require("csurf");
const validator = require("validator");
const NodeCache = require("node-cache");
// Remove: const { log } = require('./index');

const router = express.Router();

const webhookUrls = new Map();

const getWebhookUrl = (sessionId) =>
  webhookUrls.get(sessionId) || process.env.WEBHOOK_URL || "";

// Multer setup for file uploads
const mediaDir = path.join(__dirname, "media");
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, mediaDir);
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, `${randomUUID()}${ext}`);
  },
});
const upload = multer({ storage });

function initializeApi(
  sessions,
  sessionTokens,
  createSession,
  getSessionsDetails,
  deleteSession,
  log,
  userManager,
  activityLogger,
  jidNormalizedUser
) {
  // Initialize group metadata cache (5 minutes TTL, no clones for better performance)
  const groupCache = new NodeCache({ stdTTL: 5 * 60, useClones: false });
  
  // Security middlewares
  router.use(helmet());

  // More lenient rate limiter for authenticated dashboard requests
  const apiLimiter = rateLimit({
    windowMs: 1 * 60 * 1000,
    max: 100, // Increased from 30 to 100 requests per minute
    message: {
      status: "error",
      message: "Too many requests, please try again later.",
    },
    skip: (req) => {
      // Skip rate limiting for authenticated admin users
      return req.session && req.session.adminAuthed;
    },
    // Trust proxy headers for proper IP detection
    trustProxy: true,
    standardHeaders: true,
    legacyHeaders: false,
  });

  router.use(apiLimiter);
  // CSRF protection for dashboard and sensitive endpoints (not for API clients)
  // router.use(csurf()); // Uncomment if you want CSRF for all POST/DELETE

  const validateToken = (req, res, next) => {
    const authHeader = req.headers["authorization"];
    const token = authHeader && authHeader.split(" ")[1];

    if (token == null) {
      return res
        .status(401)
        .json({ status: "error", message: "No token provided" });
    }

    const sessionId =
      req.query.sessionId || req.body.sessionId || req.params.sessionId;
    if (sessionId) {
      const expectedToken = sessionTokens.get(sessionId);
      if (expectedToken && token === expectedToken) {
        return next();
      }
    }

    const isAnyTokenValid = Array.from(sessionTokens.values()).includes(token);
    if (isAnyTokenValid) {
      if (sessionId) {
        return res
          .status(403)
          .json({
            status: "error",
            message: `Invalid token for session ${sessionId}`,
          });
      }
      return next();
    }

    return res.status(403).json({ status: "error", message: "Invalid token" });
  };

  // Unprotected routes
  router.post("/sessions", async (req, res) => {
    log("API request", "SYSTEM", {
      event: "api-request",
      method: req.method,
      endpoint: req.originalUrl,
      body: req.body,
    });

    // Get current user from session
    const currentUser =
      req.session && req.session.adminAuthed
        ? {
            email: req.session.userEmail,
            role: req.session.userRole,
          }
        : null;

    // Check if user is authenticated or has master API key
    if (!currentUser) {
      const masterKey = req.headers["x-master-key"];
      const requiredMasterKey = process.env.MASTER_API_KEY;

      if (requiredMasterKey && masterKey !== requiredMasterKey) {
        log("Unauthorized session creation attempt", "SYSTEM", {
          event: "auth-failed",
          endpoint: req.originalUrl,
          ip: req.ip,
        });
        return res.status(401).json({
          status: "error",
          message: "Master API key required for session creation",
        });
      }
    }

    const { sessionId } = req.body;
    if (!sessionId) {
      log("API error", "SYSTEM", {
        event: "api-error",
        error: "sessionId is required",
        endpoint: req.originalUrl,
      });
      return res
        .status(400)
        .json({ status: "error", message: "sessionId is required" });
    }

    // Convert spaces to underscores
    const sanitizedSessionId = sessionId.trim().replace(/\s+/g, "_");

    try {
      // Pass the creator email to createSession
      const creatorEmail = currentUser ? currentUser.email : null;
      await createSession(sanitizedSessionId, creatorEmail);
      const token = sessionTokens.get(sanitizedSessionId);

      // Log activity
      if (currentUser && activityLogger) {
        await activityLogger.logSessionCreate(
          currentUser.email,
          sanitizedSessionId,
          req.ip,
          req.headers["user-agent"]
        );
      }

      log("Session created", sanitizedSessionId, {
        event: "session-created",
        sessionId: sanitizedSessionId,
        createdBy: currentUser ? currentUser.email : "api-key",
      });
      res
        .status(201)
        .json({
          status: "success",
          message: `Session ${sanitizedSessionId} created.`,
          token: token,
        });
    } catch (error) {
      log("API error", "SYSTEM", {
        event: "api-error",
        error: error.message,
        endpoint: req.originalUrl,
      });
      res
        .status(500)
        .json({
          status: "error",
          message: `Failed to create session: ${error.message}`,
        });
    }
  });

  router.get("/sessions", (req, res) => {
    log("API request", "SYSTEM", {
      event: "api-request",
      method: req.method,
      endpoint: req.originalUrl,
    });

    // Get current user from session
    const currentUser =
      req.session && req.session.adminAuthed
        ? {
            email: req.session.userEmail,
            role: req.session.userRole,
          }
        : null;

    if (currentUser) {
      // If authenticated, filter sessions based on role
      res
        .status(200)
        .json(
          getSessionsDetails(currentUser.email, currentUser.role === "admin")
        );
    } else {
      // For API access without authentication, show all sessions (backward compatibility)
      res.status(200).json(getSessionsDetails());
    }
  });

  // Campaign Management Endpoints (Session-based auth, not token-based)
  const CampaignManager = require("./campaigns");
  const CampaignSender = require("./campaign-sender");
  const RecipientListManager = require("./recipient-lists");

  // Initialize campaign manager and sender
  const campaignManager = new CampaignManager(
    process.env.TOKEN_ENCRYPTION_KEY || "default-key"
  );
  const campaignSender = new CampaignSender(
    campaignManager,
    sessions,
    activityLogger
  );
  const recipientListManager = new RecipientListManager(
    process.env.TOKEN_ENCRYPTION_KEY || "default-key"
  );

  // Middleware to check campaign access (session-based)
  const checkCampaignAccess = async (req, res, next) => {
    const currentUser =
      req.session && req.session.adminAuthed
        ? {
            email: req.session.userEmail,
            role: req.session.userRole,
          }
        : null;

    if (!currentUser) {
      return res
        .status(401)
        .json({ status: "error", message: "Authentication required" });
    }

    req.currentUser = currentUser;
    next();
  };

  // Campaign routes - these use session auth, not token auth
  router.get("/campaigns", checkCampaignAccess, (req, res) => {
    const campaigns = campaignManager.getAllCampaigns(
      req.currentUser.email,
      req.currentUser.role === "admin"
    );
    res.json(campaigns);
  });


  router.get("/campaigns/csv-template", checkCampaignAccess, (req, res) => {
    const csvContent = `WhatsApp Number,Name,Job Title,Company Name
+1234567890,John Doe,Sales Manager,ABC Corporation
+0987654321,Jane Smith,Marketing Director,XYZ Company
+1122334455,Bob Johnson,CEO,Startup Inc
+5544332211,Alice Brown,CTO,Tech Solutions
+9988776655,Charlie Davis,Product Manager,Innovation Labs`;

    res.setHeader("Content-Type", "text/csv");
    res.setHeader(
      "Content-Disposition",
      'attachment; filename="whatsapp_campaign_template.csv"'
    );
    res.send(csvContent);
  });


  // Endpoint to get campaigns that should have been started but are still in ready status (MUST be before /:id route)
  router.get("/campaigns/overdue", checkCampaignAccess, (req, res) => {
    try {
      if (!campaignManager) {
        return res
          .status(503)
          .json({ error: "Campaign manager not initialized" });
      }

      const now = new Date();
      const campaigns = campaignManager.getAllCampaigns();

      const overdueCampaigns = campaigns.filter((campaign) => {
        return (
          campaign.status === "ready" &&
          campaign.scheduledAt &&
          new Date(campaign.scheduledAt) <= now
        );
      });

      res.json({
        totalCampaigns: campaigns.length,
        overdueCampaigns: overdueCampaigns.length,
        campaigns: overdueCampaigns.map((c) => ({
          id: c.id,
          name: c.name,
          status: c.status,
          scheduledAt: c.scheduledAt,
          createdAt: c.createdAt,
          minutesOverdue: Math.floor((now - new Date(c.scheduledAt)) / 60000),
        })),
      });
    } catch (error) {
      res.status(500).json({ error: error.message });
    }
  });

  router.get("/campaigns/:id", checkCampaignAccess, (req, res) => {
    const campaign = campaignManager.loadCampaign(req.params.id);
    if (!campaign) {
      return res
        .status(404)
        .json({ status: "error", message: "Campaign not found" });
    }

    // Check access
    if (
      req.currentUser.role !== "admin" &&
      campaign.createdBy !== req.currentUser.email
    ) {
      return res
        .status(403)
        .json({ status: "error", message: "Access denied" });
    }

    res.json(campaign);
  });

  router.post("/campaigns", checkCampaignAccess, async (req, res) => {
    try {
      const campaignData = {
        ...req.body,
        createdBy: req.currentUser.email,
      };

      const campaign = campaignManager.createCampaign(campaignData);

      // Log activity
      await activityLogger.logCampaignCreate(
        req.currentUser.email,
        campaign.id,
        campaign.name,
        campaign.recipients.length
      );

      res.status(201).json(campaign);
    } catch (error) {
      res.status(400).json({ status: "error", message: error.message });
    }
  });

  router.put("/campaigns/:id", checkCampaignAccess, (req, res) => {
    try {
      const campaign = campaignManager.loadCampaign(req.params.id);
      if (!campaign) {
        return res
          .status(404)
          .json({ status: "error", message: "Campaign not found" });
      }

      // Check access
      if (
        req.currentUser.role !== "admin" &&
        campaign.createdBy !== req.currentUser.email
      ) {
        return res
          .status(403)
          .json({ status: "error", message: "Access denied" });
      }

      const updated = campaignManager.updateCampaign(req.params.id, req.body);
      res.json(updated);
    } catch (error) {
      res.status(400).json({ status: "error", message: error.message });
    }
  });

  router.delete("/campaigns/:id", checkCampaignAccess, async (req, res) => {
    const campaign = campaignManager.loadCampaign(req.params.id);
    if (!campaign) {
      return res
        .status(404)
        .json({ status: "error", message: "Campaign not found" });
    }

    // Check access
    if (
      req.currentUser.role !== "admin" &&
      campaign.createdBy !== req.currentUser.email
    ) {
      return res
        .status(403)
        .json({ status: "error", message: "Access denied" });
    }

    campaignManager.deleteCampaign(req.params.id);

    // Log activity
    await activityLogger.logCampaignDelete(
      req.currentUser.email,
      req.params.id,
      campaign.name
    );

    res.json({ status: "success", message: "Campaign deleted" });
  });

  router.post("/campaigns/:id/clone", checkCampaignAccess, async (req, res) => {
    try {
      const cloned = campaignManager.cloneCampaign(
        req.params.id,
        req.currentUser.email
      );
      res.status(201).json(cloned);
    } catch (error) {
      res.status(400).json({ status: "error", message: error.message });
    }
  });

  router.post("/campaigns/:id/send", checkCampaignAccess, async (req, res) => {
    try {
      const result = await campaignSender.startCampaign(
        req.params.id,
        req.currentUser.email
      );
      res.json(result);
    } catch (error) {
      res.status(400).json({ status: "error", message: error.message });
    }
  });

  router.post("/campaigns/:id/pause", checkCampaignAccess, async (req, res) => {
    const result = campaignSender.pauseCampaign(req.params.id);
    if (result) {
      await activityLogger.logCampaignPause(
        req.currentUser.email,
        req.params.id,
        "Campaign paused by user"
      );
      res.json({ status: "success", message: "Campaign paused" });
    } else {
      res
        .status(400)
        .json({ status: "error", message: "Campaign not running" });
    }
  });

  router.post(
    "/campaigns/:id/resume",
    checkCampaignAccess,
    async (req, res) => {
      try {
        const result = await campaignSender.resumeCampaign(
          req.params.id,
          req.currentUser.email
        );
        res.json({ status: "success", message: "Campaign resumed" });
      } catch (error) {
        res.status(400).json({ status: "error", message: error.message });
      }
    }
  );

  router.post("/campaigns/:id/retry", checkCampaignAccess, async (req, res) => {
    try {
      const result = await campaignSender.retryFailed(
        req.params.id,
        req.currentUser.email
      );
      res.json(result);
    } catch (error) {
      res.status(400).json({ status: "error", message: error.message });
    }
  });

  router.get("/campaigns/:id/status", checkCampaignAccess, (req, res) => {
    const status = campaignSender.getCampaignStatus(req.params.id);
    if (!status) {
      return res
        .status(404)
        .json({ status: "error", message: "Campaign not found" });
    }
    res.json(status);
  });

  router.get("/campaigns/:id/export", checkCampaignAccess, (req, res) => {
    const campaign = campaignManager.loadCampaign(req.params.id);
    if (!campaign) {
      return res
        .status(404)
        .json({ status: "error", message: "Campaign not found" });
    }

    // Check access
    if (
      req.currentUser.role !== "admin" &&
      campaign.createdBy !== req.currentUser.email
    ) {
      return res
        .status(403)
        .json({ status: "error", message: "Access denied" });
    }

    const csv = campaignManager.exportResults(req.params.id);
    res.setHeader("Content-Type", "text/csv");
    res.setHeader(
      "Content-Disposition",
      `attachment; filename="${campaign.name}_results.csv"`
    );
    res.send(csv);
  });

  router.post(
    "/campaigns/preview-csv",
    checkCampaignAccess,
    upload.single("file"),
    (req, res) => {
      if (!req.file) {
        return res
          .status(400)
          .json({ status: "error", message: "No file uploaded" });
      }

      try {
        const csvContent = fs.readFileSync(req.file.path, "utf-8");
        const result = campaignManager.parseCSV(csvContent);

        // Clean up uploaded file
        fs.unlinkSync(req.file.path);

        res.json(result);
      } catch (error) {
        // Clean up uploaded file
        if (req.file && fs.existsSync(req.file.path)) {
          fs.unlinkSync(req.file.path);
        }
        res.status(400).json({ status: "error", message: error.message });
      }
    }
  );


  // Recipient List Management Endpoints (Session-based auth, not token-based)

  // Get all recipient lists
  router.get("/recipient-lists", checkCampaignAccess, (req, res) => {
    const lists = recipientListManager.getAllLists(
      req.currentUser.email,
      req.currentUser.role === "admin"
    );
    res.json(lists);
  });

  // Get specific recipient list
  router.get("/recipient-lists/:id", checkCampaignAccess, (req, res) => {
    const list = recipientListManager.loadList(req.params.id);
    if (!list) {
      return res
        .status(404)
        .json({ status: "error", message: "Recipient list not found" });
    }

    // Check access
    if (
      req.currentUser.role !== "admin" &&
      list.createdBy !== req.currentUser.email
    ) {
      return res
        .status(403)
        .json({ status: "error", message: "Access denied" });
    }

    res.json(list);
  });

  // Create new recipient list
  router.post("/recipient-lists", checkCampaignAccess, (req, res) => {
    try {
      const listData = {
        ...req.body,
        createdBy: req.currentUser.email,
      };

      const list = recipientListManager.createList(listData);
      res.status(201).json(list);
    } catch (error) {
      res.status(400).json({ status: "error", message: error.message });
    }
  });

  // Update recipient list
  router.put("/recipient-lists/:id", checkCampaignAccess, (req, res) => {
    try {
      const list = recipientListManager.loadList(req.params.id);
      if (!list) {
        return res
          .status(404)
          .json({ status: "error", message: "Recipient list not found" });
      }

      // Check access
      if (
        req.currentUser.role !== "admin" &&
        list.createdBy !== req.currentUser.email
      ) {
        return res
          .status(403)
          .json({ status: "error", message: "Access denied" });
      }

      const updated = recipientListManager.updateList(req.params.id, req.body);
      res.json(updated);
    } catch (error) {
      res.status(400).json({ status: "error", message: error.message });
    }
  });

  // Delete recipient list
  router.delete("/recipient-lists/:id", checkCampaignAccess, (req, res) => {
    const list = recipientListManager.loadList(req.params.id);
    if (!list) {
      return res
        .status(404)
        .json({ status: "error", message: "Recipient list not found" });
    }

    // Check access
    if (
      req.currentUser.role !== "admin" &&
      list.createdBy !== req.currentUser.email
    ) {
      return res
        .status(403)
        .json({ status: "error", message: "Access denied" });
    }

    const success = recipientListManager.deleteList(req.params.id);
    if (success) {
      res.json({ status: "success", message: "Recipient list deleted" });
    } else {
      res
        .status(500)
        .json({ status: "error", message: "Failed to delete recipient list" });
    }
  });

  // Clone recipient list
  router.post("/recipient-lists/:id/clone", checkCampaignAccess, (req, res) => {
    try {
      const cloned = recipientListManager.cloneList(
        req.params.id,
        req.currentUser.email,
        req.body.name
      );
      res.status(201).json(cloned);
    } catch (error) {
      res.status(400).json({ status: "error", message: error.message });
    }
  });

  // Add recipient to list
  router.post(
    "/recipient-lists/:id/recipients",
    checkCampaignAccess,
    (req, res) => {
      try {
        const list = recipientListManager.loadList(req.params.id);
        if (!list) {
          return res
            .status(404)
            .json({ status: "error", message: "Recipient list not found" });
        }

        // Check access
        if (
          req.currentUser.role !== "admin" &&
          list.createdBy !== req.currentUser.email
        ) {
          return res
            .status(403)
            .json({ status: "error", message: "Access denied" });
        }

        const updated = recipientListManager.addRecipient(
          req.params.id,
          req.body
        );
        res.status(201).json(updated);
      } catch (error) {
        res.status(400).json({ status: "error", message: error.message });
      }
    }
  );

  // Update recipient in list
  router.put(
    "/recipient-lists/:id/recipients/:number",
    checkCampaignAccess,
    (req, res) => {
      try {
        const list = recipientListManager.loadList(req.params.id);
        if (!list) {
          return res
            .status(404)
            .json({ status: "error", message: "Recipient list not found" });
        }

        // Check access
        if (
          req.currentUser.role !== "admin" &&
          list.createdBy !== req.currentUser.email
        ) {
          return res
            .status(403)
            .json({ status: "error", message: "Access denied" });
        }

        const updated = recipientListManager.updateRecipient(
          req.params.id,
          req.params.number,
          req.body
        );
        res.json(updated);
      } catch (error) {
        res.status(400).json({ status: "error", message: error.message });
      }
    }
  );

  // Remove recipient from list
  router.delete(
    "/recipient-lists/:id/recipients/:number",
    checkCampaignAccess,
    (req, res) => {
      try {
        const list = recipientListManager.loadList(req.params.id);
        if (!list) {
          return res
            .status(404)
            .json({ status: "error", message: "Recipient list not found" });
        }

        // Check access
        if (
          req.currentUser.role !== "admin" &&
          list.createdBy !== req.currentUser.email
        ) {
          return res
            .status(403)
            .json({ status: "error", message: "Access denied" });
        }

        const updated = recipientListManager.removeRecipient(
          req.params.id,
          req.params.number
        );
        res.json(updated);
      } catch (error) {
        res.status(400).json({ status: "error", message: error.message });
      }
    }
  );

  // Search recipients across all lists
  router.get(
    "/recipient-lists/search/:query",
    checkCampaignAccess,
    (req, res) => {
      const results = recipientListManager.searchRecipients(
        req.params.query,
        req.currentUser.email,
        req.currentUser.role === "admin"
      );
      res.json(results);
    }
  );

  // Get recipient lists statistics
  router.get("/recipient-lists-stats", checkCampaignAccess, (req, res) => {
    const stats = recipientListManager.getStatistics(
      req.currentUser.email,
      req.currentUser.role === "admin"
    );
    res.json(stats);
  });

  // Mark recipient list as used
  router.post(
    "/recipient-lists/:id/mark-used",
    checkCampaignAccess,
    (req, res) => {
      const list = recipientListManager.loadList(req.params.id);
      if (!list) {
        return res
          .status(404)
          .json({ status: "error", message: "Recipient list not found" });
      }

      // Check access
      if (
        req.currentUser.role !== "admin" &&
        list.createdBy !== req.currentUser.email
      ) {
        return res
          .status(403)
          .json({ status: "error", message: "Access denied" });
      }

      recipientListManager.markAsUsed(req.params.id);
      res.json({ status: "success", message: "List marked as used" });
    }
  );

  // Debug endpoint to check session status
  router.get("/debug/sessions", checkCampaignAccess, (req, res) => {
    const debugInfo = {};
    sessions.forEach((session, sessionId) => {
      debugInfo[sessionId] = {
        status: session.status,
        hasSock: !!session.sock,
        sockConnected: session.sock ? "yes" : "no",
        owner: session.owner,
        detail: session.detail,
      };
    });
    res.json(debugInfo);
  });

  // All routes below this are protected by token
  router.use(validateToken);

  // Simple test endpoint
  router.get("/test/simple/:sessionId", (req, res) => {
    const { sessionId } = req.params;
    const session = sessions.get(sessionId);
    
    if (!session) {
      return res.json({ status: "error", message: "Session not found" });
    }
    
    res.json({ 
      status: "success", 
      sessionId: sessionId,
      hasSession: true,
      hasSock: !!session.sock,
      sessionStatus: session.status
    });
  });

  // Group Management Endpoints

  // Get all groups for a session
  router.get("/sessions/:sessionId/groups", async (req, res) => {
    log("API request", "SYSTEM", {
      event: "api-request",
      method: req.method,
      endpoint: req.originalUrl,
    });
    const { sessionId } = req.params;

    const session = sessions.get(sessionId);
    if (!session || !session.sock || session.status !== "CONNECTED") {
      log("API error", "SYSTEM", {
        event: "api-error",
        error: `Session ${sessionId} not found or not connected.`,
        endpoint: req.originalUrl,
      });
      return res
        .status(404)
        .json({
          status: "error",
          message: `Session ${sessionId} not found or not connected.`,
        });
    }

    try {
      // Check cache first
      const cacheKey = `groups_${sessionId}`;
      let groups = groupCache.get(cacheKey);
      
      if (!groups) {
        // Use the official Baileys method for fetching all participating groups
        log("Fetching groups from WhatsApp servers", sessionId, { 
          event: "groups-fetch-start", 
          sessionId 
        });
        
        groups = await session.sock.groupFetchAllParticipating();
        
        // Cache the results for 5 minutes
        if (groups && Object.keys(groups).length > 0) {
          groupCache.set(cacheKey, groups);
          log("Groups cached", sessionId, { 
            event: "groups-cached", 
            sessionId, 
            count: Object.keys(groups).length 
          });
        }
      } else {
        log("Groups retrieved from cache", sessionId, { 
          event: "groups-cache-hit", 
          sessionId, 
          count: Object.keys(groups).length 
        });
      }
      
      // Handle case where no groups are returned
      if (!groups || Object.keys(groups).length === 0) {
        log("No groups found", sessionId, { 
          event: "groups-fetched", 
          sessionId, 
          count: 0 
        });
        return res.status(200).json({
          status: "success",
          groups: [],
          count: 0,
          message: "No groups found for this session"
        });
      }

      // Format the response with enhanced error handling for each group
      const groupList = [];
      for (const [groupId, group] of Object.entries(groups)) {
        try {
          const formattedGroup = {
            id: group.id || groupId,
            name: group.subject || "Unknown Group",
            description: group.desc || "",
            createdAt: group.creation || null,
            owner: group.owner || null,
            participants: Array.isArray(group.participants) ? group.participants.length : 0,
            isAnnounce: group.announce === true,
            isRestricted: group.restrict === true,
            isCommunity: group.isCommunity === true,
            isCommunityAnnounce: group.isCommunityAnnounce === true,
            joinApprovalMode: group.joinApprovalMode === true,
            memberAddMode: group.memberAddMode || "all_member_add",
            size: group.size || (Array.isArray(group.participants) ? group.participants.length : 0)
          };
          groupList.push(formattedGroup);
        } catch (formatError) {
          log("Error formatting group", sessionId, {
            event: "group-format-error",
            sessionId,
            groupId,
            error: formatError.message
          });
          // Continue with other groups even if one fails
        }
      }

      log("Groups fetched successfully", sessionId, {
        event: "groups-fetched",
        sessionId,
        count: groupList.length,
        cached: !!groupCache.get(cacheKey)
      });
      
      res.status(200).json({
        status: "success",
        groups: groupList,
        count: groupList.length,
        cached: !!groupCache.get(cacheKey)
      });
      
    } catch (error) {
      // Enhanced error handling with more specific error types
      let errorMessage = "Failed to fetch groups";
      let statusCode = 500;
      
      if (error.message.includes("not-authorized") || error.message.includes("unauthorized")) {
        errorMessage = "Session not authorized to access groups";
        statusCode = 403;
      } else if (error.message.includes("rate-limit")) {
        errorMessage = "Rate limit exceeded. Please try again later";
        statusCode = 429;
      } else if (error.message.includes("connection") || error.message.includes("network")) {
        errorMessage = "Network error while fetching groups";
        statusCode = 503;
      }
      
      log("API error", "SYSTEM", {
        event: "api-error",
        error: error.message,
        errorType: error.name || "Unknown",
        endpoint: req.originalUrl,
        sessionId,
        statusCode
      });
      
      console.error(`Failed to fetch groups for ${sessionId}:`, {
        error: error.message,
        stack: error.stack,
        type: error.name
      });
      
      res.status(statusCode).json({
        status: "error",
        message: `${errorMessage}. Reason: ${error.message}`,
        errorType: error.name || "UnknownError"
      });
    }
  });

  // Get specific group details
  router.get("/sessions/:sessionId/groups/:groupId", async (req, res) => {
    log("API request", "SYSTEM", {
      event: "api-request",
      method: req.method,
      endpoint: req.originalUrl,
    });
    const { sessionId, groupId } = req.params;

    const session = sessions.get(sessionId);
    if (!session || !session.sock || session.status !== "CONNECTED") {
      log("API error", "SYSTEM", {
        event: "api-error",
        error: `Session ${sessionId} not found or not connected.`,
        endpoint: req.originalUrl,
      });
      return res
        .status(404)
        .json({
          status: "error",
          message: `Session ${sessionId} not found or not connected.`,
        });
    }

    try {
      // Ensure groupId has correct format
      const formattedGroupId = groupId.includes("@g.us")
        ? groupId
        : `${groupId}@g.us`;

      // Check cache first
      const cacheKey = `group_${sessionId}_${formattedGroupId}`;
      let metadata = groupCache.get(cacheKey);
      
      if (!metadata) {
        log("Fetching group metadata from WhatsApp servers", sessionId, { 
          event: "group-metadata-fetch-start", 
          sessionId, 
          groupId: formattedGroupId 
        });
        
        // Fetch group metadata
        metadata = await session.sock.groupMetadata(formattedGroupId);
        
        // Cache the metadata for 5 minutes
        if (metadata) {
          groupCache.set(cacheKey, metadata);
          log("Group metadata cached", sessionId, { 
            event: "group-metadata-cached", 
            sessionId, 
            groupId: formattedGroupId 
          });
        }
      } else {
        log("Group metadata retrieved from cache", sessionId, { 
          event: "group-metadata-cache-hit", 
          sessionId, 
          groupId: formattedGroupId 
        });
      }

      // Format the response with detailed information
      const groupDetails = {
        id: metadata.id,
        name: metadata.subject,
        description: metadata.desc,
        descriptionId: metadata.descId,
        createdAt: metadata.creation,
        owner: metadata.owner,
        subjectOwner: metadata.subjectOwner,
        subjectTime: metadata.subjectTime,
        descOwner: metadata.descOwner,
        descTime: metadata.descTime,
        isAnnounce: metadata.announce || false,
        isRestricted: metadata.restrict || false,
        isCommunity: metadata.isCommunity || false,
        isCommunityAnnounce: metadata.isCommunityAnnounce || false,
        joinApprovalMode: metadata.joinApprovalMode || false,
        memberAddMode: metadata.memberAddMode || false,
        participants: metadata.participants.map((p) => ({
          id: p.id,
          admin: p.admin || null,
          isAdmin: p.admin === "admin" || p.admin === "superadmin",
          isSuperAdmin: p.admin === "superadmin",
        })),
        ephemeralDuration: metadata.ephemeralDuration,
      };

      log("Group details fetched", sessionId, {
        event: "group-details-fetched",
        sessionId,
        groupId: formattedGroupId,
      });
      res.status(200).json({
        status: "success",
        group: groupDetails,
      });
    } catch (error) {
      log("API error", "SYSTEM", {
        event: "api-error",
        error: error.message,
        endpoint: req.originalUrl,
      });
      console.error(`Failed to fetch group details for ${groupId}:`, error);
      res
        .status(500)
        .json({
          status: "error",
          message: `Failed to fetch group details. Reason: ${error.message}`,
        });
    }
  });

  // Get group participants
  router.get(
    "/sessions/:sessionId/groups/:groupId/participants",
    async (req, res) => {
      log("API request", "SYSTEM", {
        event: "api-request",
        method: req.method,
        endpoint: req.originalUrl,
      });
      const { sessionId, groupId } = req.params;

      const session = sessions.get(sessionId);
      if (!session || !session.sock || session.status !== "CONNECTED") {
        log("API error", "SYSTEM", {
          event: "api-error",
          error: `Session ${sessionId} not found or not connected.`,
          endpoint: req.originalUrl,
        });
        return res
          .status(404)
          .json({
            status: "error",
            message: `Session ${sessionId} not found or not connected.`,
          });
      }

      try {
        const formattedGroupId = groupId.includes("@g.us")
          ? groupId
          : `${groupId}@g.us`;
        const metadata = await session.sock.groupMetadata(formattedGroupId);

        const participants = metadata.participants.map((p) => ({
          id: p.id,
          number: p.id.split("@")[0],
          admin: p.admin || null,
          isAdmin: p.admin === "admin" || p.admin === "superadmin",
          isSuperAdmin: p.admin === "superadmin",
        }));

        log("Group participants fetched", sessionId, {
          event: "group-participants-fetched",
          sessionId,
          groupId: formattedGroupId,
          count: participants.length,
        });
        res.status(200).json({
          status: "success",
          groupId: formattedGroupId,
          groupName: metadata.subject,
          participants: participants,
          count: participants.length,
        });
      } catch (error) {
        log("API error", "SYSTEM", {
          event: "api-error",
          error: error.message,
          endpoint: req.originalUrl,
        });
        console.error(
          `Failed to fetch group participants for ${groupId}:`,
          error
        );
        res
          .status(500)
          .json({
            status: "error",
            message: `Failed to fetch group participants. Reason: ${error.message}`,
          });
      }
    }
  );

  // Get group invite link
  router.post(
    "/sessions/:sessionId/groups/:groupId/invite",
    async (req, res) => {
      log("API request", "SYSTEM", {
        event: "api-request",
        method: req.method,
        endpoint: req.originalUrl,
      });
      const { sessionId, groupId } = req.params;

      const session = sessions.get(sessionId);
      if (!session || !session.sock || session.status !== "CONNECTED") {
        log("API error", "SYSTEM", {
          event: "api-error",
          error: `Session ${sessionId} not found or not connected.`,
          endpoint: req.originalUrl,
        });
        return res
          .status(404)
          .json({
            status: "error",
            message: `Session ${sessionId} not found or not connected.`,
          });
      }

      try {
        const formattedGroupId = groupId.includes("@g.us")
          ? groupId
          : `${groupId}@g.us`;

        // Get the invite code
        const inviteCode = await session.sock.groupInviteCode(formattedGroupId);
        const inviteLink = `https://chat.whatsapp.com/${inviteCode}`;

        log("Group invite link generated", sessionId, {
          event: "group-invite-generated",
          sessionId,
          groupId: formattedGroupId,
        });
        res.status(200).json({
          status: "success",
          groupId: formattedGroupId,
          inviteCode: inviteCode,
          inviteLink: inviteLink,
        });
      } catch (error) {
        log("API error", "SYSTEM", {
          event: "api-error",
          error: error.message,
          endpoint: req.originalUrl,
        });
        console.error(`Failed to generate invite link for ${groupId}:`, error);
        res
          .status(500)
          .json({
            status: "error",
            message: `Failed to generate invite link. Reason: ${error.message}`,
          });
      }
    }
  );

  // Get group metadata (detailed information)
  router.get(
    "/sessions/:sessionId/groups/:groupId/metadata",
    async (req, res) => {
      log("API request", "SYSTEM", {
        event: "api-request",
        method: req.method,
        endpoint: req.originalUrl,
      });
      const { sessionId, groupId } = req.params;

      const session = sessions.get(sessionId);
      if (!session || !session.sock || session.status !== "CONNECTED") {
        log("API error", "SYSTEM", {
          event: "api-error",
          error: `Session ${sessionId} not found or not connected.`,
          endpoint: req.originalUrl,
        });
        return res
          .status(404)
          .json({
            status: "error",
            message: `Session ${sessionId} not found or not connected.`,
          });
      }

      try {
        const formattedGroupId = groupId.includes("@g.us")
          ? groupId
          : `${groupId}@g.us`;

        // Fetch complete metadata
        const metadata = await session.sock.groupMetadata(formattedGroupId);

        // Try to fetch additional info if available
        let inviteCode = null;
        try {
          inviteCode = await session.sock.groupInviteCode(formattedGroupId);
        } catch (inviteError) {
          // User might not have permission to get invite code
          log("Could not fetch invite code", sessionId, {
            event: "invite-code-error",
            error: inviteError.message,
          });
        }

        const fullMetadata = {
          ...metadata,
          inviteLink: inviteCode
            ? `https://chat.whatsapp.com/${inviteCode}`
            : null,
          participantCount: metadata.participants.length,
          adminCount: metadata.participants.filter((p) => p.admin).length,
          isCurrentUserAdmin: metadata.participants.some(
            (p) =>
              p.id === session.sock.user.id &&
              (p.admin === "admin" || p.admin === "superadmin")
          ),
        };

        log("Group metadata fetched", sessionId, {
          event: "group-metadata-fetched",
          sessionId,
          groupId: formattedGroupId,
        });
        res.status(200).json({
          status: "success",
          metadata: fullMetadata,
        });
      } catch (error) {
        log("API error", "SYSTEM", {
          event: "api-error",
          error: error.message,
          endpoint: req.originalUrl,
        });
        console.error(`Failed to fetch group metadata for ${groupId}:`, error);
        res
          .status(500)
          .json({
            status: "error",
            message: `Failed to fetch group metadata. Reason: ${error.message}`,
          });
      }
    }
  );

  // Create a new group with advanced options
  router.post("/sessions/:sessionId/groups", async (req, res) => {
    log("API request", "SYSTEM", {
      event: "api-request",
      method: req.method,
      endpoint: req.originalUrl,
    });
    const { sessionId } = req.params;
    const { subject, participants, description, settings = {} } = req.body;

    // Validate required fields
    if (!subject || typeof subject !== 'string' || subject.trim().length === 0) {
      return res.status(400).json({
        status: "error",
        message: "Group subject (name) is required and must be a non-empty string",
      });
    }

    if (!Array.isArray(participants) || participants.length === 0) {
      return res.status(400).json({
        status: "error",
        message: "Participants array is required and must contain at least one participant",
      });
    }

    // Validate participant format
    const validParticipants = [];
    for (const participant of participants) {
      if (typeof participant !== 'string') {
        return res.status(400).json({
          status: "error",
          message: "Each participant must be a string (phone number)",
        });
      }
      
      // Format participant number
      const formattedParticipant = participant.includes('@s.whatsapp.net') 
        ? participant 
        : `${participant.replace(/[^\d]/g, '')}@s.whatsapp.net`;
      
      if (!formattedParticipant.includes('@s.whatsapp.net')) {
        return res.status(400).json({
          status: "error",
          message: `Invalid participant format: ${participant}`,
        });
      }
      
      validParticipants.push(formattedParticipant);
    }

    const session = sessions.get(sessionId);
    if (!session || !session.sock || session.status !== "CONNECTED") {
      log("API error", "SYSTEM", {
        event: "api-error",
        error: `Session ${sessionId} not found or not connected.`,
        endpoint: req.originalUrl,
      });
      return res.status(404).json({
        status: "error",
        message: `Session ${sessionId} not found or not connected.`,
      });
    }

    try {
      log("Creating group", sessionId, {
        event: "group-create-start",
        sessionId,
        subject: subject.trim(),
        participantCount: validParticipants.length,
      });

      // Create the group using Baileys
      const groupResult = await session.sock.groupCreate(subject.trim(), validParticipants);
      
      if (!groupResult || !groupResult.id) {
        throw new Error("Group creation failed - no group ID returned");
      }

      // Get the full group metadata for the response
      const metadata = await session.sock.groupMetadata(groupResult.id);
      
      // Add description if provided
      if (description && typeof description === 'string' && description.trim().length > 0) {
        try {
          await session.sock.groupUpdateDescription(groupResult.id, description.trim());
          log("Group description added", sessionId, {
            event: "group-description-added",
            sessionId,
            groupId: groupResult.id,
          });
        } catch (descError) {
          log("Failed to add group description", sessionId, {
            event: "group-description-failed",
            sessionId,
            groupId: groupResult.id,
            error: descError.message,
          });
        }
      }

      // Apply group settings if provided
      if (settings && typeof settings === 'object') {
        const settingsPromises = [];

        // Set announcement mode (only admins can send messages)
        if (typeof settings.announcement === 'boolean') {
          settingsPromises.push(
            session.sock.groupSettingUpdate(groupResult.id, settings.announcement ? 'announcement' : 'not_announcement')
              .catch(err => log("Failed to set announcement mode", sessionId, { error: err.message }))
          );
        }

        // Set restricted mode (only admins can edit group info)
        if (typeof settings.restricted === 'boolean') {
          settingsPromises.push(
            session.sock.groupSettingUpdate(groupResult.id, settings.restricted ? 'locked' : 'unlocked')
              .catch(err => log("Failed to set restricted mode", sessionId, { error: err.message }))
          );
        }

        // Set disappearing messages
        if (typeof settings.ephemeralDuration === 'number' && settings.ephemeralDuration >= 0) {
          settingsPromises.push(
            session.sock.sendMessage(groupResult.id, {
              disappearingMessagesInChat: settings.ephemeralDuration === 0 ? false : settings.ephemeralDuration
            }).catch(err => log("Failed to set disappearing messages", sessionId, { error: err.message }))
          );
        }

        // Wait for all settings to be applied
        if (settingsPromises.length > 0) {
          await Promise.allSettled(settingsPromises);
        }
      }

      // Clear cache for this session's groups
      const cacheKey = `groups_${sessionId}`;
      groupCache.del(cacheKey);

      const groupDetails = {
        id: metadata.id,
        name: metadata.subject,
        description: metadata.desc || "",
        createdAt: metadata.creation || Date.now(),
        owner: metadata.owner,
        participants: metadata.participants ? metadata.participants.length : validParticipants.length,
        participantDetails: metadata.participants || [],
        isAnnounce: metadata.announce === true,
        isRestricted: metadata.restrict === true,
        isCommunity: metadata.isCommunity === true,
        inviteCode: groupResult.code || null,
        created: true,
      };

      log("Group created successfully", sessionId, {
        event: "group-created",
        sessionId,
        groupId: groupResult.id,
        participantCount: validParticipants.length,
      });

      // Log activity
      if (activityLogger) {
        const currentUser = req.session && req.session.adminAuthed ? req.session.userEmail : null;
        const sessionOwner = userManager ? userManager.getSessionOwner(sessionId) : null;
        const userEmail = currentUser || (sessionOwner ? sessionOwner.email : 'api-user');

        await activityLogger.logActivity(
          userEmail,
          'group_create',
          `Created group "${subject.trim()}" with ${validParticipants.length} participants`,
          req.ip,
          req.headers['user-agent']
        );
      }

      res.status(201).json({
        status: "success",
        message: `Group "${subject.trim()}" created successfully`,
        group: groupDetails,
      });

    } catch (error) {
      let errorMessage = "Failed to create group";
      let statusCode = 500;

      if (error.message.includes("not-authorized") || error.message.includes("unauthorized")) {
        errorMessage = "Session not authorized to create groups";
        statusCode = 403;
      } else if (error.message.includes("rate-limit")) {
        errorMessage = "Rate limit exceeded. Please try again later";
        statusCode = 429;
      } else if (error.message.includes("participant") && error.message.includes("invalid")) {
        errorMessage = "One or more participants are invalid";
        statusCode = 400;
      }

      log("API error", "SYSTEM", {
        event: "api-error",
        error: error.message,
        errorType: error.name || "Unknown",
        endpoint: req.originalUrl,
        sessionId,
        statusCode,
      });

      console.error(`Failed to create group for ${sessionId}:`, {
        error: error.message,
        stack: error.stack,
        type: error.name,
        subject,
        participantCount: validParticipants.length,
      });

      res.status(statusCode).json({
        status: "error",
        message: `${errorMessage}. Reason: ${error.message}`,
        errorType: error.name || "UnknownError",
      });
    }
  });

  // Add participants to a group
  router.post("/sessions/:sessionId/groups/:groupId/participants", async (req, res) => {
    log("API request", "SYSTEM", {
      event: "api-request",
      method: req.method,
      endpoint: req.originalUrl,
    });
    const { sessionId, groupId } = req.params;
    const { participants } = req.body;

    if (!Array.isArray(participants) || participants.length === 0) {
      return res.status(400).json({
        status: "error",
        message: "Participants array is required and must contain at least one participant",
      });
    }

    const session = sessions.get(sessionId);
    if (!session || !session.sock || session.status !== "CONNECTED") {
      return res.status(404).json({
        status: "error",
        message: `Session ${sessionId} not found or not connected.`,
      });
    }

    try {
      const formattedGroupId = groupId.includes("@g.us") ? groupId : `${groupId}@g.us`;
      
      // Format participants
      const validParticipants = participants.map(p => 
        p.includes('@s.whatsapp.net') ? p : `${p.replace(/[^\d]/g, '')}@s.whatsapp.net`
      );

      const result = await session.sock.groupParticipantsUpdate(
        formattedGroupId,
        validParticipants,
        'add'
      );

      // Clear cache
      groupCache.del(`group_${sessionId}_${formattedGroupId}`);
      groupCache.del(`groups_${sessionId}`);

      log("Participants added to group", sessionId, {
        event: "group-participants-added",
        sessionId,
        groupId: formattedGroupId,
        participantCount: validParticipants.length,
      });

      res.status(200).json({
        status: "success",
        message: `Added ${validParticipants.length} participants to group`,
        results: result,
        groupId: formattedGroupId,
      });

    } catch (error) {
      log("API error", "SYSTEM", {
        event: "api-error",
        error: error.message,
        endpoint: req.originalUrl,
        sessionId,
      });

      res.status(500).json({
        status: "error",
        message: `Failed to add participants. Reason: ${error.message}`,
      });
    }
  });

  // Remove participants from a group
  router.delete("/sessions/:sessionId/groups/:groupId/participants", async (req, res) => {
    log("API request", "SYSTEM", {
      event: "api-request",
      method: req.method,
      endpoint: req.originalUrl,
    });
    const { sessionId, groupId } = req.params;
    const { participants } = req.body;

    if (!Array.isArray(participants) || participants.length === 0) {
      return res.status(400).json({
        status: "error",
        message: "Participants array is required and must contain at least one participant",
      });
    }

    const session = sessions.get(sessionId);
    if (!session || !session.sock || session.status !== "CONNECTED") {
      return res.status(404).json({
        status: "error",
        message: `Session ${sessionId} not found or not connected.`,
      });
    }

    try {
      const formattedGroupId = groupId.includes("@g.us") ? groupId : `${groupId}@g.us`;
      
      // Format participants
      const validParticipants = participants.map(p => 
        p.includes('@s.whatsapp.net') ? p : `${p.replace(/[^\d]/g, '')}@s.whatsapp.net`
      );

      const result = await session.sock.groupParticipantsUpdate(
        formattedGroupId,
        validParticipants,
        'remove'
      );

      // Clear cache
      groupCache.del(`group_${sessionId}_${formattedGroupId}`);
      groupCache.del(`groups_${sessionId}`);

      log("Participants removed from group", sessionId, {
        event: "group-participants-removed",
        sessionId,
        groupId: formattedGroupId,
        participantCount: validParticipants.length,
      });

      res.status(200).json({
        status: "success",
        message: `Removed ${validParticipants.length} participants from group`,
        results: result,
        groupId: formattedGroupId,
      });

    } catch (error) {
      log("API error", "SYSTEM", {
        event: "api-error",
        error: error.message,
        endpoint: req.originalUrl,
        sessionId,
      });

      res.status(500).json({
        status: "error",
        message: `Failed to remove participants. Reason: ${error.message}`,
      });
    }
  });

  // Promote/Demote participant
  router.put("/sessions/:sessionId/groups/:groupId/participants/:participantId", async (req, res) => {
    log("API request", "SYSTEM", {
      event: "api-request",
      method: req.method,
      endpoint: req.originalUrl,
    });
    const { sessionId, groupId, participantId } = req.params;
    const { action } = req.body;

    if (!action || !['promote', 'demote'].includes(action)) {
      return res.status(400).json({
        status: "error",
        message: "Action is required and must be either 'promote' or 'demote'",
      });
    }

    const session = sessions.get(sessionId);
    if (!session || !session.sock || session.status !== "CONNECTED") {
      return res.status(404).json({
        status: "error",
        message: `Session ${sessionId} not found or not connected.`,
      });
    }

    try {
      const formattedGroupId = groupId.includes("@g.us") ? groupId : `${groupId}@g.us`;
      const formattedParticipant = participantId.includes('@s.whatsapp.net') 
        ? participantId 
        : `${participantId.replace(/[^\d]/g, '')}@s.whatsapp.net`;

      const result = await session.sock.groupParticipantsUpdate(
        formattedGroupId,
        [formattedParticipant],
        action
      );

      // Clear cache
      groupCache.del(`group_${sessionId}_${formattedGroupId}`);
      groupCache.del(`groups_${sessionId}`);

      log(`Participant ${action}d in group`, sessionId, {
        event: `group-participant-${action}d`,
        sessionId,
        groupId: formattedGroupId,
        participant: formattedParticipant,
      });

      res.status(200).json({
        status: "success",
        message: `Participant ${action}d successfully`,
        result: result[0],
        groupId: formattedGroupId,
        participantId: formattedParticipant,
        action: action,
      });

    } catch (error) {
      log("API error", "SYSTEM", {
        event: "api-error",
        error: error.message,
        endpoint: req.originalUrl,
        sessionId,
      });

      res.status(500).json({
        status: "error",
        message: `Failed to ${action} participant. Reason: ${error.message}`,
      });
    }
  });

  // Update group settings
  router.put("/sessions/:sessionId/groups/:groupId/settings", async (req, res) => {
    log("API request", "SYSTEM", {
      event: "api-request",
      method: req.method,
      endpoint: req.originalUrl,
    });
    const { sessionId, groupId } = req.params;
    const { setting, value } = req.body;

    const validSettings = {
      'announcement': ['on', 'off'],
      'locked': ['on', 'off'],
      'memberAddMode': ['all_member_add', 'admin_add'],
      'joinApprovalMode': ['on', 'off'],
      'ephemeral': [0, 86400, 604800, 7776000] // off, 1 day, 1 week, 90 days
    };

    if (!setting || !validSettings.hasOwnProperty(setting)) {
      return res.status(400).json({
        status: "error",
        message: `Invalid setting. Valid options: ${Object.keys(validSettings).join(', ')}`,
      });
    }

    if (value === undefined || value === null) {
      return res.status(400).json({
        status: "error",
        message: "Setting value is required",
      });
    }

    const session = sessions.get(sessionId);
    if (!session || !session.sock || session.status !== "CONNECTED") {
      return res.status(404).json({
        status: "error",
        message: `Session ${sessionId} not found or not connected.`,
      });
    }

    try {
      const formattedGroupId = groupId.includes("@g.us") ? groupId : `${groupId}@g.us`;

      let result;
      switch (setting) {
        case 'announcement':
          if (!['on', 'off'].includes(value)) {
            throw new Error("announcement value must be 'on' or 'off'");
          }
          const announceSetting = value === 'on' ? 'announcement' : 'not_announcement';
          result = await session.sock.groupSettingUpdate(formattedGroupId, announceSetting);
          break;

        case 'locked':
          if (!['on', 'off'].includes(value)) {
            throw new Error("locked value must be 'on' or 'off'");
          }
          const lockSetting = value === 'on' ? 'locked' : 'unlocked';
          result = await session.sock.groupSettingUpdate(formattedGroupId, lockSetting);
          break;

        case 'memberAddMode':
          if (!['all_member_add', 'admin_add'].includes(value)) {
            throw new Error("memberAddMode value must be 'all_member_add' or 'admin_add'");
          }
          result = await session.sock.groupMemberAddMode(formattedGroupId, value);
          break;

        case 'joinApprovalMode':
          if (!['on', 'off'].includes(value)) {
            throw new Error("joinApprovalMode value must be 'on' or 'off'");
          }
          result = await session.sock.groupJoinApprovalMode(formattedGroupId, value);
          break;

        case 'ephemeral':
          if (!validSettings.ephemeral.includes(value)) {
            throw new Error(`ephemeral value must be one of: ${validSettings.ephemeral.join(', ')}`);
          }
          result = await session.sock.groupToggleEphemeral(formattedGroupId, value);
          break;
      }

      // Clear cache
      groupCache.del(`group_${sessionId}_${formattedGroupId}`);
      groupCache.del(`groups_${sessionId}`);

      log("Group setting updated", sessionId, {
        event: "group-setting-updated",
        sessionId,
        groupId: formattedGroupId,
        setting,
        value,
      });

      res.status(200).json({
        status: "success",
        message: `Group ${setting} updated to ${value}`,
        setting,
        value,
        groupId: formattedGroupId,
        result,
      });

    } catch (error) {
      log("API error", "SYSTEM", {
        event: "api-error",
        error: error.message,
        endpoint: req.originalUrl,
        sessionId,
      });

      res.status(500).json({
        status: "error",
        message: `Failed to update group ${setting}. Reason: ${error.message}`,
      });
    }
  });

  // Update group subject (name)
  router.put("/sessions/:sessionId/groups/:groupId/subject", async (req, res) => {
    log("API request", "SYSTEM", {
      event: "api-request",
      method: req.method,
      endpoint: req.originalUrl,
    });
    const { sessionId, groupId } = req.params;
    const { subject } = req.body;

    if (!subject || typeof subject !== 'string' || subject.trim().length === 0) {
      return res.status(400).json({
        status: "error",
        message: "Subject is required and must be a non-empty string",
      });
    }

    const session = sessions.get(sessionId);
    if (!session || !session.sock || session.status !== "CONNECTED") {
      return res.status(404).json({
        status: "error",
        message: `Session ${sessionId} not found or not connected.`,
      });
    }

    try {
      const formattedGroupId = groupId.includes("@g.us") ? groupId : `${groupId}@g.us`;

      await session.sock.groupUpdateSubject(formattedGroupId, subject.trim());

      // Clear cache
      groupCache.del(`group_${sessionId}_${formattedGroupId}`);
      groupCache.del(`groups_${sessionId}`);

      log("Group subject updated", sessionId, {
        event: "group-subject-updated",
        sessionId,
        groupId: formattedGroupId,
        newSubject: subject.trim(),
      });

      res.status(200).json({
        status: "success",
        message: `Group subject updated to "${subject.trim()}"`,
        groupId: formattedGroupId,
        newSubject: subject.trim(),
      });

    } catch (error) {
      log("API error", "SYSTEM", {
        event: "api-error",
        error: error.message,
        endpoint: req.originalUrl,
        sessionId,
      });

      res.status(500).json({
        status: "error",
        message: `Failed to update group subject. Reason: ${error.message}`,
      });
    }
  });

  // Update group description
  router.put("/sessions/:sessionId/groups/:groupId/description", async (req, res) => {
    log("API request", "SYSTEM", {
      event: "api-request",
      method: req.method,
      endpoint: req.originalUrl,
    });
    const { sessionId, groupId } = req.params;
    const { description } = req.body;

    const session = sessions.get(sessionId);
    if (!session || !session.sock || session.status !== "CONNECTED") {
      return res.status(404).json({
        status: "error",
        message: `Session ${sessionId} not found or not connected.`,
      });
    }

    try {
      const formattedGroupId = groupId.includes("@g.us") ? groupId : `${groupId}@g.us`;

      await session.sock.groupUpdateDescription(formattedGroupId, description || '');

      // Clear cache
      groupCache.del(`group_${sessionId}_${formattedGroupId}`);
      groupCache.del(`groups_${sessionId}`);

      log("Group description updated", sessionId, {
        event: "group-description-updated",
        sessionId,
        groupId: formattedGroupId,
        hasDescription: !!description,
      });

      res.status(200).json({
        status: "success",
        message: "Group description updated successfully",
        groupId: formattedGroupId,
        newDescription: description || '',
      });

    } catch (error) {
      log("API error", "SYSTEM", {
        event: "api-error",
        error: error.message,
        endpoint: req.originalUrl,
        sessionId,
      });

      res.status(500).json({
        status: "error",
        message: `Failed to update group description. Reason: ${error.message}`,
      });
    }
  });

  // Leave group
  router.post("/sessions/:sessionId/groups/:groupId/leave", async (req, res) => {
    log("API request", "SYSTEM", {
      event: "api-request",
      method: req.method,
      endpoint: req.originalUrl,
    });
    const { sessionId, groupId } = req.params;

    const session = sessions.get(sessionId);
    if (!session || !session.sock || session.status !== "CONNECTED") {
      return res.status(404).json({
        status: "error",
        message: `Session ${sessionId} not found or not connected.`,
      });
    }

    try {
      const formattedGroupId = groupId.includes("@g.us") ? groupId : `${groupId}@g.us`;

      await session.sock.groupLeave(formattedGroupId);

      // Clear cache
      groupCache.del(`group_${sessionId}_${formattedGroupId}`);
      groupCache.del(`groups_${sessionId}`);

      log("Left group", sessionId, {
        event: "group-left",
        sessionId,
        groupId: formattedGroupId,
      });

      res.status(200).json({
        status: "success",
        message: "Successfully left the group",
        groupId: formattedGroupId,
      });

    } catch (error) {
      log("API error", "SYSTEM", {
        event: "api-error",
        error: error.message,
        endpoint: req.originalUrl,
        sessionId,
      });

      res.status(500).json({
        status: "error",
        message: `Failed to leave group. Reason: ${error.message}`,
      });
    }
  });

  // Revoke group invite link and generate a new one
  router.delete("/sessions/:sessionId/groups/:groupId/invite", async (req, res) => {
    log("API request", "SYSTEM", {
      event: "api-request",
      method: req.method,
      endpoint: req.originalUrl,
    });
    const { sessionId, groupId } = req.params;

    const session = sessions.get(sessionId);
    if (!session || !session.sock || session.status !== "CONNECTED") {
      return res.status(404).json({
        status: "error",
        message: `Session ${sessionId} not found or not connected.`,
      });
    }

    try {
      const formattedGroupId = groupId.includes("@g.us") ? groupId : `${groupId}@g.us`;

      const newInviteCode = await session.sock.groupRevokeInvite(formattedGroupId);
      const newInviteLink = `https://chat.whatsapp.com/${newInviteCode}`;

      // Clear cache
      groupCache.del(`group_${sessionId}_${formattedGroupId}`);

      log("Group invite link revoked and regenerated", sessionId, {
        event: "group-invite-revoked",
        sessionId,
        groupId: formattedGroupId,
      });

      res.status(200).json({
        status: "success",
        message: "Group invite link revoked and new one generated",
        groupId: formattedGroupId,
        newInviteCode,
        newInviteLink,
      });

    } catch (error) {
      log("API error", "SYSTEM", {
        event: "api-error",
        error: error.message,
        endpoint: req.originalUrl,
        sessionId,
      });

      res.status(500).json({
        status: "error",
        message: `Failed to revoke invite link. Reason: ${error.message}`,
      });
    }
  });

  // Get group info from invite code
  router.get("/sessions/:sessionId/groups/invite/:inviteCode", async (req, res) => {
    log("API request", "SYSTEM", {
      event: "api-request",
      method: req.method,
      endpoint: req.originalUrl,
    });
    const { sessionId, inviteCode } = req.params;

    const session = sessions.get(sessionId);
    if (!session || !session.sock || session.status !== "CONNECTED") {
      return res.status(404).json({
        status: "error",
        message: `Session ${sessionId} not found or not connected.`,
      });
    }

    try {
      const groupInfo = await session.sock.groupGetInviteInfo(inviteCode);

      log("Group invite info fetched", sessionId, {
        event: "group-invite-info-fetched",
        sessionId,
        inviteCode,
        groupId: groupInfo.id,
      });

      res.status(200).json({
        status: "success",
        inviteCode,
        groupInfo: {
          id: groupInfo.id,
          subject: groupInfo.subject,
          owner: groupInfo.owner,
          creation: groupInfo.creation,
          size: groupInfo.size,
          desc: groupInfo.desc,
          participants: groupInfo.participants || [],
          subjectOwner: groupInfo.subjectOwner,
          subjectTime: groupInfo.subjectTime,
        },
      });

    } catch (error) {
      log("API error", "SYSTEM", {
        event: "api-error",
        error: error.message,
        endpoint: req.originalUrl,
        sessionId,
      });

      res.status(500).json({
        status: "error",
        message: `Failed to get group info from invite code. Reason: ${error.message}`,
      });
    }
  });

  // Join group using invite code
  router.post("/sessions/:sessionId/groups/join/:inviteCode", async (req, res) => {
    log("API request", "SYSTEM", {
      event: "api-request",
      method: req.method,
      endpoint: req.originalUrl,
    });
    const { sessionId, inviteCode } = req.params;

    const session = sessions.get(sessionId);
    if (!session || !session.sock || session.status !== "CONNECTED") {
      return res.status(404).json({
        status: "error",
        message: `Session ${sessionId} not found or not connected.`,
      });
    }

    try {
      const result = await session.sock.groupAcceptInvite(inviteCode);

      // Clear cache to refresh groups list
      groupCache.del(`groups_${sessionId}`);

      log("Joined group via invite", sessionId, {
        event: "group-joined-via-invite",
        sessionId,
        inviteCode,
        groupId: result,
      });

      res.status(200).json({
        status: "success",
        message: "Successfully joined group",
        inviteCode,
        groupId: result,
      });

    } catch (error) {
      log("API error", "SYSTEM", {
        event: "api-error",
        error: error.message,
        endpoint: req.originalUrl,
        sessionId,
      });

      res.status(500).json({
        status: "error",
        message: `Failed to join group. Reason: ${error.message}`,
      });
    }
  });

  // Accept GroupInviteMessage (V4 invite)
  router.post("/sessions/:sessionId/groups/accept-invite-v4", async (req, res) => {
    log("API request", "SYSTEM", {
      event: "api-request",
      method: req.method,
      endpoint: req.originalUrl,
    });
    const { sessionId } = req.params;
    const { key, inviteMessage } = req.body;

    if (!key || !inviteMessage) {
      return res.status(400).json({
        status: "error",
        message: "Both key and inviteMessage are required for V4 invite acceptance",
      });
    }

    const session = sessions.get(sessionId);
    if (!session || !session.sock || session.status !== "CONNECTED") {
      return res.status(404).json({
        status: "error",
        message: `Session ${sessionId} not found or not connected.`,
      });
    }

    try {
      const result = await session.sock.groupAcceptInviteV4(key, inviteMessage);

      // Clear cache to refresh groups list
      groupCache.del(`groups_${sessionId}`);

      log("Accepted V4 group invite", sessionId, {
        event: "group-v4-invite-accepted",
        sessionId,
        groupId: result,
      });

      res.status(200).json({
        status: "success",
        message: "Successfully accepted V4 group invite",
        result,
      });

    } catch (error) {
      log("API error", "SYSTEM", {
        event: "api-error",
        error: error.message,
        endpoint: req.originalUrl,
        sessionId,
      });

      res.status(500).json({
        status: "error",
        message: `Failed to accept V4 invite. Reason: ${error.message}`,
      });
    }
  });

  // Revoke V4 invite for specific participant
  router.delete("/sessions/:sessionId/groups/:groupId/invite-v4/:participantId", async (req, res) => {
    log("API request", "SYSTEM", {
      event: "api-request",
      method: req.method,
      endpoint: req.originalUrl,
    });
    const { sessionId, groupId, participantId } = req.params;

    const session = sessions.get(sessionId);
    if (!session || !session.sock || session.status !== "CONNECTED") {
      return res.status(404).json({
        status: "error",
        message: `Session ${sessionId} not found or not connected.`,
      });
    }

    try {
      const formattedGroupId = groupId.includes("@g.us") ? groupId : `${groupId}@g.us`;
      const formattedParticipant = participantId.includes('@s.whatsapp.net') 
        ? participantId 
        : `${participantId.replace(/[^\d]/g, '')}@s.whatsapp.net`;

      await session.sock.groupRevokeInviteV4(formattedGroupId, formattedParticipant);

      log("V4 invite revoked for participant", sessionId, {
        event: "group-v4-invite-revoked",
        sessionId,
        groupId: formattedGroupId,
        participant: formattedParticipant,
      });

      res.status(200).json({
        status: "success",
        message: "Successfully revoked V4 invite for participant",
        groupId: formattedGroupId,
        participantId: formattedParticipant,
      });

    } catch (error) {
      log("API error", "SYSTEM", {
        event: "api-error",
        error: error.message,
        endpoint: req.originalUrl,
        sessionId,
      });

      res.status(500).json({
        status: "error",
        message: `Failed to revoke V4 invite. Reason: ${error.message}`,
      });
    }
  });

  // Get pending join requests
  router.get("/sessions/:sessionId/groups/:groupId/requests", async (req, res) => {
    log("API request", "SYSTEM", {
      event: "api-request",
      method: req.method,
      endpoint: req.originalUrl,
    });
    const { sessionId, groupId } = req.params;

    const session = sessions.get(sessionId);
    if (!session || !session.sock || session.status !== "CONNECTED") {
      return res.status(404).json({
        status: "error",
        message: `Session ${sessionId} not found or not connected.`,
      });
    }

    try {
      const formattedGroupId = groupId.includes("@g.us") ? groupId : `${groupId}@g.us`;

      const requests = await session.sock.groupRequestParticipantsList(formattedGroupId);

      log("Group join requests fetched", sessionId, {
        event: "group-requests-fetched",
        sessionId,
        groupId: formattedGroupId,
        requestCount: requests.length,
      });

      res.status(200).json({
        status: "success",
        groupId: formattedGroupId,
        requests: requests || [],
        count: (requests || []).length,
      });

    } catch (error) {
      log("API error", "SYSTEM", {
        event: "api-error",
        error: error.message,
        endpoint: req.originalUrl,
        sessionId,
      });

      res.status(500).json({
        status: "error",
        message: `Failed to fetch join requests. Reason: ${error.message}`,
      });
    }
  });

  // Approve or reject join requests
  router.put("/sessions/:sessionId/groups/:groupId/requests", async (req, res) => {
    log("API request", "SYSTEM", {
      event: "api-request",
      method: req.method,
      endpoint: req.originalUrl,
    });
    const { sessionId, groupId } = req.params;
    const { participants, action } = req.body;

    if (!Array.isArray(participants) || participants.length === 0) {
      return res.status(400).json({
        status: "error",
        message: "Participants array is required and must contain at least one participant",
      });
    }

    if (!action || !['approve', 'reject'].includes(action)) {
      return res.status(400).json({
        status: "error",
        message: "Action is required and must be either 'approve' or 'reject'",
      });
    }

    const session = sessions.get(sessionId);
    if (!session || !session.sock || session.status !== "CONNECTED") {
      return res.status(404).json({
        status: "error",
        message: `Session ${sessionId} not found or not connected.`,
      });
    }

    try {
      const formattedGroupId = groupId.includes("@g.us") ? groupId : `${groupId}@g.us`;
      
      // Format participants
      const validParticipants = participants.map(p => 
        p.includes('@s.whatsapp.net') ? p : `${p.replace(/[^\d]/g, '')}@s.whatsapp.net`
      );

      const result = await session.sock.groupRequestParticipantsUpdate(
        formattedGroupId,
        validParticipants,
        action
      );

      // Clear cache if participants were approved
      if (action === 'approve') {
        groupCache.del(`group_${sessionId}_${formattedGroupId}`);
        groupCache.del(`groups_${sessionId}`);
      }

      log(`Group join requests ${action}d`, sessionId, {
        event: `group-requests-${action}d`,
        sessionId,
        groupId: formattedGroupId,
        participantCount: validParticipants.length,
      });

      res.status(200).json({
        status: "success",
        message: `${action === 'approve' ? 'Approved' : 'Rejected'} ${validParticipants.length} join requests`,
        groupId: formattedGroupId,
        action,
        results: result,
      });

    } catch (error) {
      log("API error", "SYSTEM", {
        event: "api-error",
        error: error.message,
        endpoint: req.originalUrl,
        sessionId,
      });

      res.status(500).json({
        status: "error",
        message: `Failed to ${action} join requests. Reason: ${error.message}`,
      });
    }
  });

  // Bulk add participants to group
  router.post("/sessions/:sessionId/groups/:groupId/participants/bulk", async (req, res) => {
    log("API request", "SYSTEM", {
      event: "api-request",
      method: req.method,
      endpoint: req.originalUrl,
    });

    const { sessionId, groupId } = req.params;
    const { participants } = req.body;

    if (!Array.isArray(participants) || participants.length === 0) {
      return res.status(400).json({
        status: "error",
        message: "Participants array is required and must contain at least one participant",
      });
    }

    // Format group ID
    const formattedGroupId = groupId.includes('@g.us') ? groupId : `${groupId}@g.us`;

    const session = sessions.get(sessionId);
    if (!session || !session.sock || session.status !== "CONNECTED") {
      return res.status(404).json({
        status: "error",
        message: `Session ${sessionId} not found or not connected.`,
      });
    }

    try {
      const results = [];
      const validParticipants = [];
      const errors = [];

      // Validate and format all participants
      for (const participant of participants) {
        try {
          const formattedParticipant = participant.includes('@s.whatsapp.net') 
            ? participant 
            : `${participant.replace(/[^\d]/g, '')}@s.whatsapp.net`;
          
          if (formattedParticipant.includes('@s.whatsapp.net')) {
            validParticipants.push(formattedParticipant);
          } else {
            errors.push({ participant, error: "Invalid format" });
          }
        } catch (error) {
          errors.push({ participant, error: error.message });
        }
      }

      if (validParticipants.length === 0) {
        return res.status(400).json({
          status: "error", 
          message: "No valid participants found",
          errors
        });
      }

      // Add participants in batches to avoid rate limits
      const BATCH_SIZE = 10;
      for (let i = 0; i < validParticipants.length; i += BATCH_SIZE) {
        const batch = validParticipants.slice(i, i + BATCH_SIZE);
        
        try {
          const result = await session.sock.groupParticipantsUpdate(
            formattedGroupId,
            batch,
            "add"
          );
          
          results.push(...batch.map(p => ({ participant: p, status: "added", result })));
        } catch (error) {
          batch.forEach(p => {
            errors.push({ participant: p, error: error.message });
          });
        }

        // Add small delay between batches
        if (i + BATCH_SIZE < validParticipants.length) {
          await new Promise(resolve => setTimeout(resolve, 1000));
        }
      }

      // Clear cache
      const cacheKey = `groups_${sessionId}`;
      groupCache.del(cacheKey);

      res.status(200).json({
        status: "success",
        message: `Bulk participant operation completed`,
        groupId: formattedGroupId,
        totalProcessed: participants.length,
        successful: results.length,
        failed: errors.length,
        results,
        errors: errors.length > 0 ? errors : undefined
      });

    } catch (error) {
      res.status(500).json({
        status: "error",
        message: `Failed to add participants in bulk. Reason: ${error.message}`,
      });
    }
  });

  // Bulk remove participants from group
  router.delete("/sessions/:sessionId/groups/:groupId/participants/bulk", async (req, res) => {
    log("API request", "SYSTEM", {
      event: "api-request",
      method: req.method,
      endpoint: req.originalUrl,
    });

    const { sessionId, groupId } = req.params;
    const { participants } = req.body;

    if (!Array.isArray(participants) || participants.length === 0) {
      return res.status(400).json({
        status: "error",
        message: "Participants array is required and must contain at least one participant",
      });
    }

    // Format group ID
    const formattedGroupId = groupId.includes('@g.us') ? groupId : `${groupId}@g.us`;

    const session = sessions.get(sessionId);
    if (!session || !session.sock || session.status !== "CONNECTED") {
      return res.status(404).json({
        status: "error",
        message: `Session ${sessionId} not found or not connected.`,
      });
    }

    try {
      const results = [];
      const validParticipants = [];
      const errors = [];

      // Validate and format all participants
      for (const participant of participants) {
        try {
          const formattedParticipant = participant.includes('@s.whatsapp.net') 
            ? participant 
            : `${participant.replace(/[^\d]/g, '')}@s.whatsapp.net`;
          
          if (formattedParticipant.includes('@s.whatsapp.net')) {
            validParticipants.push(formattedParticipant);
          } else {
            errors.push({ participant, error: "Invalid format" });
          }
        } catch (error) {
          errors.push({ participant, error: error.message });
        }
      }

      if (validParticipants.length === 0) {
        return res.status(400).json({
          status: "error", 
          message: "No valid participants found",
          errors
        });
      }

      // Remove participants in batches
      const BATCH_SIZE = 10;
      for (let i = 0; i < validParticipants.length; i += BATCH_SIZE) {
        const batch = validParticipants.slice(i, i + BATCH_SIZE);
        
        try {
          const result = await session.sock.groupParticipantsUpdate(
            formattedGroupId,
            batch,
            "remove"
          );
          
          results.push(...batch.map(p => ({ participant: p, status: "removed", result })));
        } catch (error) {
          batch.forEach(p => {
            errors.push({ participant: p, error: error.message });
          });
        }

        // Add small delay between batches
        if (i + BATCH_SIZE < validParticipants.length) {
          await new Promise(resolve => setTimeout(resolve, 1000));
        }
      }

      // Clear cache
      const cacheKey = `groups_${sessionId}`;
      groupCache.del(cacheKey);

      res.status(200).json({
        status: "success",
        message: `Bulk participant removal completed`,
        groupId: formattedGroupId,
        totalProcessed: participants.length,
        successful: results.length,
        failed: errors.length,
        results,
        errors: errors.length > 0 ? errors : undefined
      });

    } catch (error) {
      res.status(500).json({
        status: "error",
        message: `Failed to remove participants in bulk. Reason: ${error.message}`,
      });
    }
  });

  // Bulk promote participants to admin
  router.put("/sessions/:sessionId/groups/:groupId/participants/bulk/promote", async (req, res) => {
    log("API request", "SYSTEM", {
      event: "api-request",
      method: req.method,
      endpoint: req.originalUrl,
    });

    const { sessionId, groupId } = req.params;
    const { participants } = req.body;

    if (!Array.isArray(participants) || participants.length === 0) {
      return res.status(400).json({
        status: "error",
        message: "Participants array is required and must contain at least one participant",
      });
    }

    const formattedGroupId = groupId.includes('@g.us') ? groupId : `${groupId}@g.us`;

    const session = sessions.get(sessionId);
    if (!session || !session.sock || session.status !== "CONNECTED") {
      return res.status(404).json({
        status: "error",
        message: `Session ${sessionId} not found or not connected.`,
      });
    }

    try {
      const results = [];
      const errors = [];

      // Process each participant individually for promote operations
      for (const participant of participants) {
        try {
          const formattedParticipant = participant.includes('@s.whatsapp.net') 
            ? participant 
            : `${participant.replace(/[^\d]/g, '')}@s.whatsapp.net`;
          
          const result = await session.sock.groupParticipantsUpdate(
            formattedGroupId,
            [formattedParticipant],
            "promote"
          );
          
          results.push({ participant: formattedParticipant, status: "promoted", result });
          
          // Small delay between individual promotions
          await new Promise(resolve => setTimeout(resolve, 500));
          
        } catch (error) {
          errors.push({ participant, error: error.message });
        }
      }

      // Clear cache
      const cacheKey = `groups_${sessionId}`;
      groupCache.del(cacheKey);

      res.status(200).json({
        status: "success",
        message: `Bulk participant promotion completed`,
        groupId: formattedGroupId,
        totalProcessed: participants.length,
        successful: results.length,
        failed: errors.length,
        results,
        errors: errors.length > 0 ? errors : undefined
      });

    } catch (error) {
      res.status(500).json({
        status: "error",
        message: `Failed to promote participants in bulk. Reason: ${error.message}`,
      });
    }
  });

  // Bulk demote participants from admin
  router.put("/sessions/:sessionId/groups/:groupId/participants/bulk/demote", async (req, res) => {
    log("API request", "SYSTEM", {
      event: "api-request",
      method: req.method,
      endpoint: req.originalUrl,
    });

    const { sessionId, groupId } = req.params;
    const { participants } = req.body;

    if (!Array.isArray(participants) || participants.length === 0) {
      return res.status(400).json({
        status: "error",
        message: "Participants array is required and must contain at least one participant",
      });
    }

    const formattedGroupId = groupId.includes('@g.us') ? groupId : `${groupId}@g.us`;

    const session = sessions.get(sessionId);
    if (!session || !session.sock || session.status !== "CONNECTED") {
      return res.status(404).json({
        status: "error",
        message: `Session ${sessionId} not found or not connected.`,
      });
    }

    try {
      const results = [];
      const errors = [];

      // Process each participant individually for demote operations
      for (const participant of participants) {
        try {
          const formattedParticipant = participant.includes('@s.whatsapp.net') 
            ? participant 
            : `${participant.replace(/[^\d]/g, '')}@s.whatsapp.net`;
          
          const result = await session.sock.groupParticipantsUpdate(
            formattedGroupId,
            [formattedParticipant],
            "demote"
          );
          
          results.push({ participant: formattedParticipant, status: "demoted", result });
          
          // Small delay between individual demotions
          await new Promise(resolve => setTimeout(resolve, 500));
          
        } catch (error) {
          errors.push({ participant, error: error.message });
        }
      }

      // Clear cache
      const cacheKey = `groups_${sessionId}`;
      groupCache.del(cacheKey);

      res.status(200).json({
        status: "success",
        message: `Bulk participant demotion completed`,
        groupId: formattedGroupId,
        totalProcessed: participants.length,
        successful: results.length,
        failed: errors.length,
        results,
        errors: errors.length > 0 ? errors : undefined
      });

    } catch (error) {
      res.status(500).json({
        status: "error",
        message: `Failed to demote participants in bulk. Reason: ${error.message}`,
      });
    }
  });

  router.delete("/sessions/:sessionId", async (req, res) => {
    log("API request", "SYSTEM", {
      event: "api-request",
      method: req.method,
      endpoint: req.originalUrl,
      params: req.params,
    });
    const { sessionId } = req.params;

    // Get current user from session
    const currentUser =
      req.session && req.session.adminAuthed
        ? {
            email: req.session.userEmail,
            role: req.session.userRole,
          }
        : null;

    try {
      // Check ownership if user is authenticated
      if (currentUser && currentUser.role !== "admin" && userManager) {
        const sessionOwner = userManager.getSessionOwner(sessionId);
        if (sessionOwner && sessionOwner.email !== currentUser.email) {
          return res.status(403).json({
            status: "error",
            message: "You can only delete your own sessions",
          });
        }
      }

      await deleteSession(sessionId);

      // Log activity
      if (currentUser && activityLogger) {
        await activityLogger.logSessionDelete(
          currentUser.email,
          sessionId,
          req.ip,
          req.headers["user-agent"]
        );
      }

      log("Session deleted", sessionId, {
        event: "session-deleted",
        sessionId,
      });
      res
        .status(200)
        .json({ status: "success", message: `Session ${sessionId} deleted.` });
    } catch (error) {
      log("API error", "SYSTEM", {
        event: "api-error",
        error: error.message,
        endpoint: req.originalUrl,
      });
      res
        .status(500)
        .json({
          status: "error",
          message: `Failed to delete session: ${error.message}`,
        });
    }
  });

  async function sendMessage(sock, to, message) {
    try {
      const jid = jidNormalizedUser(to);
      const result = await sock.sendMessage(jid, message);
      return {
        status: "success",
        message: `Message sent to ${to}`,
        messageId: result.key.id,
      };
    } catch (error) {
      console.error(`Failed to send message to ${to}:`, error);
      return {
        status: "error",
        message: `Failed to send message to ${to}. Reason: ${error.message}`,
      };
    }
  }

  // Webhook setup endpoint
  router.post("/webhook", (req, res) => {
    log("API request", "SYSTEM", {
      event: "api-request",
      method: req.method,
      endpoint: req.originalUrl,
      body: req.body,
    });
    const { url, sessionId } = req.body;
    if (!url || !sessionId) {
      log("API error", "SYSTEM", {
        event: "api-error",
        error: "URL and sessionId are required.",
        endpoint: req.originalUrl,
      });
      return res
        .status(400)
        .json({ status: "error", message: "URL and sessionId are required." });
    }
    webhookUrls.set(sessionId, url);
    log("Webhook URL updated", url, {
      event: "webhook-updated",
      sessionId,
      url,
    });
    res
      .status(200)
      .json({
        status: "success",
        message: `Webhook URL for session ${sessionId} updated to ${url}`,
      });
  });

  // Add GET and DELETE endpoints for webhook management
  router.get("/webhook", (req, res) => {
    const { sessionId } = req.query;
    if (!sessionId) {
      return res
        .status(400)
        .json({ status: "error", message: "sessionId is required." });
    }
    const url = webhookUrls.get(sessionId) || null;
    res.status(200).json({ status: "success", sessionId, url });
  });

  router.delete("/webhook", (req, res) => {
    const { sessionId } = req.body;
    if (!sessionId) {
      return res
        .status(400)
        .json({ status: "error", message: "sessionId is required." });
    }
    webhookUrls.delete(sessionId);
    log("Webhook URL deleted", "", { event: "webhook-deleted", sessionId });
    res
      .status(200)
      .json({
        status: "success",
        message: `Webhook for session ${sessionId} deleted.`,
      });
  });

  // Hardened media upload endpoint
  router.post("/media", upload.single("file"), (req, res) => {
    log("API request", "SYSTEM", {
      event: "api-request",
      method: req.method,
      endpoint: req.originalUrl,
      body: req.body,
    });
    if (!req.file) {
      log("API error", "SYSTEM", {
        event: "api-error",
        error: "No file uploaded.",
        endpoint: req.originalUrl,
      });
      return res
        .status(400)
        .json({ status: "error", message: "No file uploaded." });
    }
    // Restrict file type and size
    const allowedTypes = [
      "image/jpeg",
      "image/jpg",
      "image/png",
      "image/gif",
      "image/webp",
      "application/pdf",
      "application/msword",
      "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
      "application/vnd.ms-excel",
      "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    ];
    if (!allowedTypes.includes(req.file.mimetype)) {
      fs.unlinkSync(req.file.path);
      log("API error", "SYSTEM", {
        event: "api-error",
        error: "Invalid file type.",
        endpoint: req.originalUrl,
      });
      return res
        .status(400)
        .json({
          status: "error",
          message:
            "Invalid file type. Allowed: JPEG, PNG, GIF, WebP, PDF, DOC, DOCX, XLS, XLSX.",
        });
    }
    if (req.file.size > 25 * 1024 * 1024) {
      // 25MB
      fs.unlinkSync(req.file.path);
      log("API error", "SYSTEM", {
        event: "api-error",
        error: "File too large.",
        endpoint: req.originalUrl,
      });
      return res
        .status(400)
        .json({ status: "error", message: "File too large. Max 25MB." });
    }
    const mediaId = req.file.filename;
    log("File uploaded", mediaId, { event: "file-uploaded", mediaId });
    res.status(201).json({
      status: "success",
      message: "File uploaded successfully.",
      mediaId: mediaId,
      url: `/media/${mediaId}`,
    });
  });

  // Main message sending endpoint
  router.post("/messages", async (req, res) => {
    log("API request", "SYSTEM", {
      event: "api-request",
      method: req.method,
      endpoint: req.originalUrl,
      query: req.query,
    });
    const { sessionId } = req.query;
    if (!sessionId) {
      log("API error", "SYSTEM", {
        event: "api-error",
        error: "sessionId query parameter is required",
        endpoint: req.originalUrl,
      });
      return res
        .status(400)
        .json({
          status: "error",
          message: "sessionId query parameter is required",
        });
    }
    const session = sessions.get(sessionId);
    if (!session || !session.sock || session.status !== "CONNECTED") {
      log("API error", "SYSTEM", {
        event: "api-error",
        error: `Session ${sessionId} not found or not connected.`,
        endpoint: req.originalUrl,
      });
      return res
        .status(404)
        .json({
          status: "error",
          message: `Session ${sessionId} not found or not connected.`,
        });
    }
    const messages = Array.isArray(req.body) ? req.body : [req.body];
    const results = [];
    const phoneNumbers = []; // Track all phone numbers for logging
    const messageContents = []; // Track message contents with formatting

    for (const msg of messages) {
      const { recipient_type, to, type, text, image, document } = msg;
      // Input validation
      if (!to || !type) {
        results.push({
          status: "error",
          message: 'Invalid message format. "to" and "type" are required.',
        });
        continue;
      }
      if (!validator.isNumeric(to) && !to.endsWith("@g.us")) {
        results.push({ status: "error", message: "Invalid recipient format." });
        continue;
      }

      // Add phone number to the list for logging
      phoneNumbers.push(to);

      // Track message content based on type
      let messageContent = {
        type: type,
        to: to,
      };

      if (type === "text") {
        if (
          !text ||
          typeof text.body !== "string" ||
          text.body.length === 0 ||
          text.body.length > 4096
        ) {
          results.push({
            status: "error",
            message: "Invalid text message content.",
          });
          continue;
        }
        messageContent.text = text.body; // Preserve formatting
      }
      if (type === "image" && image) {
        if (
          image.id &&
          !validator.isAlphanumeric(image.id.replace(/[\.\-]/g, ""))
        ) {
          results.push({ status: "error", message: "Invalid image ID." });
          continue;
        }
        if (image.link && !validator.isURL(image.link)) {
          results.push({ status: "error", message: "Invalid image URL." });
          continue;
        }
        messageContent.image = {
          caption: image.caption || "",
          url: image.link || `/media/${image.id}`, // Convert media ID to URL for display
        };
      }
      if (type === "document" && document) {
        if (
          document.id &&
          !validator.isAlphanumeric(document.id.replace(/[\.\-]/g, ""))
        ) {
          results.push({ status: "error", message: "Invalid document ID." });
          continue;
        }
        if (document.link && !validator.isURL(document.link)) {
          results.push({ status: "error", message: "Invalid document URL." });
          continue;
        }
        messageContent.document = {
          filename: document.filename || "document",
          url: document.link || `/media/${document.id}`, // Convert media ID to URL for display
        };
      }

      messageContents.push(messageContent);

      let destination;
      if (recipient_type === "group") {
        destination = to.endsWith("@g.us") ? to : `${to}@g.us`;
      } else {
        destination = `${to.replace(/[@s.whatsapp.net]/g, "")}@s.whatsapp.net`;
      }

      let messagePayload;
      let options = {};

      try {
        switch (type) {
          case "text":
            if (!text || !text.body) {
              throw new Error('For "text" type, "text.body" is required.');
            }
            messagePayload = { text: text.body };
            break;

          case "image":
            if (!image || (!image.link && !image.id)) {
              throw new Error(
                'For "image" type, "image.link" or "image.id" is required.'
              );
            }
            const imageUrl = image.id
              ? path.join(mediaDir, image.id)
              : image.link;
            messagePayload = {
              image: { url: imageUrl },
              caption: image.caption,
            };
            break;

          case "document":
            if (!document || (!document.link && !document.id)) {
              throw new Error(
                'For "document" type, "document.link" or "document.id" is required.'
              );
            }
            const docUrl = document.id
              ? path.join(mediaDir, document.id)
              : document.link;
            messagePayload = {
              document: { url: docUrl },
              mimetype: document.mimetype,
              fileName: document.filename,
            };
            break;

          default:
            throw new Error(`Unsupported message type: ${type}`);
        }

        const result = await sendMessage(
          session.sock,
          destination,
          messagePayload
        );
        results.push(result);
      } catch (error) {
        results.push({
          status: "error",
          message: `Failed to process message for ${to}: ${error.message}`,
        });
      }
    }

    // Log activity for each successful message
    if (activityLogger) {
      const currentUser =
        req.session && req.session.adminAuthed ? req.session.userEmail : null;
      const sessionOwner = userManager
        ? userManager.getSessionOwner(sessionId)
        : null;
      const userEmail =
        currentUser || (sessionOwner ? sessionOwner.email : "api-user");

      for (let i = 0; i < results.length; i++) {
        if (results[i].status === "success") {
          await activityLogger.logMessageSend(
            userEmail,
            sessionId,
            phoneNumbers[i],
            messages[i].type,
            req.ip,
            req.headers["user-agent"]
          );
        }
      }
    }

    log("Messages sent", sessionId, {
      event: "messages-sent",
      sessionId,
      count: results.length,
      phoneNumbers: phoneNumbers,
      messages: messageContents,
    });
    res.status(200).json(results);
  });

  router.delete("/message", async (req, res) => {
    log("API request", "SYSTEM", {
      event: "api-request",
      method: req.method,
      endpoint: req.originalUrl,
      body: req.body,
    });
    const { sessionId, messageId, remoteJid } = req.body;

    if (!sessionId || !messageId || !remoteJid) {
      log("API error", "SYSTEM", {
        event: "api-error",
        error: "sessionId, messageId, and remoteJid are required.",
        endpoint: req.originalUrl,
      });
      return res
        .status(400)
        .json({
          status: "error",
          message: "sessionId, messageId, and remoteJid are required.",
        });
    }

    const session = sessions.get(sessionId);
    if (!session || !session.sock || session.status !== "CONNECTED") {
      log("API error", "SYSTEM", {
        event: "api-error",
        error: `Session ${sessionId} not found or not connected.`,
        endpoint: req.originalUrl,
      });
      return res
        .status(404)
        .json({
          status: "error",
          message: `Session ${sessionId} not found or not connected.`,
        });
    }

    try {
      await session.sock.chatModify(
        {
          clear: { messages: [{ id: messageId, fromMe: true, timestamp: 0 }] },
        },
        remoteJid
      );

      // The above is for clearing. For actual deletion:
      await session.sock.sendMessage(remoteJid, {
        delete: { remoteJid: remoteJid, fromMe: true, id: messageId },
      });

      log("Message deleted", messageId, {
        event: "message-deleted",
        messageId,
        sessionId,
      });
      res
        .status(200)
        .json({
          status: "success",
          message: `Attempted to delete message ${messageId}`,
        });
    } catch (error) {
      log("API error", "SYSTEM", {
        event: "api-error",
        error: error.message,
        endpoint: req.originalUrl,
      });
      console.error(`Failed to delete message ${messageId}:`, error);
      res
        .status(500)
        .json({
          status: "error",
          message: `Failed to delete message. Reason: ${error.message}`,
        });
    }
  });

  // Make campaign sender available for WebSocket updates
  router.campaignSender = campaignSender;

  return router;
}

module.exports = { initializeApi, getWebhookUrl };
