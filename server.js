const express = require("express");
const cors = require("cors");
const { Pool } = require("pg");
const { Octokit } = require("@octokit/rest");
const { createAppAuth } = require("@octokit/auth-app");
const cookieParser = require("cookie-parser");
const axios = require("axios");
const { App } = require("@octokit/app");
require("dotenv").config();

const app = express();
app.use(cookieParser());
app.use(
  cors({
    origin: process.env.FRONTEND_URL,
    credentials: true,
  })
);
app.use(express.json());

const PORT = process.env.PORT || 3001;

// GitHub App initialization
const gitHubApp = new App({
  appId: process.env.GITHUB_APP_ID,
  privateKey: process.env.GITHUB_PRIVATE_KEY,
  oauth: {
    clientId: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
  },
  webhooks: {
    secret: process.env.GITHUB_WEBHOOK_SECRET,
  },
});

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl:
    process.env.NODE_ENV === "production"
      ? { rejectUnauthorized: false }
      : false,
});

// Database setup
async function setupDatabase() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        github_id INTEGER UNIQUE NOT NULL,
        github_installation_id TEXT,
        total_earnings NUMERIC DEFAULT 0,
        aadhaar_pan TEXT,
        is_verified BOOLEAN DEFAULT FALSE,
        is_active BOOLEAN ,
        authorization_revoked BOOLEAN,
        email TEXT,
        name TEXT,
        personal_access_token TEXT,
        expiry_date TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        refresh_token TEXT,
        refresh_token_expiry_date TIMESTAMP,
        solana_address TEXT
      );

      CREATE TABLE IF NOT EXISTS bounties (
        id SERIAL PRIMARY KEY,
        issue_id INTEGER NOT NULL,
        amount NUMERIC NOT NULL,
        status TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        repository TEXT,
        issue_title TEXT,
        issue_url TEXT,
        creator_id INTEGER REFERENCES users(github_id),
        claimed_by INTEGER REFERENCES users(github_id)
      );

      CREATE TABLE IF NOT EXISTS bounty_claims (
      id SERIAL PRIMARY KEY,
      bounty_id INTEGER REFERENCES bounties(id),
      user_id INTEGER REFERENCES users(github_id),
      claimed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );

    `);
    console.log("Database setup complete");
  } catch (err) {
    console.error("Error setting up database:", err);
  } finally {
    client.release();
  }
}

setupDatabase();

// Middleware for authentication
const authenticateUser = async (req, res, next) => {
  if (!req.cookies || !req.cookies.user_id) {
    return res.status(401).json({ error: "Not authenticated" });
  }
  const userId = req.cookies.user_id;

  try {
    const client = await pool.connect();
    try {
      let result = await client.query(
        "SELECT * FROM users WHERE github_id = $1",
        [userId]
      );
      let user = result.rows[0];

      if (user.authorization_revoked) {
        return res.status(401).json({ error: "Authorization revoked" });
      }

      // Check if the access token is expired
      if (new Date() > new Date(user.expiry_date)) {
        // Refresh the access token
        const newAccessToken = await refreshGitHubToken(userId);
        user = { ...user, personal_access_token: newAccessToken };
      }

      req.user = user;
      next();
    } finally {
      client.release();
    }
  } catch (error) {
    console.error("Authentication error:", error);
    res.status(500).json({ error: "Internal server error" });
  }
};

// Routes
app.get("/auth/github", (req, res) => {
  const redirectUri = process.env.GITHUB_AUTH_CALLBACK_URI;
  const clientId = process.env.GITHUB_CLIENT_ID;
  const scopes = ["user:email", "read:user"];

  const authUrl = `https://github.com/login/oauth/authorize?client_id=${clientId}&scope=${encodeURIComponent(
    scopes.join(" ")
  )}&redirect_uri=${encodeURIComponent(redirectUri)}`;

  res.json({ authUrl });
});

app.get("/auth/github/callback", async (req, res) => {
  const code = req.query.code;
  const clientId = process.env.GITHUB_CLIENT_ID;
  const clientSecret = process.env.GITHUB_CLIENT_SECRET;
  const redirectUri = process.env.GITHUB_AUTH_CALLBACK_URI;

  try {
    // Exchange code for access token
    const accessTokenResponse = await axios.post(
      "https://github.com/login/oauth/access_token",
      {
        client_id: clientId,
        client_secret: clientSecret,
        code: code,
        redirect_uri: redirectUri,
      },
      {
        headers: {
          Accept: "application/json",
        },
      }
    );

    const {
      access_token,
      expires_in,
      refresh_token,
      refresh_token_expires_in,
    } = accessTokenResponse.data;

    // Fetch user details
    const userResponse = await axios.get("https://api.github.com/user", {
      headers: {
        Authorization: `Bearer ${access_token}`,
      },
    });

    // Fetch user emails
    const emailResponse = await axios.get(
      "https://api.github.com/user/emails",
      {
        headers: {
          Authorization: `Bearer ${access_token}`,
        },
      }
    );

    const user = userResponse.data;
    const emails = emailResponse.data;

    // Get primary email
    const primaryEmail =
      emails.find((email) => email.primary)?.email || emails[0]?.email;

    let client = await pool.connect();

    try {
      // Insert or update user in the database
      await client.query(
        `
        INSERT INTO users (github_id, name, email, personal_access_token, expiry_date, refresh_token, refresh_token_expiry_date,is_active,authorization_revoked)
        VALUES ($1, $2, $3, $4, $5, $6, $7,$8,$9)
        ON CONFLICT (github_id) DO UPDATE SET
        name = EXCLUDED.name,
        email = EXCLUDED.email,
        personal_access_token = EXCLUDED.personal_access_token,
        expiry_date = EXCLUDED.expiry_date,
        refresh_token = EXCLUDED.refresh_token,
        refresh_token_expiry_date = EXCLUDED.refresh_token_expiry_date,
        is_active= EXCLUDED.is_active,
        authorization_revoked= EXCLUDED.authorization_revoked
      `,
        [
          user.id,
          user.login,
          primaryEmail,
          access_token,
          new Date(Date.now() + expires_in * 1000),
          refresh_token,
          new Date(Date.now() + refresh_token_expires_in * 1000),
          true,
          false,
        ]
      );

      res.cookie("user_id", user.id, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "none",
        maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
      });

      res.json({ success: true });
    } finally {
      client.release();
    }
  } catch (error) {
    console.error(error);
    res.status(500).send("Error during authentication");
  }
});

app.get("/api/checkAuth", authenticateUser, (req, res) => {
  res
    .status(200)
    .json({
      authenticated: true,
      isAppInstalled: req.user.installation_id !== null,
      aadhaarPanVerified: req.user.aadhaar_pan !== null,
      solanaAddressSet: req.user.solana_address !== null,
    });
});

app.post("/api/user/verify", authenticateUser, async (req, res) => {
  const client = await pool.connect();
  try {
    const { aadhaarPan } = req.body;
    const isVerified = await verifyAadhaarPan(aadhaarPan, req.cookies.user_id);
    if (isVerified) {
      res.json({ message: "Verification successful" });
    } else {
      res.status(400).json({ error: "Verification failed" });
    }
  } catch (error) {
    console.error("Error verifying Aadhaar/PAN:", error);
    res.status(500).json({ error: "Failed to verify Aadhaar/PAN" });
  } finally {
    client.release();
  }
});

// app installation
app.get("/api/github/login", authenticateUser, (req, res) => {
  const githubAuthUrl = `https://github.com/apps/${process.env.GITHUB_APP_SLUG}/installations/new`;
  res.json({ githubAuthUrl });
});

app.get("/api/github/callback", authenticateUser, async (req, res) => {
  const { installation_id, setup_action } = req.query;

  if (!installation_id) {
    return res.status(400).json({ error: "Invalid installation_id provided" });
  }

  let client;
  try {
    client = await pool.connect();
    const result = await client.query(
      "SELECT github_installation_id  FROM users WHERE github_id = $1",
      [req.cookies.user_id]
    );
    if (
      setup_action !== "update" &&
      result.rows[0].github_installation_id === installation_id
    ) {
      return res.status(200).json({ isAppInstalled: true });
    }

    const appOctokit = new Octokit({
      authStrategy: createAppAuth,
      auth: {
        appId: process.env.GITHUB_APP_ID,
        privateKey: process.env.GITHUB_PRIVATE_KEY,
        installationId: installation_id,
      },
    });
    const { data: installation } = await appOctokit.apps.getInstallation({
      installation_id,
    });

    // Update the user's github_installation_id in the database
    await client.query(
      "UPDATE users SET github_installation_id = $1 WHERE github_id = $2",
      [installation_id, installation.account.id]
    );

    res.json({ isAppInstalled: true });
  } catch (error) {
    console.error("Error in GitHub callback:", error);
    res.status(500).json({ error: "Failed to update GitHub installation" });
  } finally {
    if (client) {
      client.release();
    }
  }
});

app.post("/api/user/set_solana-address", authenticateUser, async (req, res) => {
  const client = await pool.connect();
  try {
    const { solanaAddress } = req.body;
    await client.query(
      "UPDATE users SET solana_address = $1 WHERE github_id = $2",
      [solanaAddress, req.cookies.user_id]
    );
    res.json({ message: "Solana address connected" });
  } catch (error) {
    console.error("Error connecting Solana address:", error);
    res.status(500).json({ error: "Failed to connect Solana address" });
  } finally {
    client.release();
  }
});

app.get("/api/created_bounties", authenticateUser, async (req, res) => {
  const client = await pool.connect();
  try {
    const result = await client.query(
      "SELECT * FROM bounties WHERE creator_id = $1",
      [req.user.github_id]
    );
    res.json(result.rows);
  } catch (error) {
    console.error("Error fetching bounties:", error);
    res.status(500).json({ error: "Failed to fetch bounties" });
  } finally {
    client.release();
  }
});

app.get("/api/user/bounties-to-approve", authenticateUser, async (req, res) => {
  const client = await pool.connect();
  try {
    const result = await client.query(
      `
      WITH user_bounties AS (
        SELECT id FROM bounties WHERE creator_id = $1 AND status = 'open'
      )
      SELECT 
        b.id AS bounty_id,
        b.issue_id,
        b.amount,
        b.repository,
        b.issue_title,
        b.issue_url,
        json_agg(json_build_object(
          'claimant_id', u.github_id,
          'claimant_name', u.name,
          'claimant_email', u.email,
          'claimed_at', bc.claimed_at
        )) AS claimants
      FROM user_bounties ub
      JOIN bounties b ON ub.id = b.id
      LEFT JOIN bounty_claims bc ON b.id = bc.bounty_id
      LEFT JOIN users u ON bc.user_id = u.github_id
      GROUP BY b.id, b.issue_id, b.amount, b.repository, b.issue_title, b.issue_url
      ORDER BY b.created_at DESC
    `,
      [req.user.github_id]
    );

    res.json(result.rows);
  } catch (error) {
    console.error("Error fetching bounties to approve:", error);
    res.status(500).json({ error: "Failed to fetch bounties to approve" });
  } finally {
    client.release();
  }
});

app.post("/api/approve-bounty-verify", authenticateUser, async (req, res) => {
  const { bountyId } = req.body;
  const client = await pool.connect();

  try {
    const bountyResult = await client.query(
      "SELECT * FROM bounties WHERE id = $1",
      [bountyId]
    );
    if (bountyResult.rows.length === 0) {
      return res.status(404).json({ error: "Bounty not found" });
    }
    const bounty = bountyResult.rows[0];

    const ownerResult = await client.query(
      "SELECT * FROM users WHERE github_id = $1",
      [bounty.creator_id]
    );
    const claimantResult = await client.query(
      "SELECT * FROM users WHERE github_id = $1",
      [bounty.claimed_by]
    );

    if (bounty.creator_id !== req.user.github_id) {
      return res.status(401).json({ error: "Unauthorized" });
    }
    if (bounty.claimed_by === bounty.creator_id) {
      return res
        .status(400)
        .json({ error: "you cannot claim your own bounty" });
    }

    if (ownerResult.rows.length === 0 || claimantResult.rows.length === 0) {
      return res.status(400).json({ error: "Owner or claimant not found" });
    }

    const owner = ownerResult.rows[0];
    const claimant = claimantResult.rows[0];

    if (!owner.solana_address || !claimant.solana_address) {
      return res
        .status(400)
        .json({ error: "Solana address of owner or claimant not found" });
    }

    // Update bounty status
    // await client.query('UPDATE bounties SET status = $1 WHERE id = $2', ['completed', bountyId]);

    res.json({
      fromWalletAddress: owner.solana_address,
      toWalletAddress: claimant.solana_address,
      amount: bounty.amount,
      bountyId: bountyId,
    });
  } catch (error) {
    console.error("Error approving bounty:", error);
    res.status(500).json({ error: "Failed to approve bounty" });
  } finally {
    client.release();
  }
});

app.get("/api/user/claimed-bounties", authenticateUser, async (req, res) => {
  const client = await pool.connect();
  try {
    const result = await client.query(
      `
      SELECT 
        b.id AS bounty_id,
        b.issue_id,
        b.amount,
        b.status AS bounty_status,
        b.repository,
        b.issue_title,
        b.issue_url,
        bc.claimed_at,
        CASE 
          WHEN b.claimed_by = $1 THEN 'Accepted'
          WHEN b.claimed_by IS NOT NULL AND b.claimed_by != $1 THEN 'Rejected'
          ELSE 'Pending'
        END AS claim_status
      FROM bounty_claims bc
      JOIN bounties b ON bc.bounty_id = b.id
      WHERE bc.user_id = $1
      ORDER BY bc.claimed_at DESC
    `,
      [req.user.github_id]
    );

    res.json(result.rows);
  } catch (error) {
    console.error("Error fetching claimed bounties:", error);
    res.status(500).json({ error: "Failed to fetch claimed bounties" });
  } finally {
    client.release();
  }
});

app.delete("/api/bounty/:id", authenticateUser, async (req, res) => {
  const bountyId = req.params.id;
  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    // Check if the bounty exists and the user is the owner
    const bountyResult = await client.query(
      "SELECT * FROM bounties WHERE id = $1 AND creator_id = $2",
      [bountyId, req.user.github_id]
    );
    if (bountyResult.rows.length === 0) {
      await client.query("ROLLBACK");
      return res
        .status(404)
        .json({ error: "Bounty not found or you are not the owner" });
    }
    const bounty = bountyResult.rows[0];

    // Get all claimants
    const claimantsResult = await client.query(
      "SELECT DISTINCT user_id FROM bounty_claims WHERE bounty_id = $1",
      [bountyId]
    );
    const claimants = claimantsResult.rows;

    // Delete bounty claims
    await client.query("DELETE FROM bounty_claims WHERE bounty_id = $1", [
      bountyId,
    ]);

    // Delete the bounty
    await client.query("DELETE FROM bounties WHERE id = $1", [bountyId]);

    await client.query("COMMIT");

    // Notify claimants
    const octokit = await gitHubApp.getInstallationOctokit(
      req.user.github_installation_id
    );
    for (const claimant of claimants) {
      try {
        await octokit.issues.createComment({
          owner: bounty.repository.split("/")[0],
          repo: bounty.repository.split("/")[1],
          issue_number: bounty.issue_id,
          body: `@${claimant.user_id} The bounty you claimed (ID: ${bountyId}) has been deleted by the owner.`,
        });
      } catch (error) {
        console.error(`Error notifying claimant ${claimant.user_id}:`, error);
        // Continue with other notifications even if one fails
      }
    }

    res.json({ message: "Bounty deleted successfully and claimants notified" });
  } catch (error) {
    await client.query("ROLLBACK");
    console.error("Error deleting bounty:", error);
    res.status(500).json({ error: "Failed to delete bounty" });
  } finally {
    client.release();
  }
});

app.post("/api/complete-bounty", authenticateUser, async (req, res) => {
  const { bountyId } = req.body;
  const client = await pool.connect();
  
  try {
    await client.query('UPDATE bounties SET status = $1 WHERE id = $2', ['completed', bountyId]);
    res.json({ message: "Bounty completed successfully" });
  } catch (error) {
    console.error("Error completing bounty:", error);
    res.status(500).json({ error: "Failed to complete bounty" });
  } finally {
    client.release();
  }
});

app.get("/api/user/details", authenticateUser, async (req, res) => {
  const client = await pool.connect();
  try {
    const result = await client.query(
      "SELECT * FROM users WHERE github_id = $1",
      [req.user.github_id]
    );
    if (result.rows.length > 0) {
      res.json({name: result.rows[0].name, email: result.rows[0].email});
    } else {
      res.status(404).json({ error: "User not found" });
    }
  } catch (error) {
    console.error("Error retrieving user profile:", error);
    res.status(500).json({ error: "Failed to retrieve user profile" });
  } finally {
    client.release();
  }
});

app.post("/api/github/webhooks", async (req, res) => {
  const event = req.headers["x-github-event"];
  const signature = req.headers["x-hub-signature-256"];
  const body = req.body

  try {
    await gitHubApp.webhooks.verify(body, signature);
    const payload = body;

    if (event === "installation" && payload.action === "deleted") {
      const githubId = payload.sender.id;
      const client = await pool.connect();

      try {
        // Handle the uninstallation, e.g., disable user account, clean up data
        await client.query(
          "UPDATE users SET github_installation_id = NULL WHERE github_id = $1",
          [githubId]
        );
        console.log(`User ${githubId} uninstalled the GitHub app.`);
      } finally {
        client.release();
      }
    }

    if (event === "issue_comment" && payload.action === "created") {
      const comment = payload.comment.body;
      if (comment.startsWith("/create-bounty")) {
        await handleBountyCreation(payload);
      } else if (comment.startsWith("/claim-bounty")) {
        await handleBountyClaim(payload);
      }
    } else if (event === "issues" && payload.action === "opened") {
      const issueDescription = payload.issue.body;
      if (issueDescription && issueDescription.includes("/create-bounty")) {
        await handleBountyCreation(payload);
      }
    } else if (event === "pull_request") {
      const bountyIdFromDescription = extractBountyIdFromDescription(
        payload.pull_request.body
      );

      if (payload.action === "opened" && bountyIdFromDescription) {
        await handleBountyClaim(payload, bountyIdFromDescription);
      } else if (payload.action === "created") {
        const comment = payload.comment.body;
        if (comment.startsWith("/claim-bounty")) {
          await handleBountyClaim(
            payload,
            extractBountyIdFromDescription(comment)
          );
        }
      }
    }

    res.status(200).send("Webhook received");
  } catch (error) {
    console.error("Error processing webhook:", error);
    res.status(500).json({ error: "Failed to process webhook" });
  }
});

const refreshGitHubToken = async (userId) => {
  const client = await pool.connect();
  try {
    const result = await client.query(
      "SELECT refresh_token, refresh_token_expiry_date FROM users WHERE github_id = $1",
      [userId]
    );
    const { refresh_token, refresh_token_expiry_date } = result.rows[0];

    // Check if the refresh token is still valid
    if (new Date() > new Date(refresh_token_expiry_date)) {
      await client.query(
        `
        UPDATE users SET
          personal_access_token = $1,
          refresh_token = $2,
          authorization_revoked= $3,
        WHERE github_id = $4
      `,
        [
          NULL,
          NULL, // Use the new refresh token if provided, otherwise keep the old one
          true,
          userId,
        ]
      );

      throw new Error(
        "Refresh token has expired and authorization has been revoked"
      );
    }

    // Exchange the refresh token for a new access token
    const tokenResponse = await axios.post(
      "https://github.com/login/oauth/access_token",
      {
        client_id: process.env.GITHUB_CLIENT_ID,
        client_secret: process.env.GITHUB_CLIENT_SECRET,
        refresh_token: refresh_token,
        grant_type: "refresh_token",
      },
      {
        headers: {
          Accept: "application/json",
        },
      }
    );

    const {
      access_token,
      expires_in,
      refresh_token: new_refresh_token,
      refresh_token_expires_in,
    } = tokenResponse.data;

    // Update the tokens and expiry dates in the database
    await client.query(
      `
      UPDATE users SET
        personal_access_token = $1,
        expiry_date = $2,
        refresh_token = $3,
        refresh_token_expiry_date = $4
      WHERE github_id = $5
    `,
      [
        access_token,
        new Date(Date.now() + expires_in * 1000),
        new_refresh_token || refresh_token, // Use the new refresh token if provided, otherwise keep the old one
        new Date(
          Date.now() +
            (refresh_token_expires_in * 1000 || refresh_token_expiry_date)
        ),
        userId,
      ]
    );

    return access_token;
  } catch (error) {
    console.error("Error refreshing GitHub token:", error);
    throw error;
  } finally {
    client.release();
  }
};

function extractBountyIdFromDescription(description) {
  const match = description.match(/bounty\s+(\d+)/i);
  return match ? parseInt(match[1]) : null;
}

async function handleBountyCreation(payload) {
  const amount = extractBountyIdFromDescription(payload.issue.body);
  const issueId = payload.issue.id;
  const userId = payload.comment.user.id;
  console.log("Creating bounty for issue:", issueId, "with amount:", amount);
  const client = await pool.connect();
  try {
    const result = await client.query(
      "INSERT INTO bounties (issue_id, amount, status, creator_id, repository, issue_title, issue_url) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id",
      [
        issueId,
        amount,
        "open",
        userId,
        payload.repository.full_name,
        payload.issue.title,
        payload.issue.html_url,
      ]
    );
    const bountyId = result.rows[0].id;

    const octokit = await gitHubApp.getInstallationOctokit(
      payload.installation.id
    );
    await octokit.issues.createComment({
      owner: payload.repository.owner.login,
      repo: payload.repository.name,
      issue_number: payload.issue.number,
      body: `A bounty of ${amount} rupees has been created for this issue. Bounty ID: ${bountyId}`,
    });

    return bountyId;
  } catch (error) {
    console.error("Error creating bounty:", error);
    throw error;
  } finally {
    client.release();
  }
}

async function handleBountyClaim(payload, bountyIdFromDescription) {
  const issueId = payload.issue.number;
  const userId = payload.comment.user.id;

  const client = await pool.connect();
  try {
    const result = await client.query(
      "SELECT * FROM bounties WHERE issue_id = $1 AND status = $2",
      [issueId, "open"]
    );
    if (result.rows.length === 0) {
      return;
    }
    const bounty = result.rows[0];

    await client.query(
      "UPDATE bounties SET claimed_by = $1, status = $2 WHERE id = $3",
      [userId, "claimed", bounty.id]
    );

    const octokit = await gitHubApp.getInstallationOctokit(
      payload.installation.id
    );
    await octokit.issues.createComment({
      owner: payload.repository.owner.login,
      repo: payload.repository.name,
      issue_number: payload.issue.number,
      body: `Bounty claimed successfully by user ID: ${userId}`,
    });
  } catch (error) {
    console.error("Error claiming bounty:", error);
  } finally {
    client.release();
  }
}

async function verifyAadhaarPan(aadhaarPan, userId) {
  const client = await pool.connect();
  try {
    // Implement your actual verification logic here
    const isVerified = true; // Placeholder for actual verification
    if (isVerified) {
      await client.query(
        "UPDATE users SET aadhaar_pan = $1, is_verified = $2 WHERE github_id = $3",
        [aadhaarPan, true, userId]
      );
      return true;
    } else {
      throw new Error("Verification failed");
    }
  } catch (error) {
    console.error("Error verifying Aadhaar/PAN:", error);
    throw error;
  } finally {
    client.release();
  }
}

app.listen(PORT, () => {
  console.log(`Server is running at ${PORT}`);
});
