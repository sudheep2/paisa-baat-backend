const express = require('express');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

const { Octokit } = require('@octokit/rest');
const jwt = require('jsonwebtoken');
const { App } = require('@octokit/app');

const Webhooks= require("@octokit/webhooks");

const PORT = process.env.PORT || 3001;

// Database connection (replace with your actual database setup)
const mongoose = require('mongoose');
mongoose.connect('mongodb://localhost:27017/bounty-management', {
  useNewUrlParser: true,
  useUnifiedTopology: true
});

// User schema
const userSchema = new mongoose.Schema({
  githubId: Number,
  totalEarnings: Number,
  aadhaarPan: String,
  isVerified: Boolean,
  solanaAddress: String
});

const User = mongoose.model('User', userSchema);

// Bounty schema
const bountySchema = new mongoose.Schema({
  id: String,
  issueId: Number,
  amount: Number,
  status: String,
  createdAt: Date,
  repository: String,
  issueTitle: String,
  issueUrl: String,
  creatorId: Number,
  claimedBy: Number
});

const Bounty = mongoose.model('Bounty', bountySchema);

// KYC verification API integration (replace with your actual API credentials)
const KYCService = require('kyc-service');
KYCService.initialize('YOUR_API_KEY');

// Solana transaction handling (replace with your Solana API credentials)
const SolanaWeb3 = require('@solana/web3.js');
const connection = new SolanaWeb3.Connection(process.env.SOLANA_RPC_URL);

app.get('/api/check-auth', (req, res) => {
  const githubToken = req.cookies.github_token;
  if (githubToken) {
    res.status(200).json({ authenticated: true });
  } else {
    res.status(401).json({ authenticated: false });
  }
});

app.post('/api/user/verify', async (req, res) => {
  try {
    const { aadhaarPan } = req.body;
    const userId = req.user.id; // Assuming you have user authentication in place

    const isVerified = await verifyAadhaarPan(aadhaarPan, userId);
    if (isVerified) {
      // Update user profile or proceed with other actions
      res.json({ message: 'Verification successful' });
    } else {
      res.status(400).json({ error: 'Verification failed' });
    }
  } catch (error) {
    console.error('Error verifying Aadhaar/PAN:', error);
    res.status(500).json({ error: 'Failed to verify Aadhaar/PAN' });
  }
});

app.get('/api/github/login', (req, res) => {
  const githubAuthUrl = `https://github.com/apps/${process.env.GITHUB_APP_SLUG}/installations/new`;
  res.json({ url: githubAuthUrl });
});

app.get('/api/github/callback', async (req, res) => {
  const { code, installation_id } = req.query;

  if (!code || !installation_id) {
    return res.status(400).json({ error: 'Invalid code or installation_id provided' });
  }

  try {
    const accessToken = await exchangeCodeForToken(code, installation_id);

    const octokit = new Octokit({ auth: accessToken });
    const user = await octokit.users.getAuthenticated();

    const existingUser = await User.findOne({ githubId: user.data.id });
    if (existingUser) {
      // User already exists, update access token
      existingUser.githubAccessToken = accessToken;
      await existingUser.save();
    } else {
      // Create a new user profile
      const newUser = new User({
        githubId: user.data.id,
        githubAccessToken: accessToken,
        // ... other user fields
      });
      await newUser.save();
    }
    // In a production app, you'd want to store this token securely, possibly in a database
    // associated with the user's session
    res.cookie('github_token', accessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 3600000 // 1 hour
    });

    res.redirect(`${process.env.FRONTEND_URL}/dashboard`);
  } catch (error) {
    console.error('Error in GitHub callback:', error);
    res.status(500).json({ error: 'Failed to authenticate with GitHub' });
  }
});

app.post('/api/refresh-token', async (req, res) => {
  const githubToken = req.cookies.github_token;

  if (!githubToken) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  try {
    // Verify the token and get the user's information
    const octokit = new Octokit({ auth: githubToken });
    const user = await octokit.users.getAuthenticated();

    // Exchange the refresh token for a new access token
    const { data } = await octokit.apps.createInstallationAccessToken({
      installation_id: user.data.id
    });
    const newAccessToken = data.token;

    // Update the access token in the database
    const existingUser = await User.findOne({ githubId: user.data.id });
    if (existingUser) {
      existingUser.githubAccessToken = newAccessToken;
      await existingUser.save();
    } else {
      return res.status(401).json({ error: 'User not found' });
    }

    // Set a new cookie with the refreshed token
    res.cookie('github_token', newAccessToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 3600000 // 1 hour
    });

    res.json({ message: 'Token refreshed successfully' });
  } catch (error) {
    console.error('Error refreshing token:', error);
    res.status(500).json({ error: 'Failed to refresh token' });
  }
});

app.get('/api/bounties', async (req, res) => {
  const githubToken = req.cookies.github_token;

  if (!githubToken) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  try {
    const octokit = new Octokit({ auth: token });

    // Get the authenticated user's ID from the token
    const { data: user } = await octokit.users.getAuthenticated();
    const userId = user.id;


    // Fetch bounties for the authenticated user from the database
    const bounties = await Bounty.find({ creatorId: userId });

    res.json(bounties);
  } catch (error) {
    console.error('Error fetching bounties:', error);
    res.status(500).json({ error: 'Failed to fetch bounties' });
  }
});

app.post('/api/user/details', async (req, res) => {
  try {
    const githubToken = req.cookies.github_token;

    if (!githubToken) {
      return res.status(401).json({ error: 'Not authenticated' });
    }

    const octokit = new Octokit({ auth: githubToken });
    const user = await octokit.users.getAuthenticated();

    // Store user information in the database (or update if existing)
    const existingUser = await User.findOne({ githubId: user.data.id });
    if (existingUser) {
      // User already exists, update profile if needed
      res.json(existingUser);
    } else {
      return res.status(401).json({ error: 'Not authenticated' });
    }
  } catch (error) {
    console.error('Error retrieving user profile:', error);
    res.status(500).json({ error: 'Failed to retrieve user profile' });
  }
});

app.post('/api/user/solana-address', async (req, res) => {
  try {
    const { solanaAddress } = req.body;
    const user = await User.findById(req.user.id);
    user.solanaAddress = solanaAddress;
    await user.save();
    res.json({ message: 'Solana address connected' });
  } catch (error) {
    console.error('Error connecting Solana address:', error);
    res.status(500).json({ error: 'Failed to connect Solana address' });
  }
});

app.post('/api/webhooks/github', async (req, res) => {
  const event = req.headers['x-github-event'];
  
  const webhooks = new Webhooks({
    secret: process.env.WEBHOOK_SECRET,
  });
  
    const signature = req.headers["x-hub-signature-256"];
    const body = await req.text();
    
    if (!(await webhooks.verify(body, signature))) {
      res.status(401).send("Unauthorized");
      return;
    }

    if (event === 'issue_comment' && payload.action === 'created') {
      const comment = payload.comment.body;
      if (comment.startsWith('/create-bounty')) {
        await handleBountyCreation(payload);
      } else if (comment.startsWith('/claim-bounty')) {
        await handleBountyClaim(payload);
      }
    } else if (event === 'pull_request' && (payload.action === 'closed' || payload.action === 'opened')) {
      const bountyIdFromDescription = extractBountyIdFromDescription(payload.pull_request.body);
      if (bountyIdFromDescription) {
        await handleBountyClaim(payload, bountyIdFromDescription);
      }
    }
  
  res.status(200).send('Webhook received');
});

app.post('/api/approve-bounty', async (req, res) => {
  const bountyId = req.body.bountyId;

  try {
    const bounty = await Bounty.findOne({ _id: bountyId });
    if (!bounty) {
      return res.status(404).json({ error: 'Bounty not found' });
    }

    const owner = await User.findById(bounty.creatorId);
    const claimant = await User.findById(bounty.claimedBy);

    if (!owner.solanaAddress || !claimant.solanaAddress) {
      return res.status(400).json({ error: 'Solana address of owner or claimant not found' });
    }


    // Update bounty status and send notification
    // bounty.status = 'completed';
    // await bounty.save();

    // Send notification to claimant
    // ... (your notification logic)

    res.json({fromWalletAddress: owner.solanaAddress, toWalletAddress: claimant.solanaAddress, amount: bounty.amount, bountyId: bountyId});
  } catch (error) {
    console.error('Error approving bounty:', error);
    res.status(500).json({ error: 'Failed to approve bounty' });
  }
});


async function exchangeCodeForToken(code, installationId) {
  try {
    // Generate a JSON Web Token (JWT) signed with your GitHub App's private key
    const token = jwt.sign({}, process.env.GITHUB_PRIVATE_KEY, {
      algorithm: 'RS256',
      expiresIn: '10m',
      issuer: process.env.GITHUB_APP_ID
    });

    // Create an authenticated Octokit instance using the JWT
    const octokit = new Octokit({
      auth: token,
      previews: ['machine-man-preview']
    });

    // Exchange the code for an access token
    const { data } = await octokit.apps.createInstallationAccessToken({
      installation_id: installationId
    });

    return data.token;
  } catch (error) {
    console.error('Error exchanging code for token:', error);
    throw new Error('Failed to exchange code for token');
  }
}

function extractBountyIdFromDescription(description) {
  const match = description.match(/bounty\s+(\d+)/i);
  return match ? parseInt(match[1], 10) : null;
}

async function handleBountyCreation(payload) {
  const [, amount] = payload.comment.body.split(' ');
  const issueId = payload.issue.id;
  const userId = payload.comment.user.id; // Assuming you have user authentication

  try {
    // Create the bounty
    const bounty = await Bounty.create({
      issueId,
      amount,
      status: 'open',
      creatorId: userId,
      // ... other bounty properties
    });

    // Post a confirmation comment on the PR
    const octokit = await getOctokitForInstallation(payload.installation.id);
    await octokit.issues.createComment({
      owner: payload.repository.owner.login,
      repo: payload.repository.name,
      issue_number: payload.issue.number,

      body: `A bounty of ${amount} rupees has been created for this issue. Bounty ID: ${bounty.id}`
    });

    return bounty;
  } catch (error) {
    console.error('Error creating bounty:', error);
    throw error;
  }
}

async function handleBountyClaim(payload, bountyIdFromDescription) {
  const issueId = payload.issue.number;
  const userId = payload.comment.user.id;

  try {
    const bounty = await Bounty.findOne({ issueId });
    if (!bounty) {
      return; // Bounty not found
    }

    const user = await User.findById(userId);
    if (!user) {
      return; // User not found
    }

    // Check if user is the creator of the bounty
    if (user.id !== bounty.creatorId) {
      return; // Only the creator can claim the bounty
    }

    // Check if bounty is completed
    if (bounty.status !== 'completed') {
      return; // Bounty must be completed to claim
    }

    // Claim bounty and update user's total earnings
    bounty.claimedBy = userId;
    bounty.save();

    user.totalEarnings += bounty.amount;
    user.save();

    // Post a confirmation comment on the PR
    const octokit = await getOctokitForInstallation(payload.installation.id);
    await octokit.issues.createComment({
      owner: payload.repository.owner.login,
      repo: payload.repository.name,
      issue_number: payload.issue.number,   


      body: `Bounty claimed successfully by ${user.username}`
    });
  } catch (error) {
    console.error('Error claiming bounty:', error);
  }
}

async function getOctokitForInstallation(installationId) {
  // Replace with your GitHub App credentials
  const app = new App({
    appId: process.env.GITHUB_APP_ID,
    privateKey: process.env.GITHUB_APP_PRIVATE_KEY
  });

  const octokit = await app.getInstallationOctokit(installationId);
  return octokit;
}

async function verifyAadhaarPan(aadhaarPan, userId) {
  try {
    const response = await KYCService.verify(aadhaarPan);
    if (response.verified) {
      // Update user profile
      await User.findByIdAndUpdate(userId, { aadhaarPan, isVerified: true });
      return true;
    } else {
      throw new Error('Verification failed');
    }
  } catch (error) {
    console.error('Error verifying Aadhaar/PAN:', error);
    throw error;
  }
}

async function calculateLeaderboard() {
  const users = await User.find();
  const leaderboard = users.map((user) => ({
    githubId: user.githubId,
    totalEarnings: user.totalEarnings
  })).sort((a, b) => b.totalEarnings - a.totalEarnings);

  return leaderboard;
}


app.listen(PORT, () => {
  console.log(`Server is running at ${PORT}`);
});