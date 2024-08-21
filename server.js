// server.js
const express = require('express');
const axios = require('axios');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3001;

app.get('/api/check-auth', (req, res) => {
  const githubToken = req.cookies.github_token;
  if (githubToken) {
    res.status(200).json({ authenticated: true });
  } else {
    res.status(401).json({ authenticated: false });
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

app.get('/api/bounties', async (req, res) => {
  const githubToken = req.cookies.github_token;

  if (!githubToken) {
    return res.status(401).json({ error: 'Not authenticated' });
  }

  try {
    // Fetch bounties using the GitHub token
    const bounties = await fetchBountiesForUser(githubToken);
    res.json(bounties);
  } catch (error) {
    console.error('Error fetching bounties:', error);
    res.status(500).json({ error: 'Failed to fetch bounties' });
  }
});


const { Octokit } = require('@octokit/rest');
const jwt = require('jsonwebtoken');

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

async function fetchBountiesForUser(token) {
  try {
    // Create an Octokit instance authenticated with the user's token
    const octokit = new Octokit({ auth: token });

    // Fetch the authenticated user's information
    const { data: user } = await octokit.users.getAuthenticated();

    // Fetch issues from repositories where the user has access
    // and that have a label 'bounty'
    const { data: issues } = await octokit.issues.listForAuthenticatedUser({
      filter: 'all',
      state: 'open',
      labels: 'bounty'
    });

    // Transform the issues into bounties
    const bounties = issues.map(issue => ({
      id: issue.id,
      title: issue.title,
      repoName: issue.repository.full_name,
      url: issue.html_url,
      amount: extractBountyAmount(issue.body), // You'll need to implement this function
      status: 'open' // You might want to add more complex status logic
    }));

    return bounties;
  } catch (error) {
    console.error('Error fetching bounties:', error);
    throw new Error('Failed to fetch bounties');
  }
}

// Helper function to extract bounty amount from issue body
function extractBountyAmount(body) {
  // This is a simple implementation. You might want to make it more robust.
  const match = body.match(/bounty:\s*(\d+)/i);
  return match ? parseInt(match[1], 10) : 0;
}

app.post('/api/webhooks/github', async (req, res) => {
  const event = req.headers['x-github-event'];
  const payload = req.body;

  if (event === 'issue_comment' && payload.action === 'created') {
    const comment = payload.comment.body;
    if (comment.startsWith('/create-bounty')) {
      await handleBountyCreation(payload);
    }
  }

  res.status(200).send('Webhook received');
});

async function handleBountyCreation(payload) {
  const [, amount] = payload.comment.body.split(' ');
  const installationId = payload.installation.id;
  
  const octokit = await octokitApp.getInstallationOctokit(installationId);

  const bounty = {
    id: Date.now(),
    issueId: payload.issue.id,
    amount: parseInt(amount),
    status: 'open',
    createdAt: new Date().toISOString(),
    repository: payload.repository.full_name,
    issueTitle: payload.issue.title,
    issueUrl: payload.issue.html_url
  };

  // Save bounty to database here

  // Post a comment confirming the bounty creation
  await octokit.issues.createComment({
    owner: payload.repository.owner.login,
    repo: payload.repository.name,
    issue_number: payload.issue.number,
    body: `A bounty of ${amount} rupees has been created for this issue.`
  });
}

app.get('/api/bounties', (req, res) => {
  res.json(bounties);
});

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Something went wrong!' });
});

app.listen(PORT, () => {
  console.log(`Server is running at ${PORT}`);
});
