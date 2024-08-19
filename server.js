const { App } = require('@octokit/app');
const express = require('express');
const cors = require('cors');
require('dotenv').config();

// Create an instance of Express
const app = express();

const PORT = process.env.PORT || 3000;

// In-memory storage (replace with a database in production)
const bounties = [];
const privateKey = process.env.GITHUB_PRIVATE_KEY.replace(/\\n/g, '\n');

// Create an instance of Octokit App (renamed to avoid conflict)
const octokitApp = new App({
  appId: process.env.GITHUB_APP_ID,
  privateKey,
  oauth: {
    clientId: process.env.GITHUB_CLIENT_ID,
    clientSecret: process.env.GITHUB_CLIENT_SECRET,
  },
});

const GITHUB_APP_NAME="paisa-baat"


// Middleware setup
app.use(express.json());
app.use(cors());

app.get('/api/github/login', (req, res) => {
  
  const githubAuthUrl = `https://github.com/apps/${GITHUB_APP_NAME}/installations/new`;
  
  res.json({ url: githubAuthUrl });
});

app.get('/api/github/callback', async (req, res) => {
  const { code } = req.query;
  try {
    const { token } = await octokitApp.oauth.createToken({ code });
    
    // In a real app, you'd associate this token with the user in your database
    res.redirect(`${process.env.FRONTEND_URL}/dashboard?token=${token}`);
  } catch (error) {
    console.error('Error in GitHub callback:', error);
    res.status(500).json({ error: 'Failed to authenticate with GitHub' });
  }
});

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
