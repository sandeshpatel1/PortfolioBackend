require('dotenv').config();
const express = require('express');
const nodemailer = require('nodemailer');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const validator = require('validator');

const app = express();
const PORT = process.env.PORT || 5000;

// ─── Security Middleware ─────────────────────────────────────────────────────
app.use(helmet());
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || '*',
  methods: ['GET', 'POST'],
  optionsSuccessStatus: 200,
}));
app.use(express.json({ limit: '10kb' }));

// ─── Rate Limiting ────────────────────────────────────────────────────────────
const contactLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5,
  message: { success: false, message: 'Too many messages sent. Please try again in an hour.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// ─── Email Transporter (Gmail + App Password) ────────────────────────────────
const createTransporter = () => {
  // Uses Gmail with App Password (recommended)
  // Set GMAIL_USER and GMAIL_APP_PASSWORD in .env
  if (process.env.GMAIL_USER && process.env.GMAIL_APP_PASSWORD) {
    return nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.GMAIL_USER,
        pass: process.env.GMAIL_APP_PASSWORD,
      },
    });
  }
  // Fallback: SMTP (Brevo, Mailgun, etc.)
  if (process.env.SMTP_HOST) {
    return nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: parseInt(process.env.SMTP_PORT || '587'),
      secure: false,
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS,
      },
    });
  }
  // Dev fallback: Ethereal (logs email to console, never actually sends)
  console.warn('⚠️  No mail credentials set. Using Ethereal test account.');
  return null;
};

// ─── Email Templates ──────────────────────────────────────────────────────────
const buildOwnerEmail = (data) => `
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>New Contact from Portfolio</title>
<style>
  * { margin:0; padding:0; box-sizing:border-box; }
  body { background:#0f0c07; font-family:'Segoe UI',Arial,sans-serif; padding:40px 20px; }
  .wrapper { max-width:580px; margin:0 auto; }
  .card { background:#1a1510; border:1px solid rgba(249,115,22,0.2); border-radius:20px; overflow:hidden; }
  .header { background:linear-gradient(135deg,#f97316,#f59e0b); padding:36px 36px 28px; text-align:center; }
  .header-icon { font-size:2.5rem; margin-bottom:12px; }
  .header h1 { color:white; font-size:1.5rem; font-weight:700; margin-bottom:4px; }
  .header p { color:rgba(255,255,255,0.8); font-size:0.85rem; }
  .body { padding:32px 36px; }
  .badge { display:inline-block; background:rgba(249,115,22,0.15); border:1px solid rgba(249,115,22,0.3); color:#f97316; padding:4px 12px; border-radius:100px; font-size:0.72rem; font-weight:600; text-transform:uppercase; letter-spacing:0.08em; margin-bottom:24px; }
  .field { margin-bottom:20px; }
  .field-label { font-size:0.72rem; font-weight:600; text-transform:uppercase; letter-spacing:0.1em; color:#7a6545; margin-bottom:6px; }
  .field-value { background:#0f0c07; border:1px solid rgba(249,115,22,0.15); border-radius:10px; padding:12px 16px; color:#f5ead8; font-size:0.92rem; line-height:1.6; }
  .divider { height:1px; background:rgba(249,115,22,0.1); margin:24px 0; }
  .message-box { background:linear-gradient(135deg,rgba(249,115,22,0.08),rgba(245,158,11,0.05)); border:1px solid rgba(249,115,22,0.2); border-radius:12px; padding:20px; color:#c4a97c; font-size:0.92rem; line-height:1.75; white-space:pre-wrap; }
  .footer { padding:20px 36px 28px; border-top:1px solid rgba(249,115,22,0.1); text-align:center; }
  .footer p { color:#7a6545; font-size:0.75rem; line-height:1.6; }
  .footer a { color:#f97316; text-decoration:none; }
  .grid { display:grid; grid-template-columns:1fr 1fr; gap:16px; }
  @media(max-width:480px){ .grid{grid-template-columns:1fr;} .body{padding:24px;} .header{padding:28px 24px 20px;} }
</style>
</head>
<body>
<div class="wrapper">
  <div class="card">
    <div class="header">
      <div class="header-icon">📬</div>
      <h1>New Portfolio Contact</h1>
      <p>Someone reached out via your portfolio website</p>
    </div>
    <div class="body">
      <span class="badge">🕐 ${new Date().toLocaleString('en-IN', { timeZone: 'Asia/Kolkata' })} IST</span>
      <div class="grid">
        <div class="field">
          <div class="field-label">First Name</div>
          <div class="field-value">${data.firstName}</div>
        </div>
        <div class="field">
          <div class="field-label">Last Name</div>
          <div class="field-value">${data.lastName}</div>
        </div>
      </div>
      <div class="field">
        <div class="field-label">Email Address</div>
        <div class="field-value"><a href="mailto:${data.email}" style="color:#f97316;text-decoration:none;">${data.email}</a></div>
      </div>
      <div class="field">
        <div class="field-label">Project / Subject</div>
        <div class="field-value">${data.project}</div>
      </div>
      <div class="divider"></div>
      <div class="field-label" style="margin-bottom:10px;">Message</div>
      <div class="message-box">${data.message}</div>
    </div>
    <div class="footer">
      <p>Sent from <a href="https://sandeshpatel1.github.io/MyPortfolio">your portfolio website</a><br/>Reply directly to <a href="mailto:${data.email}">${data.email}</a></p>
    </div>
  </div>
</div>
</body>
</html>`;

const buildAutoReply = (data) => `
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>Got your message!</title>
<style>
  * { margin:0; padding:0; box-sizing:border-box; }
  body { background:#f5f1eb; font-family:'Segoe UI',Arial,sans-serif; padding:40px 20px; }
  .wrapper { max-width:560px; margin:0 auto; }
  .card { background:#ffffff; border-radius:20px; overflow:hidden; box-shadow:0 8px 40px rgba(0,0,0,0.08); }
  .header { background:linear-gradient(135deg,#f97316,#f59e0b); padding:40px 36px; text-align:center; }
  .avatar { width:70px; height:70px; background:rgba(255,255,255,0.2); border-radius:50%; display:flex; align-items:center; justify-content:center; margin:0 auto 16px; font-size:1.8rem; border:3px solid rgba(255,255,255,0.4); }
  .header h1 { color:white; font-size:1.4rem; font-weight:700; margin-bottom:6px; }
  .header p { color:rgba(255,255,255,0.85); font-size:0.88rem; line-height:1.5; }
  .body { padding:36px; }
  .greeting { font-size:1.1rem; font-weight:600; color:#1a1206; margin-bottom:16px; }
  .para { color:#5c4a2a; font-size:0.92rem; line-height:1.75; margin-bottom:16px; }
  .highlight-box { background:linear-gradient(135deg,#fff7ed,#fef3c7); border:1px solid rgba(249,115,22,0.2); border-radius:12px; padding:20px 24px; margin:24px 0; }
  .highlight-box p { color:#92400e; font-size:0.88rem; line-height:1.65; }
  .highlight-box strong { color:#f97316; }
  .divider { height:1px; background:#f5ead8; margin:24px 0; }
  .footer { padding:24px 36px 32px; text-align:center; background:#fef9f0; border-top:1px solid #f5ead8; }
  .footer p { color:#8c7355; font-size:0.78rem; line-height:1.6; }
  .footer a { color:#f97316; text-decoration:none; }
  .social-links { display:flex; justify-content:center; gap:12px; margin-top:16px; }
  .social-btn { display:inline-block; background:#fff; border:1px solid #f5ead8; color:#5c4a2a; padding:7px 16px; border-radius:100px; font-size:0.78rem; font-weight:600; text-decoration:none; }
  .signature { display:flex; align-items:center; gap:12px; margin-top:8px; }
  .sig-dot { width:40px; height:40px; background:linear-gradient(135deg,#f97316,#f59e0b); border-radius:10px; display:flex; align-items:center; justify-content:center; color:white; font-weight:700; font-size:0.9rem; flex-shrink:0; }
  .sig-info { text-align:left; }
  .sig-name { font-weight:700; color:#1a1206; font-size:0.95rem; }
  .sig-role { font-size:0.75rem; color:#8c7355; }
</style>
</head>
<body>
<div class="wrapper">
  <div class="card">
    <div class="header">
      <div class="avatar">👋</div>
      <h1>Message Received!</h1>
      <p>Thank you for reaching out, ${data.firstName}. I'll be in touch shortly.</p>
    </div>
    <div class="body">
      <p class="greeting">Hey ${data.firstName},</p>
      <p class="para">I received your message and wanted to send you a quick confirmation. Your inquiry has been safely delivered to my inbox and I'm genuinely excited to read it.</p>
      <p class="para">Whether it's about a project collaboration, a job opportunity, or something else — I take every conversation seriously and value the time you took to reach out.</p>
      <div class="highlight-box">
        <p>⏰ <strong>Response Time:</strong> I typically reply within <strong>24 hours</strong>, often sooner. In the meantime, feel free to browse my <strong>GitHub</strong> or connect on <strong>LinkedIn</strong>.</p>
      </div>
      <p class="para">I'll be reviewing your message soon. Talk to you then!</p>
      <div class="divider"></div>
      <div class="signature">
        <div class="sig-dot">SP</div>
        <div class="sig-info">
          <div class="sig-name">Sandesh Patel</div>
          <div class="sig-role">Frontend Developer · MERN Stack · Mumbai 🇮🇳</div>
        </div>
      </div>
    </div>
    <div class="footer">
      <div class="social-links">
        <a href="https://www.linkedin.com/in/sandeshpatel1/" class="social-btn">LinkedIn</a>
        <a href="https://github.com/sandeshpatel1" class="social-btn">GitHub</a>
        <a href="https://sandeshpatel1.github.io/MyPortfolio" class="social-btn">Portfolio</a>
      </div>
      <p style="margin-top:16px;">You received this because you contacted <a href="mailto:patelsandesh1@gmail.com">patelsandesh1@gmail.com</a><br/>via portfolio contact form.</p>
    </div>
  </div>
</div>
</body>
</html>`;

// ─── Routes ───────────────────────────────────────────────────────────────────
app.get('/', (req, res) => {
  res.json({ status: 'ok', message: 'Sandesh Portfolio API is running 🚀', version: '2.0.0' });
});

app.get('/api/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date().toISOString(), uptime: process.uptime() });
});

app.post('/api/submit-form', contactLimiter, async (req, res) => {
  const { firstName, lastName, email, project, message } = req.body;

  // ── Validate inputs ────────────────────────────────────────────────────────
  if (!firstName || !lastName || !email || !project || !message) {
    return res.status(400).json({ success: false, message: 'All fields are required.' });
  }
  if (!validator.isEmail(email)) {
    return res.status(400).json({ success: false, message: 'Invalid email address.' });
  }
  if (message.trim().length < 10) {
    return res.status(400).json({ success: false, message: 'Message too short.' });
  }
  if (firstName.length > 50 || lastName.length > 50) {
    return res.status(400).json({ success: false, message: 'Name too long.' });
  }

  const transporter = createTransporter();

  if (!transporter) {
    // Dev mode: log but return success
    console.log('\n📧 [DEV] Would have sent email:', { firstName, lastName, email, project, message });
    return res.json({ success: true, message: 'Message received (dev mode — no email sent).' });
  }

  try {
    // Verify connection
    await transporter.verify();

    const ownerEmail = process.env.GMAIL_USER || process.env.SMTP_USER || 'patelsandesh1@gmail.com';

    // Send notification to owner
    await transporter.sendMail({
      from: `"Portfolio Contact" <${ownerEmail}>`,
      to: ownerEmail,
      replyTo: email,
      subject: `📬 New Contact: ${project} — from ${firstName} ${lastName}`,
      html: buildOwnerEmail({ firstName, lastName, email, project, message }),
    });

    // Send auto-reply to sender
    await transporter.sendMail({
      from: `"Sandesh Patel" <${ownerEmail}>`,
      to: email,
      subject: `Got your message, ${firstName}! ✅`,
      html: buildAutoReply({ firstName, lastName, email, project, message }),
    });

    console.log(`✅ Contact from ${firstName} ${lastName} <${email}> — Subject: "${project}"`);
    res.json({ success: true, message: 'Message sent successfully!' });

  } catch (err) {
    console.error('❌ Email error:', err.message);
    res.status(500).json({ success: false, message: 'Failed to send email. Please try again or email me directly.' });
  }
});


// ─── LeetCode Stats Proxy ─────────────────────────────────────────────────────
app.get('/api/leetcode/:username', async (req, res) => {
  const { username } = req.params;
  try {
    const body = JSON.stringify({
      query: `
        query userPublicProfile(\$username: String!) {
          matchedUser(username: \$username) {
            submitStats {
              acSubmissionNum {
                difficulty
                count
              }
            }
            profile {
              ranking
            }
          }
          allQuestionsCount { difficulty count }
        }
      `,
      variables: { username }
    });
    const r = await fetch('https://leetcode.com/graphql', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Referer': 'https://leetcode.com',
        'User-Agent': 'Mozilla/5.0 (compatible; portfolio-bot/1.0)',
      },
      body,
    });
    if (!r.ok) throw new Error('LeetCode API error ' + r.status);
    const json = await r.json();
    const user = json.data?.matchedUser;
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });
    const nums = user.submitStats.acSubmissionNum;
    const allQ  = json.data?.allQuestionsCount || [];
    const get = (diff) => nums.find(x => x.difficulty === diff)?.count || 0;
    const getTotal = (diff) => allQ.find(x => x.difficulty === diff)?.count || 0;
    res.json({
      success: true,
      totalSolved: get('All'),
      easySolved: get('Easy'),
      mediumSolved: get('Medium'),
      hardSolved: get('Hard'),
      totalQuestions: getTotal('All'),
      easyTotal: getTotal('Easy'),
      mediumTotal: getTotal('Medium'),
      hardTotal: getTotal('Hard'),
      ranking: user.profile?.ranking || 0,
    });
  } catch (e) {
    console.error('LeetCode proxy error:', e.message);
    res.status(502).json({ success: false, message: 'Failed to fetch LeetCode data', error: e.message });
  }
});

// ─── 404 Handler ─────────────────────────────────────────────────────────────
app.use((req, res) => res.status(404).json({ success: false, message: 'Route not found.' }));

// ─── Error Handler ────────────────────────────────────────────────────────────
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ success: false, message: 'Internal server error.' });
});

// ─── Start ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n🚀 Portfolio Backend running on port ${PORT}`);
  console.log(`📍 Health: http://localhost:${PORT}/health`);
  if (!process.env.GMAIL_USER) {
    console.log('⚠️  Set GMAIL_USER + GMAIL_APP_PASSWORD in .env to enable email sending');
  }
});