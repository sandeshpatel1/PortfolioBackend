require('dotenv').config();
const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const validator = require('validator');

const app = express();
const PORT = process.env.PORT || 5000;

// Catch anything that would otherwise crash/restart the process silently
process.on('unhandledRejection', (reason) => {
  console.error('🔥 Unhandled Rejection:', reason);
});
process.on('uncaughtException', (err) => {
  console.error('🔥 Uncaught Exception:', err);
});

// Render sits behind a reverse proxy that sets X-Forwarded-For.
// Trust exactly 1 hop so express-rate-limit can correctly identify
// unique clients instead of throwing ERR_ERL_UNEXPECTED_X_FORWARDED_FOR.
app.set('trust proxy', 1);

// ─── Security Middleware ─────────────────────────────────────────────────────
app.use(helmet());

const defaultOrigins = [
  'https://patelsandesh.netlify.app',
  'http://localhost:5173',
  'http://localhost:3000',
];
const allowedOrigins = process.env.ALLOWED_ORIGINS
  ? process.env.ALLOWED_ORIGINS.split(',').map(o => o.trim())
  : defaultOrigins;

app.use(cors({
  origin: (origin, callback) => {
    // allow requests with no origin (curl, server-to-server, health checks)
    if (!origin || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    console.warn(`⚠️  CORS blocked request from origin: ${origin}`);
    return callback(new Error('Not allowed by CORS'));
  },
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

// ─── Email Sending (Brevo HTTP API) ──────────────────────────────────────────
// Uses Brevo's transactional email API instead of raw SMTP — avoids Render's
// rotating outbound IPs needing allowlisting, and sidesteps Gmail SMTP
// connection timeouts entirely.
//
// Required env vars:
//   BREVO_API_KEY   - from Brevo dashboard → SMTP & API → API Keys
//   SENDER_EMAIL    - must be a VERIFIED sender in Brevo (Settings → Senders)
//   SENDER_NAME     - optional, defaults to "Sandesh Patel"
const sendBrevoEmail = async ({ toEmail, toName, subject, html, replyTo }) => {
  const apiKey = process.env.BREVO_API_KEY;
  if (!apiKey) {
    throw new Error('BREVO_API_KEY is not set');
  }

  const senderEmail = process.env.SENDER_EMAIL || 'patelsandesh1@gmail.com';
  const senderName = process.env.SENDER_NAME || 'Sandesh Patel';

  const payload = {
    sender: { name: senderName, email: senderEmail },
    to: [{ email: toEmail, name: toName || toEmail }],
    subject,
    htmlContent: html,
  };
  if (replyTo) payload.replyTo = { email: replyTo };

  const res = await fetch('https://api.brevo.com/v3/smtp/email', {
    method: 'POST',
    headers: {
      'api-key': apiKey,
      'Content-Type': 'application/json',
      'Accept': 'application/json',
    },
    body: JSON.stringify(payload),
  });

  if (!res.ok) {
    const errBody = await res.text().catch(() => '');
    const err = new Error(`Brevo API error ${res.status}: ${errBody}`);
    err.status = res.status;
    throw err;
  }

  return res.json();
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
  body { background:#eef0f4; font-family:'Segoe UI',-apple-system,BlinkMacSystemFont,Arial,sans-serif; padding:32px 16px; }
  .wrapper { max-width:560px; margin:0 auto; }

  /* Outer glow card */
  .card { background:#ffffff; border-radius:24px; overflow:hidden; box-shadow:0 20px 60px rgba(15,23,42,0.10), 0 2px 8px rgba(15,23,42,0.06); }

  /* Header */
  .header { position:relative; background:linear-gradient(135deg,#fb923c 0%,#f97316 45%,#ea580c 100%); padding:44px 36px 56px; text-align:center; overflow:hidden; }
  .header::before { content:''; position:absolute; top:-60px; right:-60px; width:180px; height:180px; background:rgba(255,255,255,0.12); border-radius:50%; }
  .header::after { content:''; position:absolute; bottom:-80px; left:-40px; width:160px; height:160px; background:rgba(255,255,255,0.08); border-radius:50%; }
  .status-pill { display:inline-block; background:rgba(255,255,255,0.2); border:1px solid rgba(255,255,255,0.35); color:#fff; font-size:0.7rem; font-weight:700; letter-spacing:0.08em; text-transform:uppercase; padding:6px 14px; border-radius:100px; margin-bottom:18px; position:relative; z-index:1; }
  .avatar { width:64px; height:64px; background:rgba(255,255,255,0.22); border-radius:50%; display:flex; align-items:center; justify-content:center; margin:0 auto 18px; font-size:1.7rem; border:2.5px solid rgba(255,255,255,0.5); position:relative; z-index:1; }
  .header h1 { color:#fff; font-size:1.55rem; font-weight:800; margin-bottom:8px; letter-spacing:-0.01em; position:relative; z-index:1; }
  .header p { color:rgba(255,255,255,0.92); font-size:0.9rem; line-height:1.5; max-width:340px; margin:0 auto; position:relative; z-index:1; }

  /* Floating card overlap effect */
  .body-wrap { padding:0 20px; margin-top:-28px; position:relative; z-index:2; }
  .body { background:#ffffff; border-radius:18px; padding:32px 28px; box-shadow:0 8px 24px rgba(15,23,42,0.06); }

  .greeting { font-size:1.05rem; font-weight:700; color:#1a1206; margin-bottom:14px; }
  .para { color:#5c5347; font-size:0.92rem; line-height:1.75; margin-bottom:14px; }

  .highlight-box { display:flex; gap:14px; align-items:flex-start; background:linear-gradient(135deg,#fff7ed,#fef3c7); border:1px solid rgba(249,115,22,0.22); border-radius:14px; padding:18px 20px; margin:22px 0; }
  .highlight-icon { font-size:1.3rem; line-height:1; flex-shrink:0; }
  .highlight-box p { color:#7c3d0e; font-size:0.86rem; line-height:1.65; }
  .highlight-box strong { color:#ea580c; }

  .divider { height:1px; background:#f0e8dc; margin:26px 0 22px; }

  .signature { display:flex; align-items:center; gap:14px; }
  .sig-dot { width:44px; height:44px; background:linear-gradient(135deg,#f97316,#f59e0b); border-radius:12px; display:flex; align-items:center; justify-content:center; color:#fff; font-weight:800; font-size:0.95rem; flex-shrink:0; box-shadow:0 4px 12px rgba(249,115,22,0.35); }
  .sig-info { text-align:left; }
  .sig-name { font-weight:700; color:#1a1206; font-size:0.96rem; }
  .sig-role { font-size:0.76rem; color:#8c7355; margin-top:2px; }

  /* Footer / socials */
  .footer { padding:28px 36px 34px; text-align:center; }
  .footer-label { font-size:0.72rem; font-weight:700; text-transform:uppercase; letter-spacing:0.1em; color:#a89a80; margin-bottom:14px; }
  .social-links { display:flex; justify-content:center; gap:10px; flex-wrap:wrap; }
  .social-btn { display:inline-flex; align-items:center; gap:6px; background:#fff7ed; border:1px solid #fde3c8; color:#c2410c; padding:9px 18px; border-radius:100px; font-size:0.8rem; font-weight:700; text-decoration:none; }
  .footer-note { margin-top:22px; padding-top:18px; border-top:1px solid #f0e8dc; }
  .footer-note p { color:#a89a80; font-size:0.74rem; line-height:1.7; }
  .footer-note a { color:#ea580c; text-decoration:none; font-weight:600; }

  @media(max-width:480px){ .header{padding:36px 24px 48px;} .body{padding:26px 20px;} .footer{padding:24px 20px 28px;} }
</style>
</head>
<body>
<div class="wrapper">
  <div class="card">

    <div class="header">
      <span class="status-pill">✅ Delivered</span>
      <div class="avatar">👋</div>
      <h1>Message Received!</h1>
      <p>Thanks for reaching out, ${data.firstName} — I'll be in touch shortly.</p>
    </div>

    <div class="body-wrap">
      <div class="body">
        <p class="greeting">Hey ${data.firstName},</p>
        <p class="para">I received your message and wanted to send a quick confirmation. Your inquiry has landed safely in my inbox, and I'm genuinely excited to read it.</p>
        <p class="para">Whether it's a project collaboration, a job opportunity, or just a hello — I take every conversation seriously and appreciate the time you took to reach out.</p>

        <div class="highlight-box">
          <span class="highlight-icon">⏰</span>
          <p><strong>Response time:</strong> I typically reply within <strong>24 hours</strong>, often sooner. In the meantime, feel free to browse my GitHub or connect with me on LinkedIn.</p>
        </div>

        <p class="para">I'll be reviewing your message soon — talk to you then!</p>

        <div class="divider"></div>

        <div class="signature">
          <div class="sig-dot">SP</div>
          <div class="sig-info">
            <div class="sig-name">Sandesh Patel</div>
            <div class="sig-role">Full Stack Developer · MERN Stack · Mumbai 🇮🇳</div>
          </div>
        </div>
      </div>
    </div>

    <div class="footer">
      <div class="footer-label">Let's connect</div>
      <div class="social-links">
        <a href="https://www.linkedin.com/in/sandeshpatel1/" class="social-btn">💼 LinkedIn</a>
        <a href="https://github.com/sandeshpatel1" class="social-btn">💻 GitHub</a>
        <a href="https://sandeshpatel1.github.io/MyPortfolio" class="social-btn">🌐 Portfolio</a>
      </div>
      <div class="footer-note">
        <p>You received this because you contacted <a href="mailto:patelsandesh1@gmail.com">patelsandesh1@gmail.com</a><br/>via the portfolio contact form.</p>
      </div>
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

  if (!process.env.BREVO_API_KEY) {
    // Dev mode: log but return success
    console.log('\n📧 [DEV] Would have sent email:', { firstName, lastName, email, project, message });
    return res.json({ success: true, message: 'Message received (dev mode — no email sent).' });
  }

  try {
    const ownerEmail = process.env.SENDER_EMAIL || 'patelsandesh1@gmail.com';

    // Send notification to owner
    await sendBrevoEmail({
      toEmail: ownerEmail,
      toName: 'Sandesh Patel',
      replyTo: email,
      subject: `📬 New Contact: ${project} — from ${firstName} ${lastName}`,
      html: buildOwnerEmail({ firstName, lastName, email, project, message }),
    });

    // Send auto-reply to sender
    await sendBrevoEmail({
      toEmail: email,
      toName: `${firstName} ${lastName}`,
      subject: `Got your message, ${firstName}! ✅`,
      html: buildAutoReply({ firstName, lastName, email, project, message }),
    });

    console.log(`✅ Contact from ${firstName} ${lastName} <${email}> — Subject: "${project}"`);
    res.json({ success: true, message: 'Message sent successfully!' });

  } catch (err) {
    console.error('❌ Email error:', err.message);
    res.status(500).json({
      success: false,
      message: 'Failed to send email. Please try again or email me directly.',
      debug: { message: err.message, status: err.status }, // TEMP: remove once mail flow is confirmed working
    });
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
  if (!process.env.BREVO_API_KEY) {
    console.log('⚠️  Set BREVO_API_KEY + SENDER_EMAIL in .env to enable email sending');
  }
});