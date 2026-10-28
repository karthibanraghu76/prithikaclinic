const express = require('express');
const { MongoClient, ObjectId } = require('mongodb');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const xss = require('xss');

const app = express();
app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json());
app.use(cookieParser());

let cachedDb = null;
async function connectDb() {
  if (cachedDb) return cachedDb;
  const client = new MongoClient(process.env.MONGODB_URI, { maxPoolSize: 5 });
  await client.connect();
  cachedDb = client.db('prithika_clinic');
  return cachedDb;
}

const JWT_SECRET = process.env.SESSION_SECRET || 'fallback_secret_do_not_use_in_prod';

// Auth Middleware
const auth = async (req, res, next) => {
  const token = req.cookies.admin_token;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.adminId = decoded.id;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// Admin Auth Routes
app.post('/api/admin/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const db = await connectDb();
    let admin = await db.collection('admin_users').findOne({ username });
    
    // Secure Bootstrapping from Env
    if (!admin && username === process.env.ADMIN_USERNAME && process.env.ADMIN_PASSWORD) {
      if (password === process.env.ADMIN_PASSWORD) {
        const hash = await bcrypt.hash(password, 10);
        const result = await db.collection('admin_users').insertOne({ username, passwordHash: hash, role: 'admin', active: true });
        admin = { _id: result.insertedId, username };
      }
    }
    
    if (!admin || !(await bcrypt.compare(password, admin.passwordHash || ''))) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    const token = jwt.sign({ id: admin._id }, JWT_SECRET, { expiresIn: '8h' });
    res.cookie('admin_token', token, { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax', maxAge: 8*60*60*1000 });
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: 'Server error' }); }
});

app.post('/api/admin/logout', (req, res) => {
  res.clearCookie('admin_token'); res.json({ success: true });
});
app.get('/api/admin/me', auth, (req, res) => res.json({ loggedIn: true }));

// Admin API Routes
app.get('/api/admin/dashboard', auth, async (req, res) => {
  try {
    const db = await connectDb();
    const today = new Intl.DateTimeFormat('en-CA', { timeZone: 'Asia/Kolkata' }).format(new Date());
    
    const [total, todayCount, pending, confirmed, completed, cancelled] = await Promise.all([
      db.collection('appointments').countDocuments(),
      db.collection('appointments').countDocuments({ appointmentDate: today }),
      db.collection('appointments').countDocuments({ status: 'pending' }),
      db.collection('appointments').countDocuments({ status: 'confirmed' }),
      db.collection('appointments').countDocuments({ status: 'completed' }),
      db.collection('appointments').countDocuments({ status: 'cancelled' })
    ]);
    
    const completedApps = await db.collection('appointments').find({ status: 'completed' }).toArray();
    const revenue = completedApps.reduce((acc, curr) => acc + (Number(curr.consultationFee) || 0), 0);
    
    res.json({ stats: { total, todayCount, pending, confirmed, completed, cancelled, revenue } });
  } catch (err) { res.status(500).json({ error: 'Error' }); }
});

app.get('/api/admin/appointments', auth, async (req, res) => {
  try {
    const db = await connectDb();
    const apps = await db.collection('appointments').find().sort({ appointmentDate: -1, appointmentTime: 1 }).limit(100).toArray();
    res.json(apps);
  } catch (err) { res.status(500).json({ error: 'Error' }); }
});

app.patch('/api/admin/appointments/:id/status', auth, async (req, res) => {
  try {
    const { status } = req.body;
    if (!['pending','confirmed','completed','cancelled','no_show'].includes(status)) return res.status(400).json({error:'Invalid status'});
    const db = await connectDb();
    await db.collection('appointments').updateOne({ _id: new ObjectId(req.params.id) }, { $set: { status, updatedAt: new Date() } });
    res.json({ success: true });
  } catch (err) { res.status(500).json({ error: 'Error' }); }
});

app.get('/api/admin/services', auth, async (req, res) => {
  const db = await connectDb();
  res.json(await db.collection('services').find().toArray());
});

app.post('/api/admin/services', auth, async (req, res) => {
  const db = await connectDb();
  const { name, description, durationMinutes, fee } = req.body;
  await db.collection('services').insertOne({ name: xss(name), description: xss(description), durationMinutes: Number(durationMinutes), fee: Number(fee), active: true });
  res.json({ success: true });
});

app.patch('/api/admin/services/:id', auth, async (req, res) => {
  const db = await connectDb();
  const { active } = req.body;
  await db.collection('services').updateOne({ _id: new ObjectId(req.params.id) }, { $set: { active } });
  res.json({ success: true });
});

// Admin HTML
const adminHtml = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Admin - Prithika Clinic</title>
  <style>
    :root {
      --c-primary: #248A63; --c-mint: #DFF8E9; --c-cream: #FFF9EE; 
      --c-text: #24352F; --c-white: #FFFFFF;
      --font: 'Inter', system-ui, sans-serif;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: var(--font); background: var(--c-cream); color: var(--c-text); }
    
    .clay { background: var(--c-white); border-radius: 16px; box-shadow: 8px 8px 24px rgba(36, 138, 99, 0.08), inset 4px 4px 12px #fff; padding: 1.5rem; }
    .clay-btn { background: var(--c-primary); color: #fff; border: none; border-radius: 12px; padding: 8px 16px; cursor: pointer; box-shadow: 4px 4px 10px rgba(36, 138, 99, 0.2); font-weight:600; }
    .clay-btn.sm { padding: 4px 10px; font-size: 0.8rem; }
    .clay-input { width: 100%; padding: 10px; border: 1px solid #ddd; border-radius: 8px; margin-top: 4px; margin-bottom: 12px; }
    
    /* Login */
    #login-view { height: 100vh; display: flex; align-items: center; justify-content: center; }
    .login-box { width: 100%; max-width: 400px; text-align: center; }
    
    /* Layout */
    #app-view { display: none; min-height: 100vh; display: flex; flex-direction: column; }
    @media(min-width: 768px) { #app-view { flex-direction: row; } }
    
    .sidebar { width: 100%; background: var(--c-white); padding: 2rem; box-shadow: 2px 0 10px rgba(0,0,0,0.05); }
    @media(min-width: 768px) { .sidebar { width: 250px; min-height: 100vh; position: fixed; } }
    .sidebar h2 { color: var(--c-primary); margin-bottom: 2rem; }
    .nav-item { display: block; padding: 10px 15px; margin-bottom: 10px; border-radius: 8px; cursor: pointer; font-weight: 600; color: #666; }
    .nav-item:hover, .nav-item.active { background: var(--c-mint); color: var(--c-primary); }
    
    .main-content { flex: 1; padding: 2rem; }
    @media(min-width: 768px) { .main-content { margin-left: 250px; } }
    .tab-content { display: none; }
    .tab-content.active { display: block; }
    
    /* Stats Grid */
    .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1.5rem; margin-top: 1.5rem; }
    .stat-card h3 { font-size: 1rem; color: #666; }
    .stat-card p { font-size: 2rem; font-weight: 800; color: var(--c-primary); }
    
    /* Table */
    table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
    th, td { padding: 12px; text-align: left; border-bottom: 1px solid #eee; }
    th { background: #fafafa; font-weight: 600; color: #555; }
    .badge { padding: 4px 8px; border-radius: 12px; font-size: 0.8rem; font-weight: 600; }
    .badge.pending { background: #fff3cd; color: #856404; }
    .badge.confirmed { background: #d4edda; color: #155724; }
    .badge.completed { background: #cce5ff; color: #004085; }
    .badge.cancelled { background: #f8d7da; color: #721c24; }
    
    .actions { display: flex; gap: 5px; flex-wrap: wrap; }
  </style>
</head>
<body>

  <div id="login-view">
    <div class="clay login-box">
      <h2 style="color: var(--c-primary); margin-bottom: 1.5rem;">Admin Login</h2>
      <input type="text" id="username" class="clay-input" placeholder="Username">
      <input type="password" id="password" class="clay-input" placeholder="Password">
      <button class="clay-btn" style="width:100%; margin-top:1rem;" onclick="login()">Login</button>
      <p id="login-err" style="color:red; margin-top:10px; display:none;"></p>
    </div>
  </div>

  <div id="app-view" style="display: none;">
    <div class="sidebar">
      <h2>🌿 Clinic Admin</h2>
      <div class="nav-item active" onclick="switchTab('dash')">Dashboard</div>
      <div class="nav-item" onclick="switchTab('apps')">Appointments</div>
      <div class="nav-item" onclick="switchTab('servs')">Services</div>
      <div class="nav-item" style="color:#d9534f; margin-top:2rem;" onclick="logout()">Logout</div>
    </div>
    
    <div class="main-content">
      <!-- Dashboard -->
      <div id="tab-dash" class="tab-content active">
        <h2>Dashboard Overview</h2>
        <div class="stats-grid" id="stats-container">Loading...</div>
      </div>
      
      <!-- Appointments -->
      <div id="tab-apps" class="tab-content">
        <h2>Recent Appointments</h2>
        <div class="clay" style="margin-top:1.5rem; overflow-x:auto;">
          <table>
            <thead><tr><th>Ref</th><th>Patient</th><th>Service</th><th>Date & Time</th><th>Status</th><th>Actions</th></tr></thead>
            <tbody id="apps-tbody"></tbody>
          </table>
        </div>
      </div>
      
      <!-- Services -->
      <div id="tab-servs" class="tab-content">
        <div style="display:flex; justify-content:space-between; align-items:center;">
          <h2>Manage Services</h2>
          <button class="clay-btn" onclick="document.getElementById('add-service').style.display='block'">+ Add</button>
        </div>
        
        <div id="add-service" class="clay" style="display:none; margin-top:1rem;">
          <h4>Add New Service</h4>
          <input type="text" id="s-name" class="clay-input" placeholder="Service Name">
          <input type="text" id="s-desc" class="clay-input" placeholder="Description">
          <input type="number" id="s-dur" class="clay-input" placeholder="Duration (mins)" value="30">
          <input type="number" id="s-fee" class="clay-input" placeholder="Fee (₹)">
          <button class="clay-btn sm" onclick="addService()">Save</button>
          <button class="clay-btn sm" style="background:#ccc;" onclick="document.getElementById('add-service').style.display='none'">Cancel</button>
        </div>

        <div class="clay" style="margin-top:1.5rem; overflow-x:auto;">
          <table>
            <thead><tr><th>Name</th><th>Duration</th><th>Fee</th><th>Status</th><th>Actions</th></tr></thead>
            <tbody id="servs-tbody"></tbody>
          </table>
        </div>
      </div>
    </div>
  </div>

  <script>
    async function checkAuth() {
      try {
        const res = await fetch('/api/admin/me');
        if (res.ok) { document.getElementById('login-view').style.display='none'; document.getElementById('app-view').style.display='flex'; loadDash(); }
      } catch(e) {}
    }
    checkAuth();

    async function login() {
      const u = document.getElementById('username').value;
      const p = document.getElementById('password').value;
      const res = await fetch('/api/admin/login', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({username:u, password:p}) });
      if(res.ok) { location.reload(); }
      else { document.getElementById('login-err').textContent = 'Invalid credentials'; document.getElementById('login-err').style.display='block'; }
    }

    async function logout() {
      await fetch('/api/admin/logout', { method:'POST' }); location.reload();
    }

    function switchTab(tab) {
      document.querySelectorAll('.tab-content').forEach(el => el.classList.remove('active'));
      document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
      document.getElementById('tab-'+tab).classList.add('active');
      event.target.classList.add('active');
      if(tab === 'dash') loadDash();
      if(tab === 'apps') loadApps();
      if(tab === 'servs') loadServs();
    }

    async function loadDash() {
      const res = await fetch('/api/admin/dashboard');
      const { stats } = await res.json();
      document.getElementById('stats-container').innerHTML = \`
        <div class="clay stat-card"><h3>Total Appointments</h3><p>\${stats.total}</p></div>
        <div class="clay stat-card"><h3>Today's</h3><p>\${stats.todayCount}</p></div>
        <div class="clay stat-card"><h3>Pending</h3><p>\${stats.pending}</p></div>
        <div class="clay stat-card"><h3>Confirmed</h3><p>\${stats.confirmed}</p></div>
        <div class="clay stat-card"><h3>Completed Fees Recorded</h3><p>₹\${stats.revenue}</p></div>
      \`;
    }

    async function loadApps() {
      const res = await fetch('/api/admin/appointments');
      const apps = await res.json();
      document.getElementById('apps-tbody').innerHTML = apps.map(a => \`
        <tr>
          <td>\${a.bookingReference}</td>
          <td>\${a.patientName}<br><small>\${a.patientPhone}</small></td>
          <td>\${a.serviceType}</td>
          <td>\${a.appointmentDate} <br> \${a.appointmentTime}</td>
          <td><span class="badge \${a.status}">\${a.status}</span></td>
          <td class="actions">
            \${a.status==='pending' ? \`<button class="clay-btn sm" onclick="updateApp('\${a._id}', 'confirmed')">Confirm</button>\`:''}
            \${a.status==='confirmed' ? \`<button class="clay-btn sm" style="background:#004085;" onclick="updateApp('\${a._id}', 'completed')">Complete</button>\`:''}
            \${['pending','confirmed'].includes(a.status) ? \`<button class="clay-btn sm" style="background:#d9534f;" onclick="updateApp('\${a._id}', 'cancelled')">Cancel</button>\`:''}
          </td>
        </tr>
      \`).join('');
    }

    async function updateApp(id, status) {
      if(!confirm('Mark as ' + status + '?')) return;
      await fetch('/api/admin/appointments/'+id+'/status', { method:'PATCH', headers:{'Content-Type':'application/json'}, body:JSON.stringify({status}) });
      loadApps();
    }

    async function loadServs() {
      const res = await fetch('/api/admin/services');
      const servs = await res.json();
      document.getElementById('servs-tbody').innerHTML = servs.map(s => \`
        <tr>
          <td>\${s.name}</td><td>\${s.durationMinutes}m</td><td>₹\${s.fee}</td>
          <td>\${s.active ? 'Active' : 'Inactive'}</td>
          <td>
            <button class="clay-btn sm" onclick="toggleService('\${s._id}', \${!s.active})">\${s.active ? 'Deactivate' : 'Activate'}</button>
          </td>
        </tr>
      \`).join('');
    }

    async function addService() {
      const payload = {
        name: document.getElementById('s-name').value, description: document.getElementById('s-desc').value,
        durationMinutes: document.getElementById('s-dur').value, fee: document.getElementById('s-fee').value
      };
      await fetch('/api/admin/services', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(payload) });
      document.getElementById('add-service').style.display='none';
      loadServs();
    }

    async function toggleService(id, active) {
      await fetch('/api/admin/services/'+id, { method:'PATCH', headers:{'Content-Type':'application/json'}, body:JSON.stringify({active}) });
      loadServs();
    }
  </script>
</body>
</html>
`;

app.get('/admin/*', (req, res) => res.send(adminHtml));
app.get('/admin', (req, res) => res.send(adminHtml));

if (process.env.NODE_ENV !== 'production' && require.main === module) {
  const port = process.env.PORT || 3001;
  app.listen(port, () => console.log(`Admin App running on port ${port}`));
}

module.exports = app;
