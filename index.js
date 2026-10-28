const express = require('express');
const { MongoClient, ObjectId } = require('mongodb');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const xss = require('xss');
const crypto = require('crypto');

const app = express();
app.use(helmet({ contentSecurityPolicy: false })); // CSP relaxed for inline styles/scripts in this single-file architecture
app.use(express.json({ limit: '10kb' }));

const limiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100, message: 'Too many requests' });
app.use('/api/', limiter);

let cachedDb = null;
async function connectDb() {
  if (cachedDb) return cachedDb;
  const client = new MongoClient(process.env.MONGODB_URI, { maxPoolSize: 10 });
  await client.connect();
  const db = client.db('prithika_clinic');
  
  await db.collection('appointments').createIndex({ appointmentDate: 1, appointmentTime: 1 });
  await db.collection('appointments').createIndex({ bookingReference: 1 }, { unique: true });
  
  const servicesCount = await db.collection('services').countDocuments();
  if (servicesCount === 0) {
    await db.collection('services').insertMany([
      { name: 'Initial Consultation', description: 'Comprehensive holistic assessment.', durationMinutes: 30, fee: 500, active: true },
      { name: 'Follow-up Consultation', description: 'Review progress and adjust care.', durationMinutes: 30, fee: 300, active: true },
      { name: 'General Wellness', description: 'Preventative care and immunity support.', durationMinutes: 30, fee: 500, active: true },
      { name: 'Online Consultation', description: 'Consultation via video call.', durationMinutes: 30, fee: 500, active: true }
    ]);
  }
  
  const settingsCount = await db.collection('clinic_settings').countDocuments();
  if (settingsCount === 0) {
    await db.collection('clinic_settings').insertOne({
      clinicName: 'Prithika Homeopathy Clinic', doctorName: 'Dr. Priya Raman, BHMS',
      phone: '+91 98765 43210', email: 'hello@prithikahomeoclinic.example',
      address: '24 Green Garden Road, Anna Nagar, Chennai',
      timezone: 'Asia/Kolkata', slotDuration: 30,
      openingHours: { start1: '09:00', end1: '13:00', start2: '16:00', end2: '20:00' }
    });
  }
  cachedDb = db;
  return db;
}

function getISTDateStr(d = new Date()) {
  return new Intl.DateTimeFormat('en-CA', { timeZone: 'Asia/Kolkata', year: 'numeric', month: '2-digit', day: '2-digit' }).format(d);
}
function getISTTimeStr(d = new Date()) {
  return new Intl.DateTimeFormat('en-GB', { timeZone: 'Asia/Kolkata', hour: '2-digit', minute: '2-digit' }).format(d);
}

// API Routes
app.get('/api/health', (req, res) => res.json({ status: 'ok' }));

app.get('/api/services', async (req, res) => {
  try {
    const db = await connectDb();
    const services = await db.collection('services').find({ active: true }).toArray();
    res.json(services);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/availability', async (req, res) => {
  try {
    const { date } = req.query;
    if (!date || !/^\d{4}-\d{2}-\d{2}$/.test(date)) return res.status(400).json({ error: 'Invalid date format' });
    
    const d = new Date(date);
    if (d.getDay() === 0) return res.json({ slots: [] }); // Sunday closed
    
    const todayStr = getISTDateStr();
    if (date < todayStr) return res.json({ slots: [] });
    
    const db = await connectDb();
    const settings = await db.collection('clinic_settings').findOne();
    const { start1, end1, start2, end2 } = settings.openingHours;
    
    let allSlots = [];
    const addSlots = (start, end) => {
      let [h, m] = start.split(':').map(Number);
      const [eh, em] = end.split(':').map(Number);
      while (h < eh || (h === eh && m < em)) {
        allSlots.push(`${h.toString().padStart(2, '0')}:${m.toString().padStart(2, '0')}`);
        m += settings.slotDuration;
        if (m >= 60) { h += 1; m -= 60; }
      }
    };
    addSlots(start1, end1);
    addSlots(start2, end2);
    
    if (date === todayStr) {
      const nowTime = getISTTimeStr();
      allSlots = allSlots.filter(s => s > nowTime);
    }
    
    const bookings = await db.collection('appointments').find({
      appointmentDate: date, status: { $in: ['pending', 'confirmed'] }
    }).toArray();
    
    const bookedTimes = bookings.map(b => b.appointmentTime);
    const availableSlots = allSlots.filter(s => !bookedTimes.includes(s));
    
    res.json({ slots: availableSlots });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/appointments', async (req, res) => {
  try {
    const { serviceId, date, time, name, phone, email, age, note, consent } = req.body;
    if (!serviceId || !date || !time || !name || !phone || !consent) return res.status(400).json({ error: 'Missing required fields' });
    
    const db = await connectDb();
    const service = await db.collection('services').findOne({ _id: new ObjectId(serviceId) });
    if (!service) return res.status(404).json({ error: 'Service not found' });
    
    const existing = await db.collection('appointments').findOne({ appointmentDate: date, appointmentTime: time, status: { $in: ['pending', 'confirmed'] } });
    if (existing) return res.status(409).json({ error: 'Time slot unavailable. Please select another.' });
    
    const ref = crypto.randomBytes(4).toString('hex').toUpperCase();
    const appointment = {
      bookingReference: ref, serviceType: service.name, consultationFee: service.fee,
      appointmentDate: date, appointmentTime: time, appointmentMode: 'In-Person',
      patientName: xss(name), patientPhone: xss(phone), patientEmail: xss(email || ''),
      patientAge: xss(age), bookingNote: xss(note || ''), consentAccepted: consent,
      status: 'pending', clinicTimezone: 'Asia/Kolkata', createdAt: new Date(), updatedAt: new Date()
    };
    
    await db.collection('appointments').insertOne(appointment);
    res.json({ success: true, bookingReference: ref, date, time, fee: service.fee });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/contact', async (req, res) => {
  try {
    const { name, phone, message } = req.body;
    if (!name || !phone || !message) return res.status(400).json({ error: 'Required fields missing' });
    const db = await connectDb();
    await db.collection('contact_messages').insertOne({
      name: xss(name), phone: xss(phone), message: xss(message), createdAt: new Date(), status: 'unread'
    });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

// HTML Frontend
const html = `
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Prithika Homeopathy Clinic | Natural Care. Thoughtful Healing.</title>
  <meta name="description" content="Personalised homeopathy consultations in a calm, welcoming environment in Chennai.">
  <style>
    :root {
      --c-primary: #248A63; --c-mint: #DFF8E9; --c-cream: #FFF9EE; 
      --c-coral: #FF8277; --c-lavender: #E9E3FF; --c-sky: #DDF1FF; 
      --c-yellow: #FFE9A8; --c-text: #24352F; --c-white: #FFFFFF;
      --font: 'Inter', 'Nunito', system-ui, sans-serif;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    html { scroll-behavior: smooth; }
    body { font-family: var(--font); background: var(--c-cream); color: var(--c-text); line-height: 1.6; }
    a { text-decoration: none; color: inherit; }
    ul { list-style: none; }
    
    /* Claymorphism System */
    .clay {
      background: var(--c-white); border-radius: 24px;
      box-shadow: 8px 8px 24px rgba(36, 138, 99, 0.08), inset -4px -4px 12px rgba(0,0,0,0.02), inset 4px 4px 12px rgba(255,255,255,1);
      transition: transform 0.3s, box-shadow 0.3s; padding: 2rem;
    }
    .clay-btn {
      background: var(--c-primary); color: #fff; border: none; border-radius: 16px; padding: 12px 24px;
      box-shadow: 6px 6px 16px rgba(36, 138, 99, 0.3), inset -4px -4px 8px rgba(0,0,0,0.1), inset 4px 4px 8px rgba(255,255,255,0.3);
      cursor: pointer; font-weight: 600; font-size: 1rem; transition: all 0.2s; display: inline-flex; align-items: center; justify-content: center;
    }
    .clay-btn:hover { transform: translateY(-2px); box-shadow: 8px 8px 20px rgba(36, 138, 99, 0.35), inset -4px -4px 8px rgba(0,0,0,0.1), inset 4px 4px 8px rgba(255,255,255,0.3); }
    .clay-btn:active { transform: translateY(0); box-shadow: inset 4px 4px 8px rgba(0,0,0,0.2), inset -4px -4px 8px rgba(255,255,255,0.1); }
    .clay-btn.secondary { background: var(--c-mint); color: var(--c-primary); box-shadow: 4px 4px 12px rgba(36, 138, 99, 0.1), inset -2px -2px 6px rgba(0,0,0,0.05), inset 2px 2px 6px rgba(255,255,255,0.8); }
    .clay-input {
      width: 100%; padding: 12px 16px; border: none; border-radius: 12px; background: var(--c-cream);
      box-shadow: inset 4px 4px 8px rgba(36, 138, 99, 0.05), inset -4px -4px 8px #fff;
      font-family: var(--font); font-size: 1rem; color: var(--c-text); outline: none; margin-top: 8px;
    }
    .clay-input:focus { box-shadow: inset 6px 6px 12px rgba(36, 138, 99, 0.1), inset -6px -6px 12px #fff; }

    /* Layout & Components */
    .container { max-width: 1200px; margin: 0 auto; padding: 0 5%; }
    section { padding: 5rem 0; }
    .section-title { text-align: center; margin-bottom: 3rem; font-size: 2.5rem; color: var(--c-primary); }
    
    /* Nav */
    nav { position: fixed; top: 0; width: 100%; z-index: 1000; padding: 1rem 0; transition: 0.3s; background: rgba(255, 249, 238, 0.9); backdrop-filter: blur(10px); box-shadow: 0 4px 20px rgba(0,0,0,0.03); }
    .nav-inner { display: flex; justify-content: space-between; align-items: center; }
    .logo { font-size: 1.5rem; font-weight: 800; color: var(--c-primary); display: flex; align-items: center; gap: 8px; }
    .nav-links { display: flex; gap: 2rem; align-items: center; }
    .nav-links a { font-weight: 600; }
    .nav-links a:hover { color: var(--c-primary); }
    .menu-toggle { display: none; font-size: 1.5rem; cursor: pointer; background: none; border: none; color: var(--c-primary); }

    /* Hero */
    .hero { min-height: 100vh; display: flex; align-items: center; padding-top: 6rem; position: relative; overflow: hidden; }
    .hero-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 4rem; align-items: center; }
    .hero-text h1 { font-size: 3.5rem; line-height: 1.2; margin-bottom: 1.5rem; color: var(--c-primary); }
    .hero-text p { font-size: 1.2rem; margin-bottom: 2rem; opacity: 0.9; }
    .hero-btns { display: flex; gap: 1rem; }
    .hero-visual { position: relative; }
    .blob { position: absolute; border-radius: 50%; z-index: -1; filter: blur(40px); opacity: 0.6; }
    .blob-1 { width: 300px; height: 300px; background: var(--c-coral); top: -50px; right: -50px; animation: float 6s ease-in-out infinite; }
    .blob-2 { width: 250px; height: 250px; background: var(--c-mint); bottom: -20px; left: 20px; animation: float 8s ease-in-out infinite reverse; }
    
    @keyframes float { 0%, 100% { transform: translateY(0); } 50% { transform: translateY(-20px); } }

    /* Services */
    .services-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 2rem; }
    .service-card { text-align: center; }
    .service-card h3 { color: var(--c-primary); margin: 1rem 0; }
    .service-price { font-size: 1.25rem; font-weight: 700; color: var(--c-coral); margin: 1rem 0; }
    
    /* Doctor */
    .doctor-card { display: flex; gap: 3rem; align-items: center; background: var(--c-lavender); }
    .doc-avatar { width: 200px; height: 200px; border-radius: 50%; background: #fff; display: flex; align-items: center; justify-content: center; font-size: 4rem; box-shadow: inset 4px 4px 10px rgba(0,0,0,0.1); }
    
    /* Booking Form */
    .booking-wrapper { max-width: 700px; margin: 0 auto; }
    .step { display: none; animation: fadeIn 0.4s ease; }
    .step.active { display: block; }
    @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
    .time-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(100px, 1fr)); gap: 1rem; margin-top: 1rem; }
    .time-slot { background: var(--c-cream); border: 2px solid transparent; border-radius: 12px; padding: 10px; text-align: center; cursor: pointer; transition: 0.2s; font-weight: 600; }
    .time-slot:hover { border-color: var(--c-mint); }
    .time-slot.selected { background: var(--c-primary); color: #fff; box-shadow: 0 4px 10px rgba(36, 138, 99, 0.3); }
    .form-group { margin-bottom: 1.5rem; text-align: left; }
    .form-group label { font-weight: 600; font-size: 0.9rem; }
    
    /* Mobile */
    @media(max-width: 768px) {
      .nav-links { display: none; flex-direction: column; position: absolute; top: 100%; left: 0; width: 100%; background: var(--c-cream); padding: 2rem; box-shadow: 0 10px 20px rgba(0,0,0,0.05); }
      .nav-links.active { display: flex; }
      .menu-toggle { display: block; }
      .hero-grid, .doctor-card { grid-template-columns: 1fr; text-align: center; }
      .hero-btns { justify-content: center; }
      .hero-text h1 { font-size: 2.5rem; }
      .doc-avatar { margin: 0 auto; }
    }
  </style>
</head>
<body>
  <nav>
    <div class="container nav-inner">
      <div class="logo">🌿 Prithika Clinic</div>
      <button class="menu-toggle" onclick="document.querySelector('.nav-links').classList.toggle('active')">☰</button>
      <div class="nav-links">
        <a href="#home">Home</a>
        <a href="#about">About</a>
        <a href="#services">Treatments</a>
        <a href="#doctor">Doctor</a>
        <a href="#book" class="clay-btn" style="padding: 8px 16px;">Book Now</a>
      </div>
    </div>
  </nav>

  <section id="home" class="hero">
    <div class="container hero-grid">
      <div class="hero-text">
        <h1>Care That Listens. Wellness That Matters.</h1>
        <p>Explore personalised homeopathy consultations in a calm, welcoming environment. Your health journey begins here.</p>
        <div class="hero-btns">
          <a href="#book" class="clay-btn">Book Your Appointment</a>
          <a href="#services" class="clay-btn secondary">Explore Services</a>
        </div>
      </div>
      <div class="hero-visual">
        <div class="blob blob-1"></div>
        <div class="blob blob-2"></div>
        <div class="clay" style="position: relative; z-index: 2; text-align: center;">
          <h3 style="color: var(--c-primary); margin-bottom: 10px;">Clinic Hours</h3>
          <p>Mon - Sat</p>
          <p>9:00 AM - 1:00 PM</p>
          <p>4:00 PM - 8:00 PM</p>
          <p style="color: var(--c-coral); font-weight: bold; margin-top: 10px;">Sunday Closed</p>
        </div>
      </div>
    </div>
  </section>

  <section id="about" style="background: var(--c-white);">
    <div class="container" style="text-align: center; max-width: 800px;">
      <h2 class="section-title">Welcome to Prithika Homeopathy</h2>
      <p style="font-size: 1.1rem; margin-bottom: 2rem;">We believe in a gentle, holistic approach to wellness. Our aim is to provide a comfortable patient experience where you feel heard. Please note that homeopathy is complementary, and individual treatment suitability varies.</p>
    </div>
  </section>

  <section id="services">
    <div class="container">
      <h2 class="section-title">Consultation Services</h2>
      <div class="services-grid" id="services-container">
        <!-- Loaded via JS -->
        <p>Loading services...</p>
      </div>
    </div>
  </section>

  <section id="doctor" style="background: #fff;">
    <div class="container">
      <div class="clay doctor-card">
        <div class="doc-avatar">👩🏽‍⚕️</div>
        <div>
          <h2 style="color: var(--c-primary); margin-bottom: 10px;">Dr. Priya Raman, BHMS</h2>
          <p style="font-size: 1.1rem; margin-bottom: 1.5rem;">Dr. Priya provides dedicated holistic care tailored to your unique wellness needs. With a focus on comprehensive consultations, she ensures every patient receives attentive support.</p>
          <p style="font-size: 0.85rem; opacity: 0.7; margin-bottom: 1.5rem;">*Dummy profile for demonstration purposes.</p>
          <a href="#book" class="clay-btn">Consult Doctor</a>
        </div>
      </div>
    </div>
  </section>

  <section id="why-us">
    <div class="container">
      <h2 class="section-title">Why Choose Us?</h2>
      <div class="services-grid">
        <div class="clay service-card" style="background: var(--c-mint);"><h3>Personalised Care</h3><p>Consultations tailored to your individual health background.</p></div>
        <div class="clay service-card" style="background: var(--c-sky);"><h3>Easy Scheduling</h3><p>Seamless online booking system without waiting in lines.</p></div>
        <div class="clay service-card" style="background: var(--c-yellow);"><h3>Calm Environment</h3><p>A welcoming space designed for your comfort and peace.</p></div>
        <div class="clay service-card" style="background: var(--c-lavender);"><h3>Supportive</h3><p>We guide you thoroughly at every step of your wellness journey.</p></div>
      </div>
    </div>
  </section>

  <section id="book">
    <div class="container text-center">
      <h2 class="section-title">Book an Appointment</h2>
      <div class="clay booking-wrapper">
        
        <!-- Step 1 -->
        <div id="step-1" class="step active">
          <h3>Step 1: Choose Service</h3>
          <div id="booking-services" class="services-grid" style="margin-top: 2rem;"></div>
        </div>

        <!-- Step 2 & 3 -->
        <div id="step-2" class="step">
          <h3>Step 2: Date & Time</h3>
          <div class="form-group" style="margin-top: 2rem;">
            <label>Select Date</label>
            <input type="date" id="b-date" class="clay-input" min="" onchange="fetchSlots()">
          </div>
          <div id="slots-container" class="time-grid"></div>
          <div style="margin-top: 2rem; display: flex; justify-content: space-between;">
            <button class="clay-btn secondary" onclick="goStep(1)">Back</button>
            <button class="clay-btn" id="btn-next-2" style="display:none;" onclick="goStep(3)">Next</button>
          </div>
        </div>

        <!-- Step 4 -->
        <div id="step-3" class="step">
          <h3>Step 3: Patient Details</h3>
          <div class="form-group" style="margin-top: 1rem;">
            <label>Full Name *</label><input type="text" id="b-name" class="clay-input" required>
          </div>
          <div class="form-group">
            <label>Phone Number *</label><input type="tel" id="b-phone" class="clay-input" required>
          </div>
          <div class="form-group">
            <label>Email (Optional)</label><input type="email" id="b-email" class="clay-input">
          </div>
          <div class="form-group">
            <label>Age *</label><input type="number" id="b-age" class="clay-input" required>
          </div>
          <div class="form-group">
            <label>Booking Note (Optional)</label><input type="text" id="b-note" class="clay-input">
          </div>
          <div class="form-group" style="display:flex; gap:10px; align-items:start;">
            <input type="checkbox" id="b-consent" style="margin-top:4px;">
            <label for="b-consent" style="font-weight:normal; font-size:0.85rem;">I acknowledge the clinic's privacy notice and understand this consultation does not replace emergency medical care.</label>
          </div>
          <div style="margin-top: 2rem; display: flex; justify-content: space-between;">
            <button class="clay-btn secondary" onclick="goStep(2)">Back</button>
            <button class="clay-btn" onclick="reviewBooking()">Review</button>
          </div>
        </div>

        <!-- Step 5 -->
        <div id="step-4" class="step">
          <h3>Review & Confirm</h3>
          <div style="background: var(--c-cream); padding: 1.5rem; border-radius: 12px; margin: 1.5rem 0; text-align: left;">
            <p><strong>Service:</strong> <span id="r-service"></span></p>
            <p><strong>Date & Time:</strong> <span id="r-datetime"></span></p>
            <p><strong>Fee:</strong> ₹<span id="r-fee"></span></p>
            <p><strong>Patient:</strong> <span id="r-name"></span> (<span id="r-phone"></span>)</p>
          </div>
          <p id="b-error" style="color:red; display:none; margin-bottom:1rem;"></p>
          <div style="margin-top: 2rem; display: flex; justify-content: space-between;">
            <button class="clay-btn secondary" onclick="goStep(3)">Back</button>
            <button class="clay-btn" onclick="submitBooking()" id="btn-submit">Confirm Booking</button>
          </div>
        </div>

        <!-- Success -->
        <div id="step-5" class="step" style="text-align:center;">
          <div style="font-size: 4rem; margin-bottom: 1rem;">🎉</div>
          <h3 style="color: var(--c-primary);">Booking Successful!</h3>
          <p style="margin: 1rem 0;">Your appointment reference is: <strong id="s-ref" style="font-size:1.2rem;"></strong></p>
          <p>Date: <strong id="s-date"></strong> at <strong id="s-time"></strong></p>
          <p style="font-size:0.9rem; opacity:0.8; margin: 1rem 0;">Your appointment is currently pending confirmation. We will contact you shortly.</p>
          <div style="display:flex; justify-content:center; gap:1rem; margin-top:2rem;">
            <a href="https://wa.me/919876543210" target="_blank" class="clay-btn secondary">WhatsApp Us</a>
            <button class="clay-btn" onclick="location.reload()">Done</button>
          </div>
        </div>

      </div>
    </div>
  </section>

  <footer style="background: var(--c-white); padding: 4rem 0 2rem; text-align: center;">
    <div class="container">
      <h2 style="color: var(--c-primary); margin-bottom: 1rem;">Prithika Homeopathy Clinic</h2>
      <p style="margin-bottom: 2rem;">24 Green Garden Road, Anna Nagar, Chennai, Tamil Nadu, India</p>
      <p style="font-size: 0.8rem; opacity: 0.7; max-width: 800px; margin: 0 auto 2rem;">
        Disclaimer: Information on this website is for educational purposes and does not replace professional medical assessment, diagnosis, or emergency care. All testimonials, doctor details, and contact numbers are dummy data for demonstration.
      </p>
      <p style="font-size: 0.9rem; font-weight:bold;">&copy; <span id="year"></span> Prithika Clinic. All rights reserved.</p>
    </div>
  </footer>

  <script>
    document.getElementById('year').textContent = new Date().getFullYear();
    const today = new Date().toLocaleDateString('en-CA', { timeZone: 'Asia/Kolkata' });
    document.getElementById('b-date').min = today;

    let services = [];
    let state = { serviceId: null, serviceName: '', fee: 0, date: '', time: '', name: '', phone: '', email: '', age: '', note: '', consent: false };

    async function loadServices() {
      try {
        const res = await fetch('/api/services');
        services = await res.json();
        const html = services.map(s => 
          \`<div class="clay service-card">
            <h3>\${s.name}</h3><p>\${s.description}</p><p class="service-price">₹\${s.fee}</p>
            <button class="clay-btn" onclick="selectService('\${s._id}', '\${s.name}', \${s.fee})">Book</button>
          </div>\`
        ).join('');
        document.getElementById('services-container').innerHTML = html;
        document.getElementById('booking-services').innerHTML = html;
      } catch(e) {
        document.getElementById('services-container').innerHTML = '<p>Failed to load services.</p>';
      }
    }
    loadServices();

    function goStep(n) {
      document.querySelectorAll('.step').forEach(el => el.classList.remove('active'));
      document.getElementById('step-' + n).classList.add('active');
    }

    function selectService(id, name, fee) {
      state.serviceId = id; state.serviceName = name; state.fee = fee;
      goStep(2);
    }

    async function fetchSlots() {
      const date = document.getElementById('b-date').value;
      if(!date) return;
      state.date = date;
      const container = document.getElementById('slots-container');
      container.innerHTML = 'Loading...';
      document.getElementById('btn-next-2').style.display = 'none';
      
      const res = await fetch('/api/availability?date=' + date);
      const data = await res.json();
      if(!data.slots || data.slots.length === 0) {
        container.innerHTML = '<p style="grid-column: 1/-1; color:var(--c-coral);">No slots available. Clinic may be closed or fully booked.</p>';
        return;
      }
      container.innerHTML = data.slots.map(t => 
        \`<div class="time-slot" onclick="selectTime('\${t}', this)">\${t}</div>\`
      ).join('');
    }

    function selectTime(time, el) {
      state.time = time;
      document.querySelectorAll('.time-slot').forEach(e => e.classList.remove('selected'));
      el.classList.add('selected');
      document.getElementById('btn-next-2').style.display = 'inline-flex';
    }

    function reviewBooking() {
      state.name = document.getElementById('b-name').value.trim();
      state.phone = document.getElementById('b-phone').value.trim();
      state.email = document.getElementById('b-email').value.trim();
      state.age = document.getElementById('b-age').value.trim();
      state.note = document.getElementById('b-note').value.trim();
      state.consent = document.getElementById('b-consent').checked;

      if(!state.name || !state.phone || !state.age) return alert("Please fill all required fields.");
      if(!state.consent) return alert("Please accept the privacy notice.");

      document.getElementById('r-service').textContent = state.serviceName;
      document.getElementById('r-datetime').textContent = state.date + ' at ' + state.time;
      document.getElementById('r-fee').textContent = state.fee;
      document.getElementById('r-name').textContent = state.name;
      document.getElementById('r-phone').textContent = state.phone;
      
      document.getElementById('b-error').style.display = 'none';
      goStep(4);
    }

    async function submitBooking() {
      const btn = document.getElementById('btn-submit');
      btn.innerText = 'Processing...'; btn.disabled = true;
      try {
        const res = await fetch('/api/appointments', {
          method: 'POST', headers: {'Content-Type': 'application/json'},
          body: JSON.stringify(state)
        });
        const data = await res.json();
        if(data.error) {
          document.getElementById('b-error').textContent = data.error;
          document.getElementById('b-error').style.display = 'block';
          btn.innerText = 'Confirm Booking'; btn.disabled = false;
        } else {
          document.getElementById('s-ref').textContent = data.bookingReference;
          document.getElementById('s-date').textContent = data.date;
          document.getElementById('s-time').textContent = data.time;
          goStep(5);
        }
      } catch(e) {
        document.getElementById('b-error').textContent = "Network error. Try again.";
        document.getElementById('b-error').style.display = 'block';
        btn.innerText = 'Confirm Booking'; btn.disabled = false;
      }
    }
  </script>
</body>
</html>
`;

app.get('/*', (req, res) => res.send(html));

if (process.env.NODE_ENV !== 'production' && require.main === module) {
  const port = process.env.PORT || 3000;
  app.listen(port, () => console.log(`Public App running on port ${port}`));
}

module.exports = app;
