const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const path = require('path');
require('dotenv').config();

const { 
  authenticateJWT, 
  checkRole, 
  checkDocumentAccess, 
  combinedAccess,
  readJSONFile 
} = require('./middleware/auth');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(cors());
app.use(express.static('public'));

app.use(session({
  secret: process.env.SESSION_SECRET || 'rahasia_session',
  resave: false,
  saveUninitialized: false,
}));


app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ============ PASSPORT GOOGLE OAUTH SETUP ============
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.GOOGLE_CALLBACK_URL
},
async (accessToken, refreshToken, profile, done) => {
  try {
    const users = await readJSONFile('users.json');
    
    let user = users.find(u => u.email === profile.emails[0].value);
    
    if (!user) {
      user = {
        id: users.length + 1,
        username: profile.displayName.replace(/\s+/g, '').toLowerCase(),
        email: profile.emails[0].value,
        role: 'user',
        department: 'General',
        clearance_level: 1,
        subscription: 'free',
        google_id: profile.id
      };
      users.push(user);
      await require('fs').promises.writeFile(
        path.join(__dirname, 'data', 'users.json'),
        JSON.stringify(users, null, 2)
      );
    }
    
    return done(null, user);
  } catch (error) {
    return done(error, null);
  }
}));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  const users = await readJSONFile('users.json');
  const user = users.find(u => u.id === id);
  done(null, user);
});

app.use(passport.initialize());
app.use(passport.session());

// ============ ROUTES ============

app.get('/', (req, res) => {
  res.render('login', { 
    googleClientId: process.env.GOOGLE_CLIENT_ID 
  });
});

// ============ JWT AUTHENTICATION ============
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const users = await readJSONFile('users.json');
    
    const user = users.find(u => u.username === username && u.password === password);
    
    if (!user) {
      return res.status(401).json({ error: 'Username atau password salah!' });
    }

    const token = jwt.sign(
      { 
        userId: user.id, 
        username: user.username,
        role: user.role 
      },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    res.cookie('token', token, { 
      httpOnly: true, 
      maxAge: 24 * 60 * 60 * 1000 
    });

    res.json({
      message: 'Login berhasil!',
      token: token,
      user: {
        id: user.id,
        username: user.username,
        role: user.role,
        department: user.department
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============ GOOGLE OAUTH ============
app.get('/auth/google',
  passport.authenticate('google', { 
    scope: ['profile', 'email'] 
  })
);

app.get('/auth/google/callback',
  passport.authenticate('google', { 
    failureRedirect: '/?error=google_auth_failed' 
  }),
  async (req, res) => {
    console.log('✅ Google OAuth BERHASIL!');
    console.log('👤 User:', req.user.username);
    console.log('📧 Email:', req.user.email);

    const token = jwt.sign(
      { 
        userId: req.user.id, 
        username: req.user.username,
        role: req.user.role 
      },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );
    
    console.log('🔑 Token generated:', token.substring(0, 30) + '...');
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Login Successful - Google OAuth</title>
        <style>
          * { margin: 0; padding: 0; box-sizing: border-box; }
          body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
          }
          .container {
            text-align: center;
            background: rgba(255,255,255,0.1);
            padding: 40px;
            border-radius: 15px;
            backdrop-filter: blur(10px);
          }
          .checkmark {
            font-size: 60px;
            animation: bounce 1s infinite;
          }
          @keyframes bounce {
            0%, 100% { transform: translateY(0); }
            50% { transform: translateY(-20px); }
          }
          .spinner {
            border: 4px solid rgba(255,255,255,0.3);
            border-top: 4px solid white;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 20px auto;
          }
          @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
          }
          h1 {
            margin: 20px 0;
            font-size: 24px;
          }
          p {
            color: rgba(255,255,255,0.9);
            margin-bottom: 10px;
          }
          .user-info {
            background: rgba(255,255,255,0.2);
            padding: 15px;
            border-radius: 10px;
            margin: 20px 0;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <div class="checkmark">✅</div>
          <h1>Google Login Berhasil!</h1>
          <div class="user-info">
            <p>👤 <strong>${req.user.username}</strong></p>
            <p>📧 ${req.user.email}</p>
            <p>🎭 Role: ${req.user.role}</p>
          </div>
          <p>Mengalihkan ke dashboard...</p>
          <div class="spinner"></div>
        </div>
        <script>
          // Simpan token ke localStorage
          localStorage.setItem('token', '${token}');
          console.log('✅ Token saved to localStorage');
          console.log('🔑 Token:', '${token.substring(0, 30)}...');
          
          // Redirect ke dashboard setelah 1.5 detik
            setTimeout(() => {
                window.location.replace('/dashboard?token=' + encodeURIComponent('${token}'));
            }, 1500);
        </script>
      </body>
      </html>
    `);
  }
);

app.get('/dashboard', (req, res, next) => {
  const token = req.query.token;
  if (token) {
    console.log('🔑 Dashboard diakses dengan token query');
    return res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Loading Dashboard...</title>
        <style>
          body {
            font-family: Arial;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
            margin: 0;
            background: #1a1a2e;
            color: white;
          }
          .loader { text-align: center; }
          .spinner {
            border: 4px solid rgba(255,255,255,0.3);
            border-top: 4px solid #e94560;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 20px auto;
          }
          @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
          }
        </style>
      </head>
      <body>
        <div class="loader">
          <div class="spinner"></div>
          <p>Menyimpan session...</p>
        </div>
        <script>
          // Simpan token dulu
          localStorage.setItem('token', '${token}');
          console.log('✅ Token disimpan ke localStorage');
          
          // Set cookie juga (buat jaga-jaga)
          document.cookie = 'token=${token}; path=/; max-age=86400';
          console.log('✅ Token disimpan ke cookie');
          
          // Redirect ke dashboard BERSIH tanpa query param
          window.location.replace('/dashboard');
        </script>
      </body>
      </html>
    `);
  }

  next();
}, authenticateJWT, (req, res) => {
  console.log('✅ Dashboard rendered for:', req.user.username);
  res.render('dashboard', { user: req.user });
});

// ============ API ENDPOINTS ============

app.get('/api/profile', authenticateJWT, (req, res) => {
  res.json({
    message: 'Ini endpoint yang butuh JWT token',
    user: {
      id: req.user.id,
      username: req.user.username,
      role: req.user.role,
      department: req.user.department,
      clearance_level: req.user.clearance_level,
      subscription: req.user.subscription
    }
  });
});

app.get('/api/documents', authenticateJWT, async (req, res) => {
  try {
    const documents = await readJSONFile('documents.json');
    const user = req.user;
    let filteredDocs = [];

    if (user.role === 'admin') {
      filteredDocs = documents;
    } else if (user.role === 'manager') {
      filteredDocs = documents.filter(doc => doc.department === user.department);
    } else {
      filteredDocs = documents.filter(doc => doc.owner_id === user.id);
    }

    res.json({
      message: `Dokumen difilter berdasarkan RBAC (Role: ${user.role})`,
      access_level: user.role,
      total_docs: filteredDocs.length,
      documents: filteredDocs
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/documents/:id', authenticateJWT, checkDocumentAccess, (req, res) => {
  res.json({
    message: 'Akses dokumen BERHASIL (ABAC Check passed)',
    document: req.document,
    user_access: {
      role: req.user.role,
      clearance: req.user.clearance_level,
      department: req.user.department
    }
  });
});

app.put('/api/documents/:id', authenticateJWT, 
  combinedAccess({
    allowedRoles: ['admin', 'manager', 'user'],
    requiredAttributes: {
      sameDepartment: true,
      minClearance: 3,
      premiumOnly: true
    }
  }),
  (req, res) => {
    res.json({
      message: 'Update BERHASIL! Combined RBAC + ABAC Check PASSED',
      detail: 'Role diizinkan, department sama, clearance cukup, premium OK',
      document: req.document
    });
  }
);

app.delete('/api/documents/:id', authenticateJWT,
  combinedAccess({
    allowedRoles: ['admin', 'manager'],
    requiredAttributes: {
      sameDepartment: true
    }
  }),
  (req, res) => {
    res.json({
      message: 'Delete BERHASIL!',
      detail: 'Hanya admin/manager yang bisa menghapus, dan harus dari departemen yang sama',
      document: req.document
    });
  }
);

app.get('/api/users', authenticateJWT, checkRole('admin'), async (req, res) => {
  const users = await readJSONFile('users.json');
  const safeUsers = users.map(({ password, ...user }) => user);
  res.json({
    message: 'Hanya Admin yang bisa lihat semua user!',
    users: safeUsers
  });
});

app.get('/api/auth/logout', (req, res) => {
  res.clearCookie('token');
  req.logout(() => {
    res.json({ message: 'Logout berhasil!' });
  });
});

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ error: 'Server error!' });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`=================================`);
  console.log(`Server jalan di http://localhost:${PORT}`);
  console.log(`=================================`);
  console.log(`User tersedia:`);
  console.log(`1. admin / admin123 (Role: admin)`);
  console.log(`2. manager / manager123 (Role: manager)`);
  console.log(`3. user1 / user123 (Role: user)`);
  console.log(`4. user2 / user123 (Role: user)`);
  console.log(`=================================`);
});