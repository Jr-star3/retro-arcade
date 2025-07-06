require('dotenv').config();

const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Stripe = require('stripe');
const stripe = Stripe(process.env.STRIPE_SECRET_KEY);
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');
const cors = require('cors');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const helmet = require('helmet');
const app = express();

// Configure your email transporter (credentials from .env only)
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Security middleware
app.use(helmet({
  contentSecurityPolicy: false, // Disable CSP since we're using inline scripts
  xssFilter: false, // Disable X-XSS-Protection header (deprecated)
  crossOriginEmbedderPolicy: false, // Disable unnecessary COEP header
  crossOriginOpenerPolicy: false, // Disable unnecessary COOP header
  crossOriginResourcePolicy: false, // Disable unnecessary CORP header
  originAgentCluster: false, // Disable unnecessary Origin-Agent-Cluster header
}));

// CORS configuration
const corsOptions = {
  origin: process.env.NODE_ENV === 'production' 
    ? process.env.FRONTEND_URL || 'https://yourdomain.com'
    : ['http://localhost:3000', 'http://127.0.0.1:3000', 'http://localhost:5500'],
  credentials: true,
  optionsSuccessStatus: 200
};

app.use(cors(corsOptions));

// Rate limiting for authentication endpoints
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5, // 5 attempts per window
  message: { 
    error: 'Too many authentication attempts, please try again later',
    type: 'error'
  },
  standardHeaders: true,
  legacyHeaders: false,
});

// General rate limiting
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // 100 requests per window
  message: { 
    error: 'Too many requests, please try again later',
    type: 'error'
  }
});

app.use(generalLimiter);
app.use(bodyParser.json({ limit: '10mb' }));
app.use(express.static('public'));
app.use('/games', express.static('games'));  // Serve games directory
app.use('/pages', express.static('pages'));  // Serve pages directory
app.use(express.static('.'));  // Serve files from root directory too

const db = new sqlite3.Database('./users.db');

// Initialize DB with enhanced schema - run synchronously to ensure tables exist
db.serialize(() => {
  // Create users table
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    subscribed INTEGER DEFAULT 0,
    stripe_customer_id TEXT,
    email_verified INTEGER DEFAULT 0,
    verification_token TEXT,
    verification_expires INTEGER,
    created_at INTEGER DEFAULT (strftime('%s', 'now')),
    updated_at INTEGER DEFAULT (strftime('%s', 'now')),
    last_login INTEGER,
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until INTEGER DEFAULT 0
  )`, (err) => {
    if (err) console.error('Error creating users table:', err);
    else console.log('✅ Users table ready');
  });

  // Create password_resets table
  db.run(`CREATE TABLE IF NOT EXISTS password_resets (
    email TEXT,
    token TEXT,
    expires_at INTEGER
  )`, (err) => {
    if (err) console.error('Error creating password_resets table:', err);
    else console.log('✅ Password resets table ready');
  });

  // Create game_progress table
  db.run(`CREATE TABLE IF NOT EXISTS game_progress (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT,
    game TEXT,
    score INTEGER,
    level INTEGER,
    updated_at INTEGER DEFAULT (strftime('%s', 'now')),
    UNIQUE(email, game)
  )`, (err) => {
    if (err) console.error('Error creating game_progress table:', err);
    else console.log('✅ Game progress table ready');
  });

  // Create indexes for better performance
  db.run(`CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)`, (err) => {
    if (err) console.error('Error creating users index:', err);
  });
  
  db.run(`CREATE INDEX IF NOT EXISTS idx_password_resets_token ON password_resets(token)`, (err) => {
    if (err) console.error('Error creating password_resets index:', err);
  });
  
  db.run(`CREATE INDEX IF NOT EXISTS idx_game_progress_email ON game_progress(email)`, (err) => {
    if (err) console.error('Error creating game_progress index:', err);
  });
});

// Helper function for consistent API responses (matches frontend toast system)
const sendResponse = (res, status, message, data = null, type = 'info') => {
  res.status(status).json({
    message,
    type, // 'success', 'error', 'info', 'warning' - matches frontend toast types
    data,
    timestamp: new Date().toISOString()
  });
};

// JWT authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  
  if (!token) {
    return sendResponse(res, 401, 'Access token required', null, 'error');
  }
  
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return sendResponse(res, 403, 'Invalid or expired token', null, 'error');
    }
    req.user = user;
    next();
  });
};

// Error handling middleware
const errorHandler = (err, req, res, next) => {
  console.error(`[${new Date().toISOString()}] Error:`, err);
  
  // Don't expose internal errors in production
  const isDev = process.env.NODE_ENV === 'development';
  const message = isDev ? err.message : 'Internal server error';
  
  sendResponse(res, err.status || 500, message, null, 'error');
};

// Config endpoint to provide frontend configuration
app.get('/config', (req, res) => {
  try {
    res.json({
      // Stripe disabled during free launch
      stripePublishableKey: null, // Will be enabled in Phase 2
      freeAccess: true,
      message: 'All games are currently free! Premium features coming soon.'
    });
  } catch (error) {
    console.error('Config error:', error);
    res.status(500).json({ error: 'Configuration unavailable' });
  }
});

// Registration with email verification
app.post('/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    console.log(`📝 Registration attempt: ${email}`);
    
    // Basic validation
    if (!email || !password) {
      return sendResponse(res, 400, 'Email and password are required', null, 'error');
    }
    
    // Enhanced email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return sendResponse(res, 400, 'Please enter a valid email address', null, 'error');
    }
    
    db.get('SELECT id FROM users WHERE email = ?', [email], async (err, user) => {
      if (err) {
        console.error('Database error during registration:', err);
        return sendResponse(res, 500, 'Registration failed. Please try again.', null, 'error');
      }
      
      if (user) {
        console.log(`❌ User already exists: ${email}`);
        return sendResponse(res, 400, 'An account with this email already exists', null, 'error');
      }
      
      // Hash password and create user (email verification disabled for simple launch)
      const hash = await bcrypt.hash(password, 10);
      
      db.run('INSERT INTO users (email, password, email_verified) VALUES (?, ?, 1)', 
        [email, hash], function(err) {
        if (err) {
          console.error('Database error during user creation:', err);
          return sendResponse(res, 500, 'Registration failed. Please try again.', null, 'error');
        }
        
        console.log(`✅ User created successfully: ${email} with ID: ${this.lastID}`);
        sendResponse(res, 201, 'Account created successfully! You can now log in.', 
          { userId: this.lastID }, 'success');
      });
    });
  } catch (error) {
    console.error('Registration error:', error);
    sendResponse(res, 500, 'Registration failed. Please try again.', null, 'error');
  }
});

// Email verification endpoint
app.get('/verify-email', (req, res) => {
  try {
    const { token: verificationToken } = req.query;
    
    if (!verificationToken) {
      return sendResponse(res, 400, 'Verification token is required', null, 'error');
    }
    
    db.get('SELECT * FROM users WHERE verification_token = ? AND verification_expires > ?', 
      [verificationToken, Date.now()], (err, user) => {
      if (err) {
        console.error('Database error during email verification:', err);
        return sendResponse(res, 500, 'Verification failed. Please try again.', null, 'error');
      }
      
      if (!user) {
        return sendResponse(res, 400, 'Invalid or expired verification token', null, 'error');
      }
      
      // Update user as verified
      db.run('UPDATE users SET email_verified = 1, verification_token = NULL, verification_expires = NULL WHERE id = ?', 
        [user.id], (err) => {
        if (err) {
          console.error('Error updating user verification:', err);
          return sendResponse(res, 500, 'Verification failed. Please try again.', null, 'error');
        }
        
        console.log(`✅ Email verified for user: ${user.email}`);
        sendResponse(res, 200, 'Email verified successfully! You can now log in.', null, 'success');
      });
    });
  } catch (error) {
    console.error('Email verification error:', error);
    sendResponse(res, 500, 'Verification failed. Please try again.', null, 'error');
  }
});

// Login - simplified working version
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    console.log(`🔐 Login attempt: ${email}`);
    
    // Basic validation
    if (!email || !password) {
      return sendResponse(res, 400, 'Email and password are required', null, 'error');
    }
    
    db.get('SELECT * FROM users WHERE email = ?', [email], async (err, user) => {
      if (err) {
        console.error('Database error during login:', err);
        return sendResponse(res, 500, 'Login failed. Please try again.', null, 'error');
      }

      console.log(`🔍 User found in database:`, user ? 'YES' : 'NO');

      if (!user) {
        console.log(`❌ User not found: ${email}`);
        return sendResponse(res, 401, 'Invalid email or password', null, 'error');
      }
      
      // Email verification disabled for simple launch - skip verification check
      // if (!user.email_verified) {
      //   console.log(`❌ Email not verified: ${email}`);
      //   return sendResponse(res, 401, 'Please verify your email address before logging in. Check your inbox for the verification link.', null, 'error');
      // }
      
      console.log(`🔍 User found: ${email}, checking password...`);
      const validPassword = await bcrypt.compare(password, user.password);
      console.log(`🔍 Password valid: ${validPassword}`);
      
      if (!validPassword) {
        return sendResponse(res, 401, 'Invalid email or password', null, 'error');
      }
      
      // Update last login
      db.run('UPDATE users SET last_login = ? WHERE email = ?', 
        [Math.floor(Date.now() / 1000), email]);
      
      const token = jwt.sign({ email }, process.env.JWT_SECRET || 'fallback-secret', { expiresIn: '7d' });
      
      console.log(`✅ Login successful: ${email}`);
      sendResponse(res, 200, 'Welcome back to Retro Arcade!', {
        token,
        subscribed: true // During free launch, everyone gets premium access
      }, 'success');
    });
  } catch (error) {
    console.error('Login error:', error);
    sendResponse(res, 500, 'Login failed. Please try again.', null, 'error');
  }
});

// Game progress endpoints (NEW - supports frontend game functionality)
app.post('/api/game-progress', authenticateToken, [
  body('game').isLength({ min: 1 }).withMessage('Game name is required'),
  body('score').isInt({ min: 0 }).withMessage('Score must be a positive number'),
  body('level').optional().isInt({ min: 1 }).withMessage('Level must be a positive number')
], (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return sendResponse(res, 400, 'Invalid game progress data', errors.array(), 'error');
    }

    const { game, score, level = 1 } = req.body;
    const email = req.user.email;
    
    db.run(`
      INSERT OR REPLACE INTO game_progress (email, game, score, level, updated_at) 
      VALUES (?, ?, ?, ?, ?)
    `, [email, game, score, level, Math.floor(Date.now() / 1000)], function(err) {
      if (err) {
        console.error('Error saving game progress:', err);
        return sendResponse(res, 500, 'Failed to save game progress', null, 'error');
      }
      sendResponse(res, 200, 'Game progress saved successfully!', { 
        game, score, level 
      }, 'success');
    });
  } catch (error) {
    console.error('Game progress error:', error);
    sendResponse(res, 500, 'Failed to save game progress', null, 'error');
  }
});

app.get('/api/game-progress', authenticateToken, (req, res) => {
  try {
    const email = req.user.email;
    
    db.all(
      'SELECT game, score, level, updated_at FROM game_progress WHERE email = ? ORDER BY updated_at DESC',
      [email],
      (err, rows) => {
        if (err) {
          console.error('Error loading game progress:', err);
          return sendResponse(res, 500, 'Failed to load game progress', null, 'error');
        }
        
        const progress = rows.map(row => ({
          ...row,
          updated_at: new Date(row.updated_at * 1000).toISOString()
        }));
        
        sendResponse(res, 200, 'Game progress loaded successfully', { progress }, 'success');
      }
    );
  } catch (error) {
    console.error('Game progress error:', error);
    sendResponse(res, 500, 'Failed to load game progress', null, 'error');
  }
});

// Enhanced user profile endpoint
app.get('/api/profile', authenticateToken, (req, res) => {
  try {
    const email = req.user.email;
    
    db.get(`
      SELECT 
        email, 
        subscribed, 
        created_at, 
        last_login,
        (SELECT COUNT(DISTINCT game) FROM game_progress WHERE email = ?) as games_played,
        (SELECT MAX(score) FROM game_progress WHERE email = ?) as high_score
      FROM users 
      WHERE email = ?
    `, [email, email, email], (err, user) => {
      if (err) {
        console.error('Error loading user profile:', err);
        return sendResponse(res, 500, 'Failed to load profile', null, 'error');
      }
      
      if (!user) {
        return sendResponse(res, 404, 'User not found', null, 'error');
      }
      
      const profile = {
        email: user.email,
        subscribed: !!user.subscribed,
        memberSince: new Date(user.created_at * 1000).toLocaleDateString(),
        lastLogin: user.last_login ? new Date(user.last_login * 1000).toISOString() : null,
        gamesPlayed: user.games_played || 0,
        highScore: user.high_score || 0
      };
      
      sendResponse(res, 200, 'Profile loaded successfully', profile, 'success');
    });
  } catch (error) {
    console.error('Profile error:', error);
    sendResponse(res, 500, 'Failed to load profile', null, 'error');
  }
});

// ========================================
// STRIPE ROUTES - TEMPORARILY DISABLED FOR FREE LAUNCH
// ========================================
// These routes will be enabled once we get Stripe live keys after launching the website
// Keeping the code here for easy re-activation in Phase 2

/*
// Stripe Checkout Session: Only allow one subscription per user
// Stripe Checkout Session: Enhanced with better error handling
app.post('/create-checkout-session', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return sendResponse(res, 400, 'Email is required', null, 'error');
    }

    // 1. Find or create the Stripe customer
    let customer;
    const customers = await stripe.customers.list({ email, limit: 1 });
    if (customers.data.length > 0) {
      customer = customers.data[0];
    } else {
      customer = await stripe.customers.create({ email });
      
      // Update user record with Stripe customer ID
      db.run('UPDATE users SET stripe_customer_id = ? WHERE email = ?', [customer.id, email]);
    }

    // 2. Check for active subscriptions
    const subscriptions = await stripe.subscriptions.list({
      customer: customer.id,
      status: 'all',
      limit: 10
    });

    const hasActive = subscriptions.data.some(sub =>
      ['active', 'trialing', 'past_due', 'unpaid'].includes(sub.status)
    );

    if (hasActive) {
      return sendResponse(res, 409, 'You already have an active subscription', { alreadySubscribed: true }, 'info');
    }

    // 3. Create a new Checkout session
    const session = await stripe.checkout.sessions.create({
      payment_method_types: ['card'],
      line_items: [{
        price_data: {
          currency: 'usd',
          product_data: { name: 'Premium Subscription' },
          unit_amount: 500, // $5.00
          recurring: { interval: 'month' }
        },
        quantity: 1,
      }],
      mode: 'subscription',
      customer: customer.id,
      success_url: `${process.env.FRONTEND_URL || 'http://localhost:3000'}/success.html?email=${encodeURIComponent(email)}`,
      cancel_url: `${process.env.FRONTEND_URL || 'http://localhost:3000'}/subscribe.html`,
      customer_email: email
    });

    sendResponse(res, 200, 'Checkout session created successfully', { id: session.id }, 'success');
  } catch (err) {
    console.error('Stripe checkout error:', err);
    sendResponse(res, 500, 'Failed to create checkout session. Please try again.', null, 'error');
  }
});

// Stripe Customer Portal Session with enhanced error handling
app.post('/create-customer-portal-session', async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return sendResponse(res, 400, 'Email is required', null, 'error');
    }
    
    const customers = await stripe.customers.list({ email, limit: 1 });
    
    if (!customers.data.length) {
      return sendResponse(res, 404, 'No subscription found for this account', null, 'error');
    }
    
    const session = await stripe.billingPortal.sessions.create({
      customer: customers.data[0].id,
      return_url: `${process.env.FRONTEND_URL || 'http://localhost:3000'}/arcade.html`,
    });
    
    sendResponse(res, 200, 'Redirecting to subscription management...', { url: session.url }, 'success');
  } catch (err) {
    console.error('Customer portal error:', err);
    sendResponse(res, 500, 'Could not open subscription management. Please contact support.', null, 'error');
  }
});

// Stripe webhook (for production, use raw body and verify signature)
app.post('/webhook', bodyParser.raw({type: 'application/json'}), async (req, res) => {
  const event = JSON.parse(req.body);

  // Handle successful checkout
  if (event.type === 'checkout.session.completed') {
    const email = event.data.object.customer_email;
    db.run('UPDATE users SET subscribed = 1 WHERE email = ?', [email]);
  }

  // Handle subscription cancellation (keep user status in sync)
  if (event.type === 'customer.subscription.deleted' || event.type === 'customer.subscription.canceled') {
    const customerId = event.data.object.customer;
    try {
      const customer = await stripe.customers.retrieve(customerId);
      if (customer.email) {
        db.run('UPDATE users SET subscribed = 0 WHERE email = ?', [customer.email]);
      }
    } catch (e) {
      // log error
    }
  }

  res.json({received: true});
});
*/

// ========================================
// TEMPORARY FREE ACCESS ROUTE
// ========================================
// This endpoint will return that all users have premium access during free launch
app.get('/api/subscription-status', authenticateToken, (req, res) => {
  // During free launch, everyone gets premium access
  sendResponse(res, 200, 'Free access enabled for launch period', { 
    subscribed: true, // Everyone is "subscribed" during free launch
    freeAccess: true,
    message: 'All games are currently free! Premium features coming soon.'
  }, 'success');
});

// Enhanced /me endpoint for user info and subscription status
app.get('/me', authenticateToken, (req, res) => {
  try {
    const email = req.user.email;
    
    db.get('SELECT email, subscribed, last_login FROM users WHERE email = ?', [email], (err, user) => {
      if (err) {
        console.error('Error in /me endpoint:', err);
        return sendResponse(res, 500, 'Failed to load user information', null, 'error');
      }
      
      if (!user) {
        return sendResponse(res, 404, 'User not found', null, 'error');
      }
      
      sendResponse(res, 200, 'User information loaded successfully', { 
        email: user.email, 
        subscribed: true, // During free launch, everyone gets premium access
        lastLogin: user.last_login ? new Date(user.last_login * 1000).toISOString() : null
      }, 'success');
    });
  } catch (error) {
    console.error('Error in /me endpoint:', error);
    sendResponse(res, 500, 'Failed to load user information', null, 'error');
  }
});

// Enhanced forgot password endpoint
app.post('/forgot-password', authLimiter, [
  body('email').isEmail().normalizeEmail().withMessage('Please enter a valid email address')
], (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return sendResponse(res, 400, 'Please enter a valid email address', null, 'error');
    }

    const { email } = req.body;
    
    db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
      if (err) {
        console.error('Database error in forgot password:', err);
        return sendResponse(res, 500, 'Password reset failed. Please try again.', null, 'error');
      }

      // Always send the same response for security (prevent email enumeration)
      const responseMessage = 'If your email is registered, you will receive a reset link.';
      
      if (!user) {
        return sendResponse(res, 200, responseMessage, null, 'info');
      }
      
      const token = crypto.randomBytes(32).toString('hex');
      const expiresAt = Date.now() + 3600 * 1000; // 1 hour from now
      
      // Clean up old reset tokens for this email
      db.run('DELETE FROM password_resets WHERE email = ?', [email], (err) => {
        if (err) {
          console.error('Error cleaning up old tokens:', err);
        }
        
        db.run('INSERT INTO password_resets (email, token, expires_at) VALUES (?, ?, ?)', 
          [email, token, expiresAt], (err) => {
          if (err) {
            console.error('Error storing reset token:', err);
            return sendResponse(res, 500, 'Password reset failed. Please try again.', null, 'error');
          }
          
          // Send email
          const resetLink = `${process.env.FRONTEND_URL || 'http://localhost:3000'}/forgot-password.html?token=${token}`;
          const mailOptions = {
            from: process.env.EMAIL_USER || 'motorsportprogression@gmail.com',
            to: email,
            subject: 'Password Reset - Retro Arcade',
            html: `
              <h2>Password Reset Request</h2>
              <p>You requested a password reset for your Retro Arcade account.</p>
              <p>Click the link below to reset your password:</p>
              <a href="${resetLink}" style="background: #00ffff; color: #222; padding: 12px 24px; text-decoration: none; border-radius: 8px;">Reset Password</a>
              <p>This link will expire in 1 hour.</p>
              <p>If you didn't request this reset, you can safely ignore this email.</p>
            `
          };
          
          transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
              console.error('Email sending error:', error);
              return sendResponse(res, 500, 'Failed to send reset email. Please try again.', null, 'error');
            }
            
            sendResponse(res, 200, responseMessage, null, 'success');
          });
        });
      });
    });
  } catch (error) {
    console.error('Forgot password error:', error);
    sendResponse(res, 500, 'Password reset failed. Please try again.', null, 'error');
  }
});

// Enhanced reset password endpoint
app.post('/reset-password', [
  body('token').notEmpty().withMessage('Reset token is required'),
  body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters long')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/).withMessage('Password must contain at least one uppercase letter, one lowercase letter, and one number')
], async (req, res) => {
  try {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return sendResponse(res, 400, 'Please check your password requirements', errors.array(), 'error');
    }

    const { token, password } = req.body;
    
    db.get('SELECT * FROM password_resets WHERE token = ?', [token], async (err, row) => {
      if (err) {
        console.error('Database error in reset password:', err);
        return sendResponse(res, 500, 'Password reset failed. Please try again.', null, 'error');
      }
      
      if (!row || row.expires_at < Date.now()) {
        return sendResponse(res, 400, 'Invalid or expired reset token. Please request a new password reset.', null, 'error');
      }
      
      const hash = await bcrypt.hash(password, 12);
      
      db.run('UPDATE users SET password = ?, failed_login_attempts = 0, locked_until = 0 WHERE email = ?', 
        [hash, row.email], (err) => {
        if (err) {
          console.error('Error updating password:', err);
          return sendResponse(res, 500, 'Password reset failed. Please try again.', null, 'error');
        }
        
        // Clean up the used reset token
        db.run('DELETE FROM password_resets WHERE token = ?', [token], (err) => {
          if (err) {
            console.error('Error cleaning up reset token:', err);
          }
        });
        
        sendResponse(res, 200, 'Password reset successful! You can now log in with your new password.', null, 'success');
      });
    });
  } catch (error) {
    console.error('Reset password error:', error);
    sendResponse(res, 500, 'Password reset failed. Please try again.', null, 'error');
  }
});

// Apply error handling middleware
app.use(errorHandler);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🎮 Retro Arcade Server running on http://localhost:${PORT}`);
  console.log(`📝 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🔐 JWT Secret: ${process.env.JWT_SECRET ? 'Set' : 'Using default (not secure)'}`);
  console.log(`💳 Stripe: ${process.env.STRIPE_SECRET_KEY ? 'Configured' : 'Not configured'}`);
});