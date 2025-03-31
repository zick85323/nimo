require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');
const axios = require('axios');

const app = express();

// Validate environment variables
const requiredEnvVars = ['PI_API_KEY', 'FRONTEND_URL'];
requiredEnvVars.forEach(varName => {
  if (!process.env[varName]) throw new Error(`${varName} missing in .env`);
});

// Pi Network API Configuration
const PI_API_URL = process.env.NODE_ENV === 'production' 
  ? 'https://api.minepi.com/v2' 
  : 'https://api.testnet.minepi.com/v2';

// Security Middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "https://sdk.minepi.com"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https://minepi.com"],
      connectSrc: ["'self'", PI_API_URL]
    }
  }
}));

// CORS Configuration
app.use(cors({
  origin: [
    process.env.FRONTEND_URL,
    'https://app-cdn.minepi.com'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-User-Uid']
}));

app.use(express.json({ limit: '10kb' }));
app.use(morgan('dev'));

// Rate Limiting
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Too many requests from this IP, please try again later' }
});
app.use('/api/', apiLimiter);

// Authentication Middleware
const authenticatePiRequest = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader?.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Authorization header required' });
    }

    const accessToken = authHeader.split(' ')[1];
    
    // Verify token with Pi Server
    const { data } = await axios.get(`${PI_API_URL}/me`, {
      headers: { 
        'Authorization': `Bearer ${accessToken}`,
        'Content-Type': 'application/json'
      }
    });

    if (!data.uid) {
      return res.status(401).json({ error: 'Invalid authentication token' });
    }

    req.user = {
      uid: data.uid,
      username: data.username,
      walletAddress: data.wallet_address
    };
    
    next();
  } catch (error) {
    console.error('Auth error:', error.response?.data || error.message);
    res.status(error.response?.status || 500).json({ 
      error: 'Authentication failed',
      ...(process.env.NODE_ENV === 'development' && { details: error.message })
    });
  }
};

// Balance Endpoint
app.get('/api/balance', authenticatePiRequest, async (req, res) => {
  try {
    const response = await axios.get(`${PI_API_URL}/accounts/${req.user.uid}/balance`, {
      headers: { 
        'Authorization': `Key ${process.env.PI_API_KEY}`,
        'Content-Type': 'application/json'
      }
    });
    
    res.json({
      available: response.data.available_balance,
      locked: response.data.locked_balance,
      currency: "PI",
      last_updated: new Date().toISOString()
    });
  } catch (error) {
    console.error('Balance error:', error.response?.data || error.message);
    res.status(500).json({ error: 'Failed to fetch balance' });
  }
});

// Payment Approval Endpoint
app.post('/api/approve', authenticatePiRequest, async (req, res) => {
  try {
    const { paymentId } = req.body;
    
    if (!paymentId) {
      return res.status(400).json({ error: 'Missing payment ID' });
    }

    const response = await axios.post(
      `${PI_API_URL}/payments/${paymentId}/approve`,
      {},
      {
        headers: { 
          'Authorization': `Key ${process.env.PI_API_KEY}`,
          'Content-Type': 'application/json'
        }
      }
    );
    
    res.json({
      status: response.data.status,
      payment_id: paymentId,
      amount: response.data.amount,
      memo: response.data.memo
    });
  } catch (error) {
    console.error('Approval error:', error.response?.data || error.message);
    res.status(500).json({ error: 'Payment approval failed' });
  }
});

// Payment Completion Endpoint
app.post('/api/complete', authenticatePiRequest, async (req, res) => {
  try {
    const { paymentId, txid } = req.body;
    
    if (!paymentId || !txid) {
      return res.status(400).json({ error: 'Missing payment ID or transaction ID' });
    }

    const response = await axios.post(
      `${PI_API_URL}/payments/${paymentId}/complete`,
      { txid },
      {
        headers: { 
          'Authorization': `Key ${process.env.PI_API_KEY}`,
          'Content-Type': 'application/json'
        }
      }
    );
    
    res.json({
      status: response.data.status,
      payment_id: paymentId,
      txid: txid,
      verified: response.data.transaction?.verified,
      completed_at: new Date().toISOString()
    });
  } catch (error) {
    console.error('Completion error:', error.response?.data || error.message);
    res.status(500).json({ error: 'Payment completion failed' });
  }
});

// Get Payment Details
app.get('/api/payment/:paymentId', authenticatePiRequest, async (req, res) => {
  try {
    const response = await axios.get(
      `${PI_API_URL}/payments/${req.params.paymentId}`,
      {
        headers: { 
          'Authorization': `Key ${process.env.PI_API_KEY}`,
          'Content-Type': 'application/json'
        }
      }
    );
    
    res.json({
      id: response.data.identifier,
      amount: response.data.amount,
      status: response.data.status,
      created_at: response.data.created_at,
      txid: response.data.transaction?.txid,
      verified: response.data.transaction?.verified
    });
  } catch (error) {
    console.error('Payment fetch error:', error.response?.data || error.message);
    res.status(500).json({ error: 'Failed to fetch payment details' });
  }
});

// Health Check Endpoint
app.get('/api/health', (req, res) => {
  res.json({
    status: 'operational',
    version: '1.0.0',
    environment: process.env.NODE_ENV || 'development',
    timestamp: new Date().toISOString()
  });
});

// Error Handling Middleware
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// 404 Handler
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// Start Server
const PORT = process.env.PORT;
app.listen(PORT, () => {
  console.log(`Pi Server running in ${process.env.NODE_ENV || 'development'} mode on port ${PORT}`);
});
