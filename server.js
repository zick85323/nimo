require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const axios = require('axios');
const morgan = require('morgan');
const piConfig = require('./config/pi-config');

const app = express();

// Validate environment variables
if (!process.env.PI_API_KEY) throw new Error('PI_API_KEY missing in .env');
if (!process.env.FRONTEND_URL) throw new Error('FRONTEND_URL missing in .env');

// Configuration
const PORT = process.env.PORT || 443;
const PI_API_KEY = process.env.PI_API_KEY;
const PI_API_URL = piConfig.mainnet.apiUrl;

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

app.use(cors({
    origin: process.env.FRONTEND_URL,
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json({ limit: '10kb' }));
app.use(morgan('combined'));

// Rate Limiting
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: { error: 'Too many requests from this IP, please try again later' }
});
app.use('/api/', apiLimiter);

// Enhanced Authentication Middleware
const authenticatePiRequest = async (req, res, next) => {
    try {
        const authHeader = req.headers.authorization;
        
        if (!authHeader?.startsWith('Bearer ')) {
            return res.status(401).json({ error: 'Authorization header required' });
        }

        const token = authHeader.split(' ')[1];
        
        // Verify token with Pi Server
        const { data } = await axios.get(`${PI_API_URL}/me`, {
            headers: { 
                'Authorization': `Bearer ${token}`,
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
        const status = error.response?.status || 500;
        res.status(status).json({ 
            error: error.response?.data?.message || 'Authentication failed' 
        });
    }
};

// Enhanced Balance Endpoint
app.get('/api/balance', authenticatePiRequest, async (req, res) => {
    try {
        const response = await axios.get(`${PI_API_URL}/accounts/${req.user.uid}/balance`, {
            headers: { 
                'Authorization': `Key ${PI_API_KEY}`,
                'Content-Type': 'application/json'
            }
        });
        
        res.json({
            available_balance: response.data.available_balance,
            locked_balance: response.data.locked_balance,
            currency: "PI",
            last_updated: new Date().toISOString()
        });
        
    } catch (error) {
        console.error('Balance error:', error.response?.data || error.message);
        const status = error.response?.status || 500;
        res.status(status).json({ 
            error: error.response?.data?.message || 'Failed to fetch balance' 
        });
    }
});

// Payment Approval Endpoint
app.post('/api/approve', authenticatePiRequest, async (req, res) => {
    try {
        const { paymentId } = req.body;
        
        if (!paymentId || typeof paymentId !== 'string') {
            return res.status(400).json({ error: 'Invalid payment ID' });
        }

        const response = await axios.post(
            `${PI_API_URL}/payments/${paymentId}/approve`,
            {},
            {
                headers: { 
                    'Authorization': `Key ${PI_API_KEY}`,
                    'Content-Type': 'application/json'
                }
            }
        );
        
        res.json({
            status: response.data.status,
            payment_id: paymentId,
            timestamp: new Date().toISOString()
        });
        
    } catch (error) {
        console.error('Approval error:', error.response?.data || error.message);
        const status = error.response?.status || 500;
        res.status(status).json({ 
            error: error.response?.data?.message || 'Payment approval failed' 
        });
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
                    'Authorization': `Key ${PI_API_KEY}`,
                    'Content-Type': 'application/json'
                }
            }
        );
        
        res.json({
            status: response.data.status,
            payment_id: paymentId,
            txid: txid,
            completed_at: new Date().toISOString()
        });
        
    } catch (error) {
        console.error('Completion error:', error.response?.data || error.message);
        const status = error.response?.status || 500;
        res.status(status).json({ 
            error: error.response?.data?.message || 'Payment completion failed' 
        });
    }
});

// Health Check Endpoint
app.get('/api/health', (req, res) => {
    res.json({
        status: 'operational',
        version: '1.0.0',
        timestamp: new Date().toISOString()
    });
});

// Error Handling Middleware
app.use((err, req, res, next) => {
    console.error('Server error:', err);
    res.status(500).json({ 
        error: 'Internal server error',
        message: process.env.NODE_ENV === 'development' ? err.message : undefined
    });
});

// 404 Handler
app.use((req, res) => {
    res.status(404).json({ error: 'Endpoint not found' });
});

// Start Server
app.listen(PORT, () => {
    console.log(`Server running in ${process.env.NODE_ENV || 'development'} mode on port ${PORT}`);
});