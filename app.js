const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const db = require('./config/db');
const errorHandler = require('./src/middleware/errorHandler');

require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;
const isProduction = process.env.NODE_ENV === 'production';
const localOrigins = [
  'http://localhost:3000',
  'http://localhost:5173',
  'http://localhost:5174',
  'http://127.0.0.1:3000',
  'http://127.0.0.1:5173'
];
const allowedOrigins = [
  process.env.FRONTEND_URL,
  ...(!isProduction ? localOrigins : [])
].filter(Boolean);
const connectSources = ["'self'", ...allowedOrigins];

if (!isProduction) {
  connectSources.push('http://localhost:5000', 'http://localhost:5001');
}

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com'],
      imgSrc: ["'self'", 'data:', 'blob:'],
      connectSrc: connectSources,
      frameSrc: ["'self'", 'blob:'],
      objectSrc: ["'self'", 'blob:']
    }
  }
}));

app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error('CORS policy does not allow this origin.'));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'x-device-fingerprint', 'x-share-password']
}));

app.use(rateLimit({
  windowMs: 15 * 60 * 1000,
  max: isProduction ? 300 : 1000,
  standardHeaders: true,
  legacyHeaders: false
}));

app.use(cookieParser());
app.use(express.json({ limit: '1mb' }));

app.use('/api/auth', require('./routes/auth'));
app.use('/api/documents', require('./routes/documents'));
app.use('/api/sharing', require('./routes/sharing'));
app.use('/api/audit', require('./routes/audit'));
app.use('/api/admin', require('./routes/admin'));

app.get('/health', (req, res) => {
  res.json({ status: 'HEALTHY', timestamp: new Date(), database: 'postgres' });
});

app.use(errorHandler);

db.initDb().then(() => {
  app.listen(PORT, () => {
    console.log(`DocuShield API server running on port ${PORT} in ${process.env.NODE_ENV || 'development'} mode.`);
  });
}).catch((err) => {
  console.error('Failed to initialize database. Server shutdown.', err.message);
  process.exit(1);
});

module.exports = app;
