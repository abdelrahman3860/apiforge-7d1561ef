const express = require('express');
const dns = require('dns').promises;
const validator = require('validator');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

// API key authentication middleware
app.use((req, res, next) => {
  if (req.path === '/health') return next();
  const key = req.headers['x-api-key'];
  if (process.env.API_KEY && (!key || key !== process.env.API_KEY)) {
    return res.status(401).json({ success: false, error: 'Invalid or missing API key' });
  }
  next();
});

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ success: true, message: 'DNS Health Checker API is running' });
});

// DNS health check endpoint
app.post('/check', async (req, res) => {
  try {
    const { domain } = req.body;
    
    // Validate input
    if (!domain) {
      return res.status(400).json({ 
        success: false, 
        error: 'Missing domain parameter' 
      });
    }
    
    if (!validator.isFQDN(domain)) {
      return res.status(400).json({ 
        success: false, 
        error: 'Invalid domain format' 
      });
    }
    
    const results = {
      domain,
      resolves: false,
      mx: {
        hasRecords: false,
        records: [],
        priority: null
      },
      spf: {
        hasRecord: false,
        record: null
      },
      dkim: {
        ready: false,
        selectors: []
      }
    };
    
    // Check if domain resolves
    try {
      await dns.resolve4(domain);
      results.resolves = true;
    } catch (err) {
      try {
        await dns.resolve6(domain);
        results.resolves = true;
      } catch (ipv6Err) {
        results.resolves = false;
      }
    }
    
    // Check MX records
    try {
      const mxRecords = await dns.resolveMx(domain);
      if (mxRecords && mxRecords.length > 0) {
        results.mx.hasRecords = true;
        results.mx.records = mxRecords.map(record => ({
          exchange: record.exchange,
          priority: record.priority
        }));
        // Sort by priority (lower is preferred)
        results.mx.records.sort((a, b) => a.priority - b.priority);
        results.mx.priority = results.mx.records[0].priority;
      }
    } catch (mxErr) {
      results.mx.hasRecords = false;
    }
    
    // Check SPF record
    try {
      const txtRecords = await dns.resolveTxt(domain);
      for (const txtRecord of txtRecords) {
        const record = txtRecord.join('');
        if (record.startsWith('v=spf1')) {
          results.spf.hasRecord = true;
          results.spf.record = record;
          break;
        }
      }
    } catch (spfErr) {
      results.spf.hasRecord = false;
    }
    
    // Check common DKIM selectors
    const commonSelectors = ['default', 'google', 'k1', 'selector1', 'selector2'];
    const dkimChecks = [];
    
    for (const selector of commonSelectors) {
      const dkimDomain = `${selector}._domainkey.${domain}`;
      try {
        await dns.resolveTxt(dkimDomain);
        dkimChecks.push(selector);
      } catch (dkimErr) {
        // Selector not found, continue
      }
    }
    
    results.dkim.ready = dkimChecks.length > 0;
    results.dkim.selectors = dkimChecks;
    
    res.json({
      success: true,
      data: results
    });
    
  } catch (error) {
    console.error('DNS check error:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error',
      message: 'Failed to perform DNS health check'
    });
  }
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: 'Not found',
    message: 'The requested endpoint does not exist'
  });
});

// Global error handler
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({
    success: false,
    error: 'Internal server error',
    message: 'An unexpected error occurred'
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`DNS Health Checker API running on port ${PORT}`);
});