import express from 'express';
import { createServer as createViteServer } from 'vite';
import path from 'path';
import Database from 'better-sqlite3';
import bodyParser from 'body-parser';
import cors from 'cors';
import { createProxyMiddleware } from 'http-proxy-middleware';

const PORT = 3000;
const DB_PATH = './pcap_cache.db';

console.log('Starting server initialization...');

// Initialize DB
let db: any;
try {
  console.log(`Connecting to database at ${DB_PATH}...`);
  db = new Database(DB_PATH);
  db.exec(`
    CREATE TABLE IF NOT EXISTS pcap_cache (
      hash TEXT PRIMARY KEY,
      filename TEXT,
      analysis TEXT,
      intel TEXT,
      classification TEXT,
      attack_name TEXT,
      cve_tags TEXT,
      forensic_justification TEXT,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);
  
  // Add columns if they don't exist (for existing databases)
  try { db.exec("ALTER TABLE pcap_cache ADD COLUMN attack_name TEXT"); } catch(e) {}
  try { db.exec("ALTER TABLE pcap_cache ADD COLUMN cve_tags TEXT"); } catch(e) {}
  try { db.exec("ALTER TABLE pcap_cache ADD COLUMN forensic_justification TEXT"); } catch(e) {}

  console.log('Database initialized successfully.');
} catch (err) {
  console.error('Database initialization failed:', err);
  process.exit(1);
}

async function startServer() {
  console.log('Setting up Express app...');
  const app = express();
  app.use(cors());

  // Proxy for VirusTotal to handle CORS
  console.log('Configuring VirusTotal proxy...');
  app.use('/vt-api', createProxyMiddleware({
    target: 'https://www.virustotal.com/api/v3',
    changeOrigin: true,
    pathRewrite: {
      '^/vt-api': '',
    },
    secure: false,
  }));

  app.use(bodyParser.json({ limit: '50mb' }));

  // API Routes
  console.log('Registering API routes...');
  app.get('/api/history', (req, res) => {
    try {
      const rows = db.prepare('SELECT * FROM pcap_cache ORDER BY timestamp DESC').all();
      res.json(rows.map((row: any) => ({
        ...row,
        analysis: JSON.parse(row.analysis),
        intel: JSON.parse(row.intel),
        cve_tags: row.cve_tags ? JSON.parse(row.cve_tags) : [],
        forensicJustification: row.forensic_justification
      })));
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.get('/api/check-cache/:hash', (req, res) => {
    const { hash } = req.params;
    try {
      const row: any = db.prepare('SELECT * FROM pcap_cache WHERE hash = ?').get(hash);
      if (row) {
        res.json({
          found: true,
          data: {
            ...row,
            analysis: JSON.parse(row.analysis),
            intel: JSON.parse(row.intel),
            cve_tags: row.cve_tags ? JSON.parse(row.cve_tags) : [],
            forensicJustification: row.forensic_justification
          }
        });
      } else {
        res.json({ found: false });
      }
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.post('/api/cache', (req, res) => {
    const { hash, filename, analysis, intel, classification, attack_name, cve_tags, forensic_justification } = req.body;
    try {
      const stmt = db.prepare('INSERT OR REPLACE INTO pcap_cache (hash, filename, analysis, intel, classification, attack_name, cve_tags, forensic_justification) VALUES (?, ?, ?, ?, ?, ?, ?, ?)');
      stmt.run(hash, filename, JSON.stringify(analysis), JSON.stringify(intel), classification, attack_name, JSON.stringify(cve_tags), forensic_justification);
      res.json({ success: true });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  app.delete('/api/history/:hash', (req, res) => {
    const { hash } = req.params;
    try {
      const stmt = db.prepare('DELETE FROM pcap_cache WHERE hash = ?');
      stmt.run(hash);
      res.json({ success: true });
    } catch (err: any) {
      res.status(500).json({ error: err.message });
    }
  });

  // Vite middleware for development
  if (process.env.NODE_ENV !== 'production') {
    console.log('Initializing Vite in middleware mode...');
    try {
      const vite = await createViteServer({
        server: { middlewareMode: true },
        appType: 'spa',
      });
      app.use(vite.middlewares);
      console.log('Vite middleware integrated.');
    } catch (err) {
      console.error('Vite initialization failed:', err);
      throw err;
    }
  } else {
    console.log('Serving production build...');
    const distPath = path.join(process.cwd(), 'dist');
    app.use(express.static(distPath));
    app.get('*all', (req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  console.log(`Attempting to listen on port ${PORT}...`);
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server successfully running on http://localhost:${PORT}`);
  });
}

startServer().catch(err => {
  console.error('CRITICAL: Failed to start server:', err);
  process.exit(1);
});
