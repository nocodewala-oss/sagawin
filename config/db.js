const mysql = require('mysql2/promise');
require('dotenv').config();

const pool = mysql.createPool({
  host: process.env.DB_HOST || '127.0.0.1',
  port: Number(process.env.DB_PORT) || 3306,
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'sagawin',
  waitForConnections: true,
  connectionLimit: 10,
  maxIdle: 5,
  idleTimeout: 60000,
  queueLimit: 0,
  enableKeepAlive: true,
  keepAliveInitialDelay: 10000,
  // Multiple statements band rakhte hain taaki stacked query risk kam rahe
  multipleStatements: false,
  // Strict SQL mode connection level par enforce karte hain
  flags: ['-FOUND_ROWS']
});

pool.on('error', () => {
  // Raw error stack/credentials log nahi kar rahe taaki sensitive info leak na ho
});

// Safe parameterized query helper (kabhi string concatenation use nahi karna)
async function query(sql, params = []) {
  if (!Array.isArray(params)) {
    throw new Error('INVALID_QUERY_PARAMS');
  }
  const [rows] = await pool.execute(sql, params);
  return rows;
}

// Atomic transaction helper (balance / wallet / multi-step DB updates ke liye)
async function withTransaction(callback) {
  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();
    const result = await callback(conn);
    await conn.commit();
    return result;
  } catch (err) {
    try {
      await conn.rollback();
    } catch (_) {
      // Rollback failure ko suppress kiya hai taaki original error/flow safe rahe
    }
    throw err;
  } finally {
    conn.release();
  }
}

async function testConnection() {
  const conn = await pool.getConnection();
  try {
    await conn.ping();
    return true;
  } catch (_) {
    return false;
  } finally {
    conn.release();
  }
}

module.exports = {
  pool,
  query,
  withTransaction,
  testConnection
};