require('dotenv').config();

const pool = require('./src/config/db');

async function main() {
  const result = await pool.query(
    "SELECT * FROM audit_logs WHERE action = $1 ORDER BY created_at DESC LIMIT 10",
    ['AUTH_LOGIN_FAILED']
  );

  console.log('Recent failed logins:');
  result.rows.forEach((row) => {
    console.log(`Time: ${row.created_at} | User ID: ${row.user_id} | Details: ${JSON.stringify(row.details)}`);
  });
}

main()
  .catch((err) => {
    console.error(err.message);
    process.exitCode = 1;
  })
  .finally(() => pool.end());
