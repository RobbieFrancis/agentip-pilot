// D1-shaped adapter for the pilot's fixed, parameterized SQL statements.
// All state-transition batches share one transaction-scoped PostgreSQL lock,
// preserving the original single-writer challenge/state semantics across workers.
const numericColumns = new Set(['count', 'registrations', 'active', 'authentications', 'created_at', 'expires_at', 'last_used_at', 'revoked_at', 'completed_at', 'at']);
function rows(result) {
  return result.rows.map(row => Object.fromEntries(Object.entries(row).map(([name, value]) => {
    if (numericColumns.has(name) && typeof value === 'string' && /^-?\d+$/.test(value)) {
      const number = Number(value);
      if (!Number.isSafeInteger(number)) throw new Error('Database number outside supported range');
      return [name, number];
    }
    return [name, value];
  })));
}
function compiled(sql, values) {
  let index = 0;
  const text = sql.replace(/\?/g, () => '$' + ++index);
  if (index !== values.length) throw new Error('Internal SQL parameter mismatch');
  return { text, values };
}
function safeError(error) {
  // Keep the existing public conflict response without returning database details.
  if (error?.code === '23505') return new Error('UNIQUE constraint');
  return error;
}
export function postgresAdapter(pool) {
  function statement(sql, values = []) {
    const query = compiled(sql, values);
    async function execute(connection = pool) {
      try {
        const result = await connection.query(query.text, query.values);
        return { results: rows(result), meta: { changes: result.rowCount ?? 0 } };
      } catch (error) { throw safeError(error); }
    }
    return {
      bind: (...parameters) => statement(sql, parameters),
      first: async () => (await execute()).results[0] ?? null,
      all: execute,
      run: execute,
      _execute: execute,
    };
  }
  return {
    // Unbound statements with placeholders are bound before execution.
    prepare(sql) {
      if (!sql.includes('?')) return statement(sql);
      return { bind: (...parameters) => statement(sql, parameters) };
    },
    async batch(statements) {
      const connection = await pool.connect();
      try {
        await connection.query('BEGIN');
        await connection.query('SELECT pg_advisory_xact_lock(1095193680)');
        const results = [];
        for (const item of statements) results.push(await item._execute(connection));
        await connection.query('COMMIT');
        return results;
      } catch (error) {
        await connection.query('ROLLBACK').catch(() => {});
        throw safeError(error);
      } finally { connection.release(); }
    },
  };
}
