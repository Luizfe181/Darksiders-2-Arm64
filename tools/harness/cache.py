import sqlite3
import hashlib
import json
import os

class HarnessCache:
    def __init__(self, db_path=None):
        if db_path is None:
            db_path = os.path.join("analysis", "harness_cache.sqlite")
        
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        self.db_path = db_path
        self._init_db()

    def _get_connection(self):
        return sqlite3.connect(self.db_path)

    def _init_db(self):
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS function_cache (
                    hash TEXT PRIMARY KEY,
                    func_name TEXT,
                    raw_code TEXT,
                    analyzed_code TEXT,
                    metadata TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            conn.commit()

    def compute_hash(self, raw_code: str) -> str:
        """Gera um hash SHA-256 único a partir do pseudocódigo limpo."""
        normalized = "".join(raw_code.split())
        return hashlib.sha256(normalized.encode('utf-8')).hexdigest()

    def get(self, raw_code: str):
        """Busca a análise no cache local através do hash do código."""
        code_hash = self.compute_hash(raw_code)
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT func_name, analyzed_code, metadata, created_at FROM function_cache WHERE hash = ?", 
                (code_hash,)
            )
            row = cursor.fetchone()
            if row:
                return {
                    "hash": code_hash,
                    "func_name": row[0],
                    "analyzed_code": row[1],
                    "metadata": json.loads(row[2]) if row[2] else {},
                    "cached_at": row[3],
                    "from_cache": True
                }
        return None

    def put(self, func_name: str, raw_code: str, analyzed_code: str, metadata: dict = None):
        """Salva a resposta da análise no banco SQLite."""
        code_hash = self.compute_hash(raw_code)
        metadata_str = json.dumps(metadata) if metadata else "{}"
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO function_cache (hash, func_name, raw_code, analyzed_code, metadata)
                VALUES (?, ?, ?, ?, ?)
            """, (code_hash, func_name, raw_code, analyzed_code, metadata_str))
            conn.commit()
        return code_hash