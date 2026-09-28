import os
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base

DB_PATH = os.getenv("SQLITE_DB_PATH", "smart_contract_scanner.db")
DATABASE_URL = f"sqlite+aiosqlite:///{DB_PATH}"

engine = create_async_engine(DATABASE_URL, echo=False)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)

Base = declarative_base()

async def get_db():
    async with AsyncSessionLocal() as session:
        yield session

def run_sqlite_migrations(sync_conn):
    """
    Safely inspects SQLite tables and adds any missing Trust Layer columns.
    Idempotent and non-destructive.
    """
    try:
        cursor = sync_conn.connection.cursor()

        # Migration for 'analyses'
        cursor.execute("PRAGMA table_info(analyses)")
        existing_analyses_cols = {row[1] for row in cursor.fetchall()}
        if existing_analyses_cols and "source_hash" not in existing_analyses_cols:
            cursor.execute("ALTER TABLE analyses ADD COLUMN source_hash VARCHAR(64)")

        # Migration for 'vulnerability_reports'
        cursor.execute("PRAGMA table_info(vulnerability_reports)")
        existing_rep_cols = {row[1] for row in cursor.fetchall()}
        if existing_rep_cols:
            new_cols = [
                ("source_hash", "VARCHAR(64)"),
                ("report_hash", "VARCHAR(64)"),
                ("findings_hash", "VARCHAR(64)"),
                ("analyzer_version", "VARCHAR(50)"),
                ("model_used", "VARCHAR(100)"),
                ("analysis_mode", "VARCHAR(50)"),
                ("compiler_version", "VARCHAR(100)"),
                ("git_commit", "VARCHAR(64)"),
                ("trust_metadata", "JSON"),
            ]
            for col_name, col_type in new_cols:
                if col_name not in existing_rep_cols:
                    cursor.execute(f"ALTER TABLE vulnerability_reports ADD COLUMN {col_name} {col_type}")

        cursor.close()
    except Exception as e:
        print(f"Migration warning: {e}")

async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        await conn.run_sync(run_sqlite_migrations)

