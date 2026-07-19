import os
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# 1. Safely grab the connection string from the server's hidden environment variables
DATABASE_URL = os.getenv("DATABASE_URL")

if not DATABASE_URL:
    raise ValueError("CRITICAL ERROR: DATABASE_URL environment variable is missing!")

# 2. Setup the database engine.
# We add pool_pre_ping=True to handle database connection drops gracefully.
engine = create_engine(
    DATABASE_URL, 
    pool_pre_ping=True
)

# 3. Setup database session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# 4. Base class that our models.py will inherit from
Base = declarative_base()

# 5. Dependency injection function that yields database sessions safely to API endpoints
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
      
