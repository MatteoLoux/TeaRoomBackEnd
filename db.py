import psycopg2
import os
from dotenv import load_dotenv
from sqlalchemy import create_engine

load_dotenv()

def get_conn():
    return psycopg2.connect(os.getenv("DATABASE_URL"))

def get_session_engine():
    return create_engine(os.getenv("DATABASE_URL"))
