import psycopg2
import os
from flask_sqlalchemy  import SQLAlchemy


def get_conn():
    return psycopg2.connect(os.getenv("DATABASE_URL"))

db_session = SQLAlchemy()

