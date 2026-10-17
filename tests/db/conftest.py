import os

import psycopg
import pytest
from dotenv import load_dotenv

load_dotenv()


@pytest.fixture
def conn():
    """A connection whose changes are always rolled back, so tests never leave data behind."""
    url = os.environ.get("DATABASE_URL")
    if not url:
        pytest.skip("DATABASE_URL is not set; database tests skipped")
    with psycopg.connect(url) as connection:
        # Open a transaction now. load() then uses a savepoint inside it, not its own
        # commit, so the rollback below undoes everything the test loaded.
        connection.execute("SELECT 1")
        yield connection
        connection.rollback()