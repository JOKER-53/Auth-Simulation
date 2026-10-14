import pytest
from app import create_app
from app.config import Config

class TestConfig(Config):
    TESTING = True
    SECRET_KEY = 'test-secret-key'
    SIMULATION_MODE = 'vulnerable'
    TOKEN_TTL_SECONDS = 10

@pytest.fixture
def app():
    app = create_app(TestConfig)
    return app

@pytest.fixture
def client(app):
    return app.test_client()

@pytest.fixture
def engine(app):
    return app.extensions['simulation_engine']
