from flask import Flask
from app.config import Config
from app.simulation import OAuthSimulationEngine

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize and attach the simulation engine to app extensions
    engine = OAuthSimulationEngine(
        mode=app.config.get('SIMULATION_MODE', 'vulnerable'),
        token_ttl=app.config.get('TOKEN_TTL_SECONDS', 180)
    )
    app.extensions['simulation_engine'] = engine

    # Register blueprints
    from app.routes import main_bp
    app.register_blueprint(main_bp)

    # Context processor to make simulation state globally accessible to all templates
    @app.context_processor
    def inject_simulation_context():
        return {
            'current_mode': engine.mode,
            'active_token_count': len(engine.tokens),
            'audit_log_count': len(engine.audit_logs)
        }

    return app
