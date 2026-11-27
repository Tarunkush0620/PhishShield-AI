"""
PhishShield AI — Application Entry Point
"""
import os
from dotenv import load_dotenv
load_dotenv()

from phishshield import create_app

app = create_app()

if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG", "0").lower() in ("1", "true", "yes")
    app.run(debug=debug_mode, port=5000)
