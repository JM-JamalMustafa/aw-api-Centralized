import logging
import os
from flask import Flask, send_from_directory, Blueprint, current_app
from flask_cors import CORS
# Your custom logging handler

# Logging setup
logger = logging.getLogger(__name__)

# Directory setup
BASE_DIR = os.path.dirname(os.path.abspath(__file__))  # Project root
WEBUI_DIST_FOLDER = os.path.join(BASE_DIR, "aw-webui", "dist")  # Path to UI build folder

# Create Flask app
app = Flask(
    __name__,
    static_folder=WEBUI_DIST_FOLDER,  # Serve static files from the UI build folder
    static_url_path="/",  # Base URL for static files
)

# Configure CORS
CORS(app, resources={r"/api/*": {"origins": "*"}})  # Adjust origins for production

# Serve the main index.html for the UI
@app.route("/")
def serve_ui():
    """Serve the main UI (index.html)."""
    return send_from_directory(WEBUI_DIST_FOLDER, "index.html")


# Serve other static files (e.g., JS, CSS, images)
@app.route("/<path:path>")
def serve_static_files(path):
    """Serve static files (CSS, JS, images) from the UI's dist folder."""
    return send_from_directory(WEBUI_DIST_FOLDER, path)


 # Register your API endpoints

# Main function to start the server
if __name__ == "__main__":
    try:
        app.run(
            debug=True,              # Change to False in production
            host="0.0.0.0",          # Bind to all network interfaces
            port=80,                 # Default HTTP port  # Your custom logging handler
            use_reloader=False,      # Disable auto-reloader in production
            threaded=True,           # Allow multithreading
        )
    except OSError as e:
        logger.exception(e)
        raise e
