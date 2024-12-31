# /run.py
from threading import Thread
from app import app, socketio 

if __name__ == '__main__':
    # Start Flask and WebSocket server
    socketio.run(app, debug=True, host='0.0.0.0', port=8000)
