from app import socketio

@socketio.on('connect')
def handle_connect():
    print("Client connected")

@socketio.on('disconnect')
def handle_disconnect():
    print("Client disconnected")

# Broadcast real-time data
def broadcast_data(data):
    socketio.emit('update', data)
