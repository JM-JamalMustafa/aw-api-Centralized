import sqlite3
import requests
import json
from datetime import datetime
import time
import os

# ActivityWatch Database Path (Adjust this for your setup)
AW_DB_PATH = your_path"

# Centralized Flask API URL
API_SERVER_URL = "url/api"
FETCH_INTERVAL = 1  # Fetch every 1 hour
TOKEN_FILE = "user_tokens.json"  # File to store user tokens

# Function to read tokens from a file
def read_tokens():
    if os.path.exists(TOKEN_FILE):
        with open(TOKEN_FILE, "r") as file:
            return json.load(file)
    return {}

# Function to save tokens to a file
def save_tokens(tokens):
    with open(TOKEN_FILE, "w") as file:
        json.dump(tokens, file)

# Function to login and fetch tokens for a user
def login_user(username, password):
    url = f"{API_SERVER_URL}/login"
    payload = {"username": username, "password": password}
    try:
        response = requests.post(url, json=payload)
        if response.status_code == 200:
            data = response.json()
            tokens = read_tokens()
            tokens[username] = {
                "access_token": data.get("access_token"),
                "expires_at": time.time() + 8 * 3600  # Store expiration time (8 hours)
            }
            save_tokens(tokens)
            print(f"Tokens stored for user {username}.")
        else:
            print(f"Failed to login user {username}: {response.json().get('message')}")
    except requests.RequestException as e:
        print(f"Error during login: {e}")

# Function to get a valid token
def get_valid_token(username):
    tokens = read_tokens()
    user_tokens = tokens.get(username)

    if not user_tokens or "access_token" not in user_tokens:
        print("No access token available. Please log in.")
        return None

    # Check if the token has expired
    if time.time() >= user_tokens.get("expires_at", 0):
        print("Access token expired. Please log in again.")
        return None

    return user_tokens["access_token"]

# Function to submit events to the API
def submit_events_to_api(username, events):
    api_token = get_valid_token(username)
    if not api_token:
        print(f"Unable to get a valid token for user {username}. Please log in again.")
        password = input("Enter password: ")
        login_user(username, password)
        api_token = get_valid_token(username)
        if not api_token:
            print("Failed to retrieve a valid token. Exiting.")
            return

    url = f"{API_SERVER_URL}/submit"
    headers = {"Authorization": f"Bearer {api_token}"}

    transformed_events = []
    for event in events:
        timestamp, duration, datastr, bucket_id = event
        try:
            timestamp = datetime.fromisoformat(timestamp).isoformat()
        except ValueError:
            print(f"Skipping event with invalid timestamp: {event}")
            continue
        try:
            data = json.loads(datastr)
        except json.JSONDecodeError:
            print(f"Skipping event with invalid datastr: {datastr}")
            continue

        transformed_events.append({
            "timestamp": timestamp,
            "duration": duration,
            "data": {
                "app": data.get("app", "unknown"),
                "title": data.get("title", "unknown")
            },
            "bucket_id": bucket_id
        })

    if transformed_events:
        response = requests.post(url, json=transformed_events, headers=headers)
        if response.status_code == 201:
            print(f"Data submitted successfully: {response.json()}")
        else:
            print(f"Failed to submit data: {response.text}")
    else:
        print("No events to submit.")

# Fetch events periodically
def fetch_and_submit_data(username):
    print(f"Fetching events for user {username}...")
    events = fetch_events_from_db()
    if not events:
        print("No events found.")
        return
    submit_events_to_api(username, events)

# Fetch events from ActivityWatch DB
def fetch_events_from_db():
    try:
        conn = sqlite3.connect(AW_DB_PATH)
        cursor = conn.cursor()
        query = """
            SELECT timestamp, duration, datastr, bucket_id 
            FROM eventmodel
        """
        cursor.execute(query)
        events = cursor.fetchall()
        conn.close()
        return events
    except sqlite3.Error as e:
        print(f"Error accessing ActivityWatch database: {e}")
        return None

# Main function
if __name__ == "__main__":
    print("Fetching and submitting data every hour...")

    username = input("Enter username: ")

    tokens = read_tokens()
    if username not in tokens or "access_token" not in tokens[username]:  # Check if a token exists
        password = input("Enter password: ")
        login_user(username, password)

    while True:
        fetch_and_submit_data(username)
        time.sleep(FETCH_INTERVAL * 60)  # Sleep for the specified interval
