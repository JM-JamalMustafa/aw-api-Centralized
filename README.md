# AW API

This is a RESTful API built with Flask and Flask-RESTX, designed to handle user authentication, event tracking, and centralized data storage. It supports JWT-based authentication, and users can register, log in, and submit events, among other features. Swagger documentation for the API is available at `/docs`.

## Features

- **User Registration**: Allows new users to register.
- **User Login**: Allows users to log in and obtain JWT tokens for authentication.
- **Password Change**: Authenticated users can change their passwords.
- **Event Submission**: Authenticated users can submit event data (app usage, duration, timestamp, etc.).
- **Admin Event Fetching**: Admins can fetch event data.
- **Logout**: Allows users to log out and blacklist their JWT token.

## Requirements

- Python 3.7+
- Flask
- Flask-RESTX
- Flask-JWT-Extended
- Peewee (ORM)
- bcrypt

You can install the required dependencies by running the following command:

```bash
pip install -r requirements.txt
```

## Setting Up the Project
## 1.Clone the Repository:
```bash
git clone https://github.com/JM-JamalMustafa/aw-api.git
cd aw-api
```

## 2.Set Up the Environment:

Ensure you have Python 3.7 or higher installed, then create a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows, use venv\Scripts\activate
```

## Install the required dependencies:

```bash
pip install -r requirements.txt
```
## Run the Application:

- Run the app using the run.py script:

The server will start on http://127.0.0.1:5000 by default.
