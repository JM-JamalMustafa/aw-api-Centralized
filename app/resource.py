# app/resource.py

from flask_restx import Resource, fields, Namespace
from flask import request
from flask_jwt_extended import jwt_required, get_jwt_identity, create_access_token,get_jwt
from peewee import DoesNotExist,fn
import bcrypt
from app.model import User, Event,Assignment, db  # Directly import models from `model.py`
from datetime import datetime
from peewee import IntegrityError
from flask import request, jsonify, current_app
from werkzeug.exceptions import BadRequest
import logging
from app.settings import Settings
from app.api import ServerAPI
from functools import wraps
logger = logging.getLogger(__name__)


# Create a Namespace for organizing API endpoints
ns = Namespace('Auth And Events', description='Authentication-related operations')
# Define the model for request body
register_model = ns.model('Register', {
    'username': fields.String(required=True, description='The username for the new user'),
    'password': fields.String(required=True, description='The password for the new user'),
    'role': fields.String(default='User', description='The role of the new user (default is User)')
})

# Define the login model schema using flask_restx's fields module
login_model = ns.model('Login', {
    'username': fields.String(required=True, description='The username for the user'),
    'password': fields.String(required=True, description='The password for the user')
})


# Define the change password model schema using flask_restx's fields module
change_password_model = ns.model('ChangePassword', {
    'current_password': fields.String(required=True, description='The current password of the user'),
    'new_password': fields.String(required=True, description='The new password for the user'),
    'confirm_password': fields.String(required=True, description='Confirm the new password')
})

# Define Swagger model for the response
logout_response_model = ns.model('LogoutResponse', {
    'message': fields.String(description='Response message', example='Successfully logged out')
})

# Define the models for Swagger documentation
event_data_model = ns.model('EventData', {
    'app': fields.String(required=True, description='Application name'),
    'title': fields.String(required=False, description='Window title or metadata', default='')
})

event_model = ns.model('Event', {
    'timestamp': fields.String(required=True, description='Timestamp of the event (ISO 8601 format)', example="2024-12-26T14:30:00"),
    'duration': fields.Integer(required=True, description='Duration of the event in seconds', example=120),
    'data': fields.Nested(event_data_model, description='Event details'),
    'client': fields.String(required=False, description='Client identifier', default='unknown')
})

response_model = ns.model('SubmitDataResponse', {
    'message': fields.String(description='Response message', example='Data stored successfully'),
    'stored_count': fields.Integer(description='Number of events successfully stored', example=5)
})

error_model = ns.model('ErrorResponse', {
    'message': fields.String(description='Error message', example='Missing key in event data: timestamp')
})

# Event model to submit data 
event_model = ns.model('Event', {
    'id': fields.Integer(description='Event ID', example=1),
    'timestamp': fields.String(description='Event timestamp in ISO format', example='2024-12-26T14:30:00'),
    'duration': fields.Float(required=True, description='Duration in seconds (int or float)',example="10.1"),  # Use Float to accept both
    'app': fields.String(description='Application name', example='Chrome'),
    'title': fields.String(description='Event title', example='Google Search'),
    'client': fields.String(description='Client type', example='web_client'),
    'user': fields.String(description='Username associated with the event', example='admin_user')
})

# Define the setting model
setting_model = ns.model('Setting', {
    'key': fields.String(required=True, description='Setting key', example='app_theme'),
    'value': fields.Raw(required=True, description='Setting value', example='dark_mode')
})

# Define response models
success_response_model = ns.model('SuccessResponse', {
    'message': fields.String(description="Success message", example="User 'username' updated to role 'Admin' with team 'Engineering'.")
})

error_response_model = ns.model('ErrorResponse', {
    'message': fields.String(description="Error message", example="User not found")
})


# Activity model for events
activity_model = ns.model('Activity', {
    'timestamp': fields.String(description="Event timestamp in ISO format"),
    'duration': fields.Integer(description="Duration of the activity in minutes"),
    'app': fields.String(description="App name associated with the activity"),
    'title': fields.String(description="Activity title"),
    'client': fields.String(description="Client information"),
})

# Model for team member details
team_member_model = ns.model('TeamMember', {
    'team_member': fields.String(description="Team member's username"),
    'team': fields.String(description="Team name"),
    'activities': fields.List(fields.Nested(activity_model), description="List of activities for the team member"),
    'assigned_users_activities': fields.List(
        fields.Nested(ns.model('AssignedUserActivity', {
            'assigned_user': fields.String(description="Assigned user's username"),
            'activities': fields.List(fields.Nested(activity_model), description="List of activities for the assigned user")
        })), 
        description="Activities of users assigned to this team member"
    ),
})

# Response model for `FetchTeamMembers`
fetch_team_members_response = ns.model('FetchTeamMembersResponse', {
    'team': fields.String(description="Team name"),
    'team_members_activities': fields.List(fields.Nested(team_member_model), description="List of team members and their activities"),
})


# Model for user details and activities
user_model = ns.model('User', {
    'username': fields.String(description="User's username"),
    'role': fields.String(description="User's role"),
    'team': fields.String(description="User's team, or 'Not Assigned' if no team"),
    'activities': fields.List(fields.Nested(activity_model), description="List of activities for the user"),
})

# Response model for `FetchAllUsersAndActivities`
fetch_all_users_response = ns.model('FetchAllUsersResponse', {
    'message': fields.String(description="Response message"),
    'data': fields.List(fields.Nested(user_model), description="List of all users and their activities"),
})


 #Swagger models for input data
user_model_post = ns.model('CreateUser', {
    'username': fields.String(required=True, description='The username of the user'),
    'password': fields.String(required=True, description='The password of the user'),
    'role': fields.String(description="User's role (default: 'User')"),
    'team': fields.String(description="User's team")
})

user_model_put = ns.model('UpdateUser', {
    'username': fields.String(required=True, description='The username of the user to update'),
    'role': fields.String(description="New role for the user"),
    'team': fields.String(description="New team for the user")
})

user_model_delete = ns.model('DeleteUser', {
    'username': fields.String(required=True, description='The username of the user to delete')
})

user_model_patch = ns.model('DeactivateUser', {
    'username': fields.String(required=True, description='The username of the user to deactivate')
})

# Swagger model for input data
assign_users_model = ns.model('AssignUsers', {
    'team_lead_id': fields.Integer(required=True, description='ID of the Team Leader'),
    'user_ids': fields.List(fields.Integer, required=True, description='List of user IDs to assign')
})


# Swagger model for input data
remove_assigned_user_model = ns.model('RemoveAssignedUser', {
    'team_lead_id': fields.Integer(required=True, description='ID of the Team Leader'),
    'user_id': fields.Integer(required=True, description='ID of the User to be removed')
})

# Define the input model for the request body
app_durations_model = ns.model('AppDurations', {
    'user_ids': fields.List(fields.Integer, required=True, description='List of user IDs'),
    'start_date': fields.String(required=False, description='Start date in YYYY-MM-DD format'),
    'end_date': fields.String(required=False, description='End date in YYYY-MM-DD format'),
})

# Store blacklisted tokens (In-memory or better use a database/redis for production)
BLACKLIST = set()

def role_required(allowed_roles):
    """
    Decorator to ensure the user has a specific role.
    """
    def decorator(fn):
        @wraps(fn)
        @jwt_required()
        def wrapper(*args, **kwargs):
            username = get_jwt_identity()
            try:
                user = User.get(User.username == username)
                if user.role not in allowed_roles:
                    return {'message': 'Access denied: insufficient permissions'}, 403
                # kwargs['current_user'] = user
            except DoesNotExist:
                return {'message': 'User not found'}, 404
            return fn(*args, **kwargs)
        return wrapper
    return decorator

@ns.route('/register')
class Register(Resource):
    @ns.expect(register_model) 
    def post(self):
        """
        Register a new user.
        This endpoint allows users to register by providing a username and password.

        **Body Parameters:**
        - `username`: The username for the new user (string).
        - `password`: The password for the new user (string).

        **Response:**
        - 201: User registered successfully.
        - 400: If the username already exists.
        """
        data = request.get_json()
        username = data['username']
        password = data['password']
        role = data.get('role', 'User')  # Default role is 'User'

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        try:
            User.create(username=username, password=hashed_password, role=role)
            return {'message': f'{role} {username} registered successfully !'}, 201
        except IntegrityError:
            return {'message': 'Username already exists'}, 400

@ns.route('/login') 
class Login(Resource):
    @ns.expect(login_model)  
    def post(self):
        """Login Endpoint"""
        data = request.get_json()
        username = data['username']
        password = data['password']

        user = User.get_or_none(User.username == username)
        if user and bcrypt.checkpw(password.encode('utf-8'), user.password.encode('utf-8')):
            access_token = create_access_token(identity=username)
            return {'access_token': access_token}, 200
        return {'message': 'Invalid username or password'}, 401
    
@ns.route('/change-password')
class ChangePassword(Resource):
    @jwt_required()  # Ensure JWT is required
    @ns.doc(security='BearerAuth')  # Apply security to this route
    @ns.expect(change_password_model)  # Attach the schema for validation in Swagger UI
    def post(self):
        """Change user password"""
        data = request.get_json()
        current_password = data['current_password']
        new_password = data['new_password']
        confirm_password = data['confirm_password']

        if new_password != confirm_password:
            return {'message': 'New password and confirm password do not match'}, 400

        user_identity = get_jwt_identity()

        try:
            user = User.get(User.username == user_identity)

            if not bcrypt.checkpw(current_password.encode('utf-8'), user.password.encode('utf-8')):
                return {'message': 'Current password is incorrect'}, 401

            hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
            
            user.password = hashed_password
            user.save()
            
            return {'message': 'Password updated successfully'}, 200
        
        except DoesNotExist:
            return {'message': 'User not found'}, 404



# Endpoint definition  
@ns.route('/submit')
class SubmitData(Resource):
    @jwt_required()
    @ns.expect([event_model], validate=True)  # Expecting a list of events
    @ns.response(201, 'Success', response_model)
    @ns.response(400, 'Bad Request', error_model)
    @ns.response(404, 'User Not Found', error_model)
    @ns.response(500, 'Internal Server Error', error_model)
    @ns.doc(security='BearerAuth', description="Submit event data to be stored in the centralized database, associated with the logged-in user.")
    def post(self):
        """
        Submit event data to be stored in the centralized database, associated with the logged-in user.
        """
        # Get the current user from the JWT token
        user_identity = get_jwt_identity()

        # Get the JSON data from the request
        data = request.get_json()

        # Normalize input: Convert single event dict to a list
        if isinstance(data, dict):
            data = [data]

        events_to_store = []

        for event in data:
            try:
                # Extract and validate fields
                timestamp = datetime.fromisoformat(event['timestamp'])  # Validate ISO format
                duration = float(event['duration'])  # Ensure duration is a float
                app_name = event['data']['app']
                title = event['data'].get('title', '')  # Default title to empty if not provided
                client = event.get('client', 'unknown')  # Default client to 'unknown'

                # Fetch the user based on the JWT identity
                try:
                    user = User.get(User.username == user_identity)
                except DoesNotExist:
                    return {'message': f"User with username {user_identity} does not exist."}, 404

                # Create the Event instance
                new_event = Event(
                    timestamp=timestamp,
                    duration=duration,
                    app=app_name,
                    title=title,
                    user=user,
                    client=client
                )
                events_to_store.append(new_event)
            except KeyError as e:
                return {'message': f"Missing key in event data: {str(e)}"}, 400
            except ValueError as e:
                return {'message': f"Invalid value in event data: {str(e)}"}, 400

        # Bulk insert events into the database
        try:
            Event.bulk_create(events_to_store)
        except Exception as e:
            return {'message': f"Failed to store events: {str(e)}"}, 500

        return {'message': 'Data stored successfully', 'stored_count': len(events_to_store)}, 201

    
@ns.route('/logout')
class Logout(Resource):
    @jwt_required()
    @ns.response(200, 'Success', logout_response_model)
    @ns.response(401, 'Unauthorized')
    @ns.doc(security='BearerAuth', description="Logout the user and invalidate the current JWT token.")
    def post(self):
        """Logout Endpoint - Blacklist the token"""
        jti = get_jwt()["jti"]  # Get the unique identifier for the token
        BLACKLIST.add(jti)  # Add the token identifier to the blacklist
        return {'message': 'Successfully logged out'}, 200
# AdminFetchEvents Endpoint
@ns.route('/events')
class AdminFetchEvents(Resource):
    @jwt_required()
    @ns.doc(params={
        'limit': 'Maximum number of events to fetch (optional)'
    })
    @ns.response(200, 'Success', ns.model('EventListResponse', {
        'events': fields.List(fields.Nested(event_model), description='List of events'),
        'count': fields.Integer(description='Total count of returned events', example=10)
    }))
    @ns.response(400, 'Invalid Parameter', ns.model('ErrorResponse', {
        'message': fields.String(description='Error message', example='Invalid limit value')
    }))
    @ns.response(404, 'User Not Found')
    @jwt_required()  
    def get(self):
        """
        Endpoint to fetch events for the authenticated admin user.
        The events will be fetched based on the JWT identity (username).
        """
        # Get the current user's identity (username) from the JWT token
        admin_username = get_jwt_identity()

        # Get query parameters
        limit = request.args.get('limit', None)

        # Validate limit
        try:
            limit = int(limit) if limit else None
        except ValueError:
            return {'message': 'Invalid limit value'}, 400

        # Fetch events for the authenticated admin user
        event_query = (
            Event.select(Event, User)
            .join(User)
            .where(User.username == admin_username)  
            .order_by(Event.timestamp.desc())  
        )

        # Apply limit if specified
        if limit:
            event_query = event_query.limit(limit)

        # Format the events into a response
        events = [
            {
                'id': event.id,
                'timestamp': datetime.fromisoformat(event.timestamp).isoformat(),  
                'duration': event.duration,
                'app': event.app,
                'title': event.title,
                'client': event.client,  
                'user': event.user.username,  
            }
            for event in event_query
        ]

        # Return the list of events along with the total count
        return {'events': events, 'count': len(events)}, 200


# SettingsResource Endpoint
@ns.route('/<string:settings>')
class SettingsResource(Resource):
    @ns.response(200, 'Success', setting_model)
    @ns.response(400, 'Bad Request')
    @ns.response(500, 'Internal Server Error')
    def get(self, key: str):
        # Ensure current_app.api exists
        if not hasattr(current_app, 'api'):
            return {"message": "API not initialized"}, 500
        
        data = current_app.api.get_setting(key)  # Access the settings
        return jsonify(data)
    
    @ns.expect(setting_model, validate=True)
    @ns.response(200, 'Success', setting_model)
    @ns.response(400, 'Bad Request')
    def post(self, key: str):
        if not key:
            raise BadRequest("MissingParameter", "Missing required parameter key")
        data = current_app.api.set_setting(key, request.get_json())
        return data


@ns.route('/FetchTeamMembers')
class FetchTeamMembers(Resource):
    @ns.response(200, 'Success', fetch_team_members_response)
    @ns.response(400, 'No team assigned to this Team Lead')
    @ns.response(404, 'Team Lead not found')
    @role_required(['Team Lead', 'CEO'])  # Only Team Leads or CEO can access this
    def get(self):
        """
        Fetch team members and their activities for the current Team Lead's team,
        including activities of assigned users (if any).
        """
        username = get_jwt_identity()  # JWT identity of the logged-in Team Lead
        try:
            # Fetch the Team Lead's information
            team_lead = User.get(User.username == username)

            # Ensure the Team Lead is assigned to a team
            if team_lead.team is None:
                return {'message': 'No team assigned to this Team Lead'}, 400

            # Fetch all team members (users with the same team and role = 'User')
            team_members = User.select().where(
                User.team == team_lead.team,
                User.role == 'User'  # Only fetch regular users
            )

            # Fetch activities for each team member
            result = []
            for member in team_members:
                # Query events for the current team member
                events = Event.select().where(Event.user == member)
                member_activities = [
                    {
                        'timestamp': datetime.fromisoformat(event.timestamp).isoformat(),
                        'duration': event.duration,
                        'app': event.app,
                        'title': event.title,
                        'client': event.client
                    }
                    for event in events
                ]

                # Fetch activities for assigned users (if any)
                assigned_users = User.select().where(
                    User.team == team_lead.team,
                    User.role == 'User',
                    User.id != member.id  # Exclude the current team member
                )
                assigned_users_activities = []
                for assigned_user in assigned_users:
                    assigned_user_events = Event.select().where(Event.user == assigned_user)
                    assigned_user_activities = [
                        {
                            'timestamp': datetime.fromisoformat(event.timestamp).isoformat(),
                            'duration': event.duration,
                            'app': event.app,
                            'title': event.title,
                            'client': event.client
                        }
                        for event in assigned_user_events
                    ]
                    assigned_users_activities.append({
                        'assigned_user': assigned_user.username,
                        'activities': assigned_user_activities
                    })

                # Append member details and activities to the result
                result.append({
                    'team_member': member.username,
                    'team': member.team,
                    'activities': member_activities,
                    'assigned_users_activities': assigned_users_activities  # Include activities of assigned users
                })

            return {
                'team': team_lead.team,
                'team_members_activities': result
            }, 200

        except DoesNotExist:
            return {'message': 'Team Lead not found'}, 404


@ns.route('/all-users')
class FetchAllUsersAndActivities(Resource):
    @role_required(['CEO', 'HR'])
    @ns.response(200, 'Success', fetch_all_users_response)
    @ns.response(403, 'Access denied: insufficient permissions')
    @ns.response(404, 'User not found')
    @role_required(['CEO',"HR"])  # Allow only CEO to access this endpoint
    def get(self):
        """
        Fetch all users activities.
        Accessible to the CEO only.
        """
        username = get_jwt_identity()  # Logged-in user's identity
        try:
            # Verify the user is a CEO
            ceo_user = User.get(User.username == username)
            if ceo_user.role != 'CEO':
                return {'message': 'Access denied: insufficient permissions'}, 403

            # Fetch all users except CEO
            all_users = User.select().where(User.role != 'CEO')

            # Collect activities for each user
            result = []
            for user in all_users:
                events = Event.select().where(Event.user == user)
                user_activities = [
                    {
                        'timestamp': datetime.fromisoformat(event.timestamp).isoformat(),
                        'duration': event.duration,
                        'app': event.app,
                        'title': event.title,
                        'client': event.client
                    }
                    for event in events
                ]
                result.append({
                    'username': user.username,
                    'role': user.role,
                    'team': user.team or "Not Assigned",
                    'activities': user_activities
                })

            return {
                'message': 'All users and their activities',
                'data': result
            }, 200

        except DoesNotExist:
            return {'message': 'User not found'}, 404

@ns.route('/ManageUsers')
class UserManagement(Resource):
    @ns.expect(user_model_post)
    @ns.response(201, 'User created successfully')
    @ns.response(400, 'Username already exists')
    @role_required(['CEO', 'HR'])  # Restrict to CEO and HR
    def post(self):
        """
        Create a new user.
        """
        data = request.get_json()
        username = data['username']
        password = data['password']
        role = data.get('role', 'User')  # Default role is 'User'
        team = data.get('team', None)

        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

        try:
            User.create(username=username, password=hashed_password, role=role, team=team)
            return {'message': f'User {username} created successfully with role {role}'}, 201
        except IntegrityError:
            return {'message': 'Username already exists'}, 400
        
    @ns.expect(user_model_put)
    @ns.response(200, 'User updated successfully')
    @ns.response(404, 'User not found')
    @role_required(['CEO', 'HR'])  # Restrict to CEO and HR
    def put(self):
        """
        Update an existing user's details.
        """
        data = request.get_json()
        username = data['username']
        role = data.get('role', None)
        team = data.get('team', None)

        try:
            user = User.get(User.username == username)
            if role:
                user.role = role
            if team:
                user.team = team
            user.save()
            return {'message': f'User {username} updated successfully'}, 200
        except DoesNotExist:
            return {'message': 'User not found'}, 404


    @ns.expect(user_model_delete)
    @ns.response(200, 'User deleted successfully')
    @ns.response(404, 'User not found')
    @role_required(['CEO', 'HR'])  # Restrict to CEO and HR
    def delete(self):
        """
        Delete a user.
        """
        data = request.get_json()
        username = data['username']

        try:
            user = User.get(User.username == username)
            user.delete_instance()
            return {'message': f'User {username} deleted successfully'}, 200
        except DoesNotExist:
            return {'message': 'User not found'}, 404

    @ns.expect(user_model_patch)
    @ns.response(200, 'User deactivated successfully')
    @ns.response(404, 'User not found')
    @role_required(['CEO', 'HR'])  # Restrict to CEO and HR
    def patch(self):
        """
        Deactivate a user.
        """
        data = request.get_json()
        username = data['username']

        try:
            user = User.get(User.username == username)
            user.active = False  # Assuming an `active` field in the `User` model
            user.save()
            return {'message': f'User {username} deactivated successfully'}, 200
        except DoesNotExist:
            return {'message': 'User not found'}, 404
@ns.route('/assign')
class AssignUser(Resource):
    @ns.expect(assign_users_model)
    @ns.response(201, 'Users successfully assigned')
    @ns.response(400, 'Invalid input or no users assigned')
    @role_required(['CEO', 'HR'])
    def post(self):
        """Assign multiple users to a Team Leader"""
        data = request.get_json()
        team_lead_id = data.get('team_lead_id')  # The team lead id passed in the request
        user_ids = data.get('user_ids')  # List of user IDs to assign

        if not user_ids:
            return {"message": "No users provided for assignment."}, 400

        # Ensure the Team Lead exists in the database
        team_lead = User.select().where(User.role == 'Team Lead').first()  # Use Peewee query

        if not team_lead:
            return {"message": "No team lead found."}, 400

        # Validate the team lead ID
        if team_lead.id != team_lead_id:
            return {"message": "The specified Team Leader does not exist or is invalid."}, 400

        # Iterate through the user IDs and assign them to the Team Leader
        assignments_created = 0
        for user_id in user_ids:
            # Ensure the User exists using Peewee's query method
            user = User.select().where(User.id == user_id).first()
            if not user:
                continue  # Skip if user doesn't exist
            
            # Check if assignment already exists using Peewee's query method
            existing_assignment = Assignment.select().where(Assignment.team_lead_id == team_lead_id, Assignment.user_id == user_id).first()
            if existing_assignment:
                continue  # Skip if already assigned

            # Create the new assignment
            new_assignment = Assignment(
                team_lead_id=team_lead_id,
                user_id=user_id
                  # Assuming 'current_user' has an 'id' field
            )
            new_assignment.save()  # Use Peewee's save method to commit the record
            assignments_created += 1

        if assignments_created == 0:
            return {"message": "No users were assigned. All users may already be assigned."}, 400

        return {"message": f"{assignments_created} user(s) successfully assigned to the Team Leader."}, 201

@ns.route('/remove-assigned-user')
class RemoveAssignedUser(Resource):
    @ns.expect(remove_assigned_user_model)
    @ns.response(200, 'User successfully removed from the Team Leader')
    @ns.response(400, 'Invalid input or no assignment found')
    @role_required(['CEO', 'HR'])
    def delete(self):
        """Remove an assigned user from a Team Leader"""
        data = request.get_json()
        team_lead_id = data.get('team_lead_id')  # The team lead id passed in the request
        user_id = data.get('user_id')  # The user id to be removed

        if not team_lead_id or not user_id:
            return {"message": "Both team_lead_id and user_id are required."}, 400

        # Ensure the Team Lead exists in the database
        team_lead = User.select().where(User.role == 'Team Lead', User.id == team_lead_id).first()
        if not team_lead:
            return {"message": "No team lead found with the provided ID."}, 400

        # Ensure the User exists
        user = User.select().where(User.id == user_id).first()
        if not user:
            return {"message": "The specified user does not exist."}, 400

        # Check if the user is assigned to the specified Team Leader
        assignment = Assignment.select().where(Assignment.team_lead_id == team_lead_id, Assignment.user_id == user_id).first()
        if not assignment:
            return {"message": "This user is not assigned to the specified Team Leader."}, 400

        # Remove the assignment
        assignment.delete_instance()

        return {"message": "User successfully removed from the Team Leader."}, 200
    
@ns.route('/AdminCheckDuration')
class AppDurations(Resource):
    @jwt_required()
    @role_required(['CEO', 'HR', 'Team Lead'])
    @ns.expect(app_durations_model)
    def post(self):
        # Parse input
        data = request.json
        user_ids = data.get('user_ids', None)
        start_date = data.get('start_date', None)
        end_date = data.get('end_date', None)

        # Get the current user's role
        current_user = get_jwt_identity()
        user = User.get_or_none(User.username == current_user)
        if not user or user.role not in ['Admin', 'HR', 'Team Lead']:
            return {'message': 'Permission denied'}, 403

        # Build the query based on filters
        query = Event.select(
            Event.user, User.username, Event.app, fn.SUM(Event.duration).alias('total_duration'), fn.DATE(Event.timestamp).alias('date')
        ).join(User)

        # Apply user filter
        if user_ids:
            query = query.where(Event.user.in_(user_ids))

        # Apply date range filter if both start and end dates are provided
        if start_date and end_date:
            try:
                start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
                end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
            except ValueError:
                return {'message': 'Invalid date format. Use YYYY-MM-DD.'}, 400
            query = query.where(fn.DATE(Event.timestamp).between(start_date, end_date))

        # Apply specific date filter if only one date is provided
        elif start_date:
            try:
                start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
            except ValueError:
                return {'message': 'Invalid date format. Use YYYY-MM-DD.'}, 400
            query = query.where(fn.DATE(Event.timestamp) == start_date)

        # Group the results by user, app, and date
        query = query.group_by(Event.user, Event.app, fn.DATE(Event.timestamp))

        # Prepare the response
        result = {"data": []}

        # Dictionary to hold user data for easy access
        users_data = {}

        # Loop through the query result and organize it by user, date, and app
        for row in query:
            username = row.user.username
            if username not in users_data:
                users_data[username] = {
                    "username": username,
                    "total_time": "0 hours",  # This will be calculated later
                    "activities": []
                }

            # Convert date to string format (YYYY-MM-DD)
            date_str = row.date.strftime('%Y-%m-%d')

            # If the date doesn't exist in the user's activities, initialize it
            activity_data = next((activity for activity in users_data[username]["activities"] if activity["date"] == date_str), None)
            if not activity_data:
                activity_data = {
                    "date": date_str,
                    "total_time_today": 0,  # Store as integer value for easy calculation
                    "categories": []
                }
                users_data[username]["activities"].append(activity_data)

            # Convert total duration to minutes
            total_duration_minutes = round(row.total_duration / 60)

            # Add app data to categories
            activity_data["categories"].append({
                "app": row.app,
                "total_time": f"{total_duration_minutes} min"
            })

            # Accumulate total time for this date
            activity_data["total_time_today"] += total_duration_minutes

        # Prepare the final response for total time in hours and minutes
        for username, user_data in users_data.items():
            total_time_in_minutes = sum(activity["total_time_today"] for activity in user_data["activities"])
            
            # Check if total time today is more than 60 minutes, convert to hours
            if total_time_in_minutes >= 60:
                total_time_in_hours = round(total_time_in_minutes / 60)
                user_data["total_time"] = f"{total_time_in_hours} hours"
            else:
                user_data["total_time"] = f"{total_time_in_minutes} min"

            # Convert total_time_today to hours if greater than 60 minutes, else leave it in minutes
            for activity in user_data["activities"]:
                if activity["total_time_today"] >= 60:
                    total_time_today_in_hours = round(activity["total_time_today"] / 60)
                    activity["total_time_today"] = f"{total_time_today_in_hours} hours"
                else:
                    activity["total_time_today"] = f"{activity['total_time_today']} min"

            result["data"].append(user_data)

        return jsonify(result)
