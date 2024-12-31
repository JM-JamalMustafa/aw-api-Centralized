from peewee import (
    Model,
    SqliteDatabase,
    CharField,
    TextField,
    DateTimeField,
    FloatField,
    ForeignKeyField,
    BooleanField,
    AutoField  
)
from datetime import datetime

# Database initialization
db = SqliteDatabase('activity1.db')

class User(Model):
    username = CharField(unique=True)
    password = CharField()
    role = CharField(default='User')  # CEO, Admin, Team Lead, User
    team = CharField(null=True)  # Team name (e.g., "Mobile", "Laravel", "AI")
    active = BooleanField(default=True)  # Active status
    class Meta:
        database = db

class Assignment(Model):
    id = AutoField() 
    team_lead_id = ForeignKeyField(User, backref='team_lead_assignments', on_delete='CASCADE')  
    user_id = ForeignKeyField(User, backref='user_assignments', on_delete='CASCADE')  
    
    class Meta:
        database = db

# Define the Event model
class Event(Model):
    user = ForeignKeyField(User, backref='events')
    timestamp = DateTimeField()
    duration = FloatField()  # Duration in seconds (can also be a FloatField if fractional durations)
    app = CharField()
    title = CharField(null=True)
    client = CharField(null=True)  # Foreign key reference to bucket (assuming bucket_id 
     # Back reference to 'events'

    class Meta:
        database = db

# Connect and create tables
def initialize_db():
    db.connect()
    db.create_tables([User,Assignment, Event], safe=True)
