# app/scheduler.py

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger
from datetime import datetime
import time
from app.resource import FetchAWServerData

# Initialize the scheduler
scheduler = BackgroundScheduler()

def fetch_data():
    # This method should be where you fetch and process data periodically
    fetcher = FetchAWServerData()
    username = "sample_user"  # You might want to get this dynamically
    fetcher.fetch_data_from_aw_server(username)

def setup_scheduler():
    """Setup the scheduler to periodically fetch data."""
    scheduler.add_job(
        fetch_data,
        trigger=IntervalTrigger(seconds=60),  # Set the interval to 60 seconds
        id="fetch_data_job",
        name="Fetch data from AW server",
        replace_existing=True
    )
    scheduler.start()
