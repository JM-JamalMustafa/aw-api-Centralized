import plotly.graph_objects as go
import webbrowser
import json
import requests
import random

YOUR_JWT_TOKEN= "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTczNDQxMjE3MywianRpIjoiZjlmZGM5ODctM2U4Ni00Yzk5LThmZjEtMGZhMGJjYzI3OGQ5IiwidHlwZSI6ImFjY2VzcyIsInN1YiI6IkphbWFsIiwibmJmIjoxNzM0NDEyMTczLCJjc3JmIjoiNGNmZTljZWEtM2U0My00ZDE2LThkOGUtZjA2ZDA0N2NjODlhIiwiZXhwIjoxNzM0NDQwOTczfQ.DznCU2JvKhhQYnFuCoaaN7WGHBWpLfdmqhI-8l821Ng"
# Fetch data from the API
def fetch_data():
    try:
        # Replace with your actual API endpoint and JWT token
        url = "http://127.0.0.1:8000/api/fetch"  # Replace this with your API
        headers = {
            "Authorization": f"Bearer {YOUR_JWT_TOKEN}"  # Replace with your JWT token
        }
        response = requests.get(url, headers=headers)
        response.raise_for_status()  # Raise an error if the request fails
        return response.json()
    except Exception as e:
        print(f"Error fetching data: {e}")
        return None



# Process the data to group by title and associate app categories
def process_data(events, limit=10):
    grouped_data = {}
    app_categories = {}  # Keep track of app categories for coloring

    for event in events:
        title = event['title']
        duration = event['duration'] / 60  # Convert seconds to minutes
        app = event.get('app', 'unknown.exe')  # Safely get the app field or default to 'unknown.exe'
        grouped_data[title] = grouped_data.get(title, 0) + duration
        app_categories[title] = app  # Map title to its app name

    # Sort by duration and limit the results
    sorted_data = sorted(grouped_data.items(), key=lambda x: x[1], reverse=True)
    grouped_data = dict(sorted_data[:limit])

    # Filter app categories for only the top titles
    filtered_app_categories = {title: app_categories[title] for title in grouped_data.keys()}
    return grouped_data, filtered_app_categories

# Create a Plotly visualization with category-specific colors
def create_visualization(data, app_categories):
    titles = list(data.keys())
    durations = list(data.values())

    app_colors = {
        "chrome.exe": "#FFCC80",  # Light Orange
        "Code.exe": "#80D8FF",  # Light Blue
        "explorer.exe": "#C5E1A5",  # Light Green
        "notepad.exe": "#FFF59D",  # Light Yellow
        "Discord.exe": "#CFD8DC",  # Light Gray
        "python.exe": "#FFE082",  # Soft Gold
        "Postman.exe": "#FFAB91",  # Light Coral
        "DB Browser for SQLite.exe": "#B39DDB",  # Soft Purple
        "msedge.exe": "#B3E5FC",  # Soft Cyan
        "unknown.exe": "#E0E0E0"  # Very Light Gray (Default)
    }

    # Assign colors based on app categories
    colors = [app_colors.get(app_categories[title], "#D3D3D3") for title in titles]  # Default to light gray

    # Combine title and duration into the bar text
    text_labels = [f"{title}\n{duration:.2f} min" for title, duration in zip(titles, durations)]

    # Create a horizontal bar chart
    fig = go.Figure(go.Bar(
        x=durations,
        y=titles,
        orientation='h',
        marker=dict(color=colors),
        text=text_labels,  # Add title and duration text inside the bars
        textposition='inside',  # Position text inside the bar
        insidetextanchor='middle'  # Center text inside the bar
    ))

    fig.update_layout(
        title="Top Window Titles",
        xaxis_title="Duration (minutes)",
        yaxis=dict(showticklabels=False),  # Hide Y-axis labels
        template="plotly_white",
        font=dict(size=12),  # Font size for readability
        plot_bgcolor='#F5F5F5',  # Background color
        autosize=True
    )

    return fig

# Main script
if __name__ == "__main__":
    # Fetch and process data
    data = fetch_data()
    if data and "events" in data:
        events = data["events"]
        grouped_data, app_categories = process_data(events)

        # Create visualization
        fig = create_visualization(grouped_data, app_categories)

        # Save the chart as an HTML file
        html_file = "jamal.html"
        fig.write_html(html_file)

        # Open the HTML file in the default web browser
        webbrowser.open(html_file)