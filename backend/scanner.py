import os
import sys
from pathlib import Path

# Add project root to sys.path so backend module can be imported
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

try:
    from backend.analyzer import analyze_logs
    from backend.database import create_database, save_alert
except ImportError:
    from analyzer import analyze_logs
    from database import create_database, save_alert


create_database()


print("Starting OpenSentinel scan...\n")


result = analyze_logs()


print(result)



if result["status"] == "ALERT":


    for alert in result["alerts"]:

        save_alert(alert)


        print(
            "Alert saved to database"
        )