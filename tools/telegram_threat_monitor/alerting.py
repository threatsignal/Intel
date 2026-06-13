import requests
import json
import os
from datetime import datetime
from config import Config

class AlertManager:
    def __init__(self):
        self.webhook_url = Config.DISCORD_WEBHOOK_URL
        self.log_file = "threat_log.jsonl"

    def log_locally(self, data: dict):
        """Saves the event to a local JSONL file."""
        data["timestamp"] = datetime.utcnow().isoformat()
        try:
            with open(self.log_file, "a") as f:
                f.write(json.dumps(data) + "\n")
        except Exception as e:
            print(f"Error logging locally: {e}")

    def send_discord_alert(self, data: dict):
        """Sends a formatted embedded message to Discord."""
        if not self.webhook_url:
            return

        # Map severity to colors
        colors = {
            1: 3066993,  # Green
            2: 3447003,  # Blue
            3: 16776960, # Yellow
            4: 16738740, # Orange
            5: 15158332  # Red
        }
        color = colors.get(data.get("severity", 1), 15158332)
        
        # Format IOCs nicely
        iocs = data.get("iocs", {})
        ioc_text = ""
        for key, vals in iocs.items():
            if vals:
                ioc_text += f"**{key.upper()}:** {', '.join(vals[:5])}"
                if len(vals) > 5:
                    ioc_text += f" (+{len(vals)-5} more)\n"
                else:
                    ioc_text += "\n"
        if not ioc_text:
            ioc_text = "None detected."

        embed = {
            "title": f"🚨 Threat Intel Alert: {data.get('threat_type', 'Unknown')}",
            "color": color,
            "fields": [
                {
                    "name": "Summary",
                    "value": data.get("summary", "No summary provided."),
                    "inline": False
                },
                {
                    "name": "Source Channel",
                    "value": data.get("channel", "Unknown"),
                    "inline": True
                },
                {
                    "name": "Severity",
                    "value": f"{data.get('severity', 0)} / 5",
                    "inline": True
                },
                {
                    "name": "Extracted IOCs",
                    "value": ioc_text,
                    "inline": False
                }
            ],
            "footer": {"text": "Telegram Threat Monitor | Automated Analysis"}
        }

        payload = {"embeds": [embed]}

        try:
            response = requests.post(
                self.webhook_url,
                data=json.dumps(payload),
                headers={"Content-Type": "application/json"}
            )
            if response.status_code != 204:
                print(f"Failed to send Discord alert: {response.text}")
        except Exception as e:
            print(f"Error sending Discord alert: {e}")
