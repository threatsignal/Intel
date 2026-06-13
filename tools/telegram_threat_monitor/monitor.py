import asyncio
# pyrefly: ignore [missing-import]
from telethon import TelegramClient, events
from config import Config
from extractor import IOCExtractor
from llm_analyzer import LLMAnalyzer
from alerting import AlertManager

async def main():
    # Validate environment variables
    Config.validate()
    
    print("Initializing Telegram Client...")
    client = TelegramClient('threat_monitor_session', Config.TELEGRAM_API_ID, Config.TELEGRAM_API_HASH)
    
    llm = LLMAnalyzer()
    alert_mgr = AlertManager()
    
    # We only monitor specific channels defined in config
    target_chats = Config.TARGET_CHANNELS
    
    @client.on(events.NewMessage(chats=target_chats if target_chats else None))
    async def handler(event):
        try:
            sender = await event.get_sender()
            channel_name = sender.username if getattr(sender, 'username', None) else str(event.chat_id)
            
            text = event.message.message
            if not text:
                return

            print(f"\n[+] New message detected in {channel_name} (Length: {len(text)})")
            
            # 1. Extract IOCs
            iocs = IOCExtractor.extract_all(text)
            
            # 2. Analyze with LLM
            print("    Analyzing with LLM...")
            analysis = await llm.analyze_message_async(text)
            
            # Combine data
            alert_data = {
                "channel": channel_name,
                "original_text": text,
                "translation": analysis.get("translation"),
                "summary": analysis.get("summary"),
                "severity": analysis.get("severity"),
                "threat_type": analysis.get("threat_type"),
                "iocs": iocs
            }
            
            # 3. Log and Alert
            await alert_mgr.log_locally_async(alert_data)
            
            # Only send discord alerts for severity 3 or higher to reduce noise
            if alert_data.get("severity", 0) >= 3:
                print(f"    Sending HIGH SEVERITY alert to Discord (Severity: {alert_data['severity']})")
                await alert_mgr.send_discord_alert_async(alert_data)
            else:
                print(f"    Logged locally (Severity: {alert_data.get('severity', 0)})")
                
        except Exception as e:
            print(f"[-] Error processing message: {e}")

    await client.start()
    if target_chats:
        print(f"[*] Monitoring channels: {', '.join(target_chats)}")
    else:
        print("[!] Warning: TARGET_CHANNELS not set. Monitoring ALL incoming messages.")
    
    print("[*] Waiting for new messages... (Press Ctrl+C to stop)")
    await client.run_until_disconnected()

if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[*] Shutting down Threat Monitor.")
