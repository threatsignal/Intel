# 🕵️ Dark Web & Telegram Threat Monitor

An automated Threat Intelligence pipeline that monitors underground Telegram channels, extracts Indicators of Compromise (IOCs), and uses GenAI (Gemini) to translate foreign languages and summarize threats. High-severity alerts are pushed in real-time to Discord.

## Architecture

1. **`monitor.py`**: The core daemon using `telethon` to listen for real-time messages in targeted channels.
2. **`extractor.py`**: Uses regular expressions to extract IPv4, Domains, Hashes (MD5/SHA1/SHA256), and CVEs from raw text.
3. **`llm_analyzer.py`**: Feeds the raw message to Google's Gemini LLM. The LLM translates the text (e.g., from Russian/Chinese to English), generates a 1-sentence summary, categorizes the threat, and assigns a severity score (1-5).
4. **`alerting.py`**: Logs all events to a local JSONL file for historical indexing, and sends Discord webhook alerts for any message scored Severity 3 or higher.

## Setup Instructions

1. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

2. **Configure API Keys**:
   * Copy `.env.example` to `.env`
   * Get your Telegram `API_ID` and `API_HASH` from [my.telegram.org](https://my.telegram.org)
   * Get a free Gemini API key from [Google AI Studio](https://aistudio.google.com/)
   * Create a Discord Webhook in your server settings and paste the URL.
   * Define `TARGET_CHANNELS` (e.g., `bluedot_threats,vxunderground`)

3. **Run the Monitor**:
   ```bash
   python monitor.py
   ```
   *Note: On the first run, Telegram will ask you to authenticate your phone number to create the local session file.*

## Example Discord Alert
* **Title**: 🚨 Threat Intel Alert: Ransomware
* **Summary**: A new LockBit 3.0 builder leak has been posted containing updated configuration files.
* **Source Channel**: `vxunderground`
* **Severity**: 5 / 5
* **Extracted IOCs**: 
  * HASHES: `d41d8cd98f00b204e9800998ecf8427e`
