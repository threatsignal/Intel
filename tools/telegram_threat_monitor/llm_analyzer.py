import google.generativeai as genai
from config import Config

class LLMAnalyzer:
    def __init__(self):
        genai.configure(api_key=Config.GEMINI_API_KEY)
        self.model = genai.GenerativeModel('gemini-1.5-pro')

    def analyze_message(self, text: str) -> dict:
        """
        Uses Gemini to translate text (if not English), summarize the threat, 
        and provide a severity score.
        """
        prompt = f"""
        You are an expert Threat Intelligence Analyst monitoring underground channels.
        Analyze the following message. If it's not in English, translate it.
        Provide a JSON response with the following keys:
        - "translation": English translation of the text (or the original text if already English)
        - "summary": A concise 1-2 sentence summary of the threat or activity.
        - "severity": A score from 1 (Low) to 5 (Critical) based on the impact (e.g. leaked DBs, 0-days = 5).
        - "threat_type": The category of the threat (e.g., Malware, Ransomware, Exploit, Leak, Phishing).

        Message to analyze:
        '''
        {text}
        '''
        
        Respond ONLY with valid JSON.
        """
        
        try:
            response = self.model.generate_content(prompt)
            # Naive JSON extraction (assuming the model returns pure JSON or Markdown wrapped JSON)
            result_text = response.text.strip()
            if result_text.startswith('```json'):
                result_text = result_text[7:-3]
            elif result_text.startswith('```'):
                result_text = result_text[3:-3]
                
            import json
            return json.loads(result_text)
        except Exception as e:
            print(f"LLM Analysis failed: {e}")
            return {
                "translation": "Translation failed.",
                "summary": "Could not generate summary.",
                "severity": 0,
                "threat_type": "Unknown"
            }
