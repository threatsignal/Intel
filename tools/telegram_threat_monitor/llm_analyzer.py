import json
import google.generativeai as genai
from config import Config

class LLMAnalyzer:
    def __init__(self):
        genai.configure(api_key=Config.GEMINI_API_KEY)
        self.model = genai.GenerativeModel('gemini-1.5-pro')

    async def analyze_message_async(self, text: str) -> dict:
        """
        Uses Gemini to translate text (if not English), summarize the threat, 
        and provide a severity score asynchronously.
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
        
        default_error_response = {
            "translation": "Translation failed.",
            "summary": "Could not generate summary.",
            "severity": 0,
            "threat_type": "Unknown"
        }
        
        try:
            response = await self.model.generate_content_async(prompt)
            
            # Check for safety blocks
            if response.candidates and response.candidates[0].finish_reason.name == "SAFETY":
                print("LLM Analysis blocked by safety filters.")
                default_error_response["summary"] = "Message blocked by safety filters."
                return default_error_response
            
            # Naive JSON extraction (assuming the model returns pure JSON or Markdown wrapped JSON)
            result_text = response.text.strip()
            if result_text.startswith('```json'):
                result_text = result_text[7:-3]
            elif result_text.startswith('```'):
                result_text = result_text[3:-3]
                
            return json.loads(result_text)
        except Exception as e:
            print(f"LLM Analysis failed: {e}")
            return default_error_response
