import re

class IOCExtractor:
    @staticmethod
    def extract_all(text: str) -> dict:
        """Extracts various IOCs from unstructured text."""
        iocs = {
            "ipv4": IOCExtractor.extract_ipv4(text),
            "hashes": IOCExtractor.extract_hashes(text),
            "cves": IOCExtractor.extract_cves(text),
            "domains": IOCExtractor.extract_domains(text),
            "btc_addresses": IOCExtractor.extract_btc(text),
            "eth_addresses": IOCExtractor.extract_eth(text),
        }
        return iocs

    @staticmethod
    def extract_ipv4(text: str) -> list:
        # Stricter IPv4 regex matching 0.0.0.0 to 255.255.255.255
        ipv4_pattern = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
        return list(set(ipv4_pattern.findall(text)))

    @staticmethod
    def extract_hashes(text: str) -> list:
        # Match MD5, SHA1, SHA256
        hash_pattern = re.compile(r'\b([a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b')
        return list(set(hash_pattern.findall(text)))

    @staticmethod
    def extract_cves(text: str) -> list:
        # Match CVE format e.g. CVE-2023-12345
        cve_pattern = re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE)
        return list(set(cve_pattern.findall(text)))
    
    @staticmethod
    def extract_domains(text: str) -> list:
        # Basic domain regex matching common TLDs (excluding common false positives could be added)
        domain_pattern = re.compile(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|info|biz|ru|cn|su|cc|top|xyz)\b', re.IGNORECASE)
        return list(set(domain_pattern.findall(text)))

    @staticmethod
    def extract_btc(text: str) -> list:
        # Match Bitcoin P2PKH, P2SH, and Bech32 addresses
        btc_pattern = re.compile(r'\b(?:1[A-HJ-NP-Za-km-z1-9]{25,34}|3[A-HJ-NP-Za-km-z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{39,59})\b')
        return list(set(btc_pattern.findall(text)))

    @staticmethod
    def extract_eth(text: str) -> list:
        # Match Ethereum addresses
        eth_pattern = re.compile(r'\b0x[a-fA-F0-9]{40}\b')
        return list(set(eth_pattern.findall(text)))
