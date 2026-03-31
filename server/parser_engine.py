import re
import hashlib

class ParserEngine:
    def __init__(self):
        # Define regex templates for each known source
        self.parsers = {
            "linux": r"(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<host>[^\s]+)\s+(?P<service>[^:]+):\s+(?P<message>.*)",
            "apache": r'(?P<ip>[^\s]+)\s+-\s+-\s+\[(?P<time>.*?)\]\s+"(?P<request>.*?)"\s+(?P<status>\d+)',
            "auth": r"(?P<timestamp>\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(?P<host>[^\s]+)\s+(?P<service>sshd|su|sudo)\[(?P<pid>\d+)\]:\s+(?P<message>.*)"
        }
    
    def parse_log(self, source, raw_log):
        """
        Parses a raw log string based on its predicted source.
        Returns a dictionary of parsed fields, or None if no match.
        """
        if source not in self.parsers and source != 'unknown':
            # Default to linux if source is unexpected
            pattern = self.parsers.get('linux')
            source = 'linux'
        else:
            pattern = self.parsers.get(source, self.parsers['linux'])
            
        match = re.match(pattern, raw_log)
        if match:
            return match.groupdict()
        return {"raw_message": raw_log}
        
    def extract_template(self, message):
        """
        Extracts a template by replacing variable parts (like IPs, numbers) with <*>.
        Returns the template string and its md5 hash (template ID).
        """
        if not message:
            return "<*>", hashlib.md5(b"<*>").hexdigest()
            
        # Replace IP addresses
        template = re.sub(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', '<*>', message)
        # Replace numbers/hex
        template = re.sub(r'\b[0-9a-fA-F]+\b', '<*>', template)
        # Strip extra spaces
        template = re.sub(r'\s+', ' ', template).strip()
        
        template_id = hashlib.md5(template.encode('utf-8')).hexdigest()
        
        return template, template_id
