#!/usr/bin/env python3
"""
Windows Event Decoder for SOC-A4
Normalizes sysmon and security events from the replay
"""

import json
import hashlib
from datetime import datetime
from typing import Dict, Any, Optional, List
import re

class EventDecoder:
    """Decodes and normalizes Windows event records"""
    
    # Schema versions mapping
    SCHEMA_VERSIONS = {
        "1": {"channel": "Microsoft-Windows-System/Operational", "event_code": 1},
        "2": {"channel": "Security", "event_code": "4688"},
        "3": {"channel": "Microsoft-Windows-System/Operational", "event_code": 1}
    }
    
    def __init__(self):
        self.events = []
        self.stats = {
            "total": 0,
            "decoded": 0,
            "failed": 0,
            "skipped": 0
        }
    
    def decode_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Decode a single JSONL line from the replay"""
        try:
            # Parse the JSON line
            raw_event = json.loads(line.strip())
            self.stats["total"] += 1
            
            # Extract schema version
            schema_ver = raw_event.get("schema_version", "1")
            
            # Normalize based on schema version
            normalized = self._normalize_event(raw_event, schema_ver)
            
            if normalized:
                # Add source locator and hash
                normalized["_source_locator"] = f"line_{self.stats['total']}"
                normalized["_source_hash"] = hashlib.sha256(line.encode()).hexdigest()
                normalized["_decoded_at"] = datetime.utcnow().isoformat() + "Z"
                normalized["_normalized_version"] = "1.0"
                
                self.stats["decoded"] += 1
                self.events.append(normalized)
                return normalized
            else:
                self.stats["skipped"] += 1
                return None
                
        except json.JSONDecodeError:
            self.stats["failed"] += 1
            return None
        except Exception as e:
            self.stats["failed"] += 1
            return None
    
    def _normalize_event(self, raw: Dict[str, Any], schema_ver: str) -> Optional[Dict[str, Any]]:
        """Normalize raw event to standard format"""
        try:
            normalized = {
                "event_id": raw.get("event_id", ""),
                "timestamp": self._parse_timestamp(raw.get("timestamp", "")),
                "computer": raw.get("computer", ""),
                "user": raw.get("user", ""),
                "image": raw.get("image", "").lower(),
                "parent_image": raw.get("parent_image", "").lower(),
                "command_family": raw.get("command_family", "unknown"),
                "command_line": raw.get("command_line", ""),
                "channel": self._get_channel(raw, schema_ver),
                "event_code": self._get_event_code(raw, schema_ver),
            }
            
            # Remove empty fields
            return {k: v for k, v in normalized.items() if v is not None and v != ""}
            
        except Exception:
            return None
    
    def _parse_timestamp(self, ts: str) -> str:
        """Parse and normalize timestamp to ISO format"""
        try:
            # Handle various timestamp formats
            if ts.endswith('Z'):
                return ts
            # Try to parse and reformat
            dt = datetime.fromisoformat(ts.replace('Z', '+00:00'))
            return dt.isoformat() + 'Z'
        except:
            return ts
    
    def _get_channel(self, raw: Dict[str, Any], schema_ver: str) -> str:
        """Get normalized channel name"""
        if "channel" in raw:
            return raw["channel"]
        return self.SCHEMA_VERSIONS.get(schema_ver, {}).get("channel", "unknown")
    
    def _get_event_code(self, raw: Dict[str, Any], schema_ver: str) -> str:
        """Get normalized event code"""
        if "event_code" in raw:
            return str(raw["event_code"])
        return str(self.SCHEMA_VERSIONS.get(schema_ver, {}).get("event_code", "0"))
    
    def decode_file(self, filepath: str) -> List[Dict[str, Any]]:
        """Decode an entire JSONL file"""
        self.events = []
        self.stats = {"total": 0, "decoded": 0, "failed": 0, "skipped": 0}
        
        with open(filepath, 'r') as f:
            for line in f:
                if line.strip():
                    self.decode_line(line)
        
        return self.events
    
    def get_stats(self) -> Dict[str, int]:
        """Get decoding statistics"""
        return self.stats.copy()


# Utility functions
def is_alert_event(event: Dict[str, Any]) -> bool:
    """Quick check if event might be suspicious"""
    suspicious_images = ['powershell.exe', 'cmd.exe', 'rundll32.exe', 'regsvr32.exe']
    suspicious_parents = ['winword.exe', 'wmiprvse.exe', 'services.exe']
    
    image = event.get('image', '').lower()
    parent = event.get('parent_image', '').lower()
    
    if any(s in image for s in suspicious_images):
        if any(s in parent for s in suspicious_parents):
            return True
    return False


if __name__ == "__main__":
    # Test the decoder
    decoder = EventDecoder()
    
    # Test with a sample event
    sample = '{"schema_version":"1","event_id":"EVT-14b4bf00000000","timestamp":"2026-07-08T00:00:02","channel":"Microsoft-Windows-System/Operational","event_code":1,"computer":"NS-WIN-162","user":"NORTHSTAR\\\\User141","image":"powershell.exe","parent_image":"enterprise-updater.exe","command_family":"signed_update","command_line":"powershell.exe -job c1224e596cb1"}'
    
    result = decoder.decode_line(sample)
    if result:
        print("✅ Decoder working!")
        print(json.dumps(result, indent=2))
    else:
        print("❌ Decoder failed")