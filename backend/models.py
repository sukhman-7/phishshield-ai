import datetime
from sqlalchemy import Column, Integer, String, Text, DateTime
from database import Base

class ScanLog(Base):
    __tablename__ = "scan_logs"

    id = Column(Integer, primary_key=True, index=True)
    scan_type = Column(String, index=True)       # "email", "image", or "url"
    target = Column(String, default="Unknown")   # The URL scanned or Sender Address
    threat_score = Column(Integer)
    verdict = Column(String)
    
    # SQLite does not support native arrays, so we store lists as JSON strings
    analysis_details = Column(Text, default="[]") 
    network_map = Column(Text, default="[]")      
    
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)