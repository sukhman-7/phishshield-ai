import os
import json
import requests
import base64
import cv2
import numpy as np
import pytesseract
from pyzbar.pyzbar import decode
from urllib.parse import urlparse
from typing import Optional

from fastapi import FastAPI, File, UploadFile, Form, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from google import genai
from google.genai import types
from playwright.async_api import async_playwright

# --- DATABASE IMPORTS ---
from sqlalchemy.orm import Session
import models
from database import engine, get_db

# Automatically generate database tables if they do not exist
models.Base.metadata.create_all(bind=engine)

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
client = genai.Client(api_key=GEMINI_API_KEY)

app = FastAPI(title="PhishShield AI Engine API (Persistent Edition)")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class EmailAnalysisRequest(BaseModel):
    content: str
    sender: Optional[str] = ""

class UrlAnalysisRequest(BaseModel):
    url: str

def query_gemini_threat_engine(payload: str, sender: str, context: str = "", network_data: list = None) -> dict:
    network_str = ", ".join(network_data) if network_data else "None or Not Applicable"
    prompt = f"""
    You are an expert enterprise cybersecurity SOC analyst. Analyze the following intercepted payload for phishing, fraud, or credential theft.
    
    Target Sender Address: {sender if sender else 'Unknown / Not Provided'}
    Payload Content: {payload}
    Additional Context (Sandbox/OCR): {context}
    Background Network Connections: {network_str}
    
    Evaluate the threat contextually. If the sender is 'support@microsoft.com' and the text asks for a login, that is SAFE. 
    If a URL silently contacts known malware/phishing domains or uses excessive suspicious redirects in the background, flag it as HIGH RISK.
    
    Return your analysis strictly as a JSON object with this exact schema:
    {{
        "threat_score": <int from 0 to 100>,
        "verdict": <string: "SAFE" or "SUSPICIOUS">,
        "analysis_details": [<list of specific, professional strings explaining exactly what flags triggered the score>]
    }}
    """
    try:
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt,
            config=types.GenerateContentConfig(response_mime_type="application/json"),
        )
        return json.loads(response.text)
    except Exception as e:
        error_msg = str(e)
        clean_details = []
        
        # Catch Rate Limits (429)
        if "429" in error_msg or "RESOURCE_EXHAUSTED" in error_msg:
            clean_details = [
                "SYSTEM HALT: AI Engine Rate Limit Exceeded.",
                "The Gemini API free tier quota has been temporarily exhausted.",
                "Remediation: Please wait approximately 60 seconds before initiating the next scan."
            ]
        # Catch API Key Issues
        elif "API_KEY" in error_msg.upper() or "400" in error_msg:
            clean_details = [
                "SYSTEM HALT: Authentication Failure.",
                "The system could not validate the provided Gemini API key.",
                "Remediation: Verify the GEMINI_API_KEY inside your .env configuration file."
            ]
        # Catch everything else (and truncate it so it doesn't break the UI)
        else:
            clean_details = [
                "SYSTEM HALT: Unhandled AI Engine Exception.",
                f"Diagnostic Code: {error_msg[:120]}..."
            ]

        return {
            "threat_score": 0,  # Set to 0 so it doesn't ruin your Home Dashboard KPIs
            "verdict": "ERROR",
            "analysis_details": clean_details
        }

def query_virustotal(url: str) -> dict:
    """Queries VirusTotal v3 API to see if the URL is already a known threat."""
    vt_key = os.getenv("VT_API_KEY")
    if not vt_key:
        return None

    # VirusTotal v3 API requires URLs to be base64 encoded without the '=' padding
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    headers = {"x-apikey": vt_key}

    try:
        # Retrieve the analysis report directly from the URLs endpoint
        response = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers=headers)
        if response.status_code == 200:
            data = response.json()
            stats = data['data']['attributes']['last_analysis_stats']
            
            # Extract how many security vendors flagged this as malicious
            malicious_count = stats.get('malicious', 0)
            suspicious_count = stats.get('suspicious', 0)
            
            # If 3 or more global vendors say it's bad, we block it immediately
            if malicious_count >= 3:
                return {
                    "threat_score": 95,
                    "verdict": "SUSPICIOUS",
                    "analysis_details": [
                        "SYSTEM OVERRIDE: Global Threat Database Match.",
                        f"VirusTotal Consensus: {malicious_count} enterprise security vendors flagged this exact URL as malicious.",
                        "Bypassing active sandbox. Connection blocked at the perimeter."
                    ],
                    "network_map": [],
                    "screenshot": None
                }
    except Exception as e:
        print(f"VirusTotal integration failed: {str(e)}")
        
    return None # Return None if it's safe or VT fails, so we can proceed to the Gemini sandbox

# --- NEW EXTENSION: HISTORICAL LOG EXTRACTION ENDPOINT ---
@app.get("/api/history")
def get_scan_history(db: Session = Depends(get_db)):
    # Fetch logs ordered newest first
    logs = db.query(models.ScanLog).order_by(models.ScanLog.timestamp.desc()).all()
    
    formatted_logs = []
    for log in logs:
        formatted_logs.append({
            "id": log.id,
            "scan_type": log.scan_type,
            "target": log.target,
            "threat_score": log.threat_score,
            "verdict": log.verdict,
            "analysis_details": json.loads(log.analysis_details),
            "network_map": json.loads(log.network_map),
            "timestamp": log.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        })
    return formatted_logs

@app.post("/api/analyze")
async def analyze_email(request: EmailAnalysisRequest, db: Session = Depends(get_db)):
    result = query_gemini_threat_engine(request.content, request.sender or "")
    
    # Persist log to SQLite
    db_log = models.ScanLog(
        scan_type="email",
        target=request.sender if request.sender else "Unknown Sender",
        threat_score=result.get("threat_score", 0),
        verdict=result.get("verdict", "ERROR"),
        analysis_details=json.dumps(result.get("analysis_details", []))
    )
    db.add(db_log)
    db.commit()
    
    return {"sender": request.sender, **result}

@app.post("/api/scan-image")
async def scan_image(sender: Optional[str] = Form(""), file: UploadFile = File(...), db: Session = Depends(get_db)):
    contents = await file.read()
    nparr = np.frombuffer(contents, np.uint8)
    image = cv2.imdecode(nparr, cv2.IMREAD_COLOR)
    
    extracted_text = ""
    vision_flags = "Image Analysis: "

    for qr in decode(image):
        qr_data = qr.data.decode('utf-8')
        extracted_text += f" {qr_data}"
        vision_flags += "QR Code Detected. "

    ocr_text = pytesseract.image_to_string(image).strip()
    if ocr_text:
        extracted_text += f" {ocr_text}"
        vision_flags += "Hidden text extracted via OCR."

    if not extracted_text.strip():
        db_log = models.ScanLog(scan_type="image", target=sender or "Visual Asset", threat_score=0, verdict="SAFE", analysis_details=json.dumps(["No text or QR found"]))
        db.add(db_log)
        db.commit()
        return {"sender": sender, "threat_score": 0, "verdict": "SAFE", "analysis_details": ["Vision Engine: No payloads detected."]}

    result = query_gemini_threat_engine(extracted_text, sender or "", context=vision_flags)
    
    db_log = models.ScanLog(
        scan_type="image",
        target=sender if sender else "Visual Asset",
        threat_score=result.get("threat_score", 0),
        verdict=result.get("verdict", "ERROR"),
        analysis_details=json.dumps(result.get("analysis_details", []))
    )
    db.add(db_log)
    db.commit()
    
    return {"sender": sender, "extracted_payload": extracted_text.strip(), **result}

@app.post("/api/scan-url")
async def scan_url_sandbox(request: UrlAnalysisRequest, db: Session = Depends(get_db)):
    raw_url = request.url.strip()
    target_url = raw_url if raw_url.startswith("http") else f"https://{raw_url}"
    
    parsed = urlparse(target_url)
    if not parsed.netloc or "." not in parsed.netloc:
        return {"threat_score": 0, "verdict": "INVALID URL", "analysis_details": ["URL appears incomplete."], "screenshot": None, "network_map": []}

    root_domain = parsed.netloc.lower().replace("www.", "")
    trusted_domains = ["microsoft.com", "google.com", "apple.com", "amazon.com", "github.com", "wikipedia.org", "youtube.com", "linkedin.com"]
    if root_domain in trusted_domains:
        db_log = models.ScanLog(scan_type="url", target=target_url, threat_score=0, verdict="SAFE", analysis_details=json.dumps([f"Whitelisted root domain: {root_domain}"]))
        db.add(db_log)
        db.commit()
        return {"threat_score": 0, "verdict": "SAFE", "analysis_details": [f"Deep Intel: '{root_domain}' is whitelisted."], "screenshot": None, "network_map": []}

    
    vt_result = query_virustotal(target_url)
    if vt_result:
        # If VT caught it, log it to the local SQLite database and return instantly!
        db_log = models.ScanLog(
            scan_type="url",
            target=target_url,
            threat_score=vt_result.get("threat_score", 0),
            verdict=vt_result.get("verdict", "ERROR"),
            analysis_details=json.dumps(vt_result.get("analysis_details", [])),
            network_map=json.dumps([])
        )
        db.add(db_log)
        db.commit()
        return vt_result

    screenshot_b64 = None
    page_text = ""
    contacted_domains = set()

    async def handle_request(intercepted_request):
        try:
            domain = urlparse(intercepted_request.url).netloc
            if domain: contacted_domains.add(domain)
        except: pass

    try:
        async with async_playwright() as p:
            # 1. Launch the browser with automation arguments hidden
            browser = await p.chromium.launch(headless=True)
            
            # 2. Inject standard consumer browser properties
            context = await browser.new_context(
                ignore_https_errors=True,
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
                viewport={"width": 1920, "height": 1080},
                device_scale_factor=1
            )
            
            page = await context.new_page()
            
            # Attach the wiretap before navigating
            page.on("request", handle_request)
            
            # 3. Increase timeout to 30s and change wait behavior to 'commit'
            # 'commit' means control is returned as soon as the main body HTML begins streaming
            await page.goto(target_url, timeout=30000, wait_until="commit")
            
            # Brief pause to let the page adjust visually before snapping the shot
            await page.wait_for_timeout(2000) 
            
            screenshot_bytes = await page.screenshot()
            screenshot_b64 = base64.b64encode(screenshot_bytes).decode('utf-8')
            page_text = await page.evaluate("document.body.innerText")
            page_title = await page.title()
            
            await browser.close()
            sandbox_context = f"Deep Intel: Successfully sandboxed. Page Title: '{page_title}'."
    except Exception as e:
        error_msg = repr(e)
        return {"threat_score": 75, "verdict": "SUSPICIOUS", "analysis_details": [f"Sandbox Connection Failure: {error_msg}"], "screenshot": None, "network_map": []}

    network_list = list(contacted_domains)[:30]
    truncated_text = page_text[:4000] 
    
    if truncated_text.strip():
        result = query_gemini_threat_engine(truncated_text, "Direct URL Sandboxing", context=sandbox_context, network_data=network_list)
    else:
        result = {"threat_score": 40, "verdict": "SUSPICIOUS", "analysis_details": ["Sandbox found no readable text."]}

    # Write execution records down into the database
    db_log = models.ScanLog(
        scan_type="url",
        target=target_url,
        threat_score=result.get("threat_score", 0),
        verdict=result.get("verdict", "ERROR"),
        analysis_details=json.dumps(result.get("analysis_details", [])),
        network_map=json.dumps(network_list)
    )
    db.add(db_log)
    db.commit()

    return {**result, "screenshot": screenshot_b64, "network_map": network_list}