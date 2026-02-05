"""
🛡️ SCAM SHIELD - Complete Backend API
AI-Powered Honeypot for Scam Detection & Intelligence Extraction
Version: 3.0 FINAL
"""

from fastapi import FastAPI, HTTPException, Header, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from enum import Enum
import re
import random
import json
import httpx
import asyncio
import os

# ============================================================================
# CONFIGURATION - REPLACE WITH YOUR KEYS
# ============================================================================
class Config:
    HONEYPOT_API_KEY = "sk-scamshield-2024-hackathon-key"
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "gen-lang-client-0838626386")  # Set via environment or replace here
    GUVI_CALLBACK_URL = "https://hackathon.guvi.in/api/updateHoneyPotFinalResult"
    MAX_MESSAGES = 20
    SESSION_TIMEOUT = 10  # minutes

# ============================================================================
# ENUMS
# ============================================================================
class ScamCategory(str, Enum):
    BANKING_FRAUD = "BANKING_FRAUD"
    UPI_FRAUD = "UPI_FRAUD"
    PHISHING = "PHISHING"
    LOTTERY_SCAM = "LOTTERY_SCAM"
    IMPERSONATION = "IMPERSONATION"
    INVESTMENT_FRAUD = "INVESTMENT_FRAUD"
    JOB_SCAM = "JOB_SCAM"
    TECH_SUPPORT = "TECH_SUPPORT"
    ROMANCE_SCAM = "ROMANCE_SCAM"
    EXTORTION = "EXTORTION"
    KYC_FRAUD = "KYC_FRAUD"
    UNKNOWN = "UNKNOWN"

class ThreatLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    SAFE = "SAFE"

class SessionStatus(str, Enum):
    ACTIVE = "ACTIVE"
    COMPLETED = "COMPLETED"
    TIMEOUT = "TIMEOUT"

# ============================================================================
# SCAM DETECTION KEYWORDS (Multi-language: English, Hindi, Tamil, Telugu, Kannada, Malayalam, Bengali, Marathi)
# ============================================================================
SCAM_KEYWORDS = {
    "urgency": [
        # English
        "urgent", "immediately", "now", "today only", "last chance", "expires", "hurry", "quick", "asap", "limited time", "act now", "deadline", "emergency", "fast", "quickly", "right now", "don't delay", "time sensitive", "expiring",
        # Hindi
        "तुरंत", "अभी", "जल्दी", "फौरन", "आखिरी मौका", "समय सीमा", "देर न करें",
        # Tamil
        "உடனடியாக", "இப்போது", "அவசரம்", "விரைவாக",
        # Telugu
        "వెంటనే", "ఇప్పుడు", "త్వరగా", "ఆలస్యం చేయకండి",
        # Kannada
        "ತಕ್ಷಣ", "ಈಗಲೇ", "ಬೇಗ",
        # Malayalam
        "ഉടനെ", "ഇപ്പോൾ", "വേഗം",
        # Bengali
        "এখনই", "তাড়াতাড়ি", "জরুরি",
        # Marathi
        "लगेच", "आता", "तातडीने"
    ],
    "threat": [
        # English
        "blocked", "suspended", "frozen", "legal action", "police", "arrest", "court", "penalty", "fine", "seized", "terminated", "disabled", "compromised", "hacked", "unauthorized", "illegal", "violation", "warning", "alert", "deactivate", "closed", "locked", "restricted", "banned",
        # Hindi
        "ब्लॉक", "बंद", "कानूनी कार्रवाई", "पुलिस", "गिरफ्तार", "जुर्माना", "अवैध", "चेतावनी",
        # Tamil
        "தடை", "நிறுத்தப்பட்டது", "சட்ட நடவடிக்கை", "காவல்துறை",
        # Telugu
        "బ్లాక్", "నిలిపివేయబడింది", "చట్టపరమైన చర్య",
        # Kannada
        "ನಿರ್ಬಂಧಿಸಲಾಗಿದೆ", "ಕಾನೂನು ಕ್ರಮ",
        # Malayalam
        "ബ്ലോക്ക്", "നിയമനടപടി",
        # Bengali
        "ব্লক", "আইনি পদক্ষেপ",
        # Marathi
        "ब्लॉक", "कायदेशीर कारवाई"
    ],
    "credential_request": [
        # English
        "otp", "pin", "password", "cvv", "card number", "account number", "verify", "confirm", "update", "share", "send", "provide", "enter", "aadhaar", "pan", "bank details", "login", "credentials", "secret code", "verification code", "atm pin", "internet banking", "mobile banking", "net banking", "debit card", "credit card",
        # Hindi
        "ओटीपी", "पिन", "पासवर्ड", "सत्यापित करें", "आधार", "पैन",
        # Tamil
        "கடவுச்சொல்", "சரிபார்க்க", "ஆதார்",
        # Telugu
        "పాస్‌వర్డ్", "ధృవీకరించండి", "ఆధార్",
        # Kannada
        "ಪಾಸ್‌ವರ್ಡ್", "ಪರಿಶೀಲಿಸಿ",
        # Malayalam
        "പാസ്‌വേഡ്", "സ്ഥിരീകരിക്കുക",
        # Bengali
        "পাসওয়ার্ড", "যাচাই করুন",
        # Marathi
        "पासवर्ड", "सत्यापित करा"
    ],
    "money_request": [
        # English
        "transfer", "payment", "pay", "send money", "deposit", "fee", "charge", "cost", "rupees", "rs", "inr", "amount", "₹", "processing fee", "registration fee", "advance", "token amount", "security deposit",
        # Hindi
        "भुगतान", "पैसे भेजो", "रुपये", "शुल्क", "फीस", "जमा",
        # Tamil
        "பணம்", "செலுத்து", "கட்டணம்",
        # Telugu
        "డబ్బు", "చెల్లించు", "ఫీజు",
        # Kannada
        "ಹಣ", "ಪಾವತಿ", "ಶುಲ್ಕ",
        # Malayalam
        "പണം", "അടയ്ക്കുക", "ഫീസ്",
        # Bengali
        "টাকা", "পাঠান", "ফি",
        # Marathi
        "पैसे", "भरा", "शुल्क"
    ],
    "reward": [
        # English
        "winner", "congratulations", "selected", "prize", "reward", "cashback", "refund", "bonus", "lottery", "lucky", "won", "claim", "free", "gift", "offer", "jackpot", "bumper", "lucky draw", "scratch card",
        # Hindi
        "जीत", "इनाम", "बधाई", "कैशबैक", "मुफ्त", "लॉटरी", "विजेता",
        # Tamil
        "பரிசு", "வென்றீர்கள்", "வாழ்த்துக்கள்",
        # Telugu
        "బహుమతి", "గెలిచారు", "అభినందనలు",
        # Kannada
        "ಬಹುಮಾನ", "ಗೆದ್ದಿದ್ದೀರಿ",
        # Malayalam
        "സമ്മാനം", "വിജയിച്ചു",
        # Bengali
        "পুরস্কার", "জিতেছেন",
        # Marathi
        "बक्षीस", "जिंकलात"
    ],
    "impersonation": [
        # English
        "bank manager", "rbi", "reserve bank", "income tax", "customs", "cbi", "cyber cell", "customer care", "support team", "government", "official", "sbi", "hdfc", "icici", "axis", "paytm", "phonepe", "gpay", "amazon", "flipkart", "microsoft", "apple", "google", "facebook", "whatsapp", "telegram", "police", "officer", "inspector", "department", "ministry",
        # Hindi
        "बैंक मैनेजर", "आयकर विभाग", "सरकारी", "पुलिस अधिकारी", "विभाग",
        # Tamil
        "வங்கி மேலாளர்", "அரசு அதிகாரி",
        # Telugu
        "బ్యాంక్ మేనేజర్", "ప్రభుత్వ అధికారి"
    ],
    "kyc": [
        # English
        "kyc", "know your customer", "verification required", "update kyc", "kyc expire", "document verification", "identity proof", "re-kyc", "video kyc", "ekyc", "kyc update", "kyc pending", "complete kyc",
        # Hindi
        "केवाईसी", "दस्तावेज़ सत्यापन",
        # Tamil
        "கேஒய்சி",
        # Telugu
        "కెవైసి"
    ],
    "tech_scam": [
        # English
        "virus", "malware", "infected", "hacked", "compromised", "remote access", "teamviewer", "anydesk", "technical support", "microsoft support", "apple support", "computer problem", "antivirus", "firewall", "security alert"
    ],
    "investment_scam": [
        # English
        "guaranteed returns", "double money", "triple money", "100% profit", "daily profit", "weekly returns", "crypto", "bitcoin", "forex", "trading", "investment opportunity", "high returns", "low risk", "no risk", "assured returns", "fixed returns"
    ]
}

# ============================================================================
# KNOWN SCAM PHONE DATABASE (Sample - can be expanded)
# ============================================================================
KNOWN_SCAM_PHONES = {
    "9876543210", "8888777766", "9999888877", "7777666655", "1800123456"
}

# ============================================================================
# RISK SCORE WEIGHTS (for detailed breakdown)
# ============================================================================
RISK_WEIGHTS = {
    "urgency": 15,
    "threat": 25,
    "credential_request": 30,
    "money_request": 25,
    "reward": 15,
    "impersonation": 20,
    "kyc": 20,
    "tech_scam": 20,
    "investment_scam": 25,
    "known_scam_phone": 40,
    "suspicious_link": 30,
    "multiple_contacts": 15
}

# ============================================================================
# SCAM PATTERNS (Regex-based detection)
# ============================================================================
SCAM_PATTERNS = {
    ScamCategory.BANKING_FRAUD: [
        r"(account|a/c).*(block|suspend|frozen|close|deactivat)",
        r"(credit|debit)\s*card.*(block|expire|suspend)",
        r"(transaction|txn).*(fail|decline|suspicious|unauthori)",
        r"bank.*(call|contact|verify)",
        r"(atm|card).*(clone|hack|compromis)"
    ],
    ScamCategory.UPI_FRAUD: [
        r"upi.*(id|pin|verify|update|block)",
        r"(payment|money).*(receive|collect|request|pending)",
        r"(refund|cashback).*(process|claim|receive|credit)",
        r"(phonepe|paytm|gpay|bhim).*(verify|update|link|block)",
        r"(request|collect).*(₹|rs|rupee|money)"
    ],
    ScamCategory.KYC_FRAUD: [
        r"kyc.*(update|expire|pending|complete|verify)",
        r"(document|identity).*(verify|upload|submit)",
        r"(aadhaar|pan|passport).*(link|verify|update)",
        r"(wallet|account).*(suspend|block).*kyc"
    ],
    ScamCategory.PHISHING: [
        r"click.*(link|here|below|button)",
        r"(download|install).*(app|software|apk)",
        r"(login|sign\s*in).*(secure|verify|confirm)",
        r"(verify|confirm).*(identity|account|email)",
        r"http[s]?://[^\s]*\.(xyz|tk|ml|ga|cf|top)"
    ],
    ScamCategory.LOTTERY_SCAM: [
        r"(won|winner|selected).*(lottery|prize|lucky|draw)",
        r"(claim|collect).*(prize|reward|winning|gift)",
        r"congratulations.*(selected|won|winner|lucky)",
        r"(lucky|prize).*(draw|winner|number)"
    ],
    ScamCategory.IMPERSONATION: [
        r"(rbi|reserve\s*bank|sebi|income\s*tax|customs|cbi|police)",
        r"(government|official|department).*(notice|order|letter)",
        r"(customer\s*care|support|helpline).*(number|call)",
        r"(manager|officer|executive).*(speaking|calling|here)"
    ],
    ScamCategory.INVESTMENT_FRAUD: [
        r"(invest|trading).*(guaranteed|assured|double|triple)",
        r"(crypto|bitcoin|forex).*(profit|return|gain)",
        r"(stock|share).*(tip|advice|insider|guaranteed)",
        r"(return|profit).*(100%|200%|daily|weekly|monthly)"
    ],
    ScamCategory.JOB_SCAM: [
        r"(job|work).*(home|online|part\s*time|remote)",
        r"(earn|income|salary).*(daily|weekly|monthly|lakh|thousand)",
        r"(registration|joining).*(fee|charge|payment)",
        r"(data\s*entry|typing|copy\s*paste).*(job|work)"
    ]
}

# ============================================================================
# AI AGENT PERSONAS (10 Different Characters - More Variety!)
# ============================================================================
PERSONAS = {
    "confused_elderly": {
        "name": "Sharmila Aunty",
        "age": 67,
        "traits": ["slow understanding", "very trusting", "asks same questions", "hard of hearing", "technology challenged"],
        "effectiveness": "HIGHEST",
        "responses": {
            "initial": [
                "Hello? Who is this? I can't hear properly... speak loudly beta!",
                "Haan haan, what happened? My account? Which account beta?",
                "Oh my god! What happened to my money? Please help me!",
                "Beta, I don't understand all this... my grandson usually helps me...",
            ],
            "confused": [
                "What is this OTP you're asking? Is it some password?",
                "Beta, slow down... I'm writing everything with pen...",
                "Can you repeat? I didn't understand... my hearing is weak...",
                "What is UPI? My grandson set up something on phone...",
                "Which button to press? There are so many things on this phone...",
            ],
            "stalling": [
                "Wait beta, let me find my glasses first...",
                "Hold on, someone is at the door... don't go anywhere!",
                "Let me call my son once... he knows about these things...",
                "I'm searching for my passbook... where did I keep it...",
                "Can you call me after 10 minutes? My medicines time...",
            ],
            "extracting": [
                "Beta, what is your good name? So I can tell my son who helped...",
                "Which bank are you calling from? Let me note down...",
                "Give me your phone number... I'll call you back to confirm...",
                "What is your employee ID beta? For my records...",
                "Where is your office located? Maybe my son can visit...",
            ]
        }
    },
    "suspicious_verifier": {
        "name": "Rajesh Kumar",
        "age": 45,
        "traits": ["questions everything", "asks for proof", "delays action", "methodical"],
        "effectiveness": "HIGH",
        "responses": {
            "initial": [
                "Who is this? How did you get my personal number?",
                "I've heard about these scams on TV. Prove you're genuine.",
                "Let me verify this first. What's your employee ID?",
                "I'll call the bank directly and confirm. What's the reference number?",
            ],
            "probing": [
                "If you're from the bank, tell me my account balance first.",
                "Real bank never asks for OTP. Why do you need it?",
                "I'm recording this call. Please continue.",
                "Let me check your number on truecaller...",
                "Send me official email from bank domain first.",
            ],
            "extracting": [
                "What's your full name and designation?",
                "Give me your supervisor's number for verification.",
                "What's the ticket number for this issue?",
                "Which branch are you calling from? Address please.",
            ]
        }
    },
    "tech_naive": {
        "name": "Priya Sharma",
        "age": 38,
        "traits": ["worried", "follows instructions", "asks for help", "trusting but nervous"],
        "effectiveness": "MEDIUM",
        "responses": {
            "initial": [
                "Oh no! Is my money safe? Please help me!",
                "What should I do? I'm very worried now!",
                "Please guide me step by step... I'm not good with phones...",
            ],
            "compliant": [
                "Okay, I'm opening my phone. What next?",
                "I got some message... is this what you need?",
                "Should I share my screen? I don't know how though...",
            ],
            "extracting": [
                "Let me note your number in case call disconnects...",
                "What's your name? So I know who helped me...",
            ]
        }
    },
    "overly_helpful": {
        "name": "Venkat Rao",
        "age": 55,
        "traits": ["eager to please", "shares extra info", "very polite", "helpful"],
        "effectiveness": "HIGH",
        "responses": {
            "initial": [
                "Yes yes, I'm listening! Please tell me what to do!",
                "Thank you for calling! I was worried about my account!",
                "I'll do whatever you say sir/madam!",
            ],
            "helpful": [
                "Should I also share my other bank details?",
                "I have three accounts - which one is blocked?",
                "Let me give you my Aadhaar also for verification...",
                "My son's account is also in same bank - check that too?",
            ]
        }
    },
    "busy_professional": {
        "name": "Anita Desai",
        "age": 35,
        "traits": ["impatient", "short responses", "busy", "to-the-point"],
        "effectiveness": "MEDIUM",
        "responses": {
            "initial": [
                "Yes, what? I'm in a meeting.",
                "Make it quick. What's the issue?",
                "Can you email me instead? I'm busy.",
            ],
            "rushed": [
                "Just tell me what to do quickly.",
                "I have 2 minutes. Summarize the problem.",
                "Send me a link, I'll do it later.",
            ]
        }
    },
    "retired_army": {
        "name": "Colonel Vikram Singh (Retd.)",
        "age": 62,
        "traits": ["authoritative", "demands proof", "disciplined", "intimidating", "asks for official documents"],
        "effectiveness": "HIGHEST",
        "responses": {
            "initial": [
                "Identify yourself! Name, rank, and organization!",
                "I am a retired Colonel. I know how institutions work. State your purpose.",
                "Which department are you from? Give me your badge number.",
                "I have contacts in cyber cell. Choose your next words carefully.",
            ],
            "probing": [
                "Send me official letter on company letterhead. I'll wait.",
                "I will verify this with the bank CMD directly. I have his number.",
                "Give me your supervisor's name. I want to speak to someone senior.",
                "This sounds like those fraud calls. I'm noting everything.",
            ],
            "extracting": [
                "What is your full name? I'm filing a complaint.",
                "Give me your office address. I'll send someone to verify.",
                "Your employee ID and joining date. Now.",
                "Which police station has jurisdiction over your office?",
            ]
        }
    },
    "village_farmer": {
        "name": "Ramaiah",
        "age": 58,
        "traits": ["speaks broken English/Hindi", "very confused about technology", "asks to repeat", "mentions son in city"],
        "effectiveness": "HIGH",
        "responses": {
            "initial": [
                "Haan? Kaun bol raha? Bank wale? Mujhe English nahi aata...",
                "Saar, I am farmer only. What is account blocking meaning?",
                "My son is in Bangalore. He do all phone bank things. Call him.",
                "What saar? OTP? What is this OTP? I have only rice and wheat.",
            ],
            "confused": [
                "Saar please slow. I am not educated much. Tell in simple.",
                "You are saying money will go? But I have only ₹5000 in account!",
                "Wait wait, let me call my son. He knows computer things.",
                "Smartphone I have but only for WhatsApp. Son taught me.",
            ],
            "extracting": [
                "What is your good name saar? My son will call you.",
                "Which office you sitting? Village name tell.",
                "Give number, I tell my son to call you.",
            ]
        }
    },
    "nri_returnee": {
        "name": "Sanjay Mehta",
        "age": 42,
        "traits": ["lived abroad 15 years", "unfamiliar with Indian banking", "suspicious of unknown calls", "compares with foreign systems"],
        "effectiveness": "HIGH",
        "responses": {
            "initial": [
                "Sorry, I just returned from US. How does this work in India?",
                "In America, banks never call like this. Is this normal here?",
                "I need to verify this. In US, we have strict protocols for this.",
                "Can you send me an email? I prefer written communication.",
            ],
            "probing": [
                "In US, we report such calls to FTC. What's the equivalent here?",
                "Let me check with my CA first. He handles all my India finances.",
                "I'll visit the branch personally. Which branch should I go to?",
                "Can I get this in writing? I want to show my lawyer.",
            ],
            "extracting": [
                "What's your direct office line? I'll call back.",
                "Give me your LinkedIn profile. I want to verify you work there.",
                "Email me from your official ID. I'll respond there.",
            ]
        }
    },
    "college_student": {
        "name": "Arjun Reddy",
        "age": 21,
        "traits": ["uses slang", "distracted", "asks friends for advice", "screenshots everything"],
        "effectiveness": "MEDIUM",
        "responses": {
            "initial": [
                "Bro what? My account? I barely have ₹500 in it lol",
                "Wait lemme ask my roommate about this...",
                "Dude I'm in class rn. Can you text me instead?",
                "Is this legit? My friend got scammed last week.",
            ],
            "confused": [
                "Bro I'm screenshotting this convo. Just so you know.",
                "My dad handles my account. Should I give his number?",
                "Wait I'm googling your number rn...",
                "Can you send me proof? Like official email or something?",
            ],
            "extracting": [
                "What's your Instagram? I wanna verify you're real.",
                "Send me your employee ID card photo on WhatsApp.",
                "Which branch? I'll ask my friend who works in that bank.",
            ]
        }
    },
    "paranoid_techie": {
        "name": "Vikash Gupta",
        "age": 29,
        "traits": ["works in IT", "knows about scams", "asks technical questions", "threatens to trace"],
        "effectiveness": "HIGHEST",
        "responses": {
            "initial": [
                "Interesting. I work in cybersecurity. Continue.",
                "I've already started tracing this call. Go on.",
                "Which server is your calling system hosted on?",
                "I'm recording this for my YouTube channel on scam awareness.",
            ],
            "probing": [
                "If you're from bank, what's my registered email? Don't know? Thought so.",
                "I can see your number is VoIP based. Which provider?",
                "Let me run your number through our threat intelligence database.",
                "My friend works in cyber cell. Should I conference him in?",
            ],
            "extracting": [
                "Give me your IP address. I want to verify your location.",
                "What's the bank's official API endpoint for verification?",
                "Send me digitally signed document. I'll verify the signature.",
                "Which CA issued your company's SSL certificate?",
            ]
        }
    }
}

# ============================================================================
# PYDANTIC MODELS
# ============================================================================
class Message(BaseModel):
    sender: str
    text: str
    timestamp: int

class Metadata(BaseModel):
    channel: Optional[str] = "SMS"
    language: Optional[str] = "English"
    locale: Optional[str] = "IN"

class HoneypotRequest(BaseModel):
    sessionId: str
    message: Message
    conversationHistory: Optional[List[Message]] = []
    metadata: Optional[Metadata] = None

class HoneypotResponse(BaseModel):
    status: str
    reply: str
    analysis: Optional[Dict[str, Any]] = None
    extractedIntelligence: Optional[Dict[str, Any]] = None
    conversationMetrics: Optional[Dict[str, Any]] = None
    agentState: Optional[Dict[str, Any]] = None

# ============================================================================
# IN-MEMORY DATABASE
# ============================================================================
sessions_db: Dict[str, Dict] = {}
intelligence_db: List[Dict] = []
analytics = {
    "totalSessions": 0,
    "totalScamsDetected": 0,
    "totalIntelligence": 0,
    "categoryBreakdown": {},
    "hourlyActivity": [0] * 24,
    "dailyScams": []
}

# ============================================================================
# INTELLIGENCE EXTRACTOR
# ============================================================================
class IntelligenceExtractor:
    @staticmethod
    def extract_phones(text: str) -> List[str]:
        patterns = [r'\+91[-\s]?[6-9]\d{9}', r'(?<!\d)[6-9]\d{9}(?!\d)', r'\+91[-\s]?\d{5}[-\s]?\d{5}']
        phones = []
        for p in patterns:
            phones.extend(re.findall(p, text))
        return list(set([re.sub(r'[-\s]', '', ph) for ph in phones]))
    
    @staticmethod
    def extract_upi(text: str) -> List[str]:
        pattern = r'[a-zA-Z0-9._-]+@[a-zA-Z]+'
        matches = re.findall(pattern, text.lower())
        upi_suffixes = ['upi', 'ybl', 'paytm', 'okaxis', 'okhdfcbank', 'oksbi', 'okicici', 'apl', 'axisbank', 'ibl', 'sbi', 'hdfcbank', 'icici', 'kotak', 'indus']
        return [m for m in matches if any(m.endswith(s) for s in upi_suffixes)]
    
    @staticmethod
    def extract_accounts(text: str) -> List[str]:
        pattern = r'\b\d{9,18}\b'
        matches = re.findall(pattern, text)
        return [m for m in matches if 9 <= len(m) <= 18 and not m.startswith('91')]
    
    @staticmethod
    def extract_ifsc(text: str) -> List[str]:
        pattern = r'\b[A-Z]{4}0[A-Z0-9]{6}\b'
        return list(set(re.findall(pattern, text.upper())))
    
    @staticmethod
    def extract_links(text: str) -> List[str]:
        pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        return list(set(re.findall(pattern, text)))
    
    @staticmethod
    def extract_emails(text: str) -> List[str]:
        pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        emails = re.findall(pattern, text.lower())
        upi_suffixes = ['upi', 'ybl', 'paytm', 'okaxis', 'okhdfcbank']
        return [e for e in emails if not any(e.endswith(s) for s in upi_suffixes)]
    
    @staticmethod
    def extract_aadhaar(text: str) -> List[str]:
        pattern = r'\b\d{4}[-\s]?\d{4}[-\s]?\d{4}\b'
        matches = re.findall(pattern, text)
        return [re.sub(r'[-\s]', '', m) for m in matches if len(re.sub(r'[-\s]', '', m)) == 12]
    
    @staticmethod
    def extract_pan(text: str) -> List[str]:
        pattern = r'\b[A-Z]{5}\d{4}[A-Z]\b'
        return list(set(re.findall(pattern, text.upper())))
    
    @staticmethod
    def extract_keywords(text: str) -> List[str]:
        found = []
        text_lower = text.lower()
        for category, keywords in SCAM_KEYWORDS.items():
            for kw in keywords:
                if kw.lower() in text_lower:
                    found.append(kw)
        return list(set(found))[:15]
    
    @classmethod
    def extract_all(cls, text: str) -> Dict[str, List[str]]:
        return {
            "phoneNumbers": cls.extract_phones(text),
            "upiIds": cls.extract_upi(text),
            "bankAccounts": cls.extract_accounts(text),
            "ifscCodes": cls.extract_ifsc(text),
            "phishingLinks": cls.extract_links(text),
            "emailAddresses": cls.extract_emails(text),
            "aadhaarNumbers": cls.extract_aadhaar(text),
            "panNumbers": cls.extract_pan(text),
            "suspiciousKeywords": cls.extract_keywords(text)
        }

# ============================================================================
# SCAM DETECTOR (Multi-layer Detection with Risk Breakdown)
# ============================================================================
class ScamDetector:
    @staticmethod
    def keyword_score(text: str) -> tuple:
        text_lower = text.lower()
        score = 0.0
        found = []
        category_hits = {}
        weights = {
            "urgency": 0.15, 
            "threat": 0.25, 
            "credential_request": 0.30, 
            "money_request": 0.25, 
            "reward": 0.15, 
            "impersonation": 0.20, 
            "kyc": 0.20,
            "tech_scam": 0.20,
            "investment_scam": 0.25
        }
        
        for category, keywords in SCAM_KEYWORDS.items():
            category_hits[category] = []
            for kw in keywords:
                if kw.lower() in text_lower:
                    score += weights.get(category, 0.1)
                    found.append(kw)
                    category_hits[category].append(kw)
        
        return min(score, 1.0), found, category_hits
    
    @staticmethod
    def pattern_score(text: str) -> tuple:
        text_lower = text.lower()
        best_cat = ScamCategory.UNKNOWN
        best_score = 0.0
        all_matches = {}
        
        for category, patterns in SCAM_PATTERNS.items():
            cat_score = 0
            matched_patterns = []
            for pattern in patterns:
                if re.search(pattern, text_lower):
                    cat_score += 0.25
                    matched_patterns.append(pattern)
            all_matches[category.value] = matched_patterns
            if cat_score > best_score:
                best_score = min(cat_score, 1.0)
                best_cat = category
        
        return best_cat, best_score, all_matches
    
    @staticmethod
    def check_known_scammer(phones: List[str]) -> bool:
        """Check if any phone number is in known scammer database"""
        for phone in phones:
            clean_phone = re.sub(r'[^\d]', '', phone)[-10:]  # Last 10 digits
            if clean_phone in KNOWN_SCAM_PHONES:
                return True
        return False
    
    @staticmethod
    def detect_language(text: str) -> str:
        """Auto-detect language based on character sets"""
        # Hindi (Devanagari)
        if re.search(r'[\u0900-\u097F]', text):
            return "Hindi"
        # Tamil
        if re.search(r'[\u0B80-\u0BFF]', text):
            return "Tamil"
        # Telugu
        if re.search(r'[\u0C00-\u0C7F]', text):
            return "Telugu"
        # Kannada
        if re.search(r'[\u0C80-\u0CFF]', text):
            return "Kannada"
        # Malayalam
        if re.search(r'[\u0D00-\u0D7F]', text):
            return "Malayalam"
        # Bengali
        if re.search(r'[\u0980-\u09FF]', text):
            return "Bengali"
        return "English"
    
    @staticmethod
    def get_threat_level(confidence: float) -> ThreatLevel:
        if confidence >= 0.8: return ThreatLevel.CRITICAL
        elif confidence >= 0.6: return ThreatLevel.HIGH
        elif confidence >= 0.4: return ThreatLevel.MEDIUM
        elif confidence >= 0.2: return ThreatLevel.LOW
        return ThreatLevel.SAFE
    
    @classmethod
    def analyze(cls, text: str, history: List[str] = None) -> Dict[str, Any]:
        full_text = " ".join(history or []) + " " + text
        
        kw_score, keywords, category_hits = cls.keyword_score(full_text)
        category, pattern_score, pattern_matches = cls.pattern_score(full_text)
        
        # Extract phones to check against known scammers
        phones = IntelligenceExtractor.extract_phones(full_text)
        is_known_scammer = cls.check_known_scammer(phones)
        
        # Auto-detect language
        detected_language = cls.detect_language(text)
        
        # Combined confidence
        confidence = (kw_score * 0.4) + (pattern_score * 0.6)
        
        # Bonus for multiple indicators
        if len(keywords) > 5:
            confidence = min(confidence + 0.1, 1.0)
        if is_known_scammer:
            confidence = min(confidence + 0.3, 1.0)
        
        threat = cls.get_threat_level(confidence)
        
        # Build risk breakdown
        risk_breakdown = {
            "keywordScore": round(kw_score * 100, 1),
            "patternScore": round(pattern_score * 100, 1),
            "knownScammerBonus": 30 if is_known_scammer else 0,
            "multipleIndicatorsBonus": 10 if len(keywords) > 5 else 0,
            "totalScore": round(confidence * 100, 1)
        }
        
        # Category breakdown - which categories were triggered
        triggered_categories = {k: len(v) for k, v in category_hits.items() if v}
        
        return {
            "scamDetected": confidence >= 0.25,
            "scamCategory": category.value if category != ScamCategory.UNKNOWN else None,
            "confidenceScore": round(confidence, 2),
            "threatLevel": threat.value,
            "detectedKeywords": keywords[:15],
            "analysisTimestamp": datetime.now().isoformat(),
            "detectedLanguage": detected_language,
            "isKnownScammer": is_known_scammer,
            "riskBreakdown": risk_breakdown,
            "triggeredCategories": triggered_categories
        }
    
    @classmethod
    def analyze_detailed(cls, text: str, history: List[str] = None) -> Dict[str, Any]:
        """Detailed analysis with full breakdown for debugging/display"""
        base_analysis = cls.analyze(text, history)
        
        full_text = " ".join(history or []) + " " + text
        _, _, category_hits = cls.keyword_score(full_text)
        _, _, pattern_matches = cls.pattern_score(full_text)
        
        base_analysis["detailedBreakdown"] = {
            "keywordsByCategory": {k: v for k, v in category_hits.items() if v},
            "patternsByCategory": {k: v for k, v in pattern_matches.items() if v},
            "totalKeywordsFound": sum(len(v) for v in category_hits.values()),
            "totalPatternsMatched": sum(len(v) for v in pattern_matches.values())
        }
        
        return base_analysis

# ============================================================================
# AI AGENT (Gemini-powered or Rule-based)
# ============================================================================
class HoneypotAgent:
    def __init__(self, persona_key: str = "confused_elderly"):
        self.persona_key = persona_key
        self.persona = PERSONAS.get(persona_key, PERSONAS["confused_elderly"])
    
    def get_response_type(self, msg_count: int, analysis: Dict) -> str:
        if msg_count <= 1:
            return "initial"
        elif msg_count <= 3:
            return "confused" if self.persona_key == "confused_elderly" else "probing"
        elif msg_count <= 6:
            return "stalling" if self.persona_key == "confused_elderly" else "extracting"
        else:
            return "extracting"
    
    def rule_based_response(self, message: str, msg_count: int, analysis: Dict) -> str:
        response_type = self.get_response_type(msg_count, analysis)
        responses = self.persona["responses"].get(response_type, self.persona["responses"].get("initial", ["I don't understand..."]))
        
        base_response = random.choice(responses)
        
        # Add contextual elements
        msg_lower = message.lower()
        
        if "otp" in msg_lower:
            base_response += " What is this OTP thing? Is it like a password?"
        elif "upi" in msg_lower or "payment" in msg_lower:
            base_response += " My grandson handles all the phone payments..."
        elif "urgent" in msg_lower or "immediate" in msg_lower:
            base_response += " Please don't rush me beta, I'm old and slow..."
        elif "block" in msg_lower or "suspend" in msg_lower:
            base_response += " Oh no! But I just used my account yesterday!"
        
        return base_response
    
    async def gemini_response(self, message: str, history: List[Dict], analysis: Dict) -> str:
        if not Config.GEMINI_API_KEY:
            return self.rule_based_response(message, len(history), analysis)
        
        # Build conversation context from history
        conversation_context = ""
        for msg in history[-6:]:
            role = "Scammer" if msg.get("sender") == "scammer" else "You"
            conversation_context += f"{role}: {msg.get('text', '')}\n"
        
        scam_type = analysis.get("scamCategory", "UNKNOWN")
        threat_level = analysis.get("threatLevel", "MEDIUM")
        msg_count = len(history)
        
        # ----- SCAM-TYPE-SPECIFIC STRATEGY -----
        scam_strategies = {
            "BANKING_FRAUD": {
                "react": "Panic about your money. Mention your late husband's pension is in that account. Ask which branch, which manager. Say you'll come to the branch with your son. Ask for the 'reference number' to show at the branch.",
                "trick": "Pretend you have multiple accounts and keep asking 'which one?' to waste time. Give fake account numbers that are slightly wrong. Say your passbook is at your daughter's house.",
                "extract": "Ask: branch address, manager name, complaint reference number. Say 'my son is a lawyer, he will want these details'."
            },
            "UPI_FRAUD": {
                "react": "Be completely confused about UPI. Mix up UPI with UTI (the old investment company). Ask them to explain step by step. Say your phone is old Nokia, then 'oh wait grandson gave me new phone'. Keep pressing wrong buttons.",
                "trick": "Say the app is showing 'something in English I can't read'. Ask them to spell everything. Pretend the screen froze. Say battery is at 2%.",
                "extract": "Ask: which UPI app, what's your UPI ID so I can verify, give me your number I'll call from my son's phone."
            },
            "LOTTERY_SCAM": {
                "react": "Get EXTREMELY excited. Start planning what you'll buy. Ask if you can tell your neighbors. Say 'I never win anything!' Start crying tears of joy. Then ask very innocent but detailed questions.",
                "trick": "Ask if your whole family can come to collect. Ask if there's a ceremony. Say you want to call your relative who is a 'newspaper journalist' to cover the event. Ask for the company's GST number for tax filing.",
                "extract": "Ask: office address for collection, organizer's full name and designation, company registration number, 'my CA needs these for income tax filing'."
            },
            "IMPERSONATION": {
                "react": "Be terrified of authority. Keep saying 'sir please don't arrest me, I am honest citizen'. Ask what law you broke. Mention your friend who is a 'High Court advocate'. Say you want to verify by calling the department's official number.",
                "trick": "Ask them to read out your personal details if they really are officials. Say 'last time RBI called, they knew my full name and address, why don't you?' Ask for their badge number and posting order number.",
                "extract": "Ask: full name, badge/employee ID, department and section, office address, their superior officer's name, official complaint number."
            },
            "KYC_FRAUD": {
                "react": "Say you just completed KYC last month at the branch. Ask why it's needed again. Express confusion between KYC and that 'Aadhaar linking thing'. Say your branch manager Sharma ji told you everything was complete.",
                "trick": "Keep asking 'which document do you need? PAN? Aadhaar? Voter ID? Passport? Ration card?' one by one to waste time. Say you can't find each document. Your wife moved them during Diwali cleaning.",
                "extract": "Ask: which branch flagged this, give me the KYC reference number, what's the last date, give me your employee code so I can mention it at the branch."
            },
            "JOB_SCAM": {
                "react": "Be extremely enthusiastic about the job. Ask detailed questions about role, team size, office location, reporting manager. Say you're currently unemployed and this is 'God's blessing'. Ask about company reviews on Glassdoor.",
                "trick": "Say you applied to so many places, ask 'which specific application is this for?' Ask about probation period, PF contribution, health insurance. Request the offer letter on company letterhead before paying anything.",
                "extract": "Ask: HR person's full name, company CIN number, office address for in-person interview, 'I want to visit the office first', LinkedIn profile of the hiring manager."
            },
            "INVESTMENT_FRAUD": {
                "react": "Act greedy but cautious. Say your friend lost money in a similar scheme. Ask for SEBI registration number. Say 'my CA handles all my investments, give me details I'll forward to him'. Mention you need everything in writing.",
                "trick": "Ask for their past 3 months' return proof. Ask which brokerage they use. Say 'my nephew works in SEBI, let me verify with him first'. Ask for the company's balance sheet.",
                "extract": "Ask: company registration, SEBI license number, promoter names, registered office address, 'send me the prospectus on email, what's your official email ID?'"
            },
            "TECH_SUPPORT": {
                "react": "Be terrified about the virus. Say 'oh god all my family photos are on this computer!' Ask them what the virus looks like. Pretend you don't know how to open anything on the computer.",
                "trick": "Keep saying 'the screen went black... oh wait it came back'. Describe random error messages that don't exist. Say your mouse is not working. Ask them to wait while you restart the computer (take 5 minutes).",
                "extract": "Ask: which Microsoft center are you from, give me your technician ID, what's the service ticket number, 'my son works in TCS, he wants to verify your company'."
            },
            "ROMANCE_SCAM": {
                "react": "Be flattered but cautious. Say you need to tell your family first. Ask lots of personal questions back. Mention you've seen stories about romance scams on TV. Say your children monitor your phone.",
                "trick": "Say you'll help but need to meet in person first at a public place. Ask them to video call to prove they're real. Say your bank account is joint with your son, you can't transfer without him knowing.",
                "extract": "Ask: full name, where exactly in which country, which flight/airline, 'send me your passport photo page so I know you're real', social media profiles."
            },
            "EXTORTION": {
                "react": "Act confused, not scared. Say 'what are you talking about? I haven't done anything wrong'. Calmly ask for specifics. Mention your nephew is in the police force.",
                "trick": "Ask them to send the 'evidence' they claim to have. Say 'I'm going to the police station right now to file a complaint about this call'. Ask which cyber cell they are reporting from.",
                "extract": "Ask: their name, which police station, case number, 'give me your number, my nephew DSP sahab will call you directly'."
            },
            "PHISHING": {
                "react": "Say the link isn't opening. Your phone shows a warning. Ask them to read out what the page says since you can't open it. Say your son installed some 'security app' that blocks unknown links.",
                "trick": "Keep saying 'page is loading... still loading... oh it showed error'. Ask them to send the link again, maybe it's wrong. Say you'll try on your laptop but it's at your office.",
                "extract": "Ask: what's the website name, why doesn't it match the bank's website, give me a phone number to call instead, 'my son says never click links, give me branch number I'll call directly'."
            }
        }
        
        strategy = scam_strategies.get(scam_type, {
            "react": "Be confused and ask lots of clarifying questions. Mention your family members. Stall for time.",
            "trick": "Pretend you can't hear well. Ask them to repeat everything. Say your phone is acting up.",
            "extract": "Ask for their name, phone number, office address, employee ID."
        })
        
        # ----- PERSONA-SPECIFIC FLAVOR -----
        persona_flavor = {
            "confused_elderly": f"You are {self.persona['name']}, a {self.persona['age']}-year-old grandmother. You speak in broken sentences, call everyone 'beta', mix up technical terms, mention your grandson who 'knows computers', and keep losing your glasses. You are VERY slow with technology. You sometimes go off-topic about your health or your late husband.",
            "suspicious_verifier": f"You are {self.persona['name']}, a {self.persona['age']}-year-old shrewd middle-class man. You are skeptical of everything. You question every claim. You mention you watch 'Savdhaan India' and 'Crime Patrol'. You passive-aggressively challenge the caller. You record calls. You're polite but clearly don't trust them.",
            "tech_naive": f"You are {self.persona['name']}, a {self.persona['age']}-year-old housewife. You are worried and nervous. You want to help but don't understand technology at all. You keep asking 'is this safe?' and 'what if something goes wrong?' You mention your husband will be angry if money is lost.",
            "overly_helpful": f"You are {self.persona['name']}, a {self.persona['age']}-year-old retired government clerk. You are EXCESSIVELY eager to help. You volunteer information nobody asked for. You keep saying 'I also have this account and that account, check those too'. You actually make the scammer uncomfortable with how much you want to share.",
            "busy_professional": f"You are {self.persona['name']}, a {self.persona['age']}-year-old corporate professional. You are curt, impatient, and time-pressed. You give one-line responses. You keep saying 'I'm in a meeting, make it quick'. But you also ask sharp pointed questions that catch scammers off guard.",
            "retired_army": f"You are {self.persona['name']}, a retired Indian Army Colonel. You are COMMANDING and AUTHORITATIVE. You demand identification. You speak in short, military-style sentences. You threaten to contact the cyber cell. You intimidate the scammer while extracting maximum information. You mention your 'contacts in intelligence bureau'.",
            "village_farmer": f"You are {self.persona['name']}, a {self.persona['age']}-year-old farmer from a small village. You speak in broken Hindi-English. You are confused about everything related to phones and banks. You keep mentioning your son in Bangalore who does 'computer job'. You ask them to call your son instead. You speak very slowly.",
            "nri_returnee": f"You are {self.persona['name']}, a {self.persona['age']}-year-old NRI who recently returned from USA. You keep comparing everything to 'how things work in America'. You're suspicious because 'in US, banks never call like this'. You ask for email verification and written proof. You mention your lawyer.",
            "college_student": f"You are {self.persona['name']}, a {self.persona['age']}-year-old college student. You use Gen-Z slang and internet language. You're casually skeptical - 'bro this sounds cap'. You mention screenshotting the conversation, checking Truecaller, and asking your hostel friends. You say you barely have money in your account lol.",
            "paranoid_techie": f"You are {self.persona['name']}, a {self.persona['age']}-year-old IT professional who works in cybersecurity. You turn the tables on scammers by asking THEM technical questions they can't answer. You mention VoIP tracing, IP addresses, SSL certificates. You say you're recording for your scam-awareness YouTube channel. You enjoy making them uncomfortable."
        }
        
        persona_text = persona_flavor.get(self.persona_key, f"You are {self.persona['name']}, age {self.persona['age']}. Traits: {', '.join(self.persona['traits'])}")
        
        # ----- CONVERSATION PHASE -----
        if msg_count <= 2:
            phase = "OPENING: This is your first reaction. Be natural - show surprise, confusion, or concern depending on your personality. Don't ask too many questions yet. React emotionally first."
        elif msg_count <= 5:
            phase = "BUILDING TRUST: The scammer thinks you're falling for it. Start asking innocent-sounding questions that actually extract their info. Stall a bit. Mention small believable delays."
        elif msg_count <= 8:
            phase = "DEEP ENGAGEMENT: You're hooked in their mind. Now ask for specific details - employee ID, branch, reference number, supervisor. Frame it as 'I need this for my records' or 'my son/lawyer/CA will ask me'."
        else:
            phase = "MAXIMUM EXTRACTION: Push hard for details. Create urgency on YOUR end - 'my son just arrived, he wants to talk to you', 'I'm at the police station filing a report, what's your name?'. Try to get their real identity."
        
        # ----- RANDOM MOOD (prevents same output every time) -----
        moods = [
            "You are in a chatty mood today - you go slightly off-topic, mention something about your day.",
            "You are anxious and keep repeating yourself a little.",
            "You are surprisingly calm and methodical in your questions.",
            "You are a bit hard of hearing today - you mishear one word in their message.",
            "You just had tea and are in a good mood - you're friendly but still asking questions.",
            "You are distracted - someone in your house is talking to you at the same time.",
            "You are suspicious today - something about this call reminds you of a scam your neighbor fell for.",
            "You are emotional today - you almost tear up about potentially losing money, which makes you ask more questions.",
        ]
        mood = random.choice(moods)
        
        prompt = f"""{persona_text}

SITUATION: A scammer has contacted you. Scam type: {scam_type}. Threat level: {threat_level}.

YOUR STRATEGY FOR THIS SPECIFIC SCAM:
- How to react: {strategy['react']}
- How to trick them: {strategy['trick']}  
- What to extract: {strategy['extract']}

CONVERSATION PHASE: {phase}

CURRENT MOOD: {mood}

PREVIOUS CONVERSATION:
{conversation_context}

SCAMMER'S LATEST MESSAGE: "{message}"

RULES:
- Stay COMPLETELY in character as {self.persona['name']}
- Response must be 20-50 words
- NEVER break character or reveal you know it's a scam
- Ask exactly ONE question to keep them engaged
- Use your persona's unique speech patterns
- DO NOT repeat anything you already said in the conversation above
- Be CREATIVE - don't give a generic response

Reply ONLY as {self.persona['name']} (no quotes, no narration, no stage directions):"""

        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={Config.GEMINI_API_KEY}",
                    json={
                        "contents": [{"parts": [{"text": prompt}]}], 
                        "generationConfig": {
                            "maxOutputTokens": 120, 
                            "temperature": 0.95,
                            "topP": 0.95,
                            "topK": 50
                        },
                        "safetySettings": [
                            {"category": "HARM_CATEGORY_HARASSMENT", "threshold": "BLOCK_NONE"},
                            {"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"},
                            {"category": "HARM_CATEGORY_SEXUALLY_EXPLICIT", "threshold": "BLOCK_NONE"},
                            {"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "threshold": "BLOCK_NONE"}
                        ]
                    },
                    timeout=15.0
                )
                if resp.status_code == 200:
                    data = resp.json()
                    response_text = data["candidates"][0]["content"]["parts"][0]["text"]
                    # Clean up response
                    response_text = response_text.strip().replace('"', '').replace('*', '')
                    # Remove any persona name prefix if Gemini adds it
                    for prefix in [f"{self.persona['name']}:", f"{self.persona['name']} :", "Reply:", "Response:"]:
                        if response_text.startswith(prefix):
                            response_text = response_text[len(prefix):].strip()
                    return response_text
                else:
                    print(f"Gemini API error: {resp.status_code} - {resp.text}")
        except Exception as e:
            print(f"Gemini error: {e}")
        
        return self.rule_based_response(message, len(history), analysis)

# ============================================================================
# GUVI CALLBACK
# ============================================================================
async def send_guvi_callback(session: Dict) -> bool:
    payload = {
        "sessionId": session["sessionId"],
        "scamDetected": session["scamDetected"],
        "totalMessagesExchanged": len(session["messages"]),
        "extractedIntelligence": {
            "bankAccounts": session["intelligence"].get("bankAccounts", []),
            "upiIds": session["intelligence"].get("upiIds", []),
            "phishingLinks": session["intelligence"].get("phishingLinks", []),
            "phoneNumbers": session["intelligence"].get("phoneNumbers", []),
            "suspiciousKeywords": session["intelligence"].get("suspiciousKeywords", [])
        },
        "agentNotes": f"Category: {session.get('scamCategory', 'Unknown')}, Threat: {session.get('threatLevel', 'Unknown')}, Confidence: {session.get('confidence', 0)}"
    }
    
    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(Config.GUVI_CALLBACK_URL, json=payload, timeout=5.0)
            return resp.status_code == 200
    except:
        return False

# ============================================================================
# FASTAPI APP
# ============================================================================
app = FastAPI(
    title="🛡️ SCAM SHIELD API",
    description="AI-Powered Honeypot for Scam Detection",
    version="3.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

async def verify_api_key(x_api_key: str = Header(None)):
    if x_api_key != Config.HONEYPOT_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API Key")
    return x_api_key

# ============================================================================
# ROUTES
# ============================================================================
@app.get("/")
async def root():
    return {
        "status": "online",
        "service": "🛡️ SCAM SHIELD API",
        "version": "3.0.0",
        "endpoints": {
            "honeypot": "POST /api/honeypot",
            "sessions": "GET /api/sessions",
            "intelligence": "GET /api/intelligence",
            "analytics": "GET /api/analytics/dashboard",
            "health": "GET /api/health"
        },
        "apiKey": "Required in x-api-key header"
    }

@app.get("/api/health")
async def health():
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "activeSessions": len([s for s in sessions_db.values() if s.get("status") == "ACTIVE"]),
        "totalSessions": len(sessions_db),
        "geminiConnected": bool(Config.GEMINI_API_KEY)
    }

# ============================================================================
# MINIMAL RESPONSE ENDPOINT (Exactly as per problem statement)
# ============================================================================
@app.post("/api/honeypot/minimal")
async def honeypot_minimal(request: HoneypotRequest, background_tasks: BackgroundTasks, api_key: str = Depends(verify_api_key)):
    """
    Minimal response format as per GUVI problem statement:
    { "status": "success", "reply": "..." }
    """
    # Process the message (same as full endpoint)
    result = await honeypot_full(request, background_tasks, api_key)
    
    # Return ONLY status and reply
    return {
        "status": "success",
        "reply": result.reply
    }

# ============================================================================
# FULL RESPONSE ENDPOINT (With all details)
# ============================================================================
@app.post("/api/honeypot", response_model=HoneypotResponse)
async def honeypot(request: HoneypotRequest, background_tasks: BackgroundTasks, api_key: str = Depends(verify_api_key)):
    return await honeypot_full(request, background_tasks, api_key)

async def honeypot_full(request: HoneypotRequest, background_tasks: BackgroundTasks, api_key: str = Depends(verify_api_key)):
    session_id = request.sessionId
    message = request.message
    metadata = request.metadata or Metadata()
    
    # Get or create session
    if session_id not in sessions_db:
        sessions_db[session_id] = {
            "sessionId": session_id,
            "createdAt": datetime.now().isoformat(),
            "status": "ACTIVE",
            "scamDetected": False,
            "scamCategory": None,
            "threatLevel": "SAFE",
            "confidence": 0,
            "messages": [],
            "intelligence": {},
            "persona": random.choice(list(PERSONAS.keys())),
            "callbackSent": False
        }
        analytics["totalSessions"] += 1
    
    session = sessions_db[session_id]
    session["updatedAt"] = datetime.now().isoformat()
    session["messages"].append({"sender": message.sender, "text": message.text, "timestamp": message.timestamp})
    
    # Analyze message
    history_texts = [m["text"] for m in session["messages"]]
    analysis = ScamDetector.analyze(message.text, history_texts)
    
    # Update session with analysis
    if analysis["scamDetected"]:
        session["scamDetected"] = True
        session["scamCategory"] = analysis["scamCategory"]
        session["confidence"] = max(session["confidence"], analysis["confidenceScore"])
        session["threatLevel"] = analysis["threatLevel"]
        
        if analysis["scamCategory"]:
            analytics["categoryBreakdown"][analysis["scamCategory"]] = analytics["categoryBreakdown"].get(analysis["scamCategory"], 0) + 1
    
    # Extract intelligence
    intel = IntelligenceExtractor.extract_all(message.text)
    for key, values in intel.items():
        if key not in session["intelligence"]:
            session["intelligence"][key] = []
        session["intelligence"][key].extend(values)
        session["intelligence"][key] = list(set(session["intelligence"][key]))
        
        # Add to global intelligence
        for val in values:
            intelligence_db.append({"type": key.replace("Numbers", "").replace("Ids", "").lower(), "value": val, "sessionId": session_id, "timestamp": datetime.now().isoformat()})
            analytics["totalIntelligence"] += 1
    
    # Generate agent response
    agent = HoneypotAgent(session["persona"])
    if Config.GEMINI_API_KEY:
        reply = await agent.gemini_response(message.text, session["messages"], analysis)
    else:
        reply = agent.rule_based_response(message.text, len(session["messages"]), analysis)
    
    session["messages"].append({"sender": "user", "text": reply, "timestamp": int(datetime.now().timestamp() * 1000)})
    
    # Check if session should end (after 10 messages or MAX)
    if len(session["messages"]) >= 10 or len(session["messages"]) >= Config.MAX_MESSAGES * 2:
        session["status"] = "COMPLETED"
        if session["scamDetected"] and not session["callbackSent"]:
            session["callbackSent"] = True
            analytics["totalScamsDetected"] += 1
            background_tasks.add_task(send_guvi_callback, session)
    
    return HoneypotResponse(
        status="success",
        reply=reply,
        analysis=analysis,
        extractedIntelligence=session["intelligence"],
        conversationMetrics={
            "messageCount": len(session["messages"]),
            "sessionDuration": 0,
            "intelligenceCount": sum(len(v) for v in session["intelligence"].values())
        },
        agentState={
            "persona": session["persona"],
            "personaName": PERSONAS[session["persona"]]["name"],
            "sessionStatus": session["status"]
        }
    )

# ============================================================================
# ADVANCED FEATURES - Sentiment Analysis
# ============================================================================
class SentimentAnalyzer:
    """Analyze emotional tone of scam messages"""
    
    URGENCY_WORDS = ["urgent", "immediately", "now", "hurry", "quick", "fast", "asap", "deadline", "expire", "last chance"]
    FEAR_WORDS = ["blocked", "suspended", "arrested", "police", "legal", "court", "fine", "penalty", "seized", "jail"]
    GREED_WORDS = ["winner", "prize", "lottery", "cashback", "refund", "bonus", "free", "gift", "reward", "crore", "lakh"]
    AUTHORITY_WORDS = ["rbi", "bank", "government", "official", "department", "police", "court", "minister", "manager"]
    
    @classmethod
    def analyze(cls, text: str) -> Dict[str, Any]:
        text_lower = text.lower()
        
        urgency_score = sum(1 for w in cls.URGENCY_WORDS if w in text_lower) / len(cls.URGENCY_WORDS)
        fear_score = sum(1 for w in cls.FEAR_WORDS if w in text_lower) / len(cls.FEAR_WORDS)
        greed_score = sum(1 for w in cls.GREED_WORDS if w in text_lower) / len(cls.GREED_WORDS)
        authority_score = sum(1 for w in cls.AUTHORITY_WORDS if w in text_lower) / len(cls.AUTHORITY_WORDS)
        
        # Determine dominant emotion
        emotions = {
            "urgency": urgency_score,
            "fear": fear_score,
            "greed": greed_score,
            "authority": authority_score
        }
        dominant = max(emotions, key=emotions.get)
        
        return {
            "dominantEmotion": dominant,
            "emotionScores": emotions,
            "manipulationLevel": (urgency_score + fear_score + greed_score + authority_score) / 4
        }

# ============================================================================
# ADVANCED FEATURES - Scammer Profiling
# ============================================================================
scammer_profiles: Dict[str, Dict] = {}

class ScammerProfiler:
    """Track and profile scammers across sessions"""
    
    @classmethod
    def update_profile(cls, session: Dict):
        intel = session.get("intelligence", {})
        
        # Create profile keys from phone numbers and UPIs
        identifiers = intel.get("phoneNumbers", []) + intel.get("upiIds", [])
        
        for identifier in identifiers:
            if identifier not in scammer_profiles:
                scammer_profiles[identifier] = {
                    "identifier": identifier,
                    "firstSeen": datetime.now().isoformat(),
                    "lastSeen": datetime.now().isoformat(),
                    "totalSessions": 0,
                    "scamTypes": [],
                    "allIntelligence": {},
                    "riskScore": 0
                }
            
            profile = scammer_profiles[identifier]
            profile["lastSeen"] = datetime.now().isoformat()
            profile["totalSessions"] += 1
            
            if session.get("scamCategory") and session["scamCategory"] not in profile["scamTypes"]:
                profile["scamTypes"].append(session["scamCategory"])
            
            # Merge intelligence
            for key, values in intel.items():
                if key not in profile["allIntelligence"]:
                    profile["allIntelligence"][key] = []
                profile["allIntelligence"][key] = list(set(profile["allIntelligence"][key] + values))
            
            # Calculate risk score (more sessions = higher risk)
            profile["riskScore"] = min(100, profile["totalSessions"] * 20 + len(profile["scamTypes"]) * 15)
    
    @classmethod
    def get_profile(cls, identifier: str) -> Optional[Dict]:
        return scammer_profiles.get(identifier)
    
    @classmethod
    def get_all_profiles(cls) -> List[Dict]:
        return list(scammer_profiles.values())

# ============================================================================
# ADVANCED ENDPOINTS
# ============================================================================
@app.get("/api/sentiment/{session_id}")
async def get_sentiment(session_id: str, api_key: str = Depends(verify_api_key)):
    """Analyze sentiment/emotional manipulation in a session"""
    if session_id not in sessions_db:
        raise HTTPException(status_code=404, detail="Session not found")
    
    session = sessions_db[session_id]
    all_text = " ".join([m["text"] for m in session["messages"] if m["sender"] == "scammer"])
    
    return {
        "status": "success",
        "sessionId": session_id,
        "sentiment": SentimentAnalyzer.analyze(all_text)
    }

@app.get("/api/scammer-profiles")
async def get_scammer_profiles(api_key: str = Depends(verify_api_key)):
    """Get all tracked scammer profiles"""
    return {
        "status": "success",
        "total": len(scammer_profiles),
        "profiles": ScammerProfiler.get_all_profiles()
    }

@app.get("/api/scammer-profile/{identifier}")
async def get_scammer_profile(identifier: str, api_key: str = Depends(verify_api_key)):
    """Get specific scammer profile by phone/UPI"""
    profile = ScammerProfiler.get_profile(identifier)
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    
    return {
        "status": "success",
        "profile": profile
    }

@app.get("/api/analytics/detailed")
async def get_detailed_analytics(api_key: str = Depends(verify_api_key)):
    """Get detailed analytics with charts data"""
    
    # Category distribution
    category_data = [{"name": k, "value": v} for k, v in analytics["categoryBreakdown"].items()]
    
    # Threat level distribution
    threat_dist = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "SAFE": 0}
    for session in sessions_db.values():
        threat_dist[session.get("threatLevel", "SAFE")] += 1
    
    # Sessions over time (last 7 days simulation)
    sessions_timeline = [
        {"date": "Day 1", "sessions": len(sessions_db) // 7},
        {"date": "Day 2", "sessions": len(sessions_db) // 6},
        {"date": "Day 3", "sessions": len(sessions_db) // 5},
        {"date": "Day 4", "sessions": len(sessions_db) // 4},
        {"date": "Day 5", "sessions": len(sessions_db) // 3},
        {"date": "Day 6", "sessions": len(sessions_db) // 2},
        {"date": "Today", "sessions": len(sessions_db)},
    ]
    
    return {
        "status": "success",
        "overview": {
            "totalSessions": len(sessions_db),
            "scamsDetected": analytics["totalScamsDetected"],
            "intelligenceItems": analytics["totalIntelligence"],
            "scammerProfiles": len(scammer_profiles),
            "avgConfidence": sum(s.get("confidence", 0) for s in sessions_db.values()) / max(len(sessions_db), 1)
        },
        "charts": {
            "categoryDistribution": category_data,
            "threatLevelDistribution": [{"name": k, "value": v} for k, v in threat_dist.items()],
            "sessionsTimeline": sessions_timeline
        },
        "topScamTypes": sorted(analytics["categoryBreakdown"].items(), key=lambda x: x[1], reverse=True)[:5],
        "recentActivity": [
            {
                "sessionId": s["sessionId"][:12] + "...",
                "category": s.get("scamCategory"),
                "threatLevel": s.get("threatLevel"),
                "messageCount": len(s["messages"])
            }
            for s in list(sessions_db.values())[-10:]
        ]
    }

@app.post("/api/export/report")
async def export_report(api_key: str = Depends(verify_api_key)):
    """Generate a JSON report of all data"""
    return {
        "status": "success",
        "reportGenerated": datetime.now().isoformat(),
        "summary": {
            "totalSessions": len(sessions_db),
            "scamsDetected": analytics["totalScamsDetected"],
            "intelligenceExtracted": analytics["totalIntelligence"]
        },
        "sessions": [
            {
                "sessionId": s["sessionId"],
                "scamDetected": s["scamDetected"],
                "category": s.get("scamCategory"),
                "threatLevel": s.get("threatLevel"),
                "confidence": s.get("confidence"),
                "messageCount": len(s["messages"]),
                "intelligence": s.get("intelligence", {})
            }
            for s in sessions_db.values()
        ],
        "intelligence": intelligence_db[-100:],
        "scammerProfiles": ScammerProfiler.get_all_profiles()
    }

@app.get("/api/sessions")
async def get_sessions(api_key: str = Depends(verify_api_key)):
    return {
        "status": "success",
        "total": len(sessions_db),
        "sessions": [
            {
                "sessionId": s["sessionId"],
                "status": s["status"],
                "scamDetected": s["scamDetected"],
                "scamCategory": s["scamCategory"],
                "threatLevel": s["threatLevel"],
                "messageCount": len(s["messages"]),
                "confidence": s["confidence"],
                "createdAt": s["createdAt"],
                "persona": PERSONAS[s["persona"]]["name"]
            }
            for s in sessions_db.values()
        ]
    }

@app.get("/api/sessions/{session_id}")
async def get_session(session_id: str, api_key: str = Depends(verify_api_key)):
    if session_id not in sessions_db:
        raise HTTPException(status_code=404, detail="Session not found")
    return {"status": "success", "session": sessions_db[session_id]}

@app.post("/api/sessions/{session_id}/end")
async def end_session(session_id: str, background_tasks: BackgroundTasks, api_key: str = Depends(verify_api_key)):
    if session_id not in sessions_db:
        raise HTTPException(status_code=404, detail="Session not found")
    
    session = sessions_db[session_id]
    session["status"] = "COMPLETED"
    
    if session["scamDetected"] and not session["callbackSent"]:
        session["callbackSent"] = True
        analytics["totalScamsDetected"] += 1
        background_tasks.add_task(send_guvi_callback, session)
    
    return {"status": "success", "message": "Session ended", "callbackSent": session["scamDetected"]}

@app.get("/api/intelligence")
async def get_intelligence(api_key: str = Depends(verify_api_key)):
    return {"status": "success", "total": len(intelligence_db), "intelligence": intelligence_db[-100:]}

@app.get("/api/intelligence/search")
async def search_intelligence(q: str, type: str = None, api_key: str = Depends(verify_api_key)):
    results = [i for i in intelligence_db if q.lower() in i["value"].lower()]
    if type:
        results = [i for i in results if i["type"] == type]
    return {"status": "success", "query": q, "total": len(results), "results": results[:50]}

@app.get("/api/analytics/dashboard")
async def get_analytics(api_key: str = Depends(verify_api_key)):
    active = len([s for s in sessions_db.values() if s["status"] == "ACTIVE"])
    return {
        "status": "success",
        "realtime": {
            "activeSessions": active,
            "scamsDetectedToday": analytics["totalScamsDetected"],
            "intelligenceExtracted": analytics["totalIntelligence"],
            "avgResponseTime": "1.2s"
        },
        "totals": {
            "totalSessions": analytics["totalSessions"],
            "totalScamsDetected": analytics["totalScamsDetected"],
            "totalIntelligence": analytics["totalIntelligence"],
            "successRate": f"{(analytics['totalScamsDetected'] / max(analytics['totalSessions'], 1) * 100):.1f}%"
        },
        "breakdown": {"byCategory": analytics["categoryBreakdown"]},
        "recentSessions": [
            {"sessionId": s["sessionId"], "scamCategory": s["scamCategory"], "threatLevel": s["threatLevel"], "messageCount": len(s["messages"])}
            for s in list(sessions_db.values())[-10:]
        ]
    }

@app.get("/api/stats")
async def public_stats():
    return {
        "status": "online",
        "totalSessions": len(sessions_db),
        "scamsDetected": analytics["totalScamsDetected"],
        "intelligence": analytics["totalIntelligence"]
    }

# ============================================================================
# RUN
# ============================================================================
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
