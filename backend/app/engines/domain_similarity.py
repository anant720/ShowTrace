import logging
import unicodedata
from Levenshtein import distance as levenshtein_distance
from motor.motor_asyncio import AsyncIOMotorDatabase
from app.engines.base import EngineResult
from app.models.schemas import AnalyzeRequest

logger = logging.getLogger("shadowtrace.engines.domain_similarity")

DEFAULT_TRUSTED_DOMAINS = [
    "google.com", "gmail.com", "microsoft.com", "outlook.com", "apple.com",
    "icloud.com", "yahoo.com", "hotmail.com", "live.com", "github.com",
    "adobe.com", "dropbox.com", "zoho.com", "facebook.com", "instagram.com",
    "twitter.com", "linkedin.com", "reddit.com", "tiktok.com", "snapchat.com",
    "discord.com", "whatsapp.com", "paypal.com", "chase.com", "bankofamerica.com",
    "wellsfargo.com", "citibank.com", "capitalone.com", "americanexpress.com",
    "venmo.com", "stripe.com", "coinbase.com", "robinhood.com", "fidelity.com",
    "sbi.co.in", "hdfcbank.com", "icicibank.com", "axisbank.com", "kotak.com",
    "paytm.com", "phonepe.com", "razorpay.com", "amazon.com", "ebay.com",
    "walmart.com", "flipkart.com", "shopify.com", "etsy.com", "aliexpress.com",
    "bestbuy.com", "myntra.com", "netflix.com", "youtube.com", "spotify.com",
    "disneyplus.com", "primevideo.com", "hotstar.com", "steam.com", "epicgames.com",
    "slack.com", "zoom.us", "notion.so", "figma.com", "canva.com", "gov.in",
    "irs.gov", "ssa.gov", "login.gov", "uidai.gov.in", "booking.com", "airbnb.com",
    "uber.com", "zomato.com", "swiggy.com", "bbc.com", "cnn.com", "nytimes.com",
    "cloudflare.com", "norton.com", "mcafee.com", "jio.com", "airtel.in",
    "verizon.com", "att.com",
]

CONFUSABLE_MAP = {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c',
    'у': 'y', 'х': 'x', 'ѕ': 's', 'і': 'i', 'ј': 'j',
    'ɡ': 'g', 'ɩ': 'l', 'ω': 'w', 'ν': 'v', 'τ': 't',
    '0': 'o', '1': 'l', '3': 'e', '5': 's', '8': 'b',
}

def normalize_domain(domain: str) -> str:
    normalized = unicodedata.normalize("NFKC", domain.lower())
    return "".join(CONFUSABLE_MAP.get(c, c) for c in normalized)

def strip_subdomain(hostname: str) -> str:
    parts = hostname.split(".")
    if len(parts) > 2:
        if parts[-2] in ("co", "com", "org", "net", "gov", "ac", "edu"):
            return ".".join(parts[-3:])
        return ".".join(parts[-2:])
    return hostname

async def analyze(request: AnalyzeRequest, db: AsyncIOMotorDatabase) -> EngineResult:
    hostname = request.domain.hostname
    score = 0.0
    reasons = []
    trusted = []
    try:
        cursor = db.trusted_domains.find({}, {"domain": 1})
        async for doc in cursor: trusted.append(doc["domain"])
    except: pass
    if not trusted: trusted = DEFAULT_TRUSTED_DOMAINS

    base_domain = strip_subdomain(hostname)
    normalized = normalize_domain(base_domain)

    if request.domain.isPunycode or "xn--" in hostname:
        score += 10.0
        reasons.append("Domain uses Punycode encoding")

    min_dist = float("inf")
    match = ""
    for td in trusted:
        d = levenshtein_distance(normalized, td)
        if d < min_dist: min_dist = d; match = td

    if 1 <= min_dist <= 2:
        score += 15.0
        reasons.append(f"Domain is {min_dist} edit(s) from '{match}'")
    elif min_dist == 3:
        score += 8.0
        reasons.append(f"Similar to '{match}'")

    if normalized != base_domain and not request.domain.isPunycode:
        score += 5.0
        reasons.append("Contains confusable Unicode characters")

    for td in trusted:
        td_base = td.split(".")[0]
        if len(td_base) >= 4 and td_base in base_domain and base_domain != td:
            score += 5.0
            reasons.append(f"Contains brand name '{td_base}'")
            break

    return EngineResult(engine_name="domain_similarity", score=min(score, 30.0), max_score=30.0, reasons=reasons)
