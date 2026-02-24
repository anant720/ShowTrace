import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.database import connect_db, close_db, get_db
from app.middleware.auth import OAuthMiddleware
from app.middleware.rate_limit import RateLimitMiddleware
from app.routers import analyze, report, stats
from app.utils.logging import setup_logging

logger = logging.getLogger("shadowtrace.main")

DEFAULT_TRUSTED = [
    {"domain": "google.com", "category": "tech"},

    {"domain": "microsoft.com", "category": "tech"},
    {"domain": "apple.com", "category": "tech"},
    {"domain": "amazon.com", "category": "ecommerce"},
    {"domain": "meta.com", "category": "tech"},
    {"domain": "github.com", "category": "tech"},
    {"domain": "gitlab.com", "category": "tech"},
    {"domain": "stackoverflow.com", "category": "tech"},
    {"domain": "mozilla.org", "category": "tech"},
    {"domain": "oracle.com", "category": "tech"},
    {"domain": "ibm.com", "category": "tech"},
    {"domain": "salesforce.com", "category": "tech"},
    {"domain": "adobe.com", "category": "tech"},
    {"domain": "nvidia.com", "category": "tech"},
    {"domain": "intel.com", "category": "tech"},

    # ── Email Providers ──────────────────────────────────────────
    {"domain": "gmail.com", "category": "email"},
    {"domain": "outlook.com", "category": "email"},
    {"domain": "yahoo.com", "category": "email"},
    {"domain": "live.com", "category": "email"},
    {"domain": "hotmail.com", "category": "email"},
    {"domain": "protonmail.com", "category": "email"},
    {"domain": "zoho.com", "category": "email"},
    {"domain": "icloud.com", "category": "email"},
    {"domain": "aol.com", "category": "email"},
    {"domain": "mail.com", "category": "email"},
    {"domain": "yandex.com", "category": "email"},

    # ── Social Media ─────────────────────────────────────────────
    {"domain": "facebook.com", "category": "social"},
    {"domain": "instagram.com", "category": "social"},
    {"domain": "twitter.com", "category": "social"},
    {"domain": "x.com", "category": "social"},
    {"domain": "linkedin.com", "category": "social"},
    {"domain": "reddit.com", "category": "social"},
    {"domain": "tiktok.com", "category": "social"},
    {"domain": "snapchat.com", "category": "social"},
    {"domain": "pinterest.com", "category": "social"},
    {"domain": "tumblr.com", "category": "social"},
    {"domain": "discord.com", "category": "social"},
    {"domain": "telegram.org", "category": "social"},
    {"domain": "whatsapp.com", "category": "social"},
    {"domain": "signal.org", "category": "social"},
    {"domain": "twitch.tv", "category": "social"},
    {"domain": "quora.com", "category": "social"},
    {"domain": "threads.net", "category": "social"},

    # ── Banking & Finance ────────────────────────────────────────
    {"domain": "paypal.com", "category": "finance"},
    {"domain": "chase.com", "category": "banking"},
    {"domain": "bankofamerica.com", "category": "banking"},
    {"domain": "wellsfargo.com", "category": "banking"},
    {"domain": "citibank.com", "category": "banking"},
    {"domain": "capitalone.com", "category": "banking"},
    {"domain": "usbank.com", "category": "banking"},
    {"domain": "td.com", "category": "banking"},
    {"domain": "hsbc.com", "category": "banking"},
    {"domain": "barclays.co.uk", "category": "banking"},
    {"domain": "goldmansachs.com", "category": "banking"},
    {"domain": "morganstanley.com", "category": "banking"},
    {"domain": "americanexpress.com", "category": "finance"},
    {"domain": "discover.com", "category": "finance"},
    {"domain": "visa.com", "category": "finance"},
    {"domain": "mastercard.com", "category": "finance"},
    {"domain": "stripe.com", "category": "finance"},
    {"domain": "venmo.com", "category": "finance"},
    {"domain": "cashapp.com", "category": "finance"},
    {"domain": "robinhood.com", "category": "finance"},
    {"domain": "coinbase.com", "category": "finance"},
    {"domain": "binance.com", "category": "finance"},
    {"domain": "fidelity.com", "category": "finance"},
    {"domain": "schwab.com", "category": "finance"},
    {"domain": "etrade.com", "category": "finance"},
    {"domain": "sbi.co.in", "category": "banking"},
    {"domain": "hdfcbank.com", "category": "banking"},
    {"domain": "icicibank.com", "category": "banking"},
    {"domain": "axisbank.com", "category": "banking"},
    {"domain": "kotak.com", "category": "banking"},
    {"domain": "pnbindia.in", "category": "banking"},
    {"domain": "bobfinancial.com", "category": "banking"},
    {"domain": "yesbank.in", "category": "banking"},
    {"domain": "paytm.com", "category": "finance"},
    {"domain": "phonepe.com", "category": "finance"},
    {"domain": "razorpay.com", "category": "finance"},

    # ── E-Commerce ───────────────────────────────────────────────
    {"domain": "ebay.com", "category": "ecommerce"},
    {"domain": "walmart.com", "category": "ecommerce"},
    {"domain": "target.com", "category": "ecommerce"},
    {"domain": "bestbuy.com", "category": "ecommerce"},
    {"domain": "etsy.com", "category": "ecommerce"},
    {"domain": "shopify.com", "category": "ecommerce"},
    {"domain": "aliexpress.com", "category": "ecommerce"},
    {"domain": "alibaba.com", "category": "ecommerce"},
    {"domain": "flipkart.com", "category": "ecommerce"},
    {"domain": "myntra.com", "category": "ecommerce"},
    {"domain": "ajio.com", "category": "ecommerce"},
    {"domain": "snapdeal.com", "category": "ecommerce"},
    {"domain": "meesho.com", "category": "ecommerce"},
    {"domain": "costco.com", "category": "ecommerce"},
    {"domain": "homedepot.com", "category": "ecommerce"},
    {"domain": "ikea.com", "category": "ecommerce"},
    {"domain": "wayfair.com", "category": "ecommerce"},
    {"domain": "newegg.com", "category": "ecommerce"},

    # ── Cloud / Productivity ─────────────────────────────────────
    {"domain": "dropbox.com", "category": "cloud"},
    {"domain": "notion.so", "category": "productivity"},
    {"domain": "slack.com", "category": "productivity"},
    {"domain": "zoom.us", "category": "productivity"},
    {"domain": "teams.microsoft.com", "category": "productivity"},
    {"domain": "trello.com", "category": "productivity"},
    {"domain": "asana.com", "category": "productivity"},
    {"domain": "atlassian.com", "category": "productivity"},
    {"domain": "jira.com", "category": "productivity"},
    {"domain": "figma.com", "category": "productivity"},
    {"domain": "canva.com", "category": "productivity"},
    {"domain": "docs.google.com", "category": "productivity"},
    {"domain": "drive.google.com", "category": "cloud"},
    {"domain": "onedrive.live.com", "category": "cloud"},
    {"domain": "box.com", "category": "cloud"},
    {"domain": "evernote.com", "category": "productivity"},

    # ── Entertainment & Streaming ────────────────────────────────
    {"domain": "netflix.com", "category": "entertainment"},
    {"domain": "youtube.com", "category": "entertainment"},
    {"domain": "spotify.com", "category": "entertainment"},
    {"domain": "disneyplus.com", "category": "entertainment"},
    {"domain": "hulu.com", "category": "entertainment"},
    {"domain": "hbomax.com", "category": "entertainment"},
    {"domain": "primevideo.com", "category": "entertainment"},
    {"domain": "peacocktv.com", "category": "entertainment"},
    {"domain": "crunchyroll.com", "category": "entertainment"},
    {"domain": "soundcloud.com", "category": "entertainment"},
    {"domain": "applemusic.com", "category": "entertainment"},
    {"domain": "hotstar.com", "category": "entertainment"},
    {"domain": "jiocinema.com", "category": "entertainment"},
    {"domain": "sonyliv.com", "category": "entertainment"},
    {"domain": "zee5.com", "category": "entertainment"},

    # ── Gaming ───────────────────────────────────────────────────
    {"domain": "steam.com", "category": "gaming"},
    {"domain": "steampowered.com", "category": "gaming"},
    {"domain": "epicgames.com", "category": "gaming"},
    {"domain": "playstation.com", "category": "gaming"},
    {"domain": "xbox.com", "category": "gaming"},
    {"domain": "nintendo.com", "category": "gaming"},
    {"domain": "roblox.com", "category": "gaming"},
    {"domain": "ea.com", "category": "gaming"},
    {"domain": "blizzard.com", "category": "gaming"},
    {"domain": "riotgames.com", "category": "gaming"},

    # ── Government & Education ───────────────────────────────────
    {"domain": "gov.in", "category": "government"},
    {"domain": "irs.gov", "category": "government"},
    {"domain": "ssa.gov", "category": "government"},
    {"domain": "login.gov", "category": "government"},
    {"domain": "usa.gov", "category": "government"},
    {"domain": "nhs.uk", "category": "government"},
    {"domain": "gov.uk", "category": "government"},
    {"domain": "uidai.gov.in", "category": "government"},
    {"domain": "incometax.gov.in", "category": "government"},
    {"domain": "digilocker.gov.in", "category": "government"},
    {"domain": "mit.edu", "category": "education"},
    {"domain": "stanford.edu", "category": "education"},
    {"domain": "harvard.edu", "category": "education"},
    {"domain": "coursera.org", "category": "education"},
    {"domain": "udemy.com", "category": "education"},
    {"domain": "khanacademy.org", "category": "education"},
    {"domain": "edx.org", "category": "education"},

    # ── Travel & Transport ───────────────────────────────────────
    {"domain": "booking.com", "category": "travel"},
    {"domain": "airbnb.com", "category": "travel"},
    {"domain": "expedia.com", "category": "travel"},
    {"domain": "tripadvisor.com", "category": "travel"},
    {"domain": "uber.com", "category": "transport"},
    {"domain": "lyft.com", "category": "transport"},
    {"domain": "makemytrip.com", "category": "travel"},
    {"domain": "goibibo.com", "category": "travel"},
    {"domain": "irctc.co.in", "category": "travel"},
    {"domain": "ola.com", "category": "transport"},

    # ── News & Media ─────────────────────────────────────────────
    {"domain": "bbc.com", "category": "news"},
    {"domain": "cnn.com", "category": "news"},
    {"domain": "nytimes.com", "category": "news"},
    {"domain": "reuters.com", "category": "news"},
    {"domain": "theguardian.com", "category": "news"},
    {"domain": "forbes.com", "category": "news"},
    {"domain": "bloomberg.com", "category": "news"},
    {"domain": "washingtonpost.com", "category": "news"},
    {"domain": "timesofindia.com", "category": "news"},
    {"domain": "ndtv.com", "category": "news"},
    {"domain": "hindustantimes.com", "category": "news"},
    {"domain": "thehindu.com", "category": "news"},
    {"domain": "wikipedia.org", "category": "reference"},

    # ── Health & Fitness ─────────────────────────────────────────
    {"domain": "webmd.com", "category": "health"},
    {"domain": "mayoclinic.org", "category": "health"},
    {"domain": "healthline.com", "category": "health"},
    {"domain": "practo.com", "category": "health"},
    {"domain": "1mg.com", "category": "health"},

    # ── Telecom & ISP ────────────────────────────────────────────
    {"domain": "jio.com", "category": "telecom"},
    {"domain": "airtel.in", "category": "telecom"},
    {"domain": "vi.com", "category": "telecom"},
    {"domain": "att.com", "category": "telecom"},
    {"domain": "verizon.com", "category": "telecom"},
    {"domain": "t-mobile.com", "category": "telecom"},

    # ── Food Delivery ────────────────────────────────────────────
    {"domain": "zomato.com", "category": "food"},
    {"domain": "swiggy.com", "category": "food"},
    {"domain": "doordash.com", "category": "food"},
    {"domain": "ubereats.com", "category": "food"},
    {"domain": "grubhub.com", "category": "food"},

    # ── Security & Antivirus ─────────────────────────────────────
    {"domain": "norton.com", "category": "security"},
    {"domain": "mcafee.com", "category": "security"},
    {"domain": "kaspersky.com", "category": "security"},
    {"domain": "malwarebytes.com", "category": "security"},
    {"domain": "avast.com", "category": "security"},
    {"domain": "virustotal.com", "category": "security"},
    {"domain": "cloudflare.com", "category": "security"},
    {"domain": "letsencrypt.org", "category": "security"},
]


@asynccontextmanager
async def lifespan(app: FastAPI):
    setup_logging()
    logger.info("ShadowTrace Backend starting up...")
    await connect_db()

    db = get_db()

    # Seed trusted domains (upsert — won't duplicate)
    count = await db.trusted_domains.count_documents({})
    if count < len(DEFAULT_TRUSTED):
        inserted = 0
        for td in DEFAULT_TRUSTED:
            result = await db.trusted_domains.update_one(
                {"domain": td["domain"]},
                {"$setOnInsert": td},
                upsert=True,
            )
            if result.upserted_id:
                inserted += 1
        logger.info(f"Trusted domains: {inserted} new, {len(DEFAULT_TRUSTED)} total defined")

    # Seed or repair admin user + default organization
    from passlib.context import CryptContext
    from datetime import datetime, timezone as tz
    from bson import ObjectId

    pwd_ctx = CryptContext(schemes=["bcrypt"], deprecated="auto")

    # Ensure a default organization exists for the bootstrap admin
    default_org = await db.organizations.find_one({"slug": "default"})
    if not default_org:
        now = datetime.now(tz.utc)
        default_org_doc = {
            "name": "Default Organization",
            "slug": "default",
            "subscription_tier": "community",
            "created_at": now,
        }
        result = await db.organizations.insert_one(default_org_doc)
        default_org_id = str(result.inserted_id)
        default_org_doc["_id"] = result.inserted_id
        default_org = default_org_doc
        logger.info("Default organization created for admin bootstrap")
    else:
        default_org_id = str(default_org["_id"])

    admin_user = await db.admin_users.find_one({"username": settings.ADMIN_USERNAME})
    if not admin_user:
        await db.admin_users.insert_one({
            "username": settings.ADMIN_USERNAME,
            "password_hash": pwd_ctx.hash(settings.ADMIN_PASSWORD),
            "role": "admin",
            "org_id": default_org_id,
            "created_at": datetime.now(tz.utc),
        })
        logger.info(f"Admin user '{settings.ADMIN_USERNAME}' seeded and bound to org {default_org_id}")
    else:
        # If the admin exists but has no org assignment, bind to default org
        if not admin_user.get("org_id"):
            await db.admin_users.update_one(
                {"_id": admin_user["_id"]},
                {"$set": {"org_id": default_org_id}},
            )
            logger.info(f"Admin user '{settings.ADMIN_USERNAME}' bound to default org {default_org_id}")

    # Start background tasks (anomaly detection, etc.)
    from app.services.background_tasks import start_background_tasks, stop_background_tasks
    start_background_tasks(db)

    # ── Phase 1.5: Integrity index provisioning ──────────────────────
    # nonce_registry: unique dedup index + TTL auto-purge
    await db.nonce_registry.create_index("nonce", unique=True, background=True)
    await db.nonce_registry.create_index(
        "expires_at", expireAfterSeconds=0, background=True
    )
    # forensic_chain: compound index for O(log n) chain lookups
    await db.forensic_chain.create_index(
        [("installation_id", 1), ("seq", 1)], unique=True, background=True
    )
    # scan_logs: index on installation_id + seq for chain-of-custody queries
    await db.scan_logs.create_index(
        [("installation_id", 1), ("seq", 1)], background=True
    )
    logger.info("Phase 1.5 integrity indexes provisioned")
    # ─────────────────────────────────────────────────────────────────

    logger.info("ShadowTrace Backend ready")
    yield
    logger.info("ShadowTrace Backend shutting down...")
    await stop_background_tasks()
    await close_db()


app = FastAPI(
    title="ShadowTrace API",
    description="Real-Time Phishing & Credential Exfiltration Detection Engine",
    version="3.0.0",
    lifespan=lifespan,
)

# Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(RateLimitMiddleware)
app.add_middleware(OAuthMiddleware)

# Routers
app.include_router(analyze.router)
app.include_router(report.router)
app.include_router(stats.router)

# Phase 4, 5 & 6 + Persistence routers
from app.routers import auth, analytics, feedback, organizations, intelligence, policies, connectors, remediation, simulation, marketplace, persistence, integrity, devices, incidents
app.include_router(auth.router)
app.include_router(analytics.router)
app.include_router(feedback.router)
app.include_router(organizations.router)
app.include_router(intelligence.router)
app.include_router(policies.router)
app.include_router(connectors.router)
app.include_router(remediation.router)
app.include_router(simulation.router)
app.include_router(marketplace.router)
app.include_router(persistence.router)
app.include_router(integrity.router)
app.include_router(devices.router)
app.include_router(incidents.router)


@app.get("/health", tags=["System"])
async def health_check():
    return {"status": "healthy", "version": "3.0.0", "database": "mongodb-atlas"}

