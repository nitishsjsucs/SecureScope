#!/usr/bin/env python3
"""
Demo script to populate sample data for testing the SexySecure UI.

This adds:
- Sources data to some high-profile CVEs
- Chatter scores to some CVEs
- Verified status to a few CVEs

Usage:
    python populate_demo_data.py
"""

import os
import sys
from datetime import datetime, timezone, timedelta
import random

from dotenv import load_dotenv
from pymongo import MongoClient

# Load environment variables
load_dotenv()

MONGODB_URI = os.getenv("MONGODB_URI")
DATABASE_NAME = "vulntracker"
COLLECTION_NAME = "cves"

# High-profile CVEs to populate with demo data
DEMO_CVES = [
    "CVE-2021-44228",  # Log4j
    "CVE-2021-45046",  # Log4j follow-up
    "CVE-2024-3094",  # xz backdoor
    "CVE-2023-44487",  # HTTP/2 Rapid Reset
    "CVE-2023-4863",  # WebP vulnerability
    "CVE-2024-21762",  # Fortinet
    "CVE-2023-20198",  # Cisco IOS XE
    "CVE-2023-22515",  # Confluence
    "CVE-2023-46747",  # F5 BIG-IP
    "CVE-2023-20273",  # Cisco
]

# Source configurations for demo
SOURCES = [
    {"source": "nvd", "delay_days": 0},
    {"source": "mitre", "delay_days": 1},
    {"source": "cisa_kev", "delay_days": 2},
    {"source": "firecrawl", "delay_days": -1},  # Firecrawl finds things early
    {"source": "openwall", "delay_days": 0},
    {"source": "github_advisory", "delay_days": 1},
    {"source": "exploitdb", "delay_days": 3},
]


def generate_sources(base_date: datetime, num_sources: int = None) -> list:
    """Generate random source data for a CVE."""
    if num_sources is None:
        num_sources = random.randint(2, 5)

    selected = random.sample(SOURCES, min(num_sources, len(SOURCES)))
    sources = []

    for src in selected:
        first_seen = base_date + timedelta(days=src["delay_days"])
        sources.append(
            {
                "source": src["source"],
                "first_seen": first_seen.isoformat(),
                "url": None,  # Could add URLs later
            }
        )

    return sources


def main():
    """Populate demo data."""
    if not MONGODB_URI:
        print("Error: MONGODB_URI environment variable not set")
        sys.exit(1)

    print("Connecting to MongoDB...")
    client = MongoClient(MONGODB_URI)
    db = client[DATABASE_NAME]
    collection = db[COLLECTION_NAME]

    # Test connection
    try:
        client.admin.command("ping")
        print("Connected successfully!")
    except Exception as e:
        print(f"Error connecting to MongoDB: {e}")
        sys.exit(1)

    print("\nPopulating demo data...")

    for cve_id in DEMO_CVES:
        doc = collection.find_one({"_id": cve_id})
        if not doc:
            print(f"  {cve_id}: Not found in database, skipping")
            continue

        # Generate demo data
        created_at = doc.get("created_at") or datetime.now(timezone.utc)
        if isinstance(created_at, str):
            created_at = datetime.fromisoformat(created_at.replace("Z", "+00:00"))

        sources = generate_sources(created_at, random.randint(3, 6))
        chatter_score = random.randint(60, 100)  # High-profile CVEs = high chatter

        # Mark some as verified
        is_verified = random.random() > 0.5

        update = {
            "$set": {
                "sources": sources,
                "chatter_score": chatter_score,
            }
        }

        if is_verified:
            update["$set"]["sexysecure.verified"] = True
            update["$set"]["sexysecure.verified_at"] = datetime.now(
                timezone.utc
            ).isoformat()
            update["$set"]["sexysecure.verified_by"] = "demo_user"
            update["$set"]["sexysecure.status"] = "verified"

        collection.update_one({"_id": cve_id}, update)

        status = "verified" if is_verified else "not verified"
        print(f"  {cve_id}: {len(sources)} sources, chatter={chatter_score}, {status}")

    # Also add some random chatter scores to recent CVEs
    print("\nAdding chatter scores to recent CVEs...")
    recent_cves = list(
        collection.find({"chatter_score": None}, {"_id": 1})
        .sort("updated_at", -1)
        .limit(50)
    )

    for doc in recent_cves:
        # Random chatter score, weighted towards lower values
        score = random.choices(
            [
                random.randint(0, 20),
                random.randint(20, 50),
                random.randint(50, 80),
                random.randint(80, 100),
            ],
            weights=[50, 30, 15, 5],
        )[0]

        collection.update_one({"_id": doc["_id"]}, {"$set": {"chatter_score": score}})

    print(f"  Updated {len(recent_cves)} CVEs with chatter scores")

    print("\nDemo data populated successfully!")
    print("\nYou can now test the UI at:")
    print("  - http://localhost:3000/ (dashboard with chatter indicators)")
    print(
        "  - http://localhost:3000/cve/CVE-2021-44228 (Log4j with sources & verified badge)"
    )

    client.close()


if __name__ == "__main__":
    main()
