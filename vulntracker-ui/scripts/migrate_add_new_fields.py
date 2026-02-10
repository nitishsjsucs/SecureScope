#!/usr/bin/env python3
"""
Migration script to add new fields (sources, chatter_score) to existing CVE documents.

This script adds the new fields to documents that don't have them yet.
Run this once after deploying the new schema.

Usage:
    python migrate_add_new_fields.py
"""

import os
import sys
from datetime import datetime, timezone

from dotenv import load_dotenv
from pymongo import MongoClient, UpdateMany

# Load environment variables
load_dotenv()

MONGODB_URI = os.getenv("MONGODB_URI")
DATABASE_NAME = "vulntracker"
COLLECTION_NAME = "cves"


def migrate():
    """Add new fields to existing documents."""
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

    total_docs = collection.count_documents({})
    print(f"Total documents in collection: {total_docs:,}")

    # Add 'sources' field to documents that don't have it
    print("\nAdding 'sources' field to documents...")
    result = collection.update_many(
        {"sources": {"$exists": False}}, {"$set": {"sources": []}}
    )
    print(f"  Updated {result.modified_count:,} documents with 'sources' field")

    # Add 'chatter_score' field to documents that don't have it
    print("\nAdding 'chatter_score' field to documents...")
    result = collection.update_many(
        {"chatter_score": {"$exists": False}}, {"$set": {"chatter_score": None}}
    )
    print(f"  Updated {result.modified_count:,} documents with 'chatter_score' field")

    # Create new indexes
    print("\nCreating indexes for new fields...")
    try:
        collection.create_index([("sources.source", 1)])
        print("  Created index on sources.source")
    except Exception as e:
        print(f"  Warning: {e}")

    try:
        collection.create_index([("chatter_score", -1)])
        print("  Created index on chatter_score")
    except Exception as e:
        print(f"  Warning: {e}")

    print("\nMigration complete!")
    client.close()


if __name__ == "__main__":
    migrate()
