#!/usr/bin/env python3
"""
Create MongoDB indexes for SexySecure CVE database.

Run this once after setting up the database to improve query performance.
These indexes are critical for fast vendor filtering, sorting, and searching.

Usage:
    python create_indexes.py
"""

import os
import sys
from pymongo import MongoClient, ASCENDING, DESCENDING, TEXT
from pymongo.errors import OperationFailure
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

MONGODB_URI = os.getenv("MONGODB_URI")
if not MONGODB_URI:
    print("Error: MONGODB_URI environment variable not set")
    sys.exit(1)


def safe_create_index(collection, keys, name, **kwargs):
    """Create an index, ignoring if it already exists."""
    try:
        collection.create_index(keys, name=name, **kwargs)
        print(f"    Created: {name}")
    except OperationFailure as e:
        if "already exists" in str(e):
            print(f"    Exists:  {name}")
        else:
            print(f"    Error:   {name} - {e}")


def create_indexes():
    """Create all necessary indexes for the CVE database."""
    client = MongoClient(MONGODB_URI)
    db = client.get_default_database()
    cves = db["cves"]
    products = db["products"]
    emails = db["emails"]

    print("Creating indexes for 'cves' collection...")

    # 1. Index on vendors array (critical for vendor filtering)
    safe_create_index(cves, [("vendors", ASCENDING)], "vendors_1")

    # 2. Index on created_at (for sorting by newest)
    safe_create_index(cves, [("created_at", DESCENDING)], "created_at_-1")

    # 3. Index on updated_at (for sorting by recently updated)
    safe_create_index(cves, [("updated_at", DESCENDING)], "updated_at_-1")

    # 4. Compound index for CVSS sorting
    safe_create_index(
        cves,
        [
            ("metrics.cvssV3_1.data.score", DESCENDING),
            ("metrics.cvssV4_0.data.score", DESCENDING),
            ("updated_at", DESCENDING),
        ],
        "cvss_score_-1",
    )

    # 5. Index on sexysecure.verified
    safe_create_index(
        cves, [("sexysecure.verified", ASCENDING)], "sexysecure.verified_1"
    )

    # 6. Index on sexysecure.status
    safe_create_index(cves, [("sexysecure.status", ASCENDING)], "sexysecure.status_1")

    # 7. Compound index for verified + created_at
    safe_create_index(
        cves,
        [("sexysecure.verified", ASCENDING), ("created_at", DESCENDING)],
        "verified_created_at",
    )

    # 8. Index on weaknesses array
    safe_create_index(cves, [("weaknesses", ASCENDING)], "weaknesses_1")

    # 9. Text index for fallback search
    try:
        cves.create_index(
            [("description", TEXT), ("title", TEXT)],
            name="text_search",
            default_language="english",
        )
        print("    Created: text_search")
    except OperationFailure as e:
        if "already exists" in str(e) or "text index" in str(e).lower():
            print("    Exists:  text_search (or equivalent)")
        else:
            print(f"    Error:   text_search - {e}")

    print("\nCreating indexes for 'products' collection...")

    # 10. Index on product name
    safe_create_index(products, [("name", ASCENDING)], "name_1")

    # 11. Index on github_owner and github_repo
    safe_create_index(
        products,
        [("github_owner", ASCENDING), ("github_repo", ASCENDING)],
        "github_owner_repo",
    )

    # 12. Index on status
    safe_create_index(products, [("status", ASCENDING)], "status_1")

    print("\nCreating indexes for 'emails' collection...")

    # 13. Unique index on message_id to prevent duplicates
    safe_create_index(emails, [("message_id", ASCENDING)], "message_id_1", unique=True)

    # 14. Index on timestamp for sorting
    safe_create_index(emails, [("timestamp", DESCENDING)], "timestamp_-1")

    # 15. Index on category for filtering
    safe_create_index(emails, [("analysis.category", ASCENDING)], "analysis.category_1")

    # 16. Index on read status for filtering unread
    safe_create_index(emails, [("read", ASCENDING)], "read_1")

    # 17. Compound index for filtering + sorting
    safe_create_index(
        emails,
        [("analysis.category", ASCENDING), ("timestamp", DESCENDING)],
        "category_timestamp",
    )

    # 18. Index on CVE IDs mentioned in emails
    safe_create_index(emails, [("analysis.cve_ids", ASCENDING)], "analysis.cve_ids_1")

    print("\n" + "=" * 50)
    print("Index creation complete!")
    print("=" * 50)

    # List all indexes
    print("\nCurrent indexes on 'cves' collection:")
    for index in cves.list_indexes():
        print(f"  - {index['name']}: {index['key']}")

    print("\nCurrent indexes on 'products' collection:")
    for index in products.list_indexes():
        print(f"  - {index['name']}: {index['key']}")

    print("\nCurrent indexes on 'emails' collection:")
    for index in emails.list_indexes():
        print(f"  - {index['name']}: {index['key']}")

    client.close()


if __name__ == "__main__":
    create_indexes()
