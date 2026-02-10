#!/usr/bin/env python3
"""
SexySecure CVE Import Script

Imports CVE data from the opencve-kb repository into MongoDB Atlas.
Now includes source provenance tracking (mitre, nvd, vulnrichment, redhat)
and advisory extraction (EUVD, GHSA, Debian, Ubuntu).

Usage:
    python import_cves.py           # Incremental import (only new/changed CVEs)
    python import_cves.py --full    # Full re-import of all CVEs

Environment variables (or .env file):
    MONGODB_URI - MongoDB connection string
"""

import argparse
import glob
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv
from git import Repo
from git.exc import GitCommandError, InvalidGitRepositoryError
from pymongo import MongoClient, UpdateOne
from pymongo.errors import BulkWriteError
from tqdm import tqdm

# Load environment variables
load_dotenv()

# Configuration
MONGODB_URI = os.getenv("MONGODB_URI")
DATABASE_NAME = "vulntracker"
COLLECTION_NAME = "cves"

KB_REPO_URL = "https://github.com/opencve/opencve-kb.git"
KB_REPO_PATH = Path(__file__).parent.parent / "data" / "opencve-kb"
LAST_IMPORT_FILE = Path(__file__).parent / ".last_import"

# Batch size for bulk operations
BATCH_SIZE = 1000


def get_mongodb_client():
    """Create and return MongoDB client."""
    if not MONGODB_URI:
        print("Error: MONGODB_URI environment variable not set")
        print("Set it in .env file or export MONGODB_URI=mongodb+srv://...")
        sys.exit(1)

    return MongoClient(MONGODB_URI)


def clone_or_pull_repo():
    """Clone the opencve-kb repo if not exists, otherwise pull latest."""
    if KB_REPO_PATH.exists():
        print(f"Repository exists at {KB_REPO_PATH}")
        try:
            repo = Repo(KB_REPO_PATH)
            print("Pulling latest changes...")
            origin = repo.remotes.origin
            origin.fetch()
            # Get the current branch's tracking branch
            current_branch = repo.active_branch
            tracking_branch = current_branch.tracking_branch()
            if tracking_branch:
                repo.head.reset(tracking_branch.commit, index=True, working_tree=True)
                print(f"Updated to {repo.head.commit.hexsha[:8]}")
            return repo
        except InvalidGitRepositoryError:
            print(f"Error: {KB_REPO_PATH} is not a valid git repository")
            sys.exit(1)
        except GitCommandError as e:
            print(f"Git error: {e}")
            sys.exit(1)
    else:
        print(f"Cloning {KB_REPO_URL} to {KB_REPO_PATH}...")
        print("This may take a while (repository is ~2GB)...")
        KB_REPO_PATH.parent.mkdir(parents=True, exist_ok=True)
        repo = Repo.clone_from(KB_REPO_URL, KB_REPO_PATH, progress=CloneProgress())
        print(f"\nCloned successfully to {KB_REPO_PATH}")
        return repo


class CloneProgress:
    """Progress callback for git clone."""

    def __call__(self, op_code, cur_count, max_count=None, message=""):
        if max_count:
            pct = (cur_count / max_count) * 100
            print(f"\r  Progress: {pct:.1f}% {message}", end="", flush=True)


def get_last_import_time():
    """Get the timestamp of the last successful import."""
    if LAST_IMPORT_FILE.exists():
        try:
            return datetime.fromisoformat(LAST_IMPORT_FILE.read_text().strip())
        except (ValueError, OSError):
            pass
    return None


def save_last_import_time():
    """Save the current timestamp as the last import time."""
    LAST_IMPORT_FILE.write_text(datetime.now(timezone.utc).isoformat())


def get_changed_files_since(repo, since_time):
    """Get list of CVE files changed since the given time."""
    if since_time is None:
        return None  # Signal to process all files

    try:
        # Find commits since last import
        since_str = since_time.strftime("%Y-%m-%d %H:%M:%S")
        commits = list(repo.iter_commits(since=since_str))

        if not commits:
            print("No new commits since last import")
            return set()

        print(f"Found {len(commits)} new commits since last import")

        # Collect all changed files
        changed_files = set()
        for commit in commits:
            for diff in commit.diff(commit.parents[0] if commit.parents else None):
                if diff.a_path and diff.a_path.endswith(".json"):
                    changed_files.add(diff.a_path)
                if diff.b_path and diff.b_path.endswith(".json"):
                    changed_files.add(diff.b_path)

        return changed_files
    except Exception as e:
        print(f"Warning: Could not determine changed files: {e}")
        print("Falling back to file modification time check")
        return None


def find_cve_files(changed_files=None):
    """Find all CVE JSON files in the repository."""
    pattern = str(KB_REPO_PATH / "**" / "CVE-*.json")
    all_files = glob.glob(pattern, recursive=True)

    if changed_files is not None:
        # Filter to only changed files
        changed_paths = {str(KB_REPO_PATH / f) for f in changed_files}
        files = [f for f in all_files if f in changed_paths]
        print(
            f"Processing {len(files)} changed CVE files (out of {len(all_files)} total)"
        )
        return files

    print(f"Found {len(all_files)} CVE files")
    return all_files


def extract_sources(data: Dict[str, Any], cve_id: str) -> List[Dict[str, Any]]:
    """
    Extract source provenance from the raw KB data.

    Detects which providers contributed to this CVE:
    - mitre: MITRE CVE Program (cvelistV5)
    - nvd: NIST National Vulnerability Database
    - vulnrichment: CISA Vulnrichment (KEV/SSVC data)
    - redhat: Red Hat Security
    - cisa_kev: If in CISA KEV catalog (from metrics)
    """
    sources = []
    opencve = data.get("opencve", {})

    # Check MITRE
    mitre_data = data.get("mitre")
    if mitre_data:
        first_seen = mitre_data.get("created")
        if first_seen and isinstance(first_seen, str):
            # Already ISO format
            pass
        else:
            first_seen = datetime.now(timezone.utc).isoformat()

        sources.append(
            {
                "source": "mitre",
                "first_seen": first_seen,
                "url": f"https://www.cve.org/CVERecord?id={cve_id}",
            }
        )

    # Check NVD
    nvd_data = data.get("nvd")
    if nvd_data:
        first_seen = nvd_data.get("created")
        if first_seen and isinstance(first_seen, str):
            pass
        else:
            first_seen = datetime.now(timezone.utc).isoformat()

        sources.append(
            {
                "source": "nvd",
                "first_seen": first_seen,
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            }
        )

    # Check Vulnrichment (CISA)
    vulnrichment_data = data.get("vulnrichment")
    if vulnrichment_data:
        sources.append(
            {
                "source": "vulnrichment",
                "first_seen": datetime.now(timezone.utc).isoformat(),
                "url": None,  # No direct URL for vulnrichment
            }
        )

    # Check Red Hat
    redhat_data = data.get("redhat")
    if redhat_data:
        first_seen = redhat_data.get("created")
        if first_seen and isinstance(first_seen, str):
            pass
        else:
            first_seen = datetime.now(timezone.utc).isoformat()

        sources.append(
            {
                "source": "redhat",
                "first_seen": first_seen,
                "url": f"https://access.redhat.com/security/cve/{cve_id}",
            }
        )

    # Check CISA KEV (from metrics in opencve section)
    kev_data = opencve.get("metrics", {}).get("kev")
    if kev_data:
        date_added = kev_data.get("dateAdded")
        if date_added:
            # KEV dateAdded is typically YYYY-MM-DD format
            try:
                if "T" not in date_added:
                    date_added = f"{date_added}T00:00:00+00:00"
            except:
                date_added = datetime.now(timezone.utc).isoformat()
        else:
            date_added = datetime.now(timezone.utc).isoformat()

        sources.append(
            {
                "source": "cisa_kev",
                "first_seen": date_added,
                "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            }
        )

    return sources


def extract_advisories(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Extract security advisories from the KB data.

    Supported advisory sources:
    - euvd: EU Vulnerability Database
    - ghsa: GitHub Security Advisories
    - debian: Debian Security Advisories (DSA/DLA)
    - ubuntu: Ubuntu Security Notices (USN)
    """
    advisories = []

    for advisory in data.get("advisories", []):
        advisory_id = advisory.get("id")
        source = advisory.get("source")
        title = advisory.get("title")
        url = advisory.get("url")

        if advisory_id and source:
            advisories.append(
                {
                    "id": advisory_id,
                    "source": source,
                    "title": title or "",
                    "url": url or "",
                }
            )

    return advisories


def parse_cve_file(filepath):
    """Parse a CVE JSON file and return a document for MongoDB."""
    try:
        with open(filepath, "r") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        print(f"Warning: Could not parse {filepath}: {e}")
        return None

    opencve = data.get("opencve", {})

    # Extract core fields
    cve_id = data.get("cve")
    if not cve_id:
        return None

    # Parse dates
    created_at = None
    updated_at = None

    created_data = opencve.get("created", {}).get("data")
    if created_data:
        try:
            created_at = datetime.fromisoformat(created_data.replace("Z", "+00:00"))
        except ValueError:
            pass

    updated_data = opencve.get("updated", {}).get("data")
    if updated_data:
        try:
            updated_at = datetime.fromisoformat(updated_data.replace("Z", "+00:00"))
        except ValueError:
            pass

    # Extract source provenance
    sources = extract_sources(data, cve_id)

    # Extract advisories
    advisories = extract_advisories(data)

    # Extract EPSS score if available
    epss_data = data.get("epss", {})
    epss_score = epss_data.get("score") if epss_data else None

    # Build document
    doc = {
        "_id": cve_id,
        "description": opencve.get("description", {}).get("data"),
        "title": opencve.get("title", {}).get("data"),
        "metrics": opencve.get("metrics", {}),
        "vendors": opencve.get("vendors", {}).get("data", []),
        "weaknesses": opencve.get("weaknesses", {}).get("data", []),
        "created_at": created_at,
        "updated_at": updated_at,
        # Source provenance (which providers have data for this CVE)
        "_kb_sources": sources,
        # Security advisories
        "_kb_advisories": advisories,
        # EPSS score (if available at top level)
        "_kb_epss": epss_score,
        # Import metadata (always updated on sync)
        "_last_synced_at": datetime.now(timezone.utc),
    }

    return doc


def create_indexes(collection):
    """Create indexes for efficient querying."""
    print("Creating indexes...")

    indexes = [
        ("updated_at", -1),
        ("created_at", -1),
        ("vendors", 1),
        ("weaknesses", 1),
        ("sexysecure.verified", 1),
        ("sexysecure.status", 1),
        ("sexysecure.priority", 1),
        ("metrics.cvssV3_1.data.score", -1),
        ("metrics.cvssV4_0.data.score", -1),
        ("metrics.kev", 1),
        ("sources.source", 1),
        ("advisories.source", 1),
        ("chatter_score", -1),
    ]

    for field, direction in indexes:
        try:
            collection.create_index([(field, direction)])
            print(f"  Created index on {field}")
        except Exception as e:
            print(f"  Warning: Could not create index on {field}: {e}")


def get_default_sexysecure():
    """Return default SexySecure pipeline tracking fields."""
    return {
        "verified": False,
        "verified_at": None,
        "verified_by": None,
        "status": "imported",
        "notes": None,
        "tags": [],
        "priority": None,
        "reviewed_at": None,
        "reviewed_by": None,
    }


def get_default_chatter_score():
    """Return default chatter score.

    Chatter score (0-100) indicates how much traction the CVE is getting
    on social media and security forums. None means not yet calculated.
    """
    return None


def merge_sources(existing_sources: List[Dict], new_sources: List[Dict]) -> List[Dict]:
    """
    Merge new KB sources with existing sources.
    Preserves firecrawl and other non-KB sources while updating KB sources.
    """
    # Index existing sources by type
    existing_by_type = {s.get("source"): s for s in (existing_sources or [])}

    # KB source types that should be updated from KB
    kb_source_types = {"mitre", "nvd", "vulnrichment", "redhat", "cisa_kev"}

    # Start with non-KB sources (firecrawl, openwall, etc.)
    merged = [
        s for s in (existing_sources or []) if s.get("source") not in kb_source_types
    ]

    # Add/update KB sources
    for new_source in new_sources:
        source_type = new_source.get("source")
        if source_type in existing_by_type:
            # Keep existing first_seen date if earlier
            existing = existing_by_type[source_type]
            if existing.get("first_seen") and new_source.get("first_seen"):
                try:
                    existing_date = datetime.fromisoformat(
                        existing["first_seen"].replace("Z", "+00:00")
                    )
                    new_date = datetime.fromisoformat(
                        new_source["first_seen"].replace("Z", "+00:00")
                    )
                    if existing_date < new_date:
                        new_source["first_seen"] = existing["first_seen"]
                except:
                    pass
        merged.append(new_source)

    return merged


def import_cves(full_import=False):
    """Main import function."""
    print("=" * 60)
    print("SexySecure CVE Import Script")
    print("With Source Provenance & Advisory Tracking")
    print("=" * 60)

    # Connect to MongoDB
    print("\nConnecting to MongoDB...")
    client = get_mongodb_client()
    db = client[DATABASE_NAME]
    collection = db[COLLECTION_NAME]

    # Test connection
    try:
        client.admin.command("ping")
        print("Connected successfully!")
    except Exception as e:
        print(f"Error connecting to MongoDB: {e}")
        sys.exit(1)

    # Clone or pull repository
    print("\n" + "-" * 40)
    repo = clone_or_pull_repo()

    # Determine which files to process
    print("\n" + "-" * 40)
    if full_import:
        print("Full import requested - processing all CVE files")
        changed_files = None
    else:
        last_import = get_last_import_time()
        if last_import:
            print(f"Last import: {last_import.isoformat()}")
            changed_files = get_changed_files_since(repo, last_import)
            if changed_files is not None and len(changed_files) == 0:
                print("No changes to import")
                return
        else:
            print("No previous import found - performing full import")
            changed_files = None

    # Find CVE files
    cve_files = find_cve_files(changed_files)

    if not cve_files:
        print("No CVE files to process")
        return

    # Create indexes on first import
    if collection.count_documents({}) == 0:
        create_indexes(collection)

    # Process files in batches
    print("\n" + "-" * 40)
    print("Importing CVEs...")

    operations = []
    processed = 0
    skipped = 0
    errors = 0

    # Stats for sources
    source_stats = {
        "mitre": 0,
        "nvd": 0,
        "vulnrichment": 0,
        "redhat": 0,
        "cisa_kev": 0,
    }
    advisory_count = 0

    for filepath in tqdm(cve_files, desc="Processing", unit="CVE"):
        doc = parse_cve_file(filepath)
        if doc is None:
            skipped += 1
            continue

        cve_id = doc["_id"]
        kb_sources = doc.pop("_kb_sources", [])
        kb_advisories = doc.pop("_kb_advisories", [])
        kb_epss = doc.pop("_kb_epss", None)

        # Track stats
        for src in kb_sources:
            src_type = src.get("source")
            if src_type in source_stats:
                source_stats[src_type] += 1
        advisory_count += len(kb_advisories)

        # Build the update operation
        # For new documents: set sources and advisories directly
        # For existing documents: we need to merge sources intelligently
        operation = UpdateOne(
            {"_id": cve_id},
            [
                {
                    "$set": {
                        "description": doc["description"],
                        "title": doc["title"],
                        "metrics": doc["metrics"],
                        "vendors": doc["vendors"],
                        "weaknesses": doc["weaknesses"],
                        "created_at": doc["created_at"],
                        "updated_at": doc["updated_at"],
                        "_last_synced_at": doc["_last_synced_at"],
                        # Always update advisories from KB (authoritative)
                        "advisories": kb_advisories,
                        # Merge sources: keep firecrawl etc, update KB sources
                        "sources": {
                            "$cond": {
                                "if": {"$isArray": "$sources"},
                                "then": {
                                    "$concatArrays": [
                                        # Keep non-KB sources (firecrawl, openwall, etc.)
                                        {
                                            "$filter": {
                                                "input": "$sources",
                                                "as": "s",
                                                "cond": {
                                                    "$not": {
                                                        "$in": [
                                                            "$$s.source",
                                                            [
                                                                "mitre",
                                                                "nvd",
                                                                "vulnrichment",
                                                                "redhat",
                                                                "cisa_kev",
                                                            ],
                                                        ]
                                                    }
                                                },
                                            }
                                        },
                                        # Add new KB sources
                                        kb_sources,
                                    ]
                                },
                                "else": kb_sources,
                            }
                        },
                        # Set sexysecure only if not exists
                        "sexysecure": {
                            "$cond": {
                                "if": {"$ifNull": ["$sexysecure", False]},
                                "then": "$sexysecure",
                                "else": get_default_sexysecure(),
                            }
                        },
                        # Set chatter_score only if not exists
                        "chatter_score": {
                            "$cond": {
                                "if": {"$ifNull": ["$chatter_score", False]},
                                "then": "$chatter_score",
                                "else": None,
                            }
                        },
                        # Set imported_at only if not exists
                        "_imported_at": {
                            "$cond": {
                                "if": {"$ifNull": ["$_imported_at", False]},
                                "then": "$_imported_at",
                                "else": datetime.now(timezone.utc),
                            }
                        },
                    }
                }
            ],
            upsert=True,
        )
        operations.append(operation)
        processed += 1

        # Execute batch
        if len(operations) >= BATCH_SIZE:
            try:
                collection.bulk_write(operations, ordered=False)
            except BulkWriteError as e:
                errors += e.details.get("nErrors", 0)
            operations = []

    # Execute remaining operations
    if operations:
        try:
            collection.bulk_write(operations, ordered=False)
        except BulkWriteError as e:
            errors += e.details.get("nErrors", 0)

    # Save last import time
    save_last_import_time()

    # Summary
    print("\n" + "=" * 60)
    print("Import Complete!")
    print("=" * 60)
    print(f"  Processed: {processed:,}")
    print(f"  Skipped:   {skipped:,}")
    print(f"  Errors:    {errors:,}")
    print(f"  Total CVEs in database: {collection.count_documents({}):,}")
    print()
    print("Source Provenance Stats:")
    for src, count in source_stats.items():
        print(f"  {src}: {count:,}")
    print(f"  Total advisories extracted: {advisory_count:,}")

    client.close()


def main():
    parser = argparse.ArgumentParser(
        description="Import CVE data from opencve-kb into MongoDB"
    )
    parser.add_argument(
        "--full",
        action="store_true",
        help="Force full re-import of all CVEs (ignores last import time)",
    )

    args = parser.parse_args()

    try:
        import_cves(full_import=args.full)
    except KeyboardInterrupt:
        print("\n\nImport cancelled by user")
        sys.exit(1)


if __name__ == "__main__":
    main()
