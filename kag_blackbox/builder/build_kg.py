#!/usr/bin/env python3
"""
Entry point: build the KAG-Blackbox knowledge graph in Neo4j.

Usage:
  python3 build_kg.py [--nuclei-dir DIR] [--mapping CSV] [--readmes DIR] [--clear]

Requires Neo4j running at bolt://127.0.0.1:7687.
"""
import argparse
import logging
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "common"))
sys.path.insert(0, os.path.dirname(__file__))

from config import (
    NEO4J_URI, NEO4J_USER, NEO4J_PASSWORD,
    NUCLEI_TEMPLATES_DIR, VULHUB_MAPPING_CSV, VULHUB_READMES_DIR,
)
from schema import init_schema, inject_cwe_seeds, clear_all
from kg_builder import (
    build_from_nuclei, build_from_vulhub, build_from_vulhub_fingerprints,
    build_from_other_vul, set_source_priority,
    build_fingerprint_index, get_stats,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("kag_blackbox")


def main():
    parser = argparse.ArgumentParser(description="Build KAG-Blackbox KG in Neo4j")
    parser.add_argument("--nuclei-dir", default=NUCLEI_TEMPLATES_DIR)
    parser.add_argument("--mapping", default=VULHUB_MAPPING_CSV)
    parser.add_argument("--readmes", default=VULHUB_READMES_DIR)
    parser.add_argument("--fingerprints",
                        default="/data/lqy/framework/blackbox-docker/vulhub_fingerprints",
                        help="Path to vulhub_fingerprints JSON directory (highest priority)")
    parser.add_argument("--surper-nuclei",
                        default="",
                        help="Path to surper-666 nuclei templates directory (highest priority)")
    parser.add_argument("--other-vul",
                        default="",
                        help="Path to other_vul.zip (low-priority supplementary templates)")
    parser.add_argument("--no-vulhub-mapping", action="store_true",
                        help="Skip Phase 3 (vulhub mapping + READMEs, superseded by fingerprints)")
    parser.add_argument("--clear", action="store_true",
                        help="Clear all BB_ nodes before building")
    args = parser.parse_args()

    from neo4j import GraphDatabase
    log.info(f"Connecting to Neo4j at {NEO4J_URI}")
    driver = GraphDatabase.driver(NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD))

    try:
        driver.verify_connectivity()
        log.info("Neo4j connected")
    except Exception as e:
        log.error(f"Cannot connect to Neo4j: {e}")
        sys.exit(1)

    t0 = time.time()

    if args.clear:
        log.info("Clearing existing BB_ nodes ...")
        clear_all(driver)

    log.info("=" * 60)
    log.info("  KAG-Blackbox Knowledge Graph Builder")
    log.info("=" * 60)

    log.info("Phase 1: Schema + CWE seeds")
    init_schema(driver)
    inject_cwe_seeds(driver)

    log.info("Phase 2: Nuclei templates")
    n_products, n_cves, n_pocs, n_fps = build_from_nuclei(driver, args.nuclei_dir)
    log.info(f"  Products: {n_products}, CVEs: {n_cves}, PoCs: {n_pocs}, Fingerprints: {n_fps}")

    if not args.no_vulhub_mapping:
        log.info("Phase 3: Vulhub mapping + READMEs (legacy, use --no-vulhub-mapping to skip)")
        n_vulhub = build_from_vulhub(driver, args.mapping, args.readmes)
    else:
        log.info("Phase 3: Skipped (--no-vulhub-mapping)")

    log.info("Phase 4: Surper-666 fingerprints (highest priority=2)")
    n_fp = build_from_vulhub_fingerprints(driver, args.fingerprints)

    if args.surper_nuclei:
        log.info("Phase 4a: Surper-666 Nuclei templates (highest priority=2)")
        n_sp, n_sp_cve, n_sp_poc, n_sp_fp = build_from_nuclei(driver, args.surper_nuclei)
        log.info(f"  Products: {n_sp}, CVEs: {n_sp_cve}, PoCs: {n_sp_poc}, Fingerprints: {n_sp_fp}")

    if args.other_vul:
        log.info("Phase 4.5: Other vulnerability templates (low-priority, priority=0)")
        n_other, n_other_poc = build_from_other_vul(driver, args.other_vul)

    log.info("Phase 5: Set source priority labels")
    set_source_priority(driver)

    log.info("Phase 6: Fingerprint index")
    build_fingerprint_index(driver)

    stats = get_stats(driver)
    elapsed = time.time() - t0

    log.info("")
    log.info("=" * 60)
    log.info("  KG Build Complete")
    log.info("=" * 60)
    for label, count in stats.items():
        log.info(f"  {label}: {count}")
    log.info(f"  Build time: {elapsed:.1f}s")
    log.info("=" * 60)

    driver.close()


if __name__ == "__main__":
    main()
