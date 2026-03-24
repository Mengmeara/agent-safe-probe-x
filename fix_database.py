#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Fix ChromaDB embedding dimension mismatch by deleting and recreating the database.

This script deletes the old ChromaDB database that was created with a different
embedding model (1536 dimensions) so it can be recreated with the current model (4096 dimensions).
"""

import os
import shutil
import sys

def main():
    # Default database path
    default_db_path = 'memory_db/chroma_db'
    
    # Check if path is provided as argument
    if len(sys.argv) > 1:
        db_path = sys.argv[1]
    else:
        db_path = default_db_path
    
    # Check if database exists
    if not os.path.exists(db_path):
        print(f"Database path '{db_path}' does not exist.")
        print("Nothing to delete.")
        return
    
    # Confirm deletion
    print(f"WARNING: This will delete the database at: {os.path.abspath(db_path)}")
    print("All data in this database will be lost!")
    
    response = input("Are you sure you want to continue? (yes/no): ")
    if response.lower() not in ['yes', 'y']:
        print("Cancelled.")
        return
    
    # Delete the database
    try:
        shutil.rmtree(db_path)
        print(f"✓ Successfully deleted database at: {db_path}")
        print(f"\nThe database will be automatically recreated with the correct")
        print(f"embedding dimensions when you run the program again.")
    except Exception as e:
        print(f"✗ Error deleting database: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()

