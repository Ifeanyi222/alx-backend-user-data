#!/usr/bin/env python3
"""Encrypting passwords """
import bcrypt

def hash_password(password: str) -> bytes:
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password




"""Check valid password"""

def is_valid(hashed_password: bytes, password: str) -> bool:

    if bcrypt.checkpw(password.encode('utf-8'), hashed_password):
    
        valid = True
        return valid
    else:
        return False

    


