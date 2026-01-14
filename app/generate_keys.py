"""
This script calls generate_new_key_pair method of token_generator and generate new private and public JWKs, run it only during startup or key rotation.
"""

from .token_generator import generate_new_key_pair
import json

keys = generate_new_key_pair()

print("PRIVATE KEY (Add to .env as SUPABASE_JWT_PRIVATE_KEY):")
print(json.dumps(keys["private_jwk"]))
print("----------------------------------------------------------------------------------------")
print("PUBLIC KEY (Add to .env as SUPABASE_JWT_PUBLIC_KEY): ")
print(json.dumps(keys["public_jwk"]))
print("----------------------------------------------------------------------------------------")
print(f"KEY ID (kid): {keys['kid']}")