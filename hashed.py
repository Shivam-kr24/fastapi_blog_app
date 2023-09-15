import secrets

# Generate a random 32-character secret key
SECRET_KEY = secrets.token_hex(32)

# Print the generated secret key
print("Generated Secret Key:", SECRET_KEY)
