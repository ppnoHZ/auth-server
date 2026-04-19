try:
    from passlib.context import CryptContext
    c = CryptContext(schemes=["bcrypt"])
    c.hash("a"*100)
except Exception as e:
    print(f"Error 3: {e}")

try:
    c = CryptContext(schemes=["bcrypt"])
    c.hash(("a"*100)[:72])
except Exception as e:
    print(f"Error 4: {e}")
