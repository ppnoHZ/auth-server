from passlib.context import CryptContext
c = CryptContext(schemes=["bcrypt"])
for i in range(70, 75):
    try:
        c.hash("a"*i)
        print(f"Success for {i}")
    except Exception as e:
        print(f"Failed for {i}: {e}")
