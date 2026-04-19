from passlib.context import CryptContext
pwd_context_1 = CryptContext(schemes=["bcrypt"], deprecated="auto")
try:
    pwd_context_1.hash("a"*100)
except Exception as e:
    print(f"Error 1: {e}")

pwd_context_2 = CryptContext(schemes=["bcrypt"], deprecated="auto", bcrypt__truncate_error=False)
try:
    pwd_context_2.hash("a"*100)
except Exception as e:
    print(f"Error 2: {e}")
