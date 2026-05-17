import re


USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9_]+$")
EMAIL_PATTERN = re.compile(r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)")


def validate_username(username: str) -> str:
    normalized = username.strip()
    if not normalized or len(normalized) < 3 or len(normalized) > 50 or not USERNAME_PATTERN.match(normalized):
        raise ValueError("用户名只能包含字母、数字和下划线，且长度必须在3-50个字符之间")
    return normalized


def validate_email(email: str) -> str:
    normalized = email.strip().lower()
    if not normalized or len(normalized) > 100 or not EMAIL_PATTERN.match(normalized):
        raise ValueError("请输入有效的电子邮件地址")
    return normalized


def validate_password(password: str) -> str:
    if len(password) < 6 or len(password) > 100:
        raise ValueError("密码长度必须在6-100个字符之间")

    if not (
        any(char.islower() for char in password)
        and any(char.isupper() for char in password)
        and any(char.isdigit() for char in password)
        and any(not char.isalnum() for char in password)
    ):
        raise ValueError("密码必须包含大写字母、小写字母、数字和至少一个特殊字符")

    return password