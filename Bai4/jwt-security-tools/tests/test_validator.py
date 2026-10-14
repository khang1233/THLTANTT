from jwt_validator.validator import JWTValidator
import jwt
import datetime

def generate_token(secret):
    payload = {"sub": "test", "exp": datetime.datetime.now(datetime.timezone.utc)
               + datetime.timedelta(minutes=5)}
    return jwt.encode(payload, secret, algorithm="HS256")

def test_valid_token():
    secret = "secret"
    token = generate_token(secret)
    validator = JWTValidator(secret)
    result = validator.validate(token)
    assert result["valid"] is True
    assert result["payload"]["sub"] == "test"

def test_invalid_signature():
    token = generate_token("wrong")
    validator = JWTValidator("correct")
    result = validator.validate(token)
    assert result["valid"] is False
