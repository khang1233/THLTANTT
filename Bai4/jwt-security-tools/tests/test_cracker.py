from jwt_cracker.cracker import JWTCracker
import jwt
import tempfile

def test_crack_token():
    secret = "secret"
    token = jwt.encode({"sub": "test"}, secret, algorithm="HS256")

    with tempfile.NamedTemporaryFile(mode="w+", delete=False) as f:
        f.write("wrongpass\n123456\nsecret\n")
        f.seek(0)
        cracker = JWTCracker(token, f.name)
        found = cracker.crack()

    assert found == "secret"
