import flask
import json
from flask import request
import jwt
import hashlib
import base64
from datetime import datetime, timedelta
import OpenSSL.crypto

pemfile = open("DONOTUSETHISKEY.key", 'r')
keystring_pem = pemfile.read()

token_payload_dict = {
    "iss": "gen_jwt",
    "sub": "gen_jwt",
    # "aud": "None",
    #"exp": int(str(datetime.utcnow())) + 86400,
    #'nbf': datetime.utcnow(),
    #'iat': datetime.utcnow(),
    }

encoded_token = jwt.encode(token_payload_dict, keystring_pem, algorithm='RS256') #, headers={'kid': kid}

idp_mock_response = {
                     "token": str(encoded_token, 'utf-8')
}


print(json.dumps(idp_mock_response))
