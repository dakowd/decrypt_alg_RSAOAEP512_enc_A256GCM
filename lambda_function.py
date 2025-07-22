import json
import base64
from jwcrypto.common import json_decode
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def b64url_decode(data):
    data += '=' * (-len(data) % 4)  # Add padding if needed
    return base64.urlsafe_b64decode(data)

def base64url_decode_json(jwt_part):
    return json.loads(b64url_decode(jwt_part).decode('utf-8'))

def decrypt_jwe(jwe_token, private_key_pem):
    # Step 1: Split token into parts
    parts = jwe_token.split('.')
    if len(parts) != 5:
        return {
            'statusCode': 400,
            'headers': {
                'Content-Type': 'text/plain'
            },
            'body': "Invalid JWE"
        }

    encoded_header, encrypted_key_b64, iv_b64, ciphertext_b64, tag_b64 = parts

    header = json.loads(b64url_decode(encoded_header))
    encrypted_key = b64url_decode(encrypted_key_b64)
    iv = b64url_decode(iv_b64)
    ciphertext = b64url_decode(ciphertext_b64)
    tag = b64url_decode(tag_b64)
    aad = encoded_header.encode()  # AAD is the base64url-encoded header

    # Step 2: Load RSA private key
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode(),
        password=None
    )

    # Step 3: Decrypt the CEK using RSA-OAEP with SHA512
    cek = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA512()),
            algorithm=hashes.SHA512(),
            label=None
        )
    )

    # Step 4: Decrypt payload using A256GCM (AES-GCM with 256-bit CEK)
    aesgcm = AESGCM(cek)
    decrypted = aesgcm.decrypt(iv, ciphertext + tag, aad)
    return decrypted.decode('utf-8')  # This is the nested JWT string

def decode_jwt(jwt_str):
    parts = jwt_str.split('.')
    
    if len(parts) != 3:
        return {
            'statusCode': 400,
            'headers': {
                'Content-Type': 'text/plain'
            },
            'body': "Invalid JWT format"
        }

    header = base64url_decode_json(parts[0])
    payload = base64url_decode_json(parts[1])
    # parts[2] is the signature — not needed if we’re not verifying
    return payload

def lambda_handler(event, context):
    try:
        body_str = event.get('body')
        if not body_str:
            return {
                'statusCode': 400,
                'headers': {
                    'Content-Type': 'text/plain'
                },
                'body': "Missing body in event"
            }

        body = json.loads(body_str)

        jwe_token = body.get('jwe_token')
        pem_str = body.get('private_key')
        pem_str = pem_str.replace('\\n', '\n')

        if not jwe_token or not pem_str:
            return {
                'statusCode': 400,
                'headers': {
                    'Content-Type': 'text/plain'
                },
                'body': "Missing jwe_token or private_key in request body"
            }

        # Decrypt the JWE to get the JWT
        decrypted_jwt = decrypt_jwe(jwe_token, pem_str)

        # Decode the JWT payload
        #decoded_payload = decode_jwt(decrypted_jwt)

        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'text/plain'
            },
            'body': decrypted_jwt
        }

    except Exception as e:
        return {
            'statusCode': 400,
            'headers': {
                'Content-Type': 'text/plain'
            },
            'body': str(e)
        }
