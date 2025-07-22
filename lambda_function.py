import json
from jwcrypto import jwk, jwe
from jwcrypto.common import json_decode

def lambda_handler(event, context):
    try:
        jwe_token = event['jwe_token']
        private_key_pem = event['private_key']

        # Load private key
        key = jwk.JWK.from_pem(private_key_pem.encode('utf-8'))

        # Prepare JWE object and decrypt
        jwetoken = jwe.JWE()
        jwetoken.deserialize(jwe_token)
        jwetoken.decrypt(key)

        # Get decrypted payload
        decrypted_payload = jwetoken.payload.decode('utf-8')

        return {
            'statusCode': 200,
            'body': decrypted_payload
        }
    except Exception as e:
        return {
            'statusCode': 500,
            'error': str(e)
        }
