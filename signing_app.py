from flask import Flask, render_template_string, request
import requests
import json
import base64
import time
from datetime import datetime, timedelta

# JWT specific imports
from jose import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

app = Flask(__name__)

# --- DocuSign API Configuration for JWT Grant ---
# Replace with your actual values obtained from DocuSign Admin/Developer account
INTEGRATION_KEY = 'c9b4d8d7-dc71-4ff1-9325-cc6f545d596a'  # Client ID
USER_ID = 'f5e619d1-0227-42e9-96f5-17e82cd4fa4c'        # The GUID of the user who will be making API calls (must have consented to the app)
PRIVATE_KEY_BYTES = """-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAr1uJGosdfwrdn78oo3SVIlo5SEdn1CPx8Rdzfwsajf7tMkmt
C/CLDiWPpNuLquQuCsEU1dbpZt3aZHCLS8wrL3LzPYaZbUnotlsYfGGnxF88jk/d
28f98Z9hl32ic0AguOTkANUV1/3jOWXyMEPAWTcGu/nCbWZTcrhtsU/ccMELG/Gx
A9rsgyDpBOCbfQqqhzb5PLxaQDRBkBLLfdD7Xzt5jeeHqnWc4enH0aPy1GoIQ3LY
SrDy+gN/5kH0JooK5MGIuJC144/vZfFqP3JCUqadUXDy0c+FBZj31asMr5p5nwPc
nJk+9vND2M6Sz+6Suykm9Kg19Kwo0cPIZmHJJwIDAQABAoIBABplGX1d/0dGKBc0
O4u5r/uxv6Q6Nfi1SGT/y1S4znsdKjBC7WyPUn8DTFyGPL8GWvUnca7BC0opOVxG
THv7nsHPov6vKfJMs7NEgapckKzQS68oJRRAmuApxhN6x7RirLTn+cyI8SFyh9H1
9GnWE40vk9tA5vEh++GYEnrOszcNYm4u3q/BnlKsgI/wWSEYvWVkXjlOlLCr/mM9
MNxxgG41EMLMVaJ/QkDyni4B7/5hpkMB0+VBsVv03LKK4OeHvgHf6FBVF6WtM9h/
Pza1DtSHoMJZ3wyhSw9f3/U6a6A4QPj8KCmJtTgWeszxoHbm2K+1W+bwDQX8nhZY
kcn05bECgYEA4GxCjFFXfi3GrZck5eLCZEZj5oY1IMva+D0lDAYvmB233qh9E7eX
OHO3gkx3TfKMC4PnBnpGhPn/v04Tq3JDeK5u+ObKrz9eusJKrvZ/OLJtnebUsqyy
T5vuiIdh7FMfHkTZm0C2rI70nRsrG0r2XIHZPKF1ptwNukvmEUI14VsCgYEAyAfv
uNPuPn01m96Cx4GQGDZdF3HOS9R9KHjqN0jtFzWJpwt72KcEH4iF22pa6AkmM5Mh
95aW/3T/OEeR7wYFwcyiVLayJdlweEIzvZq9kqRCV1/QypceFOv8WqeVJCsKDrq5
5DO3SG7sQTwPzXTCYeTdouZKR4WSRHCNPvBfVSUCgYB57nftstgdhxN2BzOV7zD8
uD3Y5rwA2KFc1CPHt6iuNh9LSzHBv7Laigx/L7p2UDyEmSKxI0gjQY0RTINlWAyO
if9jHkmrE3wNbjiTfPu8Oz1RWDPh6/BpTmg4J44tjy/OC0xLjMpzUKxYm4U9K+pU
cnwr8/FvOgn/WPNkFxwdFwKBgFocESau+g1WdFbyJvHe8N2nZ8pO70MDxxn7Vm9v
P7cL3CXPK4xOuLHH250bTTZoILhtGIkjYoRT3UEqJJiLmv5Rw/Lrllcsm9jg4dQR
KEMuEeCwfis1ZkzAfh8MjUgMx2wZO/KMRY2wwmckum2wonxdEGb43Q9ZIaoJFef7
esatAoGAbjTdW7T7SJlxsJuocvvwluFPwWcLQH9EEa41ejxqRWK7O6zH9L1Skqp4
azBS7QOi3uHpLhVg2LIHSgYwgzyTmD46iHCilDJ4FFMkkV4wSmfbVM4m7/iF9W1s
6zTqd26pE2mZ44XgTxEY5tGyoX+5H1b9CVKncN8zGOAVqpyoJP4=
-----END RSA PRIVATE KEY-----"""
doc_file_path = "/Users/abhay.nelaturu/Downloads/sample pdf.pdf"
ACCOUNT_ID = '5d72dc01-0dc7-4f64-9380-593270983810'
SIGNER_EMAIL = 'abhaykumar.cvr@gmail.com'
SIGNER_NAME = 'AKCVR'
CLIENT_USER_ID = '1000' # This uniquely identifies your signer within the envelope for embedded signing
BASE_PATH = 'https://demo.docusign.net/restapi' # For developer sandbox
OAUTH_BASE_URL = 'https://account-d.docusign.com/oauth/token' # For demo environment token endpoint
# Global variable to store and manage token for reusability
cached_access_token = None
token_expiration_time = None

# --- Document content (Base64 encoded) ---
# Replace this with your actual Base64 encoded document string.
# Example: a very simple PDF with "/sn1/" where the signature should go
# You would usually generate this from a file:
# with open("path/to/your/document.pdf", "rb") as pdf_file:
#    DOCUMENT_BASE64_CONTENT = base64.b64encode(pdf_file.read()).decode('utf-8')

with open(doc_file_path, "rb") as file:
            doc_b64 = base64.b64encode(file.read()).decode("ascii")


DOCUMENT_NAME = 'SampleDocument.pdf'
DOCUMENT_ID = '1'

def get_access_token_jwt():
    """
    Obtains a DocuSign access token using the JWT Grant flow.
    Caches the token and refreshes it if expired.
    """
    global cached_access_token, token_expiration_time

    # Check if token exists and is still valid
    if cached_access_token and token_expiration_time and datetime.now() < token_expiration_time - timedelta(minutes=5):
        print("Using cached access token.")
        return cached_access_token
    print("Generating new access token via JWT Grant...")
    try:
        # Load the private key
        private_key = serialization.load_pem_private_key(
            PRIVATE_KEY_BYTES.encode("utf-8"),
            password=None,
            backend=default_backend()
        )
        # JWT Header
        jwt_header = {
            "alg": "RS256",
            "typ": "JWT"
        }
        # JWT Claims
        # 'exp' (expiration time) must be in Unix epoch time, max 1 hour from now
        now = int(time.time())
        claims = {
            "iss": INTEGRATION_KEY,
            "sub": USER_ID,
            "aud": "account-d.docusign.com", # For demo environment
            "scope": "signature impersonation", # Request necessary scopes
            "iat": now,
            "exp": now + 60 * 60 # Expires in 1 hour
        }
        # Encode the JWT
        assertion = jwt.encode(claims, private_key, algorithm='RS256', headers=jwt_header)
        # Prepare the token request
        token_request_data = {
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": assertion
        }
        headers = {
            "Content-Type": "application/x-www-form-urlencoded"
        }
        # Make the POST request to the OAuth token endpoint
        response = requests.post(OAUTH_BASE_URL, data=token_request_data, headers=headers)
        response.raise_for_status() # Raise an exception for bad status codes
        token_data = response.json()
        print(f"Token API Response:\n{json.dumps(token_data, indent=2)}")
        access_token = token_data.get("access_token")
        expires_in = token_data.get("expires_in") # Typically 3600 seconds (1 hour)
        if not access_token:
            raise Exception("Access token not found in response.")
        cached_access_token = access_token
        token_expiration_time = datetime.now() + timedelta(seconds=expires_in)
        print("Access token generated successfully.")
        return cached_access_token
    except requests.exceptions.RequestException as e:
        print(f"Error requesting access token: {e}")
        if 'response' in locals():
            print(f"Response status: {response.status_code}")
            print(f"Response body: {response.text}")
        raise
    except Exception as e:
        print(f"An unexpected error occurred during token generation: {e}")
        raise
@app.route('/')
def home():
    return """
    <h1>DocuSign Embedded Signing with Universal Signature Pen</h1>
    <p>This example will generate an access token, create an envelope with Universal Signature Pen, and then generate an embedded signing URL.</p>
    <form action="sign" method="post">
        <label for="signer_email">Signer Email:</label>
        <input type="email" name="signer_email" id="signer_email" placeholder="Enter signer email" required>
        <br><br>
        <label for="signer_name">Signer Name:</label>
        <input type="text" name="signer_name" id="signer_name" placeholder="Enter signer name" required>
        <br><br>
        <label for="auth_method">Authentication Method:</label>
        <select name="auth_method" id="auth_method" onchange="toggleAuthValue()">
            <option value="password">One-Time Password</option>
            <option value="sms">SMS</option>
        </select>
        <br><br>
        <label for="auth_value">Authentication Value:</label>
        <input type="text" name="auth_value" id="auth_value" placeholder="Enter password or phone number (+13303103330)" required>
        <br><br>
        <button type="submit">Generate Token, Create Envelope, and Start Embedded Signing</button>
    </form>
    
    <script>
    function toggleAuthValue() {
        const authMethod = document.getElementById('auth_method').value;
        const authValueInput = document.getElementById('auth_value');
        if (authMethod === 'sms') {
            authValueInput.placeholder = 'Enter phone number (+13303103330)';
        } else {
            authValueInput.placeholder = 'Enter password (123456)';
        }
    }
    </script>
    """

@app.route('/sign', methods=['POST'])
def sign_document():
    envelope_id = None
    recipient_view_url = None
    try:
        # Get form data
        signer_email = request.form.get('signer_email', SIGNER_EMAIL)
        signer_name = request.form.get('signer_name', SIGNER_NAME)
        auth_method = request.form.get('auth_method', 'password')  # 'password' or 'sms'
        auth_value = request.form.get('auth_value', '123456')  # password or phone number
        
        # Get (or refresh) the access token
        access_token = get_access_token_jwt()
        if not access_token:
            raise Exception("Failed to obtain access token.")
        
        # Step 1: Create and Send the Envelope
        print("Step 1: Creating and Sending the Envelope...")
        envelope_id = create_and_send_envelope_with_auth(access_token, signer_email, signer_name, auth_method, auth_value)
        print(f"Envelope sent with ID: {envelope_id}")
        
        # Step 2: Generate the Recipient View for Embedded Signing
        print("Step 2: Generating Recipient View URL...")
        recipient_view_url = generate_recipient_view(access_token, envelope_id, signer_email, signer_name)
        print(f"Recipient View URL generated: {recipient_view_url}")
        
        # Return the signing link without opening embedded interface
        return f"""
        <h1>DocuSign Signing Link Generated</h1>
        <p><strong>Envelope ID:</strong> {envelope_id}</p>
        <p><strong>Signer:</strong> {signer_name} ({signer_email})</p>
        <p><strong>Signing URL:</strong></p>
        <p><a href="{recipient_view_url}" target="_blank">{recipient_view_url}</a></p>
        <br>
        <p>Click the link above to open the signing interface in a new tab.</p>
        <p><a href="/">← Back to Home</a></p>
        """
        
    except Exception as e:
        print(f"An error occurred: {e}")
        return f"An error occurred during the signing process: {e}", 500

def create_and_send_envelope_with_auth(access_token, signer_email, signer_name, auth_method, auth_value):
    """
    Creates an envelope with Universal Signature Pen authentication options.
    """
    # Configure signature provider options based on auth method
    if auth_method == 'sms':
        signature_provider_options = {
            "sms": auth_value  # Phone number like "+13303103330"
        }
    else:  # default to password
        signature_provider_options = {
            "oneTimePassword": auth_value
        }
    
    signer_config = {
        "email": signer_email,
        "name": signer_name,
        "recipientId": "1",
        "clientUserId": CLIENT_USER_ID,
        "routingOrder": "1",
        "deliveryMethod": "email",
        "recipientSignatureProviders": [
            {
                "signatureProviderName": "UniversalSignaturePen_OpenTrust_Hash_TSP",
                "signatureProviderOptions": signature_provider_options
            }
        ],
        "tabs": {
            "signHereTabs": [
                {
                    "anchorString": "/sn1/",
                    "anchorUnits": "pixels",
                    "anchorXOffset": "20",
                    "anchorYOffset": "10",
                    "tabLabel": "SignHereTab1",
                    "name": "Sign Here",
                    "optional": "false",
                    "scaleValue": 1
                },
                {
                    # Add a second sign here tab at absolute position if no anchor found
                    "documentId": DOCUMENT_ID,
                    "pageNumber": "1",
                    "xPosition": "100",
                    "yPosition": "200",
                    "tabLabel": "SignHereTab2",
                    "name": "Signature",
                    "optional": "false",
                    "scaleValue": 1
                }
            ],
            "dateSignedTabs": [
                {
                    "documentId": DOCUMENT_ID,
                    "pageNumber": "1", 
                    "xPosition": "300",
                    "yPosition": "200",
                    "tabLabel": "DateSignedTab",
                    "name": "Date Signed"
                }
            ],
            "fullNameTabs": [
                {
                    "documentId": DOCUMENT_ID,
                    "pageNumber": "1",
                    "xPosition": "100", 
                    "yPosition": "150",
                    "tabLabel": "FullNameTab",
                    "name": "Full Name"
                }
            ]
        }
    }
    witness_config = {
        "witnessFor": "1",
        "email": "witness_email@example.com", # The witness's actual email
        "name": "Witness Name",
        "recipientId": "2",
        "routingOrder": "2",
        "deliveryMethod": "email", # Ensures email notification is sent
        # NO "clientUserId" KEY HERE
        "tabs": {
            "signHereTabs": [
                {
                    "documentId": "1",
                    "pageNumber": "1",
                    "xPosition": "190",
                    "yPosition": "247"
                }
            ]
        }
    }

    envelope_definition = {
        "emailSubject": "Please sign this document",
        "documents": [
            {
                "documentBase64": doc_b64,
                "name": DOCUMENT_NAME,
                "fileExtension": DOCUMENT_NAME.split('.')[-1],
                "documentId": DOCUMENT_ID
            }
        ],
        "recipients": {
            "signers": [signer_config],
            "witnesses": [witness_config]
        },
        "status": "sent" # Setting status to "sent" immediately sends the envelope
    }
    
    url = f"{BASE_PATH}/v2.1/accounts/{ACCOUNT_ID}/envelopes"
    headers = {
        "Authorization": f"Bearer {access_token}", # Use the generated token    
        "Content-Type": "application/json"
    }
    
    print(f"Envelope Definition JSON:\n{json.dumps(envelope_definition, indent=2)}")
    
    resp = requests.post(url, headers=headers, json=envelope_definition)
    
    print(f"Response Status Code: {resp.status_code}")
    print(f"Response Headers: {resp.headers}")
    print(f"Response Body: {resp.text}")
    
    if not resp.ok:
        try:
            error_details = resp.json()
            print(f"Error Details: {json.dumps(error_details, indent=2)}")
        except:
            print(f"Could not parse error response as JSON")
        raise Exception(f"Failed to create envelope. Status: {resp.status_code}, Response: {resp.text}")
    
    response_json = resp.json()
    print(f"Create Envelope API Response (JSON):\n{json.dumps(response_json, indent=2)}")
    envelope_id = response_json.get("envelopeId")
    if not envelope_id:
        raise Exception(f"Failed to create envelope. No envelopeId in response: {resp.text}")
    return envelope_id

# ...existing code...

def create_and_send_envelope(access_token, signer_email, signer_name):
    """
    Creates an envelope with a document, recipient, and digital signature tabs,
    then sends it for signing.
    Returns the envelope ID.
    """
    # Build signer configuration with enhanced tabs and Universal Signature Pen
    signer_config = {
        "email": signer_email,
        "name": signer_name,
        "recipientId": "1",
        "clientUserId": CLIENT_USER_ID, # Important for embedded signing
        "routingOrder": "1",
        "deliveryMethod": "email",
        "recipientSignatureProviders": [
            {
                "signatureProviderName": "UniversalSignaturePen_OpenTrust_Hash_TSP",
                "signatureProviderOptions": {
                    "oneTimePassword": "123456"  # You can make this dynamic or configurable
                }
            }
        ],
        "tabs": {
            "signHereTabs": [
                {
                    "anchorString": "/sn1/",
                    "anchorUnits": "pixels",
                    "anchorXOffset": "20",
                    "anchorYOffset": "10",
                    "tabLabel": "SignHereTab1",
                    "name": "Sign Here",
                    "optional": "false",
                    "scaleValue": 1
                },
                {
                    # Add a second sign here tab at absolute position if no anchor found
                    "documentId": DOCUMENT_ID,
                    "pageNumber": "1",
                    "xPosition": "100",
                    "yPosition": "200",
                    "tabLabel": "SignHereTab2",
                    "name": "Signature",
                    "optional": "false",
                    "scaleValue": 1
                }
            ],
            "dateSignedTabs": [
                {
                    "documentId": DOCUMENT_ID,
                    "pageNumber": "1", 
                    "xPosition": "300",
                    "yPosition": "200",
                    "tabLabel": "DateSignedTab",
                    "name": "Date Signed"
                }
            ],
            "fullNameTabs": [
                {
                    "documentId": DOCUMENT_ID,
                    "pageNumber": "1",
                    "xPosition": "100", 
                    "yPosition": "150",
                    "tabLabel": "FullNameTab",
                    "name": "Full Name"
                }
            ]
        }
    }

    witness_config = {
        "witnessFor": "1",
        "ev": "witness_email@example.com", # The witness's actual email
        "name": "Witness Name",
        "recipientId": "2",
        "routingOrder": "2",
        "deliveryMethod": "email", # Ensures email notification is sent
        # NO "clientUserId" KEY HERE
        "tabs": {
            "signHereTabs": [
                {
                    "documentId": "1",
                    "pageNumber": "1",
                    "xPosition": "190",
                    "yPosition": "247"
                }
            ]
        }
    }
    
    envelope_definition = {
        "emailSubject": "Please sign this document with Universal Signature Pen",
        "documents": [
            {
                "documentBase64": doc_b64,
                "name": DOCUMENT_NAME,
                "fileExtension": DOCUMENT_NAME.split('.')[-1],
                "documentId": DOCUMENT_ID
            }
        ],
        "recipients": {
            "signers": [signer_config],
            "witnesses": [witness_config]
        },
        "status": "sent" # Setting status to "sent" immediately sends the envelope
    }
    
    url = f"{BASE_PATH}/v2.1/accounts/{ACCOUNT_ID}/envelopes"
    headers = {
        "Authorization": f"Bearer {access_token}", # Use the generated token    
        "Content-Type": "application/json"
    }
    
    print(f"Envelope Definition JSON:\n{json.dumps(envelope_definition, indent=2)}")
    
    resp = requests.post(url, headers=headers, json=envelope_definition)
    
    print(f"Response Status Code: {resp.status_code}")
    print(f"Response Headers: {resp.headers}")
    print(f"Response Body: {resp.text}")
    
    if not resp.ok:
        try:
            error_details = resp.json()
            print(f"Error Details: {json.dumps(error_details, indent=2)}")
        except:
            print(f"Could not parse error response as JSON")
        raise Exception(f"Failed to create envelope. Status: {resp.status_code}, Response: {resp.text}")
    
    response_json = resp.json()
    print(f"Create Envelope API Response (JSON):\n{json.dumps(response_json, indent=2)}")
    envelope_id = response_json.get("envelopeId")
    if not envelope_id:
        raise Exception(f"Failed to create envelope. No envelopeId in response: {resp.text}")
    return envelope_id

def generate_recipient_view(access_token, envelope_id, signer_email, signer_name):
    """
    Generates the recipient view URL for an embedded signer.
    """
    url = f"{BASE_PATH}/v2.1/accounts/{ACCOUNT_ID}/envelopes/{envelope_id}/views/recipient"
    headers = {
        "Authorization": f"Bearer {access_token}", # Use the generated token
        "Content-Type": "application/json"
    }
    data = {
        "returnUrl": "http://localhost:5000/return", # URL to redirect to after signing
        "authenticationMethod": "None",
        "email": signer_email,
        "userName": signer_name,
        "clientUserId": CLIENT_USER_ID # Must match the clientUserId in the envelope definition
    }
    
    print(f"Recipient View Request JSON:\n{json.dumps(data, indent=2)}")
    
    resp = requests.post(url, headers=headers, json=data)
    
    print(f"Recipient View Response Status Code: {resp.status_code}")
    print(f"Recipient View Response Body: {resp.text}")
    
    if not resp.ok:
        try:
            error_details = resp.json()
            print(f"Recipient View Error Details: {json.dumps(error_details, indent=2)}")
        except:
            print(f"Could not parse recipient view error response as JSON")
        raise Exception(f"Failed to generate recipient view URL. Status: {resp.status_code}, Response: {resp.text}")
    
    response_json = resp.json()
    print(f"Generate Recipient View API Response (JSON):\n{json.dumps(response_json, indent=2)}")
    recipient_view_url = response_json.get("url")
    if not recipient_view_url:
        raise Exception(f"Failed to generate recipient view URL. No 'url' in response: {resp.text}")
    return recipient_view_url
@app.route('/return')
def return_url():
    event = request.args.get('event')
    if event == 'signing_complete':
        return "Signing complete successfully! You can close this window or navigate back to the application."
    elif event == 'cancel':
        return "Signing session was cancelled. You can close this window."
    elif event == 'decline':
        return "Signing was declined. You can close this window."
    else:
        return f"Signing session ended with event: {event}. You can close this window."
if __name__ == '__main__':
    # Install required libraries:
    # pip install Flask requests python-jose cryptography
    app.run(debug=True)