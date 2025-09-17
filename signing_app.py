import base64
import logging
from datetime import datetime, timedelta
from flask import Flask, request
import requests
import json

# Import the official DocuSign SDK
from docusign_esign import ApiClient, EnvelopesApi

app = Flask(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# --- CONFIGURATION (Move to config.ini or environment variables for production) ---
INTEGRATION_KEY = 'dfba8887-518b-488d-a787-76794a3a6c9d'
USER_ID = 'f5e619d1-0227-42e9-96f5-17e82cd4fa4c'
ACCOUNT_ID = '5d72dc01-0dc7-4f64-9380-593270983810'
BASE_PATH = 'demo.docusign.net'  # e.g., demo.docusign.net for developer sandbox
OAUTH_HOST_NAME = 'account-d.docusign.com' # e.g., account-d.docusign.com for developer sandbox

# --- Helper Function for Authentication (Using DocuSign SDK) ---
def get_docusign_api_client():
    """
    Authenticates with DocuSign using JWT Grant and returns an API client.
    This is the robust method used by the official SDK.
    """
    try:
        api_client = ApiClient()
        api_client.host = f"https://{BASE_PATH}/restapi"
        
        with open("private.key", "rb") as key_file:
            private_key = key_file.read()

        token_response = api_client.request_jwt_user_token(
            client_id=INTEGRATION_KEY,
            user_id=USER_ID,
            oauth_host_name=OAUTH_HOST_NAME,
            private_key_bytes=private_key,
            expires_in=3600,
            scopes=["signature", "impersonation"]
        )
        access_token = token_response.access_token
        api_client.set_default_header("Authorization", "Bearer " + access_token)
        logging.info("DocuSign API client created and authenticated successfully.")
        return api_client
    except Exception as e:
        logging.error(f"Error creating DocuSign API client: {e}", exc_info=True)
        raise

# --- Routes ---
@app.route('/')
def home():
    # ... (Your HTML form code remains exactly the same)
    return """
    <h1>DocuSign Embedded Signing</h1>
    <form action="sign" method="post">
        <label for="signer_email">Signer Email:</label>
        <input type="email" name="signer_email" id="signer_email" required><br><br>
        <label for="signer_name">Signer Name:</label>
        <input type="text" name="signer_name" id="signer_name" required><br><br>
        <button type="submit">Create Envelope and Get Signing Link</button>
    </form>
    """

@app.route('/sign', methods=['POST'])
def sign_document():
    try:
        signer_email = request.form['signer_email']
        signer_name = request.form['signer_name']
        
        # 1. Get the authenticated API client
        api_client = get_docusign_api_client()

        # 2. Prepare and send the envelope
        envelope_definition = create_envelope_definition(signer_email, signer_name)
        envelopes_api = EnvelopesApi(api_client)
        results = envelopes_api.create_envelope(account_id=ACCOUNT_ID, envelope_definition=envelope_definition)
        envelope_id = results.envelope_id
        logging.info(f"Envelope created with ID: {envelope_id}")

        # 3. Create the recipient view for embedded signing
        recipient_view_request = {
            "returnUrl": "https://docusign.com", # Redirect URL after signing
            "authenticationMethod": "none",
            "email": signer_email,
            "userName": signer_name,
            "clientUserId": "1000" # Must match the clientUserId in the envelope
        }
        results = envelopes_api.create_recipient_view(account_id=ACCOUNT_ID, envelope_id=envelope_id, recipient_view_request=recipient_view_request)
        
        # 4. Return the signing URL
        signing_url = results.url
        return f"""
        <h1>Signing Link Generated</h1>
        <p><strong>Envelope ID:</strong> {envelope_id}</p>
        <p><a href="{signing_url}" target="_blank">Click Here to Sign</a></p>
        """
    except Exception as e:
        logging.error(f"An error occurred during the signing process: {e}", exc_info=True)
        return f"An error occurred: {e}", 500

def create_envelope_definition(signer_email, signer_name):
    """Creates the JSON definition for the envelope."""
    
    with open("sample pdf.pdf", "rb") as file:
        doc_b64 = base64.b64encode(file.read()).decode("ascii")

    return {
        "emailSubject": "Please sign this document",
        "documents": [{
            "documentBase64": doc_b64,
            "name": "Example Document",
            "fileExtension": "pdf",
            "documentId": "1"
        }],
        "recipients": {
            "signers": [{
                "email": signer_email,
                "name": signer_name,
                "recipientId": "1",
                "clientUserId": "1000", # Required for embedded signing
                "tabs": {
                    "signHereTabs": [
                        {
                            # This tab uses a fixed position on the first page.
                            # This will satisfy the "place signing tabs" requirement.
                            "xPosition": "100",
                            "yPosition": "150",
                            "documentId": "1",
                            "pageNumber": "1"
                        },
                        {
                            # The anchor string tab is kept as a fallback.
                            "anchorString": "/sn1/"
                        }
                    ]
                }
            }]
        },
        "status": "sent"
    }

if __name__ == '__main__':
    app.run(debug=True)