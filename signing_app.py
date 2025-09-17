# Find this function and replace the whole thing
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
                "clientUserId": "1000",
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