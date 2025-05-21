from app import app
from flask import request, redirect
from ssl import SSLContext, PROTOCOL_TLSv1_2
import os

# Force HTTPS redirect
@app.before_request
def enforce_https():
    if not request.is_secure:
        url = request.url.replace('http://', 'https://', 1)
        return redirect(url, code=301)

if __name__ == '__main__':
    # Verify certificate files exist
    cert_path = 'certs/server.crt'
    key_path = 'certs/server.key'
    
    if not os.path.exists(cert_path) or not os.path.exists(key_path):
        print(f"Error: Certificate files not found at {cert_path} or {key_path}")
        exit(1)
    
    # Create SSL context with strong ciphers
    context = SSLContext(PROTOCOL_TLSv1_2)
    context.load_cert_chain(cert_path, key_path)
    context.set_ciphers('ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256')
    
    # Run on standard HTTPS port
    app.run(ssl_context=context, host='0.0.0.0', port=443, debug=False)