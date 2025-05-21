# SecureDocs
# SecureDocs

SecureDocs is a secure document management web application built with Flask. It provides features such as user authentication with 2FA, file encryption, digital signatures, HMAC integrity checks, audit logging, and admin management.

## Features

- **User Registration & Login**
  - Password policy: minimum 8 characters, includes uppercase, lowercase, numbers, and special characters.
  - Unique username and email enforced.
  - Two-factor authentication (2FA) using TOTP (Google Authenticator).
  - SSO support: Okta, Google, GitHub.
- **File Management**
  - Upload PDF, DOCX, and TXT files.
  - Files are encrypted with AES-256.
  - Each file is signed with an RSA digital signature.
  - HMAC-SHA256 integrity check for every file.
  - File description support.
  - Download files with automatic decryption and integrity verification.
  - Edit file name and description.
  - Delete files securely.
  - Preview TXT and PDF files before upload.
- **User Profile**
  - Update name, email, and password.
  - Password change with strength meter and validation.
  - Delete account (with password confirmation).
- **Admin Panel**
  - Add, edit (username, email, name), delete users.
  - Change user roles (User/Admin).
  - View all users and their details.
  - Upload documents for any user.
  - View, edit, delete, and verify all documents.
  - View system audit logs.
- **Audit Logging**
  - All critical actions (login, file upload, edit, delete, user management, etc.) are logged with timestamp and details.
- **Security**
  - CSRF protection on all forms.
  - Security headers: X-Content-Type-Options, X-Frame-Options, X-XSS-Protection, Strict-Transport-Security.
  - HTTPS enforced (requires SSL certificates).
  - JWT-based session management.
  - QR code generation for 2FA setup.
- **Password Reset**
  - Secure password reset via email with expiring token.
  - Email sent using SMTP (Gmail App Password recommended).
- **UI/UX**
  - Modern, responsive design with glassmorphism and animated backgrounds.
  - Bootstrap 5, Animate.css, Boxicons, GSAP for animations.
  - Drag-and-drop file upload with progress bar.
  - Modal dialogs for editing and confirmation.
  - Custom error and success messages.

## Requirements

- Python 3.8+
- Flask
- Flask-Login
- Flask-SQLAlchemy
- Authlib
- pyotp
- qrcode
- pyjwt
- cryptography
- pycryptodome
- Bootstrap 5 (CDN)
- GSAP (CDN)
- Animate.css (CDN)
- Boxicons (CDN)
- SheetJS (for file preview, CDN)

Install dependencies with:

```bash
pip install -r requirements.txt
```

## Setup

1. Clone the repository.
2. Ensure you have a valid Gmail App Password for email sending.
3. Generate SSL certificates and place them in the `certs/` directory as `server.crt` and `server.key`.
4. Run the application:

```bash
python app.py
```

5. Access the app at [https://localhost:5000](https://localhost:5000).

## Configuration

- **Email**: Update `SMTP_USERNAME` and `SMTP_PASSWORD` in `app.py` with your Gmail address and app password.
- **OAuth/SSO**: Configure Okta, Google, and GitHub credentials in `app.py` as needed.
- **Encryption Keys**: The app generates and stores RSA keys in the `certs/` directory on first run.
- **Uploads**: Uploaded files are stored in the `Uploads/` directory, encrypted and signed.
- **Templates**: All HTML templates are in the `templates/` directory (or `cets/` if you changed the template folder).

## Usage

- **Register**: Create a new user account. Scan the QR code with Google Authenticator or similar app.
- **Login**: Enter your credentials, then provide the OTP from your authenticator app.
- **Upload Files**: Upload PDF, DOCX, or TXT files. Files are encrypted, signed, and integrity-protected.
- **Download Files**: Download and decrypt your files. Integrity is checked before download.
- **Verify Signature**: Verify the digital signature of any uploaded file.
- **Edit Files**: Change file name and description via modal dialog.
- **Admin Panel**: Admin users can manage users (add, edit username/email/name, delete, change role), view audit logs, and manage all files.
- **Password Reset**: Use the "Forgot Password" link to reset your password via email.
- **Profile**: Update your name, email, and password. Delete your account if needed.

## Project Structure

```
securedocs/
│
├── app.py                # Main Flask application
├── requirements.txt      # Python dependencies
├── certs/                # SSL and RSA key files
├── static/               # Static files (CSS, JS, QR codes)
├── templates/            # HTML templates (or 'cets/' if changed)
├── Uploads/              # Encrypted file storage
└── securedocs.db         # SQLite database
```

## Default Admin

- Username: `admin`
- Password: `admin123@`
- Email: `admin@example.com`

Change these credentials after first login.

## Security Notes

- Use strong, unique secrets for production.
- Configure SSL certificates for HTTPS.
- Set up proper SMTP credentials for email.
- Never share your 2FA secret or QR code.
- Regularly monitor audit logs for suspicious activity.
- All sensitive operations are logged for auditing.
- CSRF tokens are required for all POST forms.

## Technologies Used

- **Backend**: Flask, Flask-Login, Flask-SQLAlchemy, Authlib, pyotp, qrcode, pyjwt, cryptography, pycryptodome
- **Frontend**: Bootstrap 5, Animate.css, Boxicons, GSAP, SheetJS, custom CSS/JS
- **Security**: AES-256 encryption, RSA digital signatures, HMAC-SHA256, JWT, CSRF, HTTPS

## License

MIT License.
