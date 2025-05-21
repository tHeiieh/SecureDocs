# Import necessary libraries for the application
import os  # For file system operations and environment variables
import pyotp  # For generating and verifying TOTP (2FA)
import qrcode  # For generating QR codes for 2FA setup
import jwt  # For JSON Web Token handling
import datetime  # For handling timestamps
from datetime import UTC  # For timezone-aware datetime
import hmac  # For generating HMAC for file integrity
import secrets  # For generating secure random tokens
from flask import Flask, request, render_template, redirect, url_for, flash, session, make_response  # Flask web framework components
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user  # For user session management
from authlib.integrations.flask_client import OAuth  # For OAuth-based SSO
from werkzeug.utils import secure_filename  # For secure file handling
from werkzeug.security import generate_password_hash, check_password_hash  # For password hashing
from Crypto.Cipher import AES  # For AES encryption
from Crypto.Hash import SHA256  # For SHA-256 hashing
from flask_sqlalchemy import SQLAlchemy  # For database ORM
from functools import wraps  # For creating decorators
import re  # For password validation regex
from cryptography.hazmat.primitives import serialization, hashes  # For RSA key handling and signing
from cryptography.hazmat.primitives.asymmetric import rsa, padding  # For RSA encryption and signature padding
from cryptography.hazmat.backends import default_backend  # For cryptographic backend
import smtplib  # For sending emails
from email.mime.text import MIMEText  # For email text content
from email.mime.multipart import MIMEMultipart  # For multipart email messages

# Initialize Flask application
app = Flask(__name__)
# Set a secure secret key for session management
app.secret_key = os.urandom(24).hex()
# Define upload folder for storing files
UPLOAD_FOLDER = 'Uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
# Configure SQLite database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///securedocs.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Disable modification tracking for performance

# Email configuration for password reset emails
SMTP_SERVER = 'smtp.gmail.com'  # SMTP server for Gmail
SMTP_PORT = 587  # TLS port for Gmail
SMTP_USERNAME = 'mohamednasserelmasry123@gmail.com'  # Replace with your Gmail address
SMTP_PASSWORD = 'qhvn qbnr smqp vbcz'  # Replace with your Gmail App Password

# Add min function to Jinja2 environment for template use
app.jinja_env.globals.update(min=min)

# Initialize SQLAlchemy for database operations
db = SQLAlchemy(app)

# JWT Configuration for session tokens
JWT_SECRET = os.urandom(32).hex()  # Generate a random secret for JWT
JWT_ALGORITHM = 'HS256'  # Algorithm for JWT signing
JWT_EXPIRATION_MINUTES = 30  # Token expiration time

# AES Encryption Key (32 bytes for AES-256)
# In production, use a key management system instead of hardcoding
ENCRYPTION_KEY = b'ThisIsASecretKey1234567890123456'
# HMAC Key for file integrity checks
HMAC_KEY = b'ThisIsAHMACKey1234567890123456'

# Initialize Flask-Login for user session management
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'  # Redirect to login page if not authenticated

# Initialize OAuth for SSO integration
oauth = OAuth(app)

# Configure Okta SSO
oauth.register(
    name='okta',
    client_id='A9lM3BtJrYiXdwmGNZkg6MFqpNLTTBi4',
    client_secret='9Ax1XEHSoJyrU9cr8Ta-zVpBr4MhZM9AaPGYoTmzRTbFRkARXpLYHScbXWGHFmIB',
    server_metadata_url='https://dev-f0iw6qa3vsqzg6ad.us.auth0.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid profile email'},
)


# Function to generate or load RSA key pair for file signing
def generate_key_pair():
    private_key_path = 'certs/signing_key.pem'
    public_key_path = 'certs/signing_pub.pem'
    
    # Create certs directory if it doesn't exist
    if not os.path.exists('certs'):
        os.makedirs('certs')
    
    # Generate new key pair if files don't exist
    if not os.path.exists(private_key_path) or not os.path.exists(public_key_path):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        
        # Save private key to file
        with open(private_key_path, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        # Save public key to file
        with open(public_key_path, 'wb') as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
    
    # Load keys from files
    with open(private_key_path, 'rb') as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    with open(public_key_path, 'rb') as f:
        public_key = serialization.load_pem_public_key(
            f.read(),
            backend=default_backend()
        )
    
    return private_key, public_key

# Generate or load RSA key pair
PRIVATE_KEY, PUBLIC_KEY = generate_key_pair()

# Database Models
class User(UserMixin, db.Model):
    # Define User model with necessary fields
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(200))  # Hashed password
    totp_secret = db.Column(db.String(32))  # Secret for TOTP 2FA
    role = db.Column(db.String(10), default='User')  # User or Admin role
    email = db.Column(db.String(150), unique=True, nullable=False)
    name = db.Column(db.String(150))

    def verify_password(self, password):
        # Verify password against stored hash
        return check_password_hash(self.password_hash, password)

    def verify_totp(self, token):
        # Verify TOTP token
        totp = pyotp.TOTP(self.totp_secret)
        return totp.verify(token)

class File(db.Model):
    # Define File model for storing file metadata
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(255), nullable=False)
    encrypted_path = db.Column(db.String(255), nullable=False)  # Path to encrypted file
    signature_path = db.Column(db.String(255), nullable=False)  # Path to signature
    hmac_value = db.Column(db.String(64), nullable=False)  # HMAC for integrity
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=datetime.datetime.now(UTC))
    description = db.Column(db.Text, nullable=True)  # File description
    user = db.relationship('User', backref=db.backref('files', lazy=True))

class AuditLog(db.Model):
    # Define AuditLog model for tracking user actions
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    action = db.Column(db.String(255), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.now(UTC))
    details = db.Column(db.Text)
    user = db.relationship('User', backref=db.backref('audit_logs', lazy=True))

class PasswordResetToken(db.Model):
    # Define PasswordResetToken model for password reset functionality
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(100), unique=True, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    used = db.Column(db.Boolean, default=False)
    user = db.relationship('User', backref=db.backref('reset_tokens', lazy=True))

# Flask-Login user loader
@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

# Decorator to restrict routes to admin users
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'Admin':
            flash('Access denied. Admin role required.')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Validate password against policy
def validate_password(password):
    # Ensure password meets complexity requirements
    if len(password) < 8:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'[0-9]', password):
        return False
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        return False
    return True

# Generate Json web token for session 
def generate_jwt(username):
    payload = {
        'sub': username,
        'exp': datetime.datetime.now(UTC) + datetime.timedelta(minutes=JWT_EXPIRATION_MINUTES)
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

# Verify JWT
def verify_jwt(token):
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
        return None

# Log user actions to AuditLog
def log_action(user_id, action, details=None):
    audit_log = AuditLog(user_id=user_id, action=action, details=details)
    db.session.add(audit_log)
    db.session.commit()

# Send password reset email
def send_reset_email(email, token):
    msg = MIMEMultipart()
    msg['From'] = SMTP_USERNAME
    msg['To'] = email
    msg['Subject'] = 'Password Reset Request'
    
    reset_url = url_for('reset_password', token=token, _external=True, _scheme='https')
    body = f"""
    Hello,

    You have requested to reset your password. Please click the link below to reset your password:
    {reset_url}

    This link will expire in 1 hour. If you did not request a password reset, please ignore this email or contact support.
    
    Do not share this link with anyone.

    Best regards,
    SecureDocs Team
    """
    msg.attach(MIMEText(body, 'plain'))
    
    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USERNAME, SMTP_PASSWORD)
            server.send_message(msg)
        return True
    except Exception as e:
        print(f"Error sending email: {str(e)}")
        return False

# Initialize admin user if it doesn't exist
def init_admin_user():
    admin_username = 'admin'
    admin_email = 'admin@example.com'
    admin_password = 'admin123@'
    
    if not db.session.get(User, User.query.filter_by(username=admin_username).first().id if User.query.filter_by(username=admin_username).first() else None):
        totp_secret = pyotp.random_base32()
        password_hash = generate_password_hash(admin_password)
        admin_user = User(
            username=admin_username,
            password_hash=password_hash,
            totp_secret=totp_secret,
            role='Admin',
            email=admin_email,
            name='Administrator'
        )
        db.session.add(admin_user)
        db.session.commit()
        
        # Generate QR code for admin 2FA
        uri = pyotp.TOTP(totp_secret).provisioning_uri(name=admin_username, issuer_name="SecureDocs")
        img = qrcode.make(uri)
        os.makedirs("static/qrcodes", exist_ok=True)
        img_path = f"static/qrcodes/{admin_username}.png"
        img.save(img_path)
        
        log_action(admin_user.id, 'Admin User Creation', f'Created admin user: {admin_username}')

# Generate CSRF token for session
@app.before_request
def generate_csrf_token():
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(16)

# Initialize database and admin user
with app.app_context():
    db.create_all()
    init_admin_user()

# Route for index page (redirects to login)
@app.route('/')
def index():
    return redirect(url_for('login'))

# Route for user registration
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        password_confirm = request.form['password_confirm']
        email = request.form['email']
        name = request.form['name']

        # Validate password match
        if password != password_confirm:
            flash('Passwords do not match.')
            return redirect(url_for('register'))

        # Check for existing username or email
        if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
            flash('Username or email already exists.')
            return redirect(url_for('register'))

        # Validate password complexity
        if not validate_password(password):
            flash('Password must be at least 8 characters, with uppercase, lowercase, numbers, and special characters.')
            return redirect(url_for('register'))

        # Create new user
        totp_secret = pyotp.random_base32()
        password_hash = generate_password_hash(password)
        user = User(username=username, password_hash=password_hash, totp_secret=totp_secret, email=email, name=name)
        db.session.add(user)
        db.session.commit()

        # Generate QR code for 2FA
        uri = pyotp.TOTP(totp_secret).provisioning_uri(name=username, issuer_name="SecureDocs")
        img = qrcode.make(uri)
        os.makedirs("static/qrcodes", exist_ok=True)
        img_path = f"static/qrcodes/{username}.png"
        img.save(img_path)

        log_action(user.id, 'User Registration', f'User {username} registered')
        flash("Scan the QR code and then login with your OTP.")
        return redirect(url_for('two_factor', username=username))

    return render_template('register.html')

# Route for user login
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and user.verify_password(password):
            log_action(user.id, 'Login Attempt', 'Successful password verification')
            return redirect(url_for('two_factor', username=username))
        else:
            log_action(None, 'Login Attempt', f'Failed login for username {username}')
            flash('Invalid username or password.')
    return render_template('login.html')

# Route for password reset request
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        
        if not user:
            flash('This email address is not registered with us.')
            return redirect(url_for('forgot_password'))
        
        # Generate and store reset token
        token = secrets.token_urlsafe(32)
        expires_at = datetime.datetime.now(UTC) + datetime.timedelta(hours=1)
        reset_token = PasswordResetToken(
            user_id=user.id,
            token=token,
            expires_at=expires_at,
            used=False
        )
        db.session.add(reset_token)
        db.session.commit()
        
        # Send reset email
        if send_reset_email(email, token):
            log_action(user.id, 'Password Reset Request', f'Password reset requested for {email}')
            flash('A password reset link has been sent to your email.')
        else:
            log_action(user.id, 'Password Reset Request Failed', f'Failed to send password reset email for {email}')
            flash('Error sending password reset email. Please try again later.')
        
        return redirect(url_for('forgot_password'))
    
    return render_template('forgot_password.html')

# Route for password reset
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    reset_token = PasswordResetToken.query.filter_by(token=token, used=False).first()
    
    # Validate token expiration
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    if not reset_token or reset_token.expires_at.replace(tzinfo=datetime.timezone.utc) < now_utc:
        flash('The password reset link is invalid or has expired.')
        return redirect(url_for('forgot_password'))
    
    if request.method == 'POST':
        password = request.form['password']
        password_confirm = request.form['password_confirm']
        
        if password != password_confirm:
            flash('Passwords do not match.')
            return redirect(url_for('reset_password', token=token))
        
        if not validate_password(password):
            flash('Password must be at least 8 characters, with uppercase, lowercase, numbers, and special characters.')
            return redirect(url_for('reset_password', token=token))
        
        user = db.session.get(User, reset_token.user_id)
        if not user:
            flash('User not found.')
            return redirect(url_for('forgot_password'))
        
        # Update password and mark token as used
        user.password_hash = generate_password_hash(password)
        reset_token.used = True
        db.session.commit()
        
        log_action(user.id, 'Password Reset', f'Password reset successful for {user.email}')
        flash('Your password has been reset successfully. You can now log in with your new password.')
        return redirect(url_for('login'))
    
    return render_template('reset_password.html', token=token)

# Route for 2FA verification
@app.route('/2fa', methods=['GET', 'POST'])
def two_factor():
    if request.method == 'POST':
        otp = request.form['otp']
        username = request.form['username']
        user = User.query.filter_by(username=username).first()
        if user and user.verify_totp(otp):
            login_user(user)
            session['is_2fa_verified'] = True
            token = generate_jwt(username)
            session['jwt'] = token
            log_action(user.id, '2FA Login', 'Successful 2FA verification')
            return redirect(url_for('dashboard'))
        else:
            log_action(user.id if user else None, '2FA Attempt', 'Failed 2FA verification')
            flash('Invalid OTP. Try again.')
            return redirect(url_for('two_factor', username=username))

    username = request.args.get('username')
    user = User.query.filter_by(username=username).first()
    if not user:
        flash("User not found.")
        return redirect(url_for('login'))

    # Generate QR code for 2FA setup
    uri = pyotp.TOTP(user.totp_secret).provisioning_uri(name=username, issuer_name="SecureDocs")
    img = qrcode.make(uri)
    os.makedirs("static/qrcodes", exist_ok=True)
    img_path = f"static/qrcodes/{username}.png"
    img.save(img_path)
    return render_template('two_factor.html', username=username, qr_path=img_path)

# Route for Okta SSO login
@app.route('/login/okta')
def login_okta():
    redirect_uri = url_for('okta_callback', _external=True, _scheme='https')
    return oauth.okta.authorize_redirect(redirect_uri)

# Route for Google SSO login
@app.route('/login/google')
def login_google():
    redirect_uri = url_for('google_callback', _external=True, _scheme='https')
    return oauth.google.authorize_redirect(redirect_uri)

# Route for GitHub SSO login
@app.route('/login/github')
def login_github():
    redirect_uri = url_for('github_callback', _external=True, _scheme='https')
    return oauth.github.authorize_redirect(redirect_uri)

# Okta callback route
@app.route('/authorization-code/callback')
def okta_callback():
    token = oauth.okta.authorize_access_token()
    user_info = token.get('userinfo') or oauth.okta.parse_id_token(token)
    username = user_info['email']
    email = user_info['email']
    name = user_info.get('name', username.split('@')[0])

    user = User.query.filter_by(email=email).first()
    if not user:
        totp_secret = pyotp.random_base32()
        user = User(username=username, email=email, name=name, totp_secret=totp_secret)
        db.session.add(user)
    elif not user.totp_secret:
        user.totp_secret = pyotp.random_base32()
    db.session.commit()

    log_action(user.id, 'Okta SSO Login', f'User {username} logged in via Okta')
    return redirect(url_for('two_factor', username=username))

# Google callback route
@app.route('/google/callback')
def google_callback():
    token = oauth.google.authorize_access_token()
    user_info = token.get('userinfo') or oauth.google.parse_id_token(token)
    username = user_info['email']
    email = user_info['email']
    name = user_info.get('name', username.split('@')[0])

    user = User.query.filter_by(email=email).first()
    if not user:
        totp_secret = pyotp.random_base32()
        user = User(username=username, email=email, name=name, totp_secret=totp_secret)
        db.session.add(user)
    elif not user.totp_secret:
        user.totp_secret = pyotp.random_base32()
    db.session.commit()

    log_action(user.id, 'Google SSO Login', f'User {username} logged in via Google')
    return redirect(url_for('two_factor', username=username))

# GitHub callback route
@app.route('/github/callback')
def github_callback():
    token = oauth.github.authorize_access_token()
    user_info = oauth.github.get('user').json()
    username = user_info['login'] + '@github'
    email = user_info.get('email', username)
    name = user_info.get('name', username.split('@')[0])

    user = User.query.filter_by(email=email).first()
    if not user:
        totp_secret = pyotp.random_base32()
        user = User(username=username, email=email, name=name, totp_secret=totp_secret)
        db.session.add(user)
    elif not user.totp_secret:
        user.totp_secret = pyotp.random_base32()
    db.session.commit()

    log_action(user.id, 'GitHub SSO Login', f'User {username} logged in via GitHub')
    return redirect(url_for('two_factor', username=username))

# Dashboard route
@app.route('/dashboard')
@login_required
def dashboard():
    if not session.get('is_2fa_verified'):
        return redirect(url_for('two_factor', username=current_user.username))

    token = session.get('jwt')
    decoded = verify_jwt(token)
    if not decoded:
        log_action(current_user.id, 'Session Expired', 'User session expired')
        flash('Session expired. Please login again.')
        return redirect(url_for('login'))

    # Compute file count based on role
    file_count = File.query.count() if current_user.role == 'Admin' else File.query.filter_by(user_id=current_user.id).count()
    
    # Compute pending actions (files uploaded in last 24 hours)
    time_threshold = datetime.datetime.now(UTC) - datetime.timedelta(hours=24)
    pending_actions = File.query.filter(File.uploaded_at >= time_threshold).count() if current_user.role == 'Admin' else File.query.filter(File.user_id == current_user.id, File.uploaded_at >= time_threshold).count()
    
    files = File.query.filter_by(user_id=current_user.id).order_by(File.uploaded_at.desc()).limit(5).all() if current_user.role != 'Admin' else File.query.order_by(File.uploaded_at.desc()).limit(5).all()
    response = make_response(render_template('dashboard.html', username=current_user.username, role=current_user.role, file_count=file_count, files=files, pending_actions=pending_actions))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

# File upload route
@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    if not session.get('is_2fa_verified'):
        return redirect(url_for('two_factor', username=current_user.username))

    if request.method == 'POST':
        file = request.files.get('document')
        user_id = request.form.get('user_id', current_user.id)  # Admin can specify user_id
        description = request.form.get('description', '').strip()  # Get file description
        if not file or not file.filename:
            flash("No file selected.")
            return redirect(request.url)

        # Validate file type
        if not file.filename.lower().endswith(('.pdf', '.docx', '.txt')):
            flash("Only PDF, DOCX, and TXT files are allowed.")
            return redirect(request.url)

        # Verify user_id for Admins
        upload_user = db.session.get(User, user_id) if current_user.role == 'Admin' else current_user
        if not upload_user:
            flash("Invalid user selected.")
            return redirect(request.url)

        try:
            os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)

            # Read and save raw file
            raw_data = file.read()
            if not raw_data:
                flash("Empty file uploaded.")
                return redirect(request.url)

            with open(file_path, 'wb') as f:
                f.write(raw_data)

            # Compute HMAC and hash
            hash_obj = SHA256.new(raw_data)
            hmac_obj = hmac.new(HMAC_KEY, raw_data, digestmod=SHA256)
            hmac_value = hmac_obj.hexdigest()

            # Encrypt file
            cipher = AES.new(ENCRYPTION_KEY, AES.MODE_EAX)
            ciphertext, tag = cipher.encrypt_and_digest(raw_data)

            encrypted_file_path = file_path + '.enc'
            with open(encrypted_file_path, 'wb') as ef:
                ef.write(cipher.nonce + tag + ciphertext)

            # Sign file
            signed_file_path = file_path + '.sig'
            signature = PRIVATE_KEY.sign(
                raw_data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            with open(signed_file_path, 'wb') as sf:
                sf.write(signature)

            # Log debug info
            log_action(current_user.id, 'File Upload Debug', 
                      f'File: {filename}, Raw data size: {len(raw_data)}, Signature size: {len(signature)}, For user: {upload_user.username}')

            # Store file record
            file_record = File(
                filename=filename,
                encrypted_path=encrypted_file_path,
                signature_path=signed_file_path,
                hmac_value=hmac_value,
                user_id=upload_user.id,
                description=description
            )
            db.session.add(file_record)
            db.session.commit()

            log_action(current_user.id, 'File Upload', f'Uploaded file: {filename} for user: {upload_user.username}')
            flash('File uploaded, encrypted, and signed successfully!')
            return redirect(url_for('upload'))

        except OSError as e:
            flash(f'File operation error: {str(e)}')
            log_action(current_user.id, 'File Upload Error', f'Failed to upload file: {filename}, Error: {str(e)}')
            return redirect(request.url)
        except Exception as e:
            flash(f'Error processing file: {str(e)}')
            log_action(current_user.id, 'File Upload Error', f'Failed to upload file: {filename}, Error: {str(e)}')
            return redirect(request.url)

    users = User.query.all() if current_user.role == 'Admin' else []
    return render_template('upload.html', users=users, role=current_user.role)

# Route to edit file metadata
@app.route('/edit_file/<int:file_id>', methods=['POST'])
@login_required
def edit_file(file_id):
    if not session.get('is_2fa_verified'):
        return redirect(url_for('two_factor', username=current_user.username))

    file_record = db.session.get(File, file_id)
    if not file_record or (file_record.user_id != current_user.id and current_user.role != 'Admin'):
        flash('File not found or access denied.')
        return redirect(url_for('list_files'))

    new_filename = request.form.get('new_filename')
    new_description = request.form.get('new_description')
    if not new_filename:
        flash('New filename cannot be empty.')
        return redirect(url_for('list_files'))

    new_filename = secure_filename(new_filename)
    if not new_filename.lower().endswith(('.pdf', '.docx', '.txt')):
        flash('New filename must end with .pdf, .docx, or .txt.')
        return redirect(url_for('list_files'))

    try:
        file_record.filename = new_filename
        if new_description is not None:
            file_record.description = new_description.strip()
        db.session.commit()
        log_action(current_user.id, 'File Edit', f'Edited filename of file ID {file_id} to {new_filename}, description updated.')
        flash('File name and description updated successfully.')
    except Exception as e:
        flash(f'Error updating file: {str(e)}')
        log_action(current_user.id, 'File Edit Error', f'Failed to edit file ID {file_id}, Error: {str(e)}')
    return redirect(url_for('list_files'))

# Route to list files
@app.route('/files')
@login_required
def list_files():
    if not session.get('is_2fa_verified'):
        return redirect(url_for('two_factor', username=current_user.username))

    token = session.get('jwt')
    decoded = verify_jwt(token)
    if not decoded:
        flash('Session expired. Please login again.')
        return redirect(url_for('login'))

    files = File.query.filter_by(user_id=current_user.id).all() if current_user.role != 'Admin' else File.query.all()
    response = make_response(render_template('files.html', files=files, role=current_user.role))
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    return response

# Route to download files
@app.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    if not session.get('is_2fa_verified'):
        return redirect(url_for('two_factor', username=current_user.username))

    file_record = db.session.get(File, file_id)
    if not file_record or (file_record.user_id != current_user.id and current_user.role != 'Admin'):
        flash('File not found or access denied.')
        return redirect(url_for('list_files'))

    try:
        with open(file_record.encrypted_path, 'rb') as ef:
            data = ef.read()
            nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
            cipher = AES.new(ENCRYPTION_KEY, AES.MODE_EAX, nonce=nonce)
            decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)

        hmac_obj = hmac.new(HMAC_KEY, decrypted_data, digestmod=SHA256)
        computed_hmac = hmac_obj.hexdigest()
        if computed_hmac != file_record.hmac_value:
            flash(f'Integrity check failed. Computed HMAC: {computed_hmac}, Stored HMAC: {file_record.hmac_value}')
            log_action(current_user.id, 'File Download', f'Integrity check failed for file: {file_record.filename}')
            return redirect(url_for('list_files'))

        log_action(current_user.id, 'File Download', f'Downloaded file: {file_record.filename}')
        response = make_response(decrypted_data)
        response.headers['Content-Disposition'] = f'attachment; filename={file_record.filename}'
        response.headers['Content-Type'] = 'application/octet-stream'
        return response
    except Exception as e:
        flash(f'Error decrypting file: {str(e)}')
        log_action(current_user.id, 'File Download Error', f'Failed to download file: {file_record.filename}, Error: {str(e)}')
        return redirect(url_for('list_files'))

# Route to verify file signatures
@app.route('/verify/<int:file_id>')
@login_required
def verify_signature(file_id):
    if not session.get('is_2fa_verified'):
        return redirect(url_for('two_factor', username=current_user.username))

    file_record = db.session.get(File, file_id)
    if not file_record or (file_record.user_id != current_user.id and current_user.role != 'Admin'):
        flash('File not found or access denied.')
        return redirect(url_for('list_files'))

    try:
        original_file_path = file_record.encrypted_path.replace('.enc', '')
        signature_file_path = file_record.signature_path

        if not os.path.exists(original_file_path):
            flash(f'Original file not found: {original_file_path}')
            log_action(current_user.id, 'Signature Verification', f'Failed to verify file: {file_record.filename}, Original file missing')
            return redirect(url_for('list_files'))

        if not os.path.exists(signature_file_path):
            flash(f'Signature file not found: {signature_file_path}')
            log_action(current_user.id, 'Signature Verification', f'Failed to verify file: {file_record.filename}, Signature file missing')
            return redirect(url_for('list_files'))

        with open(original_file_path, 'rb') as f:
            original_data = f.read()
        with open(signature_file_path, 'rb') as sf:
            signature = sf.read()

        if not original_data:
            flash('Original file is empty.')
            log_action(current_user.id, 'Signature Verification', f'Failed to verify file: {file_record.filename}, Empty original file')
            return redirect(url_for('list_files'))

        if not signature:
            flash('Signature file is empty.')
            log_action(current_user.id, 'Signature Verification', f'Failed to verify file: {file_record.filename}, Empty signature file')
            return redirect(url_for('list_files'))

        log_action(current_user.id, 'Signature Verification Debug', 
                  f'File: {file_record.filename}, Original size: {len(original_data)}, Signature size: {len(signature)}')

        PUBLIC_KEY.verify(
            signature,
            original_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        log_action(current_user.id, 'Signature Verification', f'Verified file: {file_record.filename}')
        flash('Signature verification successful!')
    except ValueError as e:
        flash(f'Signature verification failed: Invalid signature - {str(e)}')
        log_action(current_user.id, 'Signature Verification', f'Failed to verify file: {file_record.filename}, Error: Invalid signature - {str(e)}')
    except Exception as e:
        flash(f'Signature verification failed: {str(e)}')
        log_action(current_user.id, 'Signature Verification', f'Failed to verify file: {file_record.filename}, Error: {str(e)}')
    return redirect(url_for('list_files'))

# Route to delete files
@app.route('/delete/<int:file_id>', methods=['POST'])
@login_required
def delete_file(file_id):
    if not session.get('is_2fa_verified'):
        return redirect(url_for('two_factor', username=current_user.username))

    file_record = db.session.get(File, file_id)
    if not file_record or (file_record.user_id != current_user.id and current_user.role != 'Admin'):
        flash('File not found or access denied.')
        return redirect(url_for('list_files'))

    try:
        os.remove(file_record.encrypted_path)
        os.remove(file_record.signature_path)
        os.remove(file_record.encrypted_path.replace('.enc', ''))
        db.session.delete(file_record)
        db.session.commit()
        log_action(current_user.id, 'File Deletion', f'Deleted file: {file_record.filename}')
        flash('File deleted successfully.')
    except Exception as e:
        flash(f'Error deleting file: {str(e)}')
        log_action(current_user.id, 'File Deletion Error', f'Failed to delete file: {file_record.filename}, Error: {str(e)}')
    return redirect(url_for('list_files'))

# Route to manage user profile
@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if not session.get('is_2fa_verified'):
        return redirect(url_for('two_factor', username=current_user.username))

    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form.get('password')
        password_confirm = request.form.get('password_confirm')

        if email != current_user.email and User.query.filter_by(email=email).first():
            flash('Email already in use.')
            return redirect(url_for('profile'))

        if password and password != password_confirm:
            flash('Passwords do not match.')
            return redirect(url_for('profile'))

        current_user.name = name
        current_user.email = email
        if password and validate_password(password):
            current_user.password_hash = generate_password_hash(password)
        elif password:
            flash('Invalid password format.')
            return redirect(url_for('profile'))

        db.session.commit()
        log_action(current_user.id, 'Profile Update', f'Updated profile for {current_user.username}')
        flash('Profile updated successfully.')
        return redirect(url_for('profile'))

    return render_template('profile.html', user=current_user)

# Route for admin user management
@app.route('/admin/users', methods=['GET', 'POST'])
@admin_required
def manage_users():
    if request.method == 'POST':
        action = request.form['action']
        if action == 'add_user':
            username = request.form['username']
            email = request.form['email']
            name = request.form['name']
            password = request.form['password']
            role = request.form['role']

            if User.query.filter_by(username=username).first() or User.query.filter_by(email=email).first():
                flash('Username or email already exists.')
                return redirect(url_for('manage_users'))

            if not validate_password(password):
                flash('Password must be at least 8 characters, with uppercase, lowercase, numbers, and special characters.')
                return redirect(url_for('manage_users'))

            totp_secret = pyotp.random_base32()
            password_hash = generate_password_hash(password)
            user = User(
                username=username,
                password_hash=password_hash,
                totp_secret=totp_secret,
                email=email,
                name=name,
                role=role
            )
            db.session.add(user)
            db.session.commit()

            uri = pyotp.TOTP(totp_secret).provisioning_uri(name=username, issuer_name="SecureDocs")
            img = qrcode.make(uri)
            os.makedirs("static/qrcodes", exist_ok=True)
            img_path = f"static/qrcodes/{username}.png"
            img.save(img_path)

            log_action(current_user.id, 'User Creation', f'Created user: {username} with role {role}')
            flash(f'User {username} created successfully.')
        elif action == 'delete':
            user_id = request.form['user_id']
            user = db.session.get(User, user_id)
            if not user:
                flash('User not found.')
                return redirect(url_for('manage_users'))
            db.session.delete(user)
            db.session.commit()
            log_action(current_user.id, 'User Deletion', f'Deleted user: {user.username}')
            flash('User deleted successfully.')
        elif action == 'change_role':
            user_id = request.form['user_id']
            new_role = request.form['role']
            user = db.session.get(User, user_id)
            if not user:
                flash('User not found.')
                return redirect(url_for('manage_users'))
            if new_role in ['User', 'Admin']:
                user.role = new_role
                db.session.commit()
                log_action(current_user.id, 'Role Change', f'Changed role of {user.username} to {new_role}')
                flash(f'User role changed to {new_role}.')
        elif action == 'edit_user':
            user_id = request.form['user_id']
            username = request.form.get('username')
            email = request.form['email']
            name = request.form['name']
            user = db.session.get(User, user_id)
            if not user:
                flash('User not found.')
                return redirect(url_for('manage_users'))
            if username != user.username and User.query.filter_by(username=username).first():
                flash('Username already in use.')
                return redirect(url_for('manage_users'))
            if email != user.email and User.query.filter_by(email=email).first():
                flash('Email already in use.')
                return redirect(url_for('manage_users'))
            user.username = username
            user.email = email
            user.name = name
            db.session.commit()
            log_action(current_user.id, 'User Edit', f'Edited user: {username}, new email: {email}, new name: {name}')
            flash('User information updated successfully.')
        return redirect(url_for('manage_users'))

    users = User.query.all()
    files = File.query.all()
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()
    return render_template('admin.html', users=users, files=files, logs=logs)

# Route for admin audit logs
@app.route('/admin/logs')
@admin_required
def audit_logs():
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()
    return render_template('audit_logs.html', logs=logs)

# Route for logout
@app.route('/logout')
@login_required
def logout():
    user_id = current_user.id
    logout_user()
    session.pop('jwt', None)
    session.pop('is_2fa_verified', None)
    log_action(user_id, 'Logout', 'User logged out')
    flash('Logged out successfully.')
    return redirect(url_for('login'))

# Add security headers to all responses
@app.after_request
def apply_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

# Run the application with SSL
if __name__ == '__main__':
    app.run(ssl_context=('certs/server.crt', 'certs/server.key'), host='0.0.0.0', port=5000, debug=True)