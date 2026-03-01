from flask import Flask, render_template, request, redirect, url_for, flash, session, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import os
import pyotp
import qrcode
from io import BytesIO
import base64
import uuid
import logging
import functools
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import secrets
import warnings
from sqlalchemy import exc as sa_exc
warnings.simplefilter("default")
warnings.simplefilter("ignore", category=sa_exc.LegacyAPIWarning)

# Configure logging
logging.basicConfig(
    filename='security.log',
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('healthcare_security')

# App configuration
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///healthcare.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)  # Shorter session for security

# Setup database
db = SQLAlchemy(app)

# Setup login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = "Please log in to access this page."
login_manager.login_message_category = "warning"

# AES-256 Encryption Setup
def get_encryption_key():
    """Get or generate the AES-256 encryption key"""
    key = os.environ.get('ENCRYPTION_KEY')
    if key:
        try:
            # Convert from hex string to bytes
            return bytes.fromhex(key)
        except ValueError:
            logger.error("Invalid ENCRYPTION_KEY format in environment variables")
    
    # If no key or invalid key, generate a new one
    # This will reset all encrypted data if the server restarts without setting ENCRYPTION_KEY
    logger.warning("Generating new encryption key - all previous encrypted data will be lost!")
    return AESGCM.generate_key(bit_length=256)

# Initialize the AES-256 encryption key
ENCRYPTION_KEY = get_encryption_key()
aesgcm = AESGCM(ENCRYPTION_KEY)

def encrypt_data(data):
    """Encrypt data using AES-256-GCM"""
    if data is None:
        return None
    
    # Convert string to bytes if needed
    if isinstance(data, str):
        data = data.encode('utf-8')
    
    # Generate a random nonce (must be unique for each encryption)
    nonce = os.urandom(12)
    
    # Encrypt the data
    encrypted = aesgcm.encrypt(nonce, data, None)
    
    # Combine nonce and encrypted data for storage
    return base64.b64encode(nonce + encrypted).decode('utf-8')

def decrypt_data(encrypted_data):
    """Decrypt data that was encrypted with AES-256-GCM"""
    if encrypted_data is None:
        return None
    
    try:
        # Decode the base64 string
        data = base64.b64decode(encrypted_data)
        
        # Extract the nonce (first 12 bytes)
        nonce = data[:12]
        encrypted = data[12:]
        
        # Decrypt the data
        decrypted = aesgcm.decrypt(nonce, encrypted, None)
        
        return decrypted.decode('utf-8')
    except Exception as e:
        logger.error(f"Decryption error: {str(e)}")
        raise ValueError("Failed to decrypt data. The encryption key may have changed.")

# Models
class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    user_first_name = db.Column(db.String(80), nullable = False)
    user_last_name = db.Column(db.String(80), nullable = False)
    password_hash = db.Column(db.String(128), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    role = db.Column(db.String(20), nullable=False, default='patient')  # admin, doctor, patient
    totp_secret = db.Column(db.String(32), nullable=True)  # For 2FA
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.now)
    last_login = db.Column(db.DateTime, nullable=True)
    
    # Relationship to patient
    patient = db.relationship('Patient', backref='user', uselist=False)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def generate_totp_secret(self):
        """Generate a new TOTP secret for 2FA"""
        self.totp_secret = pyotp.random_base32()
        return self.totp_secret
    
    def get_totp_uri(self):
        """Get the TOTP URI for authenticator apps"""
        if not self.totp_secret:
            return None
        
        return pyotp.totp.TOTP(self.totp_secret).provisioning_uri(
            name=self.email,
            issuer_name="Secure Healthcare"
        )
    
    def verify_totp(self, token):
        """Verify a TOTP token"""
        if not self.totp_secret:
            return False
            
        totp = pyotp.TOTP(self.totp_secret)
        return totp.verify(token)

class Patient(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    first_name_encrypted = db.Column(db.Text, nullable=False)
    last_name_encrypted = db.Column(db.Text, nullable=False)
    dob_encrypted = db.Column(db.Text, nullable=False)
    address_encrypted = db.Column(db.Text, nullable=False)
    phone_encrypted = db.Column(db.Text, nullable=False)
    doctor_encrypted = db.Column(db.Text, nullable = False)
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)
    
    # Medical records relationship
    medical_records = db.relationship('MedicalRecord', backref='patient', lazy=True)
    
    @property
    def first_name(self):
        return decrypt_data(self.first_name_encrypted)
    
    @first_name.setter
    def first_name(self, value):
        self.first_name_encrypted = encrypt_data(value)
    
    @property
    def last_name(self):
        return decrypt_data(self.last_name_encrypted)
    
    @last_name.setter
    def last_name(self, value):
        self.last_name_encrypted = encrypt_data(value)
    
    @property
    def dob(self):
        return decrypt_data(self.dob_encrypted)
    
    @dob.setter
    def dob(self, value):
        self.dob_encrypted = encrypt_data(value)
    
    @property
    def address(self):
        return decrypt_data(self.address_encrypted)
    
    @address.setter
    def address(self, value):
        self.address_encrypted = encrypt_data(value)
    
    @property
    def phone(self):
        return decrypt_data(self.phone_encrypted)
    
    @phone.setter
    def phone(self, value):
        self.phone_encrypted = encrypt_data(value)

    @property
    def patient_doctor(self):
        try:
            return decrypt_data(self.doctor_encrypted)
        except Exception as e:
            logger.error(f"Error decrypting doctor for patient {self.id}: {e}")
            return "[Decryption Error]"
    
    @patient_doctor.setter
    def patient_doctor(self, value):
        self.doctor_encrypted = encrypt_data(value)

class MedicalRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patient.id'), nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    record_type = db.Column(db.String(50), nullable=False)
    diagnosis_encrypted = db.Column(db.Text, nullable=True)
    treatment_encrypted = db.Column(db.Text, nullable=True)
    medication_encrypted = db.Column(db.Text, nullable=True)
    notes_encrypted = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.now)
    updated_at = db.Column(db.DateTime, default=datetime.now, onupdate=datetime.now)
    
    # Doctor relationship
    doctor = db.relationship('User', backref='medical_records')
    
    @property
    def diagnosis(self):
        return decrypt_data(self.diagnosis_encrypted) if self.diagnosis_encrypted else None
    
    @diagnosis.setter
    def diagnosis(self, value):
        self.diagnosis_encrypted = encrypt_data(value) if value else None
    
    @property
    def treatment(self):
        return decrypt_data(self.treatment_encrypted) if self.treatment_encrypted else None
    
    @treatment.setter
    def treatment(self, value):
        self.treatment_encrypted = encrypt_data(value) if value else None
    
    @property
    def medication(self):
        return decrypt_data(self.medication_encrypted) if self.medication_encrypted else None
    
    @medication.setter
    def medication(self, value):
        self.medication_encrypted = encrypt_data(value) if value else None
    
    @property
    def notes(self):
        return decrypt_data(self.notes_encrypted) if self.notes_encrypted else None
    
    @notes.setter
    def notes(self, value):
        self.notes_encrypted = encrypt_data(value) if value else None

class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    action = db.Column(db.String(50), nullable=False)
    table_name = db.Column(db.String(50), nullable=False)
    record_id = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.now)
    ip_address = db.Column(db.String(45), nullable=True)
    user_agent = db.Column(db.String(255), nullable=True)
    details = db.Column(db.Text, nullable=True)
    
    # User relationship
    user = db.relationship('User', backref='audit_logs')

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Decorator for role-based access control
def role_required(roles):
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role not in roles:
                logger.warning(f"Unauthorized access attempt to {request.path} by user {current_user.id if current_user.is_authenticated else 'anonymous'}")
                abort(403)  # Forbidden
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# HIPAA compliance logging
def log_action(action, table_name, record_id, details=None):
    """Log actions for HIPAA compliance"""
    if current_user.is_authenticated:
        audit_log = AuditLog(
            user_id=current_user.id,
            action=action,
            table_name=table_name,
            record_id=record_id,
            ip_address=request.remote_addr,
            user_agent=request.headers.get('User-Agent', ''),
            details=details
        )
        db.session.add(audit_log)
        db.session.commit()
        logger.info(f'Action logged: {action} on {table_name} with ID {record_id} by user {current_user.id}')

# Basic security headers
@app.after_request
def add_security_headers(response):
    """Add security headers to all responses"""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' cdn.jsdelivr.net; style-src 'self' cdn.jsdelivr.net; img-src 'self' data:;"
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            if user.totp_secret:
                # Store user ID in session for 2FA verification
                session['user_id_for_2fa'] = user.id
                return redirect(url_for('verify_2fa'))
            else:
                # If 2FA is not set up, log in directly (only for testing)
                login_user(user)
                user.last_login = datetime.now()
                db.session.commit()
                
                logger.info(f"User {user.id} logged in without 2FA")
                flash('Login successful. Please set up two-factor authentication for better security.', 'warning')
                return redirect(url_for('dashboard'))
        else:
            logger.warning(f"Failed login attempt for username: {username}")
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/verify-2fa', methods=['GET', 'POST'])
def verify_2fa():
    # Check if user has passed the first authentication factor
    if 'user_id_for_2fa' not in session:
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        user = User.query.get(session['user_id_for_2fa'])
        totp_code = request.form.get('totp_code')
        
        if user and user.verify_totp(totp_code):
            login_user(user)
            user.last_login = datetime.now()
            db.session.commit()
            session.pop('user_id_for_2fa', None)
            
            logger.info(f"User {user.id} completed 2FA authentication")
            flash('Two-factor authentication successful!', 'success')
            return redirect(url_for('dashboard'))
        else:
            logger.warning(f"Failed 2FA attempt for user ID: {session['user_id_for_2fa']}")
            flash('Invalid verification code', 'danger')
    
    return render_template('verify_2fa.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    # In a real system, you might want to limit registration or require an admin to create accounts
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        user_first_name = request.form.get('user_first_name')
        user_last_name = request.form.get('user_last_name')
        role = 'patient'  # Default role
        
        # Check if username or email already exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return render_template('register.html')
        
        if User.query.filter_by(email=email).first():
            flash('Email already exists', 'danger')
            return render_template('register.html')
        
        # Create user
        user = User(username=username, email=email, role= 'patient', user_first_name = user_first_name, user_last_name = user_last_name)
        user.set_password(password)
        user.generate_totp_secret()  # Generate 2FA secret
        
        db.session.add(user)
        db.session.commit()
        
        # Store user ID for setup 2FA page
        session['user_id_for_2fa_setup'] = user.id
        
        logger.info(f"New user registered: {user.id} - {username}")
        flash('Registration successful! Please set up two-factor authentication.', 'success')
        return redirect(url_for('setup_2fa'))
    
    return render_template('register.html')

@app.route('/setup-2fa')
def setup_2fa():
    if 'user_id_for_2fa_setup' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id_for_2fa_setup'])
    
    if not user:
        session.pop('user_id_for_2fa_setup', None)
        return redirect(url_for('login'))
    
    # Generate QR code for TOTP
    totp_uri = user.get_totp_uri()
    qr = qrcode.make(totp_uri)
    buffered = BytesIO()
    qr.save(buffered, format="PNG")
    qr_code = base64.b64encode(buffered.getvalue()).decode("utf-8")
    
    return render_template('setup_2fa.html', qr_code=qr_code, secret=user.totp_secret)

@app.route('/complete-2fa-setup', methods=['POST'])
def complete_2fa_setup():
    if 'user_id_for_2fa_setup' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id_for_2fa_setup'])
    
    if not user:
        session.pop('user_id_for_2fa_setup', None)
        return redirect(url_for('login'))
    
    totp_code = request.form.get('totp_code')
    
    if user.verify_totp(totp_code):
        session.pop('user_id_for_2fa_setup', None)
        logger.info(f"User {user.id} completed 2FA setup")
        flash('Two-factor authentication set up successfully!', 'success')
        return redirect(url_for('login'))
    else:
        logger.warning(f"Failed 2FA setup verification for user {user.id}")
        flash('Invalid verification code. Please try again.', 'danger')
        return redirect(url_for('setup_2fa'))

@app.route('/dashboard')
@login_required
def dashboard():
    """User dashboard based on role"""
    if current_user.role == 'admin':
        # Admin dashboard
        users = User.query.all()
        return render_template('admin_dashboard.html', users=users)
    
    elif current_user.role == 'doctor':
        # Doctor dashboard - show all patients
        patients = Patient.query.all()
        log_action('VIEW', 'Patient', 0, 'Viewed all patients')
        return render_template('doctor_dashboard.html', patients=patients)
    
    elif current_user.role == 'patient':
        # Patient dashboard - show only their data
        patient = Patient.query.filter_by(user_id=current_user.id).first()
        
        if patient:
            medical_records = MedicalRecord.query.filter_by(patient_id=patient.id).all()
            log_action('VIEW', 'MedicalRecord', patient.id, 'Viewed own medical records')
        else:
            medical_records = []
        
        return render_template('patient_dashboard.html', patient=patient, medical_records=medical_records)
    
    # Default dashboard
    return render_template('dashboard.html')

@app.route('/create-patient-profile', methods=['GET', 'POST'])
@login_required
@role_required(['patient'])
def create_patient_profile():
    """Allow patients to create their profile if they don't have one"""
    # Check if patient already has a profile
    existing_profile = Patient.query.filter_by(user_id=current_user.id).first()
    if existing_profile:
        flash('You already have a patient profile', 'info')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        try:
            patient = Patient(user_id=current_user.id)
            patient.first_name = request.form.get('first_name')
            patient.last_name = request.form.get('last_name')
            patient.dob = request.form.get('dob')
            patient.address = request.form.get('address')
            patient.phone = request.form.get('phone')
            patient.patient_doctor = request.form.get('patient_doctor')
            
            db.session.add(patient)
            db.session.commit()
            
            log_action('CREATE', 'Patient', patient.id, 'Created own patient profile')
            flash('Patient profile created successfully!', 'success')
            return redirect(url_for('dashboard'))
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error creating patient profile: {str(e)}")
            flash(f'Error creating patient profile', 'danger')
    
    return render_template('create_patient_profile.html')

@app.route('/patient/<int:patient_id>')
@login_required
@role_required(['admin', 'doctor'])
def view_patient(patient_id):
    """View patient details and medical records"""
    patient = Patient.query.get_or_404(patient_id)
    medical_records = MedicalRecord.query.filter_by(patient_id=patient_id).all()
    
    log_action('VIEW', 'Patient', patient_id, f'Viewed patient details')
    return render_template('patient_detail.html', patient=patient, medical_records=medical_records)

@app.route('/patient/<int:patient_id>/add-record', methods=['GET', 'POST'])
@login_required
@role_required(['doctor'])
def add_medical_record(patient_id):
    """Add a medical record for a patient"""
    patient = Patient.query.get_or_404(patient_id)
    
    if request.method == 'POST':
        try:
            record = MedicalRecord(
                patient_id=patient_id,
                doctor_id=current_user.id,
                record_type=request.form.get('record_type')
            )
            record.diagnosis = request.form.get('diagnosis')
            record.treatment = request.form.get('treatment')
            record.medication = request.form.get('medication')
            record.notes = request.form.get('notes')
            
            db.session.add(record)
            db.session.commit()
            
            log_action('CREATE', 'MedicalRecord', record.id, f'Created medical record for patient {patient_id}')
            flash('Medical record added successfully!', 'success')
            return redirect(url_for('view_patient', patient_id=patient_id))
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error adding medical record: {str(e)}")
            flash(f'Error adding medical record', 'danger')
    
    return render_template('add_medical_record.html', patient=patient)

@app.route('/profile')
@login_required
def profile():
    """View user profile"""
    # If user is a patient, get their patient record
    patient = None
    if current_user.role == 'patient':
        patient = Patient.query.filter_by(user_id=current_user.id).first()
    
    return render_template('profile.html', patient=patient)

@app.route('/logout')
def logout():
    """Logout user"""
    if current_user.is_authenticated:
        logger.info(f"User {current_user.id} logged out")
        logout_user()
        # Clear all session data to ensure complete logout
        session.clear()
        flash('You have been logged out successfully.', 'success')
    return redirect(url_for('login'))

@app.route('/add-patient', methods=['GET', 'POST'])
@login_required
@role_required(['admin', 'doctor'])
def add_patient():
    """Add a new patient to the system"""
    if request.method == 'POST':
        try:
            # Create a new user account for the patient
            username = request.form.get('username')
            email = request.form.get('email')
            user_first_name = request.form.get('first_name')
            user_last_name = request.form.get('last_name') 
            
            # Check if username or email already exists
            if User.query.filter_by(username=username).first():
                flash('Username already exists', 'danger')
                return render_template('add_patient.html')
            
            if User.query.filter_by(email=email).first():
                flash('Email already exists', 'danger')
                return render_template('add_patient.html')
            
            # Create patient user account
            password = secrets.token_urlsafe(10)  # Generate a random secure password
            patient_user = User(username=username, email=email, role='patient', user_first_name = user_first_name, user_last_name = user_last_name)
            patient_user.set_password(password)
            patient_user.generate_totp_secret()  # Generate 2FA secret
            
            db.session.add(patient_user)
            db.session.commit()  # Commit to get user ID
            
            # Create patient profile
            patient = Patient(user_id=patient_user.id)
            patient.first_name = request.form.get('first_name')
            patient.last_name = request.form.get('last_name')
            patient.dob = request.form.get('dob')
            patient.address = request.form.get('address')
            patient.phone = request.form.get('phone')
            patient.patient_doctor = request.form.get('patient_doctor')
            
            db.session.add(patient)
            db.session.commit()
            
            log_action('CREATE', 'Patient', patient.id, f'Created new patient by {current_user.username}')
            
            flash(f'Patient added successfully! Temporary password: {password}', 'success')
            return redirect(url_for('view_patient', patient_id=patient.id))
        
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error adding patient: {str(e)}")
            flash(f'Error adding patient: {str(e)}', 'danger')
    
    return render_template('add_patient.html')

@app.route('/add-user', methods=['GET', 'POST'])
@login_required
@role_required(['admin', 'doctor'])
def add_user():
    """Add a new user to the system"""
    if request.method == 'POST':
        try:
            # Create a new user account for the patient
            username = request.form.get('username')
            email = request.form.get('email')
            user_first_name = request.form.get('first_name')
            user_last_name = request.form.get('last_name') 
            role = request.form.get('role')
            
            # Check if username or email already exists
            if User.query.filter_by(username=username).first():
                flash('Username already exists', 'danger')
                return render_template('add_patient.html')
            
            if User.query.filter_by(email=email).first():
                flash('Email already exists', 'danger')
                return render_template('add_patient.html')
            
            # Create patient user account
            password = secrets.token_urlsafe(10)  # Generate a random secure password
            user = User(username=username, email=email, role= role, user_first_name = user_first_name, user_last_name = user_last_name)
            user.set_password(password)
            user.generate_totp_secret()  # Generate 2FA secret
            
            db.session.add(user)
            db.session.commit()  # Commit to get user ID
            
            log_action('CREATE', role, user.id, f'Created new user by {current_user.username}')
            
            flash(f'User added successfully! Temporary password: {password}. Secret Key for 2FA: {user.totp_secret}', 'success', )
        
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error adding user: {str(e)}")
            flash(f'Error adding user: {str(e)}', 'danger')
    
    return render_template('add_user.html')

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    """Allow users to change their password"""
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # Validate input
        if not current_user.check_password(current_password):
            flash('Current password is incorrect', 'danger')
            return redirect(url_for('change_password'))
        
        if new_password != confirm_password:
            flash('New passwords do not match', 'danger')
            return redirect(url_for('change_password'))
        
        # Password complexity requirements
        if len(new_password) < 10:
            flash('Password must be at least 10 characters long', 'danger')
            return redirect(url_for('change_password'))
        
        if not any(c.isupper() for c in new_password) or not any(c.islower() for c in new_password) or not any(c.isdigit() for c in new_password):
            flash('Password must contain uppercase, lowercase, and numbers', 'danger')
            return redirect(url_for('change_password'))
        
        # Update password
        current_user.set_password(new_password)
        db.session.commit()
        
        log_action('UPDATE', 'User', current_user.id, 'Changed password')
        flash('Password updated successfully', 'success')
        return redirect(url_for('profile'))
    
    return render_template('change_password.html')

@app.route('/init-db')
def init_db():
    """Initialize the database with test data - only in development mode"""
    if not app.debug:
        return 'Not allowed in production mode', 403
    
    try:
        # Create database tables
        db.create_all()
        
        # Create admin user if not exists
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(username='admin', email='admin@example.com', role='admin', user_first_name = 'Alan', user_last_name = 'Adminson')
            admin.set_password('admin123')
            admin.totp_secret = None  # Disable 2FA for testing
            db.session.add(admin)
            
        # Create doctor user if not exists
        doctor = User.query.filter_by(username='doctor').first()
        if not doctor:
            doctor = User(username='doctor', email='doctor@example.com', role='doctor', user_first_name = 'Donald', user_last_name = 'Doctorson')
            doctor.set_password('doctor123')
            doctor.totp_secret = None  # Disable 2FA for testing
            db.session.add(doctor)
            
        # Create patient user if not exists
        patient_user = User.query.filter_by(username='patient').first()
        if not patient_user:
            patient_user = User(username='patient', email='patient@example.com', role='patient', user_first_name = 'Penny', user_last_name = 'Patientson')
            patient_user.set_password('patient123')
            patient_user.totp_secret = None  # Disable 2FA for testing
            db.session.add(patient_user)
        
        # Commit users first to ensure they have IDs
        db.session.commit()
        
        # Add a patient record for the patient user if it doesn't exist
        patient = Patient.query.filter_by(user_id=patient_user.id).first()
        if not patient:
            patient = Patient(user_id=patient_user.id)
            patient.first_name = "Penny"
            patient.last_name = "Patientson"
            patient.dob = "1980-01-01"
            patient.address = "123 Main St, Anytown, US"
            patient.phone = "555-123-4567"
            patient.patient_doctor = "Dr. Donald Doctorson"
            db.session.add(patient)
            
            # Commit the patient to get an ID before creating the medical record
            db.session.commit()
            
            # Now add a sample medical record with the valid patient ID
            record = MedicalRecord(
                patient_id=patient.id,
                doctor_id=doctor.id,
                record_type="Consultation"
            )
            record.diagnosis = "Seasonal allergies"
            record.treatment = "Rest and hydration"
            record.medication = "Loratadine 10mg daily"
            record.notes = "Patient reported feeling better after initial treatment"
            db.session.add(record)
        
        # Final commit for any remaining changes
        db.session.commit()
        
        return '''
        <h1>Database initialized with test data</h1>
        <p>Created test accounts:</p>
        <ul>
            <li><strong>Admin:</strong> username=admin, password=admin123</li>
            <li><strong>Doctor:</strong> username=doctor, password=doctor123</li>
            <li><strong>Patient:</strong> username=patient, password=patient123</li>
        </ul>
        <p><a href="/login">Go to login page</a></p>
        '''
    except Exception as e:
        db.session.rollback()
        return f'Error initializing database: {str(e)}', 500

@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', error_code=404, error_message="Page not found"), 404

@app.errorhandler(403)
def forbidden(e):
    return render_template('error.html', error_code=403, error_message="Access forbidden"), 403

@app.errorhandler(500)
def internal_server_error(e):
    logger.error(f"Internal server error: {str(e)}")
    return render_template('error.html', error_code=500, error_message="Internal server error"), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    
    # Check if encryption key is set
    if not os.environ.get('ENCRYPTION_KEY'):
        print("WARNING: ENCRYPTION_KEY environment variable not set. A temporary key will be generated.")
        print("This will cause all encrypted data to be lost when the server restarts.")
        print(f"Generated temporary key: {ENCRYPTION_KEY.hex()}")
        print("Set this as an environment variable to preserve encrypted data.")
    
    # In production, you would use HTTPS
    app.run(debug=True)
