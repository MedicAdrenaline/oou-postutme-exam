from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import requests, secrets, os, uuid, string, random,time, threading
from email_utils import send_otp_email, send_exam_pins_email, send_reset_password_email
from functools import wraps
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime, timedelta, timezone
from flask_migrate import Migrate

def admin_login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin'):
            flash("Admin access required.", "error")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def generate_pin_for_exam(mode, user_id):
    pin_code = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
    new_pin = Pin(
        user_id=user_id,
        pin_code=pin_code,
        exam_mode=mode,
        is_used=False,
        is_active=False)
    db.session.add(new_pin)
    db.session.commit()
    return pin_code

def get_user_by_email_or_username(identifier):
    return User.query.filter(
        (User.email == identifier) | (User.username == identifier)
    ).first()
# Load environment variables
from config import Config

app = Flask(__name__)

app.config.from_object(Config)
app.secret_key = Config.SECRET_KEY

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "admin_login"

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = f"mysql+pymysql://{Config.DB_USER}:{Config.DB_PASSWORD}@{Config.DB_HOST}:{Config.DB_PORT}/{Config.DB_NAME}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
migrate = Migrate(app, db) 

# Models
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    is_verified = db.Column(db.Boolean, default=False)
    otp = db.Column(db.Integer)
    pin_attempts = db.Column(db.Integer, default=0)
    last_attempt_time = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    blocked_modes = db.Column(db.JSON, default={}) 
    reset_token = db.Column(db.String(128), nullable=True)
    reset_token_expiration = db.Column(db.DateTime, nullable=True)
    
    def set_password(self, password):
        self.password = generate_password_hash(password) 
# Example: {"JAMB": "2025-05-10 15:30:00", "WAEC": "2025-05-10 16:00:00"}

class Pin(db.Model):
    __tablename__ = 'pins'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    pin_code = db.Column(db.String(100), nullable=False)
    is_used = db.Column(db.Boolean, default=False)
    exam_mode = db.Column(db.String(50), nullable=False)  # e.g., JAMB, WAEC, POST-UTME, A-LEVEL, MAIN
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=False)  # Add this line to your model
    user = db.relationship('User', backref=db.backref('pins', lazy=True))  # Assuming the 'User' model exists

class Question(db.Model):
    __tablename__ = 'questions'
    id = db.Column(db.Integer, primary_key=True)
    exam_mode = db.Column(db.String(100), nullable=False)
    question_text = db.Column(db.Text, nullable=False)
    option_a = db.Column(db.String(255), nullable=False)
    option_b = db.Column(db.String(255), nullable=False)
    option_c = db.Column(db.String(255), nullable=False)
    option_d = db.Column(db.String(255), nullable=False)
    correct_option = db.Column(db.String(1), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Score(db.Model):
    __tablename__ = 'scores'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    exam_mode = db.Column(db.String(100), nullable=False)
    score = db.Column(db.Integer, nullable=False)
    total_questions = db.Column(db.Integer, nullable=False)
    date_taken = db.Column(db.DateTime, default=datetime.utcnow)

class Admin(db.Model):
    __tablename__ = 'admin'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Helper functions
def generate_unique_pin():
    while True:
        new_pin = str(random.randint(100000, 999999))
        if not Pin.query.filter_by(pin_code=new_pin).first():
            return new_pin

def verify_paystack_transaction(reference):
    secret_key = os.getenv('PAYSTACK_SECRET_KEY')
    headers = {
        "Authorization": f"Bearer {secret_key}"
    }
    response = requests.get(f"https://api.paystack.co/transaction/verify/{reference}", headers=headers)
    return response.json()

def clean_unverified_users():
    while True:
        time.sleep(3600)
        with app.app_context():
            expiration = datetime.utcnow() - timedelta(hours=24)
            users_to_delete = User.query.filter(
                User.is_verified == False,
                User.created_at < expiration
            ).all()
            for u in users_to_delete:
                db.session.delete(u)
            db.session.commit()
            if users_to_delete:
                print(f"Cleaned {len(users_to_delete)} unverified users.")

# Function to handle PIN verification
def verify_pin(exam_mode):
    # Get the entered PIN from the form
    pin = request.form['pin']
    user_id = session.get('user_id')

    # Check if the user is logged in
    if not user_id:
        flash("You need to log in to access the exam page.")
        return redirect(url_for('login'))

    # Fetch the user and check if they are blocked
    user = User.query.get(user_id)
    if not user:
        flash("User not found.")
        return redirect(url_for('login'))

    # Check if the user is blocked from entering PINs in this mode
    current_time = datetime.utcnow()
    blocked_until = user.blocked_modes.get(exam_mode)

    if blocked_until and current_time < datetime.fromisoformat(blocked_until):
        remaining_time = (datetime.fromisoformat(blocked_until) - current_time).total_seconds() // 60
        flash(f"You are blocked from entering PINs in {exam_mode}. Try again after {int(remaining_time)} minutes.")
        return redirect(url_for('exam_homepage'))

    # Retrieve the pin record
    pin_record = Pin.query.filter_by(user_id=user_id, exam_mode=exam_mode, pin_code=pin, is_used=False).first()

    # If valid PIN is found
    if pin_record:
        # Check device ID
        device_id = request.user_agent.string
        if pin_record.device_id and pin_record.device_id != device_id:
            flash("This PIN is tied to another device.")
            return redirect(url_for('exam_homepage'))

        # Update pin as used and reset attempt counter
        pin_record.is_used = True
        user.pin_attempts = 0  # Reset attempts after successful login
        pin_record.device_id = device_id  # Associate the device ID
        db.session.commit()

        # Redirect to the exam start page based on the mode
        redirect_mapping = {
            "JAMB": 'jamb_page',
            "WAEC": 'waec_page',
            "POST-UTME": 'postutme_page',
            "A-LEVEL": 'alevel_page'
        }
        return redirect(url_for(redirect_mapping.get(exam_mode)))

    # If invalid PIN
    user.pin_attempts += 1
    db.session.commit()

    # Block the user for 24 hours after 5 attempts
    if user.pin_attempts >= 5:
        block_time = current_time + timedelta(hours=24)
        user.blocked_modes[exam_mode] = block_time.isoformat()
        db.session.commit()
        flash("You have been blocked from entering PINs in all exam modes for 24 hours.")
        return redirect(url_for('exam_homepage'))

    flash("Incorrect PIN. Please try again.")
    return redirect(url_for(f'verify_{exam_mode.lower()}_pin'))

# Routes
@app.route('/')
def welcome():
      return render_template('welcome.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']

        if password != confirm_password:
            flash("Passwords don't match.")
            return redirect(url_for('register'))

        existing_user = User.query.filter((User.username == username) | (User.email == email)).first()
        if existing_user:
            if existing_user.is_verified:
                flash('Username or Email already exists and is verified.')
                return redirect(url_for('register'))
            db.session.delete(existing_user)
            db.session.commit()

        otp = random.randint(100000, 999999)
        hashed_pw = generate_password_hash(password)

        new_user = User(username=username, email=email, password=hashed_pw, otp=otp)
        db.session.add(new_user)
        db.session.commit()

        send_otp_email(email, otp)
        session['pending_user_id'] = new_user.id

        flash('OTP sent to your email. Verify to proceed.')
        return redirect(url_for('verify_otp'))

    return render_template('register.html')


@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    if 'pending_user_id' not in session:
        flash("No pending verification.")
        return redirect(url_for('register'))

    user = User.query.get(session['pending_user_id'])
    if not user:
        flash("Invalid session. Please register again.")
        return redirect(url_for('register'))

    if request.method == 'POST':
        entered_otp = request.form['otp']
        if str(user.otp) == entered_otp:
            user.is_verified = True
            user.otp = None
            db.session.commit()
            session.pop('pending_user_id', None)
            flash('Account verified! Please log in.')
            return redirect(url_for('login'))
        else:
            flash("Incorrect OTP.")

    return render_template('verify_otp.html')

@app.route('/resend-otp')
def resend_otp():
    if 'pending_user_id' not in session:
        flash("No registration in progress.")
        return redirect(url_for('register'))

    user = User.query.get(session['pending_user_id'])
    if user:
        user.otp = random.randint(100000, 999999)
        db.session.commit()
        send_otp_email(user.email, user.otp)
        flash("New OTP sent.")
    return redirect(url_for('verify_otp'))


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username_or_email = request.form.get('username_or_email')
        password = request.form.get('password')

        if not username_or_email or not password:
            flash('Please fill out both fields.', 'error')
            return redirect(url_for('login'))

        # Authenticate the user by username or email
        user = User.query.filter((User.username == username_or_email) | (User.email == username_or_email)).first()

        # Check if the user exists and the password is correct
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            flash('Login successful!', 'success')
            return redirect(url_for('exam_homepage'))

        flash('Invalid username or password.', 'error')
        return redirect(url_for('login'))

    return render_template('login.html')

# Function to generate a random OTP
def generate_otp():
    return ''.join(random.choices(string.digits, k=6))

def generate_reset_token(length=5):
    # Generate a random 5-character alphanumeric token
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')

        # Verify if the email exists in the database
        user = User.query.filter_by(email=email).first()
        if user:
            # Generate a 5-character token
            token = generate_reset_token()
            # Set expiration to 1 hour from now
            expiration_time = datetime.now(timezone.utc) + timedelta(hours=1)

            # Update user record with the token and expiration
            user.reset_token = token
            user.reset_token_expiration = expiration_time
            db.session.commit()

            # Send the token via email
            send_reset_password_email(email, token)

            flash("A reset token has been sent to your email. Please check your inbox.", "info")
            return redirect(url_for('reset_password'))  
        else:
            flash("This email is not registered.", "error")

    return render_template('forgot_password.html')

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == 'POST':
        token = request.form.get('token')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if new_password != confirm_password:
            flash("Passwords do not match.", "error")
            return redirect(request.url)

        # Find user by token
        user = User.query.filter_by(reset_token=token).first()

        if not user:
            flash("Invalid or expired token.", "error")
            return redirect(url_for('forgot_password'))

        # Check if token is expired
        if user.reset_token_expiration and datetime.utcnow() > user.reset_token_expiration:
            flash("The reset link has expired. Please request a new one.", "error")
            return redirect(url_for('forgot_password'))

        # Update password
        user.password = generate_password_hash(new_password)
        user.reset_token = None
        user.reset_token_expiration = None

        db.session.commit()

        flash("Your password has been successfully reset.", "info")
        return redirect(url_for('login'))

    # If GET request, just render the form
    token = request.args.get('token')
    return render_template('reset_password.html', token=token)

@app.route('/exam_homepage')
def exam_homepage():
    # Check if the user is logged in
    if 'user_id' not in session:
        flash("You need to log in to access the exam page.")
        return redirect(url_for('login'))
    
    # Get the logged-in user's username (optional for personalized greeting)
    user = User.query.get(session['user_id'])
    
    # Render the exam homepage, passing the username for display
    return render_template('exam_homepage.html', username=user.username)


@app.route('/exam/jamb', methods=['GET', 'POST'])
def jamb_exam():
    # JAMB Exam Page - Enter PIN and Start Exam
    return render_template('jamb.html')


@app.route('/exam/waec', methods=['GET', 'POST'])
def waec_exam():
    # WAEC Exam Page - Enter PIN and Start Exam
    return render_template('waec.html')


@app.route('/exam/postutme', methods=['GET', 'POST'])
def postutme_exam():
    # POST-UTME Exam Page - Enter PIN and Start Exam
    return render_template('postutme.html')


@app.route('/exam/alevel', methods=['GET', 'POST'])
def alevel_exam():
    # A-LEVEL Exam Page - Enter PIN and Start Exam
    return render_template('alevel.html')


@app.route('/admission-updates')
def admission_updates():
    # Admission Updates Page
    return render_template('admission_updates.html')

@app.route('/verify_jamb_pin', methods=['POST'])
def verify_jamb_pin():
    return verify_pin('JAMB')

@app.route('/verify_waec_pin', methods=['POST'])
def verify_waec_pin():
    return verify_pin('WAEC')

@app.route('/verify_postutme_pin', methods=['POST'])
def verify_postutme_pin():
    return verify_pin('POST-UTME')

@app.route('/verify_alevel_pin', methods=['POST'])
def verify_alevel_pin():
    return verify_pin('A-LEVEL')
    
@app.route('/generate-pin', methods=['GET', 'POST'])
def generate_pin():
    if 'user_id' not in session:
        flash("Login first.")
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])

    if request.method == 'POST':
        selected_modes = request.form.getlist('modes')
        payment_method = request.form['payment_method']
        email = user.email

        if not selected_modes:
            flash('Please select at least one exam mode.', 'error')
            return redirect(url_for('generate_pin'))

        amount = calculate_amount(selected_modes)

        session['selected_modes'] = selected_modes
        session['payment_method'] = payment_method
        session['expected_amount'] = amount

        if payment_method == 'paystack':
            reference = str(uuid.uuid4())
            session['payment_reference'] = reference
            payment_response = initiate_paystack_payment(email, amount, reference)

            if payment_response.get('status'):
                return redirect(payment_response['data']['authorization_url'])
            else:
                flash('Payment initiation failed. Try again.', 'error')
                return redirect(url_for('generate_pin'))

        elif payment_method in ['whatsapp_proof', 'whatsapp_chat']:
            flash('Please contact admin via WhatsApp with payment proof for PIN activation.', 'info')
            return redirect(url_for('generate_pin'))

    return render_template('generate_pin.html')

def calculate_amount(selected_modes):
    amount = 0
    for mode in selected_modes:
        if mode == 'alevel':
            amount += 3000
        else:
            amount += 2000
    return amount

def initiate_paystack_payment(email, amount, reference):
    paystack_secret = os.getenv('PAYSTACK_SECRET_KEY')
    headers = {
        "Authorization": f"Bearer {paystack_secret}",
        "Content-Type": "application/json"
    }
    data = {
        "email": email,
        "amount": amount * 100,
        "reference": reference,
        "callback_url": "http://localhost:5000/payment_callback"
    }
    response = requests.post("https://api.paystack.co/transaction/initialize", json=data, headers=headers)
    return response.json()

@app.route('/payment_callback')
def payment_callback():
    reference = request.args.get('reference')
    if not reference:
        flash("Missing payment reference.")
        return redirect(url_for('dashboard'))

    user_id = session.get('user_id')
    selected_modes = session.get('selected_modes')

    if not user_id or not selected_modes:
        flash("Session expired or invalid.")
        return redirect(url_for('dashboard'))

    verification = verify_paystack_transaction(reference)
    if verification.get("data", {}).get("status") == "success":
        user = User.query.get(user_id)
        generated_pins = []

        for mode in selected_modes:
            new_pin = Pin(
                user_id=user.id,
                pin_code=generate_unique_pin(),
                exam_mode=mode
            )
            db.session.add(new_pin)
            db.session.commit()
            generated_pins.append(f"{mode.upper()}: {new_pin.pin_code}")

        send_exam_pins_email(user.email, generated_pins)
        flash("Payment successful. PIN(s) sent to your email.")
    else:
        flash("Payment verification failed.")

    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out.")
    return redirect(url_for('login'))

# Helper function to generate a random PIN
def generate_pin():
    return ''.join(random.choices(string.digits, k=6))


@app.route('/admin-login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        admin = Admin.query.filter_by(username=username).first()
        if admin and admin.check_password(password):
            session['admin_logged_in'] = True  # Optional, for your own tracking
            session['is_admin'] = True  # Required for @admin_login_required decorator
            flash('Logged in successfully as admin.', 'success')
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Invalid admin credentials.', 'error')
            return redirect(url_for('admin_login'))
    
    return render_template('admin_login.html')


@app.route('/admin-dashboard', methods=['GET', 'POST'])
def admin_dashboard():
    if 'admin_logged_in' not in session:
        return redirect(url_for('admin_login'))

    # Handle PIN sending from dashboard
    if request.method == 'POST':
        username_or_email = request.form['username_or_email']
        selected_modes = request.form.getlist('modes')

        user = User.query.filter(
            (User.username == username_or_email) | 
            (User.email == username_or_email)
        ).first()

        if not user:
            flash('User not found.')
        elif not selected_modes:
            flash('Please select at least one exam mode.')
        else:
            pin_code = generate_pin()
            for mode in selected_modes:
                new_pin = Pin(user_id=user.id, pin_code=pin_code, exam_mode=mode.upper(), is_active=True)
                db.session.add(new_pin)
            db.session.commit()

            send_exam_pins_email(user.email, {mode.upper(): pin_code for mode in selected_modes})
            flash(f"PIN sent to {user.email} for {', '.join(selected_modes).upper()}.")

    # Fetch data for dashboard display
    inactive_pins = Pin.query.filter_by(is_active=False).all()
    users = User.query.all()

    return render_template('admin_dashboard.html', users=users, inactive_pins=inactive_pins)


@app.route('/admin-activate-pin', methods=['POST'])
def activate_pin():
    if 'admin_logged_in' not in session:
        return redirect(url_for('admin_login'))

    pin_id = request.form.get('pin_id')
    pin = Pin.query.get(pin_id)
    if pin:
        pin.is_active = True
        db.session.commit()
        flash('PIN activated successfully.')
    return redirect(url_for('admin_dashboard'))

@app.route('/mark-pin-used', methods=['POST'])
def mark_pin_as_used():
    if 'admin_logged_in' not in session:
        return redirect(url_for('admin_login'))

    pin_id = request.form.get('pin_id')
    pin = Pin.query.get(pin_id)
    if pin:
        pin.is_used = True
        db.session.commit()
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/send_pin', methods=['GET', 'POST'])
@admin_login_required
def admin_send_pin():
    if request.method == 'POST':
        username_or_email = request.form.get('username_or_email')
        selected_modes = request.form.getlist('modes')

        # Validate inputs
        if not username_or_email or not selected_modes:
            flash("Please provide a username/email and select at least one exam mode.", "error")
            return redirect(url_for('admin_send_pin'))

        # Look up user
        user = User.query.filter(
            (User.email == username_or_email) | (User.username == username_or_email)
        ).first()

        if not user:
            flash("User not found. Please check the username or email.", "error")
            return redirect(url_for('admin_send_pin'))

        # Generate pins for each selected mode
        pins_dict = {}
        for mode in selected_modes:
            pins_dict[mode] = generate_pin_for_exam(mode, user.id)

        # Send email
        try:
            send_exam_pins_email(user.email, pins_dict)
            flash("PINs generated and sent successfully!", "success")
        except Exception as e:
            flash(f"Failed to send email: {str(e)}", "error")

        return redirect(url_for('admin_dashboard'))

    # GET request: Show form
    return render_template('send_pin.html')  # A separate form page for admin to send pins)
    
@app.route('/admin-logout')
def admin_logout():
    session.pop('admin_logged_in', None)
    flash("Logged out successfully.")
    return redirect(url_for('admin_login'))

@app.route('/exam_access', methods=['POST'])
@login_required
def exam_access():
    pin_code = request.form.get('pin_code')  # Get the pin_code from the form
    device_id = request.form.get('device_id')  # Get the device_id from the form (sent by JavaScript)

    # Print device_id from the form
    print("Form Device ID:", device_id)  # This will show the device_id sent from the form via JavaScript

    # Fetch the pin object from the database based on the pin_code
    pin = Pin.query.filter_by(pin_code=pin_code).first()

    if not pin:
        flash("Invalid PIN.", "error")
        return redirect(url_for('dashboard'))

    # Print device_id from the database
    print("Database Device ID:", pin.device_id)  # This will show the device_id from the database for this pin
    print(request.form)
    
    if not pin.is_active:
        flash("PIN not yet activated. Contact support.", "error")
        return redirect(url_for('dashboard'))

    if pin.is_used and pin.device_id != device_id:
        flash("This PIN is already in use on another device.", "error")
        return redirect(url_for('dashboard'))

    # First-time use: Save the device_id and mark the PIN as used
    if not pin.is_used:
        pin.device_id = device_id  # Save the device_id to the pin in the database
        pin.is_used = True  # Mark the PIN as used
        db.session.commit()  # Commit the changes to the database

    # Store the PIN in the session
    session['exam_pin'] = pin_code  # Store the pin code in the session for later use

    # Redirect to the exam page
    return redirect(url_for('start_exam'))

if __name__ == '__main__':
    threading.Thread(target=clean_unverified_users, daemon=True).start()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)