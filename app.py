# IMPORTS 
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, json, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import requests, secrets, os, uuid, string, random, time, threading
from email_utils import send_otp_email, send_exam_pins_email, send_reset_password_email
from functools import wraps
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_migrate import Migrate
from apscheduler.schedulers.background import BackgroundScheduler
import atexit
from werkzeug.utils import secure_filename
from config import Config
from dotenv import load_dotenv
load_dotenv()
from sqlalchemy.dialects.mysql import JSON
from sqlalchemy.ext.mutable import MutableDict
from sqlalchemy.sql.expression import func
from sqlalchemy.sql import func
from sqlalchemy.exc import IntegrityError
import app 
from collections import defaultdict
from datetime import datetime, timezone, timedelta
now = datetime.utcnow
from app import app
import openai, requests, wolframalpha
from transformers import pipeline  
from openai import OpenAI
from sqlalchemy import text
from schools import SCHOOL_NAME


app = Flask(__name__)

# Database configuration
app.config.from_object(Config)
db = SQLAlchemy(app)

# Login Manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "admin_login"
@login_manager.user_loader
def load_user(user_id):
    print("user id:", user_id)
    return User.query.get(int(user_id))
UPLOAD_FOLDER = 'static/uploads/pqs'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
UPLOAD_FOLDER = 'static/uploads/pqs'
ALLOWED_EXTENSIONS = {'pdf'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ====== #
# MODELS #
# ====== #
# Default helpers
def default_mode_attempts():
    return {
        "jamb": 0,
        "waec": 0,
        "postutme": 0,
        "alevel": 0
    }
def default_blocked_modes():
    return {
        "jamb": False,
        "waec": False,
        "postutme": False,
        "alevel": False
    }
class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    is_verified = db.Column(db.Boolean, default=False)
    otp = db.Column(db.Integer)
    pin_attempts = db.Column(MutableDict.as_mutable(JSON), default=default_mode_attempts)# Use MutableDict to auto-track changes inside the JSON columns
    blocked_modes = db.Column(MutableDict.as_mutable(JSON), default=default_blocked_modes)
    reset_token = db.Column(db.String(128), nullable=True)
    reset_token_expiration = db.Column(db.DateTime, nullable=True)
    last_attempt_time = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    school = db.Column(db.String(100), nullable=False)
    
class Pin(db.Model):
    __tablename__ = 'pins'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    pin_code = db.Column(db.String(100), nullable=False)
    is_used = db.Column(db.Boolean, default=False)
    device_id = db.Column(db.String(255), nullable=True)
    exam_mode = db.Column(db.String(50), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=False)
    user = db.relationship('User', backref=db.backref('pins', lazy=True))
    school = db.Column(db.String(100), nullable=False)

class UserExamSession(db.Model):
    __tablename__ = 'user_exam_session'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    subject = db.Column(db.String(200), nullable=False)
    exam_mode = db.Column(db.String(100), nullable=False)
    question_ids = db.Column(db.Text, nullable=False)  # comma-separated question IDs
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='exam_sessions')

# Question model
class Question(db.Model):
    __tablename__ = 'questions'
    id = db.Column(db.Integer, primary_key=True)
    exam_mode = db.Column(db.String(100), nullable=False)
    subject = db.Column(db.String(200), nullable=False)
    question_text = db.Column(db.Text, nullable=True)  # nullable=True if question can be image-based only
    question_image = db.Column(db.String(255), nullable=True)  # image URL or path
    option_a = db.Column(db.String(255), nullable=False)
    option_b = db.Column(db.String(255), nullable=False)
    option_c = db.Column(db.String(255), nullable=False)
    option_d = db.Column(db.String(255), nullable=False)
    correct_option = db.Column(db.String(1), nullable=False)
    explanation = db.Column(db.Text, nullable=True)  # explanation text
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    school = db.Column(db.String(100), nullable=False)

class ExamAttempt(db.Model):
    __tablename__ = 'exam_attempts'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    exam_mode = db.Column(db.String(100), nullable=False)  # 'jamb'
    subjects = db.Column(db.String(255), nullable=False)  # store as JSON string or CSV of selected subjects
    questions_json = db.Column(db.Text, nullable=False)  # JSON list of question IDs for this attempt
    answers_json = db.Column(db.Text, nullable=True)  # JSON dict of {question_id: selected_answer}
    time_remaining = db.Column(db.Integer, default=7200)  # seconds left
    status = db.Column(db.String(20), default='ongoing')  # 'ongoing' or 'submitted'
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    user = db.relationship('User', backref='exam_attempts')
    submitted_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_retake = db.Column(db.Boolean, default=False)

class QuestionAttempt(db.Model):
    __tablename__ = 'question_attempts'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)  # You can link this to your User model if needed
    question_id = db.Column(db.Integer, db.ForeignKey('questions.id'), nullable=False)
    exam_mode = db.Column(db.String(100), nullable=False)
    subject = db.Column(db.String(200), nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    selected_option = db.Column(db.String(1), nullable=True)
    is_correct = db.Column(db.Boolean, nullable=True)

    #ExamREsult
class ExamResult(db.Model):
    __tablename__ = 'exam_results'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    exam_mode = db.Column(db.String(100), nullable=False)
    score = db.Column(db.Integer, nullable=False)
    total = db.Column(db.Integer, nullable=False)  # total questions
    percentage = db.Column(db.Float, nullable=False)
    subject_scores = db.Column(db.Text, nullable=True)  # JSON string
    selected_subjects = db.Column(db.Text, nullable=True) # NEW: JSON string of selected subject
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class DonatedPQ(db.Model):
    __tablename__ = 'donated_pq'  # Note: needs double underscores for SQLAlchemy to recognize it
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    title = db.Column(db.String(150), nullable=False)
    subject = db.Column(db.String(100), nullable=False)
    exam_type = db.Column(db.String(50), nullable=False)
    filename = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    device_id = db.Column(db.String(100), nullable=False)  # ✅ Add this line

class AdmissionUpdate(db.Model):
    __tablename__ = 'updates'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)
    views = db.Column(db.Integer, default=0)
    likes = db.Column(db.Integer, default=0)
    comments = db.relationship('Comment', backref='update', lazy=True)
    reactions = db.relationship('PostReaction', backref='update', lazy=True)
    image_filename = db.Column(db.String(120))

class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    update_id = db.Column(db.Integer, db.ForeignKey('updates.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)
    replies = db.relationship('Reply', backref='comment', lazy=True)
    user = db.relationship('User', backref='comments')
    reactions = db.relationship('CommentReaction', backref='comment', lazy=True)

class Reply(db.Model):
    __tablename__ = 'replies'
    id = db.Column(db.Integer, primary_key=True)
    comment_id = db.Column(db.Integer, db.ForeignKey('comments.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    user = db.relationship('User', backref='replies')
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, default=datetime.utcnow)

class PostReaction(db.Model):
    __tablename__ = 'post_reaction'
    id = db.Column(db.Integer, primary_key=True)
    post_id = db.Column(db.Integer, db.ForeignKey('updates.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    user = db.relationship('User', backref='post_reaction')
    reaction = db.Column(db.String(10))  # "like", "heart"

class CommentReaction(db.Model):
    __tablename__ = 'comments_reaction'
    id = db.Column(db.Integer, primary_key=True)
    comment_id = db.Column(db.Integer, db.ForeignKey('comments.id'))
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    user = db.relationship('User', backref='comment_reaction')
    reaction = db.Column(db.String(10))

class PostView(db.Model):
    __tablename__ = 'post_view'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    update_id = db.Column(db.Integer, db.ForeignKey('updates.id'))

class Admin(db.Model):
    __tablename__ = 'admin'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)   

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    def set_password(self, password):
        self.password = generate_password_hash(password)
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


# =================== #
# REGISTRATION ROUTES #
# =================== #
@app.route('/')
def welcome():
      return render_template('welcome.html')

@app.route('/app-instructions' , methods=['GET', 'POST'])
def app_instructions():
    return render_template('app_instructions.html')

@app.route('/postutme-instructions' , methods=['GET', 'POST'])
def postutme_instructions():
    return render_template('postutme_instructions.html')

@app.route('/courses-cutoff' , methods=['GET', 'POST'])
def courses_cutoff():
    return render_template('courses_cutoff.html')

@app.route('/oou-aggregate-calculator', methods=['GET', 'POST'])
def oou_aggregate_calculator():
    aggregate = None
    error = None
    if request.method == 'POST':
        try:
            jamb = float(request.form['jamb'])
            postutme = float(request.form['postutme'])
            if 0 <= jamb <= 400 and 0 <= postutme <= 100:
                aggregate = round((jamb / 400 * 60) + (postutme / 100 * 40), 2)
            else:
                error = "JAMB score must be between 0–400 and Post-UTME between 0–100."
        except ValueError:
            error = "Please enter valid numbers."
    return render_template("oou_aggregate_calculator.html", aggregate=aggregate, error=error)

@app.route('/donate_pq', methods=['GET', 'POST'])
def donate_pq():
    device_id = request.cookies.get('device_id')
    if not device_id:
        device_id = str(uuid.uuid4())

    if request.method == 'POST':
        title = request.form['title']
        name = request.form['name']
        subject = request.form['subject']
        exam_type = request.form['exam_type']
        description = request.form.get('description', '')
        file = request.files['file']

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(save_path)

            # Save to DB
            new_pq = DonatedPQ(
                title=title,
                name=name,
                subject=subject,
                exam_type=exam_type,
                filename=filename,
                description=description,
                upload_date=datetime.utcnow(),
                device_id=device_id
            )
            db.session.add(new_pq)
            db.session.commit()

            flash("Past Question uploaded successfully!", "success")
            resp = make_response(redirect(url_for('donate_pq')))
            resp.set_cookie('device_id', device_id, max_age=60 * 60 * 24 * 365 * 2)  # 2 years
            return resp
        else:
            flash("Only PDF files are allowed.", "danger")

    # Show donated PQs
    donated_pqs = DonatedPQ.query.order_by(DonatedPQ.id.desc()).all()
    resp = make_response(render_template('donate_pq.html', pqs=donated_pqs, user_device=device_id))
    resp.set_cookie('device_id', device_id, max_age=60 * 60 * 24 * 365 * 2)
    return resp

@app.route('/delete_pq/<int:pq_id>', methods=['POST'])
def delete_pq(pq_id):
    pq = DonatedPQ.query.get_or_404(pq_id)
    user_device = request.cookies.get('device_id')

    if pq.device_id != user_device:
        flash("You’re not authorized to delete this file.", "danger")
        return redirect(url_for('donate_pq'))
    # Delete file from uploads
    file_path = os.path.join(app.root_path, 'static/uploads/pqs', pq.filename)
    if os.path.exists(file_path):
        os.remove(file_path)
    # Remove record from database
    db.session.delete(pq)
    db.session.commit()
    flash("Past Question deleted successfully.", "success")
    return redirect(url_for('donate_pq'))

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
        new_user = User(username=username, email=email, password=hashed_pw, otp=otp, school=SCHOOL_NAME)
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


from schools import SCHOOL_NAME

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username_or_email = request.form.get('username_or_email')
        password = request.form.get('password')

        if not username_or_email or not password:
            flash('Please fill out both fields.', 'error')
            return redirect(url_for('login'))

        # Only fetch users that match the current school
        user = User.query.filter(
            ((User.username == username_or_email) | (User.email == username_or_email)) &
            (User.school == SCHOOL_NAME)
        ).first()

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard'))

        flash('Invalid login details.', 'error')
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
            expiration_time = datetime.utcnow() + timedelta(hours=1)
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

# ================================== #
# Function to Clean Unverified Users #
# ================================== #
def clean_unverified_users():
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
# Initialize and start the scheduler
scheduler = BackgroundScheduler()
scheduler.add_job(clean_unverified_users, 'interval', hours=1)
scheduler.start()
# Shut down the scheduler when exiting the app
atexit.register(lambda: scheduler.shutdown())


# Helper functions to generate a random PIN
def generate_unique_pin():
    while True:
        new_pin = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
        if not Pin.query.filter_by(pin_code=new_pin).first():
            return new_pin
        
@app.route('/generate-pin', methods=['GET', 'POST'])
def generate_pin():
    if 'user_id' not in session:
        flash("Login first.")
        return redirect(url_for('login'))
    user = User.query.get(session['user_id'])
    if request.method == 'POST':
        selected_modes = request.form.getlist('exam_mode')
        payment_method = request.form['payment_method']
        email = user.email
        if not selected_modes:
            flash('Select the checkbox below to proceed.', 'error')
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

##PAYSTACK
def initiate_paystack_payment(email, amount, reference):
    paystack_secret = os.getenv('PAYSTACK_SECRET_KEY')
    headers = {
        "Authorization": f"Bearer {paystack_secret}",
        "Content-mode": "application/json"
    }
    data = {
        "email": email,
        "amount": amount * 100,
        "reference": reference,
        "callback_url": "http://localhost:5000/payment_callback"
    }
    response = requests.post("https://api.paystack.co/transaction/initialize", json=data, headers=headers)
    return response.json()

def verify_paystack_transaction(reference):
    secret_key = os.getenv('PAYSTACK_SECRET_KEY')
    headers = {
        "Authorization": f"Bearer {secret_key}"
    }
    response = requests.get(f"https://api.paystack.co/transaction/verify/{reference}", headers=headers)
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


@app.route('/dashboard')
def dashboard():
    # Check if the user is logged in
    if 'user_id' not in session:
        flash("You need to log in to access the dashboard.")
        return redirect(url_for('login'))
    # Get the logged-in user's username
    user = User.query.get(session['user_id'])
     # Render the dashboard, passing the username for display
    return render_template('dashboard.html', username=user.username)


@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out.")
    return redirect(url_for('login'))


# ================= #
# Exam mode Routes  #
# ================= #
def is_blocked_for_exam(user, exam_mode):
    blocked_until = user.blocked_modes.get(exam_mode)
    if blocked_until and isinstance(blocked_until, str):
        blocked_until = datetime.fromisoformat(blocked_until)
        if blocked_until.tzinfo:  # Remove timezone if it exists
            blocked_until = blocked_until.replace(tzinfo=None)
    if blocked_until and blocked_until > datetime.utcnow():
        return True, blocked_until
    return False, None

@app.route('/exam/postutme', methods=['GET', 'POST'])
def postutme_exam():
    user = db.session.get(User, session.get('user_id'))
    if not user:
        flash("Session expired. Please log in again.", "danger")
        return redirect(url_for('login'))

    blocked, blocked_until = is_blocked_for_exam(user, 'postutme')
    
    return render_template(
        'postutme.html',
        blocked=blocked,
        blocked_until=blocked_until,
        current_time=datetime.utcnow()  # ✅ This line fixes the Jinja2 error
    )

# =========================== #
# PIN Verification Function   #
# =========================== #
def verify_pin(pin, device_id, exam_mode, user):
    blocked_until = user.blocked_modes.get(exam_mode)
    if blocked_until and isinstance(blocked_until, str):
        blocked_until = datetime.fromisoformat(blocked_until)
        if blocked_until.tzinfo:
            blocked_until = blocked_until.replace(tzinfo=None)
    if blocked_until and blocked_until > datetime.utcnow():
        flash(f"You are blocked from accessing {exam_mode.upper()} until {blocked_until}.", "error")
        return False

    pin_entry = Pin.query.filter_by(pin_code=pin, exam_mode=exam_mode).first()
    attempts = user.pin_attempts.get(exam_mode, 0)

    if not pin_entry or pin_entry.school != SCHOOL_NAME:
        attempts += 1
        user.pin_attempts[exam_mode] = attempts
        if attempts >= 5:
            block_time = datetime.utcnow() + timedelta(hours=24)
            user.blocked_modes[exam_mode] = block_time.isoformat()
            flash(f"You are now blocked from {exam_mode.upper()} for 24 hours due to multiple incorrect attempts.", "error")
        else:
            flash(f"Invalid PIN. Attempts left: {5 - attempts}", "error")
        db.session.commit()
        return False

    user.pin_attempts[exam_mode] = 0
    user.blocked_modes[exam_mode] = False

    if not pin_entry.device_id:
        pin_entry.device_id = device_id
        pin_entry.is_used = True
        db.session.commit()
        flash("PIN verified and locked to your device.", "success")
        return True

    if pin_entry.device_id == device_id:
        flash("PIN verified.", "success")
        return True

    flash("PIN already used on another device.", "error")
    return False


# =====================
# PIN Verification Routes
# =====================
@app.route('/verify_postutme_pin', methods=['POST'])
def verify_postutme_pin_route():
    pin = request.form.get('pin')
    device_id = request.form.get('device_id')
    user = User.query.get(session.get('user_id'))
    if user and verify_pin(pin, device_id, 'postutme', user):
        flash("PIN verified successfully! Welcome to your POSTUTME dashboard.", "success")
        return redirect(url_for('postutme_dashboard'))
    flash("Invalid or already used PIN. Please try again.", "error")
    return redirect(url_for('postutme_exam'))


############
#POST UTME #
############
@app.route('/postutme_dashboard', methods=['GET', 'POST'])
def postutme_dashboard():
    user = db.session.get(User, session.get('user_id'))
    if not user:
        flash("Session expired. Please log in again.", "danger")
        return redirect(url_for('login'))

    if request.method == 'POST':
        selected_subjects = request.form.getlist('subjects')

        # Ensure "English" is compulsory and only appears once
        if 'English' in selected_subjects:
            selected_subjects.remove('English')

        if len(selected_subjects) < 3:
            flash("You must select at least 3 subjects in addition to English (total of 4 subjects).", "danger")
            return redirect(url_for('postutme_dashboard'))
        elif len(selected_subjects) > 4:
            flash("You can only select 3 subjects. English is compulsory and automatically added.", "danger")
            return redirect(url_for('postutme_dashboard'))

        selected_subjects_full = ['English'] + selected_subjects
        retake = request.form.get('retake') == 'true'

        # Save subject selection in session
        session['postutme_subjects'] = selected_subjects_full
        session['current_subject'] = 'English'
        session.pop('postutme_answers', None)

        if not retake:
            # Expire any existing ongoing attempt
            previous_attempt = ExamAttempt.query.filter_by(
                user_id=user.id,
                exam_mode='POSTUTME',
                status='ongoing'
            ).first()
            if previous_attempt:
                previous_attempt.status = 'expired'
                db.session.commit()

            questions_per_subject = {}

            # Get all previous question IDs for each subject across past attempts
            past_attempts = ExamAttempt.query.with_entities(ExamAttempt.questions_json).filter_by(
                user_id=user.id,
                exam_mode='POSTUTME'
            ).all()

            # Build used question ID mapping by subject
            subject_used_ids = {}
            for record in past_attempts:
                if record[0]:  # if questions_json exists
                    past_qs = json.loads(record[0])
                    for subj, ids in past_qs.items():
                        subject_used_ids.setdefault(subj, set()).update(ids)

            for subject in selected_subjects_full:
                num_questions = 10

                # Fetch all questions for that subject
                all_questions = Question.query.filter(
                    func.lower(Question.subject) == subject.lower(),
                    Question.exam_mode == 'POSTUTME',
                    Question.school == SCHOOL_NAME
                ).all()

                # Filter out seen questions
                seen_ids = subject_used_ids.get(subject, set())
                unseen_questions = [q for q in all_questions if q.id not in seen_ids]

                # If unseen is not enough, fallback to full pool
                question_pool = unseen_questions if len(unseen_questions) >= num_questions else all_questions

                if len(question_pool) < num_questions:
                    flash(f"Not enough questions for {subject} in {SCHOOL_NAME}. Try again later.", "danger")
                    return redirect(url_for('postutme_dashboard'))

                # Shuffle and select
                random.shuffle(question_pool)
                selected_ids = [q.id for q in question_pool[:num_questions]]
                questions_per_subject[subject] = selected_ids

            # Save new attempt
            new_attempt = ExamAttempt(
                user_id=user.id,
                exam_mode='POSTUTME',
                status='ongoing',
                subjects=json.dumps(selected_subjects_full),
                questions_json=json.dumps(questions_per_subject),
                started_at=datetime.utcnow()
            )
            db.session.add(new_attempt)
            db.session.commit()
            session['postutme_attempt_id'] = new_attempt.id
        flash("Start New Exam or Retake Last Exam Below", "success")
        return redirect(url_for('postutme_exam_page'))
    # Handle GET: show last result
    last_result = ExamResult.query.filter_by(
        user_id=user.id,
        exam_mode='POSTUTME'
    ).order_by(ExamResult.id.desc()).first()

    if session.get('show_postutme_flash'):
        flash("PIN verified successfully! Welcome to your POSTUTME dashboard.", "success")
        session.pop('show_postutme_flash', None)

    return render_template('postutme_dashboard.html', result=last_result, user=user)


@app.route('/postutme_exam_page', methods=['GET'])
def postutme_exam_page():
    user = db.session.get(User, session.get('user_id'))
    if not user:
        flash("Session expired. Please log in again.", "danger")
        return redirect(url_for('login'))

    attempt_id = session.get('postutme_attempt_id')
    if not attempt_id:
        flash("No active exam session found. Please restart from dashboard.", "danger")
        return redirect(url_for('postutme_dashboard'))

    attempt = db.session.get(ExamAttempt, attempt_id)
    if not attempt or attempt.status != 'ongoing':
        flash("Invalid or expired attempt. Please restart from dashboard.", "danger")
        return redirect(url_for('postutme_dashboard'))

    selected_subjects = json.loads(attempt.subjects)
    questions_json = json.loads(attempt.questions_json)

    questions = {}

    for subject in selected_subjects:
        q_ids = questions_json.get(subject, [])
        if not q_ids:
            flash(f"No questions found for {subject}.", "danger")
            return redirect(url_for('postutme_dashboard'))

        # Fetch only questions belonging to current school
        q_list = Question.query.filter(
            Question.id.in_(q_ids),
            Question.school == SCHOOL_NAME
        ).all()

        # Maintain order of question IDs
        q_list_sorted = sorted(
            [q for q in q_list if q.id in q_ids],
            key=lambda q: q_ids.index(q.id)
        )

        questions[subject] = [{
            'id': q.id,
            'question_text': q.question_text,
            'question_image': q.question_image,
            'option_a': q.option_a,
            'option_b': q.option_b,
            'option_c': q.option_c,
            'option_d': q.option_d
        } for q in q_list_sorted]

    return render_template(
        'postutme_exam_page.html',
        questions=questions,
        subjects=selected_subjects,
        user=user,
        reset_local_storage=True
    )

@app.route('/submit_postutme_exam', methods=['POST'])
def submit_postutme_exam():
    try:
        app.logger.info("➡️ SUBMIT_POSTUTME_EXAM CALLED")
        user = db.session.get(User, session.get('user_id'))
        if not user:
            flash("Session expired. Please log in again.", "danger")
            return redirect(url_for('login'))

        attempt_id = session.get('postutme_attempt_id')
        if not attempt_id:
            flash("No active exam session found.", "danger")
            return redirect(url_for('postutme_dashboard'))

        attempt = db.session.get(ExamAttempt, attempt_id)
        if not attempt or attempt.status != 'ongoing':
            flash("Exam already submitted or not found.", "warning")
            return redirect(url_for('postutme_dashboard'))

        selected_subjects = json.loads(attempt.subjects)
        questions_by_subject = json.loads(attempt.questions_json)

        if not selected_subjects:
            flash("Invalid subject selection.", "danger")
            return redirect(url_for('postutme_dashboard'))

        scores = {sub.lower(): {'correct': 0, 'total': 10} for sub in selected_subjects}
        answers_dict = {}

        for key, selected_option in request.form.items():
            if key.startswith('answers[') and key.endswith(']'):
                try:
                    qid = int(key[8:-1])
                    question = Question.query.get(qid)
                    if not question:
                        continue
                    subj = question.subject.lower()
                    if subj in scores and question.correct_option == selected_option:
                        scores[subj]['correct'] += 1
                    answers_dict[str(qid)] = selected_option
                except Exception as e:
                    app.logger.warning(f"Error grading {key}: {e}")
                    continue

        total_correct = 0
        for subj, data in scores.items():
            correct = data['correct']
            total = data['total']
            over_100 = round((correct / total) * 100, 2)
            scores[subj]['over_100'] = over_100
            total_correct += correct

        total_possible = len(selected_subjects) * 10
        percentage = round((total_correct / total_possible) * 100, 2)

        attempt.status = 'submitted'
        attempt.answers_json = json.dumps(answers_dict)
        attempt.submitted_at = datetime.utcnow()
        db.session.add(attempt)

        result = ExamResult(
            user_id=user.id,
            exam_mode='POSTUTME',
            score=total_correct,
            total=total_possible,
            percentage=percentage,
            subject_scores=json.dumps(scores),
            selected_subjects=json.dumps(selected_subjects)
        )
        db.session.add(result)
        db.session.commit()

        session.pop('postutme_subjects', None)
        session.pop('postutme_answers', None)
        session.pop('postutme_attempt_id', None)

        flash("Exam submitted successfully.", "success")
        return redirect(url_for('postutme_result', result_id=result.id))

    except Exception as e:
        app.logger.error(f"Exception in submit_postutme_exam: {e}")
        flash(f"Error during submission: {e}", "danger")
        return redirect(url_for('postutme_exam_page'))

@app.route('/retake_postutme_exam', methods=['POST'])
def retake_postutme_exam():
    user = db.session.get(User, session.get('user_id'))
    if not user:
        flash("Session expired. Please log in again.", "danger")
        return redirect(url_for('login'))

    # Get the latest submitted POSTUTME attempt
    previous_attempt = ExamAttempt.query.filter_by(
        user_id=user.id, exam_mode='POSTUTME', status='submitted'
    ).order_by(ExamAttempt.id.desc()).first()

    if not previous_attempt:
        flash("No previous POSTUTME exam found to retake.", "danger")
        return redirect(url_for('postutme_dashboard'))

    try:
        previous_subjects = json.loads(previous_attempt.subjects)
        previous_qids = json.loads(previous_attempt.questions_json)

        app.logger.info(f"[RETAKE] Subjects: {previous_subjects}")
        app.logger.info(f"[RETAKE] Question IDs: {previous_qids}")

        # Validate the structure
        if not isinstance(previous_qids, dict) or not all(
            isinstance(q_list, list) and q_list for q_list in previous_qids.values()
        ):
            raise ValueError("Invalid or empty question lists.")

    except (ValueError, TypeError, json.JSONDecodeError) as e:
        app.logger.error(f"❌ Error decoding previous attempt: {e}")
        flash("Previous POSTUTME exam data is corrupted or incomplete.", "danger")
        return redirect(url_for('postutme_dashboard'))

    # Expire any ongoing POSTUTME attempt
    ongoing = ExamAttempt.query.filter_by(
        user_id=user.id, exam_mode='POSTUTME', status='ongoing'
    ).first()
    if ongoing:
        ongoing.status = 'expired'
        db.session.commit()

    # Use constant for duration (in seconds)
    POSTUTME_DURATION = 1800

    # Create a new retake attempt
    new_attempt = ExamAttempt(
        user_id=user.id,
        exam_mode='POSTUTME',
        status='ongoing',
        is_retake=True,
        subjects=json.dumps(previous_subjects),
        questions_json=json.dumps(previous_qids),
        started_at=datetime.utcnow(),
        time_remaining=POSTUTME_DURATION
    )
    db.session.add(new_attempt)
    db.session.commit()

    # Prepare session
    session['postutme_subjects'] = previous_subjects
    session['postutme_attempt_id'] = new_attempt.id
    session.pop('postutme_answers', None)
    session.pop('postutme_time_left', None)  # Optional cleanup

    flash("Start New Exam or Retake Last Exam Below. Good luck!", "success")
    return redirect(url_for('postutme_exam_page'))  # Rename if needed

@app.route('/postutme_result/<int:result_id>')
def postutme_result(result_id):
    result = ExamResult.query.get_or_404(result_id)
    user = User.query.get(result.user_id)
    username = user.username if user else "Anonymous"

    # Get related exam attempt
    attempt = ExamAttempt.query.filter_by(
        user_id=result.user_id,
        exam_mode='POSTUTME',
        status='submitted'
    ).order_by(ExamAttempt.id.desc()).first()

    if attempt and attempt.started_at and attempt.submitted_at:
        duration = attempt.submitted_at - attempt.started_at
        exam_duration = str(duration).split('.')[0]

        # ✅ Format the exam date here
        exam_date = attempt.started_at.strftime('%d %B %Y')
    else:
        exam_duration = "N/A"
        exam_date = "Unknown"

    subject_order = json.loads(attempt.subjects or '[]') if attempt else []
    detailed_scores = {}
    total_score = 0
    correct_answers = 0
    questions_grouped = {}

    if attempt:
        questions_by_subject = json.loads(attempt.questions_json or '{}')
        answers = json.loads(attempt.answers_json or '{}')

        all_qids = [qid for qlist in questions_by_subject.values() for qid in qlist]
        questions = Question.query.filter(Question.id.in_(all_qids)).all()
        questions_dict = {q.id: q for q in questions}

        for subject in subject_order:
            subject_cap = subject.capitalize()
            qids = questions_by_subject.get(subject, [])
            correct_count = 0
            questions_grouped[subject_cap] = []

            for idx, qid in enumerate(qids, start=1):
                q = questions_dict.get(qid)
                if not q:
                    continue

                selected = answers.get(str(qid))
                is_correct = selected and q.correct_option.upper() == selected.upper()
                if is_correct:
                    correct_count += 1

                def get_full_option_text(letter):
                    if not letter:
                        return "No answer"
                    letter = letter.upper()
                    opt = getattr(q, f"option_{letter.lower()}", "")
                    return f"{letter} - {opt}" if opt else f"{letter} - Unknown"

                questions_grouped[subject_cap].append({
                    'number': idx,
                    'text': q.question_text,
                    'userAnswer': get_full_option_text(selected) if selected else "Unanswered",
                    'correctAnswer': get_full_option_text(q.correct_option),
                    'correct': is_correct,
                    'explanation': q.explanation or "No explanation."
                })

            score_over_10 = correct_count
            total_score += score_over_10
            correct_answers += correct_count

            detailed_scores[subject_cap] = {
                'correct': correct_count,
                'total': 10,
                'over_100': round((correct_count / 10) * 100, 2)
            }
    percentage = round((total_score / (len(subject_order) * 10)) * 100, 2) if subject_order else 0

    session.pop('postutme_subjects', None)
    session.pop('postutme_question_ids', None)
    session.pop('postutme_answers', None)

    return render_template(
        "postutme_result.html",
        result=result,
        username=username,
        exam_duration=exam_duration,
        exam_date=exam_date,  # ✅ Don't forget to pass this
        correct_answers=correct_answers,
        detailed_scores=detailed_scores,
        total_score=total_score,
        total_percentage=percentage,
        grouped_questions=questions_grouped
    )

@app.route('/postutme_leaderboard')
def postutme_leaderboard():
    user = db.session.get(User, session.get('user_id'))
    if not user:
        flash("Session expired. Please log in again.", "danger")
        return redirect(url_for('login'))

    raw_leaderboard = db.session.query(
        ExamResult,
        User.username
    ).join(User, ExamResult.user_id == User.id).filter(
        ExamResult.exam_mode == 'POSTUTME'
    ).order_by(ExamResult.percentage.desc(), ExamResult.created_at.asc()).all()

    leaderboard = []
    for idx, (result, username) in enumerate(raw_leaderboard, start=1):
        attempt = ExamAttempt.query.filter_by(
            user_id=result.user_id,
            exam_mode='POSTUTME',
            status='submitted',
            subjects=result.selected_subjects
        ).filter(
            ExamAttempt.submitted_at <= result.created_at
        ).order_by(ExamAttempt.submitted_at.desc()).first()

        if not attempt or attempt.is_retake:
            continue

        if attempt.started_at and attempt.submitted_at:
            duration = attempt.submitted_at - attempt.started_at
            exam_duration = str(duration).split('.')[0]
            exam_date = attempt.submitted_at.strftime('%Y-%m-%d %H:%M')
            duration_seconds = duration.total_seconds()
        else:
            exam_duration = "N/A"
            exam_date = result.created_at.strftime('%Y-%m-%d %H:%M')
            duration_seconds = float('inf')
        # ✅ Use subject_scores to calculate correct score out of 10 per subject
        subject_scores = json.loads(result.subject_scores or '{}')
# ✅ Skip if less than 5 subjects attempted
        if len(subject_scores) < 4:
            continue
        raw_correct = sum(s['correct'] for s in subject_scores.values())
        total_possible = len(subject_scores) * 10
        percentage = round((raw_correct / total_possible) * 100, 2) if total_possible else 0        
        leaderboard.append({
            'name': username,
            'score': f"{raw_correct}/{total_possible}",
            'percentage': percentage,
            'duration_seconds': duration_seconds,
            'exam_duration': exam_duration,
            'date': exam_date
        })
    # Sort by percentage DESC, then duration ASC
    sorted_leaderboard = sorted(leaderboard, key=lambda x: (-x['percentage'], x['duration_seconds']))
    # Assign ranks with tie-handling
    top_20 = []
    rank = 1
    prev_entry = None
    for entry in sorted_leaderboard:
        if prev_entry and entry['percentage'] == prev_entry['percentage'] and entry['duration_seconds'] == prev_entry['duration_seconds']:
            entry['rank'] = rank
        else:
            entry['rank'] = len(top_20) + 1
            rank = entry['rank']
        top_20.append(entry)
        if len(top_20) == 20:
            break
        prev_entry = entry
    return render_template('postutme_leaderboard.html', leaderboard=top_20, result=result)

@app.route('/postutme_past_results')
def postutme_past_results():
    user = db.session.get(User, session.get('user_id'))
    if not user:
        flash("Session expired. Please log in again.", "danger")
        return redirect(url_for('login'))

    last_results = ExamResult.query.filter_by(user_id=user.id, exam_mode='POSTUTME')\
                                   .order_by(ExamResult.created_at.desc()).all()
    result_data = []
    for result in last_results:
        scores = json.loads(result.subject_scores or '{}')
        subjects_with_scores = []
        total_raw_score = 0
        total_possible = 0

        for subject, data in scores.items():
            subject_name = subject.capitalize()
            subject_score = round(data.get('correct', 0), 2)
            score_over_100 = round(data.get('over_100', 0), 2)
            subjects_with_scores.append(f"{subject_name} - {subject_score}/10")
            total_raw_score += subject_score
            total_possible += 10  # Each subject is over 10

        subjects_display = ', '.join(subjects_with_scores) if subjects_with_scores else "No subjects"

        # Calculate accurate percentage
        percentage = round((total_raw_score / total_possible) * 100, 2) if total_possible else 0

        attempt = ExamAttempt.query.filter_by(
            user_id=user.id,
            exam_mode='POSTUTME',
            status='submitted',
            subjects=result.selected_subjects
        ).filter(
            ExamAttempt.submitted_at <= result.created_at
        ).order_by(ExamAttempt.submitted_at.desc()).first()

        if attempt and attempt.started_at and attempt.submitted_at:
            duration = attempt.submitted_at - attempt.started_at
            exam_duration = str(duration).split('.')[0]
            exam_date = attempt.submitted_at.strftime('%d %B %Y')
        else:
            exam_duration = str(duration).split('.')[0]
            exam_date = result.created_at.strftime('%d %B %Y')

        result_data.append({
            'subject': subjects_display,
            'score': total_raw_score,
            'total': total_possible,
            'percentage': percentage,
            'date': exam_date,
            'time_spent': exam_duration
        })
    return render_template('postutme_past_results.html', result_data=result_data, result=result if last_results else None)


#  ADRENA AI ROUTE
@app.route('/adrena-ai', methods=['GET', 'POST'])
def adrena_ai():
    return render_template("adrena_ai.html")

@app.route('/updates', methods=['GET', 'POST'])
def updates():
    user = db.session.get(User, session.get('user_id'))
    updates = AdmissionUpdate.query.order_by(AdmissionUpdate.date_posted.desc()).all()
    if user:
        for update in updates:
            already_viewed = PostView.query.filter_by(user_id=user.id, update_id=update.id).first()
            if not already_viewed:
                view = PostView(user_id=user.id, update_id=update.id)
                update.views += 1
                db.session.add(view)
        db.session.commit()
    if request.method == 'POST':
        if not user:
            flash("Session expired. Please log in again.", "danger")
            return redirect(url_for('login'))
        update_id = request.form.get('update_id')
        comment_text = request.form.get('comment')
        if update_id and comment_text:
            comment = Comment(update_id=int(update_id), content=comment_text, user_id=user.id)
            db.session.add(comment)
            db.session.commit()
            flash("Comment posted.", "success")
            return redirect(url_for('updates', _anchor=f"update-{update_id}"))
    return render_template('updates.html', updates=updates)


# COMMENT ON UPDATE
@app.route('/comment/<int:update_id>', methods=['POST'])
def comment_on_update(update_id):
    user = db.session.get(User, session.get('user_id'))
    update = AdmissionUpdate.query.get_or_404(update_id)
    content = request.form.get('comment')
    if user and content:
        comment = Comment(update_id=update.id, content=content, user_id=user.id)
        db.session.add(comment)
        db.session.commit()
        flash("Comment posted.", "success")
    else:
        flash("Please log in and write a valid comment.", "danger")
    return redirect(url_for('updates', _anchor=f"update-{update.id}"))


# REPLY TO A COMMENT
@app.route('/reply_comment/<int:comment_id>', methods=['POST'])
def reply_comment(comment_id):
    user = db.session.get(User, session.get('user_id'))
    if not user:
        flash("Session expired. Please log in again.", "danger")
        return redirect(url_for('login'))

    content = request.form['reply']
    reply = Reply(comment_id=comment_id, content=content, user_id=user.id)
    db.session.add(reply)
    db.session.commit()
    update_id = Comment.query.get(comment_id).update_id
    return redirect(url_for('updates', _anchor=f"update-{update_id}"))


# LIKE UPDATE
@app.route('/like_update/<int:update_id>', methods=['POST'])
def like_update(update_id):
    user = db.session.get(User, session.get('user_id'))
    if not user:
        flash("Session expired. Please log in again.", "danger")
        return redirect(url_for('login'))
    update = AdmissionUpdate.query.get_or_404(update_id)
    existing_reaction = PostReaction.query.filter_by(post_id=update.id, user_id=user.id).first()
    if existing_reaction:
        # Remove the like
        db.session.delete(existing_reaction)
        if update.likes > 0:
            update.likes -= 1
        db.session.commit()
        flash("Like removed.", "info")
    else:
        # Add a like
        reaction = PostReaction(post_id=update.id, user_id=user.id, reaction='like')
        db.session.add(reaction)
        update.likes += 1
        db.session.commit()
        flash("You liked this post.", "success")
    return redirect(url_for('updates', _anchor=f"update-{update.id}"))

# LIKE A COMMENT
@app.route('/like_comment/<int:comment_id>', methods=['POST'])
def like_comment(comment_id):
    user = db.session.get(User, session.get('user_id'))
    if not user:
        flash("Please log in to like comments.", "danger")
        return redirect(url_for('login'))
    comment = Comment.query.get_or_404(comment_id)
    existing_like = CommentReaction.query.filter_by(comment_id=comment.id, user_id=user.id).first()
    if existing_like:
        db.session.delete(existing_like)
        db.session.commit()
        flash("Like removed from comment.", "info")
    else:
        new_like = CommentReaction(comment_id=comment.id, user_id=user.id)
        db.session.add(new_like)
        db.session.commit()
        flash("Comment liked!", "success")
    return redirect(url_for('updates', _anchor=f"update-{comment.update_id}"))

if __name__ == '__main__':
    threading.Thread(target=clean_unverified_users, daemon=True).start()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)