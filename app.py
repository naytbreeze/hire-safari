# Flask and extensions
from flask import Flask, render_template, request, redirect, session, url_for, jsonify, flash
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from flask_wtf import CSRFProtect
from flask_wtf.csrf import generate_csrf, CSRFError

# Environment variables
from dotenv import load_dotenv
import os

# Load environment variables before config import
load_dotenv()

# Use Production config for deployment
from config import ProductionConfig

# Rest of your imports...
from sqlalchemy import or_, desc
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename
import stripe
from datetime import datetime, timedelta
import json
import logging
import time


# Configure production logging
logging.basicConfig(
    filename='app.log',
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(ProductionConfig)

# Directory Configuration
basedir = os.path.abspath(os.path.dirname(__file__))
UPLOAD_FOLDER = os.path.join(basedir, 'static', 'uploads')

# Ensure required directories exist
for directory in [os.path.join(basedir, 'instance'), UPLOAD_FOLDER]:
    if not os.path.exists(directory):
        os.makedirs(directory, mode=0o755)

# Initialize extensions
db = SQLAlchemy(app)
mail = Mail(app)
csrf = CSRFProtect(app)

# Stripe configuration
stripe.api_key = 'sk_test_51O1vhLLXnN9fPIAoWiFJAb1LoTlmg8a1qdYlLMYI0MBp8nTyUArHygkzPcnE4QYRaYDgnGN0T6gBpTc1p3ZSBnbt00bDN8PinG'

# File upload configuration
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    """Helper function for file uploads"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Make CSRF token available in all templates
@app.context_processor
def inject_csrf_token():
    return dict(form={'csrf_token': generate_csrf()})

# CSRF error handler
@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    return render_template('error_page.html', 
                         message="CSRF token validation failed. Please try again."), 400

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(500), nullable=False)  # Changed from 150 to 500
    role = db.Column(db.String(50), nullable=False, default='user')
    verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def is_lister(self):
        return self.role == 'lister' and self.verified

class Listing(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    address = db.Column(db.String(200))
    city = db.Column(db.String(100))
    state = db.Column(db.String(100))
    zip_code = db.Column(db.String(20))
    phone = db.Column(db.String(20))
    email = db.Column(db.String(120))
    website = db.Column(db.String(200))
    price_range = db.Column(db.String(50))
    business_hours = db.Column(db.JSON)
    images = db.Column(db.JSON)
    status = db.Column(db.String(20), default='active')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    user = db.relationship('User', backref=db.backref('listings', lazy=True))

class Booking(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    listing_id = db.Column(db.Integer, db.ForeignKey('listing.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    booking_date = db.Column(db.Date, nullable=False)
    booking_time = db.Column(db.String(10), nullable=False)
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    notes = db.Column(db.Text)
    
    listing = db.relationship('Listing', backref=db.backref('bookings', lazy=True))
    user = db.relationship('User', backref=db.backref('bookings', lazy=True))

# Initialize database
def init_db():
    with app.app_context():
        db.create_all()
        logger.info("Database initialized successfully")

def save_uploaded_files(files):
    saved_files = []
    for file in files:
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            saved_files.append(filename)
    return saved_files

def send_verification_email(user_email):
    try:
        print(f"Starting email send to {user_email}")
        print(f"Mail settings: Server={app.config['MAIL_SERVER']}, Port={app.config['MAIL_PORT']}")
        
        s = URLSafeTimedSerializer(app.secret_key)
        token = s.dumps(user_email, salt='email-verify-salt')
        verification_url = url_for('verify_email', token=token, _external=True)

        msg = Message(
            'Verify Your Email - Hire Safari',
            sender=app.config['MAIL_USERNAME'],
            recipients=[user_email]
        )
        msg.body = f'''
        Welcome to Hire Safari!

        Please verify your email by clicking the following link:
        {verification_url}

        This link will expire in 24 hours.

        Best regards,
        The Hire Safari Team
        '''
        
        print("Attempting to send email...")
        mail.send(msg)
        print("Email sent successfully")
        logger.info(f"Verification email sent to {user_email}")
        return True
    except Exception as e:
        print(f"Error sending email: {str(e)}")
        logger.error(f"Error sending verification email to {user_email}: {str(e)}")
        return False

def send_booking_notification(user_id, booking):
    user = User.query.get(user_id)
    if not user:
        return False
        
    try:
        msg = Message(
            'New Booking Request - Hire Safari',
            recipients=[user.email]
        )
        msg.body = f'''
        You have a new booking request:
        Date: {booking.booking_date}
        Time: {booking.booking_time}
        
        Please log in to your dashboard to manage this booking.
        
        Best regards,
        The Hire Safari Team
        '''
        mail.send(msg)
        return True
    except Exception as e:
        logger.error(f"Error sending booking notification: {str(e)}")
        return False

def send_booking_status_notification(booking):
    try:
        print("=== Email Settings ===")
        print(f"Server: {app.config.get('MAIL_SERVER')}")
        print(f"Port: {app.config.get('MAIL_PORT')}")
        print(f"Username: {app.config.get('MAIL_USERNAME')}")
        print(f"SSL: {app.config.get('MAIL_USE_SSL')}")
        print(f"TLS: {app.config.get('MAIL_USE_TLS')}")
        
        user = User.query.get(booking.user_id)
        if not user:
            print("User not found!")
            return False
            
        try:
            status_text = "confirmed" if booking.status == "confirmed" else "cancelled"
            
            # Email to user - they get lister's contact info
            user_msg = Message(
                f'Booking {status_text.title()} - Hire Safari',
                sender=app.config.get('MAIL_USERNAME'),
                recipients=[user.email]
            )
            user_msg.body = f'''
            Your booking has been {status_text}:
            
            Service: {booking.listing.title}
            Date: {booking.booking_date}
            Time: {booking.booking_time}
            
            {'Contact information:' if status_text == 'confirmed' else ''}
            {f'Phone: {booking.listing.phone}' if status_text == 'confirmed' else ''}
            {f'Email: {booking.listing.email}' if status_text == 'confirmed' else ''}
            {f'Address: {booking.listing.address}, {booking.listing.city}, {booking.listing.state}' if status_text == 'confirmed' else ''}
            
            Best regards,
            The Hire Safari Team
            '''
            print("Attempting to send email to user...")
            mail.send(user_msg)
            print("Email sent to user successfully!")
            
            if status_text == "confirmed":
                # Send notification to lister
                lister = User.query.get(booking.listing.user_id)
                if lister:
                    lister_msg = Message(
                        f'New Booking Confirmed - Hire Safari',
                        sender=app.config.get('MAIL_USERNAME'),
                        recipients=[lister.email]
                    )
                    lister_msg.body = f'''
                    A booking has been confirmed for your service:
                    
                    Service: {booking.listing.title}
                    Date: {booking.booking_date}
                    Time: {booking.booking_time}
                    
                    Customer Contact Information:
                    Name: {user.username}
                    Email: {user.email}
                    
                    Best regards,
                    The Hire Safari Team
                    '''
                    print("Attempting to send email to lister...")
                    mail.send(lister_msg)
                    print("Email sent to lister successfully!")
            
            return True
        except Exception as e:
            print(f"Error sending notification email: {str(e)}")
            return False
            
    except Exception as e:
        print(f"Error in send_booking_status_notification: {str(e)}")
        return False

# Routes start here...

# Routes - Authentication
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = {'csrf_token': generate_csrf()}  # Generate CSRF token for form
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if User.query.filter((User.username == username) | (User.email == email)).first():
            flash('Username or email already exists', 'error')
            return redirect(url_for('signup'))

        user = User(
            username=username,
            email=email,
            password=generate_password_hash(password),
            role='user',
            verified=True  # Regular users are auto-verified
        )
        
        try:
            db.session.add(user)
            db.session.commit()
            
            session['user_id'] = user.id
            session['username'] = user.username
            session['user_role'] = user.role
            
            flash('Account created successfully!', 'success')
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            db.session.rollback()
            flash('Error creating account', 'error')
            return redirect(url_for('signup'))
    
    return render_template('signup.html', form=form)

@app.route('/sign-in', methods=['GET', 'POST'])
def sign_in():
    form = {'csrf_token': generate_csrf()}
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['user_role'] = user.role
            
            if user.role == 'lister' and not user.verified:
                flash('Please verify your email first', 'warning')
            return redirect(url_for('dashboard'))
            
        flash('Invalid email or password', 'error')
    
    return render_template('sign-in.html', form=form)

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out successfully', 'success')
    return redirect(url_for('index'))

@app.route('/verify/<token>')
def verify_email(token):
    try:
        s = URLSafeTimedSerializer(app.secret_key)
        email = s.loads(token, salt='email-verify-salt', max_age=86400)
        
        user = User.query.filter_by(email=email).first()
        
        if not user:
            flash('Invalid verification link. Please sign up first.', 'error')
            return redirect(url_for('signup'))
        
        if user.verified:
            flash('Email already verified. Please sign in.', 'info')
            return redirect(url_for('sign_in'))
        
        user.verified = True
        db.session.commit()
        
        session['verified_email'] = email
        
        return redirect(url_for('complete_account_setup'))
            
    except Exception as e:
        logger.error(f"Error verifying email: {str(e)}")
        flash('Invalid or expired verification link', 'error')
        return redirect(url_for('sign_in'))

@app.route('/complete-account-setup', methods=['GET', 'POST'])
def complete_account_setup():
    if 'verified_email' not in session:
        flash('Please verify your email first', 'error')
        return redirect(url_for('pricing'))
    
    if request.method == 'POST':
        try:
            email = session['verified_email']
            username = request.form.get('username')
            password = request.form.get('password')
            
            user = User.query.filter_by(email=email).first()
            if not user:
                flash('User not found', 'error')
                return redirect(url_for('pricing'))
            
            user.username = username
            user.password = generate_password_hash(password)
            
            db.session.commit()
            
            session.pop('verified_email', None)
            
            session['user_id'] = user.id
            session['username'] = user.username
            session['user_role'] = user.role
            
            flash('Account setup completed! Welcome to Hire Safari!', 'success')
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            logger.error(f"Error in account setup: {str(e)}")
            flash('Error setting up account', 'error')
            return redirect(url_for('complete_account_setup'))
    
    return render_template('complete_account_setup.html', 
                         email=session['verified_email'],
                         form={'csrf_token': generate_csrf()})

@app.route('/health')
def health_check():
    try:
        # Check if we can connect to the database
        db.session.execute('SELECT 1')
        return jsonify({
            'status': 'healthy',
            'database': 'connected',
            'tables': [table for table in db.engine.table_names()]
        })
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e)
        }), 500

@app.route('/init-db')
def init_database():
    try:
        db.create_all()
        # Create a test admin user
        if not User.query.filter_by(email='admin@example.com').first():
            admin = User(
                username='admin',
                email='admin@example.com',
                password=generate_password_hash('admin123'),
                role='admin',
                verified=True
            )
            db.session.add(admin)
            db.session.commit()
        return jsonify({
            'status': 'success',
            'message': 'Database initialized',
            'tables': [table for table in db.engine.table_names()]
        })
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500
@app.route('/reset-db')
def reset_database():
    try:
        print("Starting database reset...")
        inspector = db.inspect(db.engine)
        existing_tables = inspector.get_table_names()
        print(f"Existing tables: {existing_tables}")
        
        print("Dropping all tables...")
        db.drop_all()
        
        print("Creating all tables...")
        db.create_all()
        
        # Check the new table structure
        inspector = db.inspect(db.engine)
        new_tables = inspector.get_table_names()
        
        # Specifically check the user table columns
        user_columns = {column['name']: column for column in inspector.get_columns('user')}
        password_length = user_columns['password']['type'].length if 'password' in user_columns else 'unknown'
        
        return jsonify({
            'status': 'success',
            'message': 'Database reset successfully',
            'details': {
                'previous_tables': existing_tables,
                'new_tables': new_tables,
                'password_column_length': password_length
            }
        })
    except Exception as e:
        print(f"Error resetting database: {str(e)}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

# Routes - Main Pages
@app.route('/')
def index():
    try:
        # Force database initialization without checking tables
        db.create_all()
        
        # Basic render without any database queries first
        return render_template('index.html', 
                             featured_listings=[],
                             username=None,
                             now=datetime.now())
                             
    except Exception as e:
        error_html = f"""
        <html>
            <head><title>Site Status</title></head>
            <body>
                <h1>Site Status</h1>
                <p>Database URL: {app.config.get('SQLALCHEMY_DATABASE_URI', 'Not set').split('@')[1] if app.config.get('SQLALCHEMY_DATABASE_URI') else 'Not set'}</p>
                <p>Error: {str(e)}</p>
                <hr/>
                <p><a href="/init-db">Click to Initialize Database</a></p>
            </body>
        </html>
        """
        return error_html, 200

@app.route('/dashboard')
def dashboard():
    if not session.get('user_id'):
        flash('Please log in to access the dashboard', 'error')
        return redirect(url_for('sign_in'))
        
    try:
        user = User.query.get(session['user_id'])
        if not user:
            flash('User not found', 'error')
            return redirect(url_for('sign_in'))
        
        # Get user's bookings (bookings they made)
        user_bookings = Booking.query.filter_by(user_id=user.id).all()
        
        listings = []
        lister_bookings = []
        
        if user.role == 'lister' and user.verified:
            # Get lister's listings
            listings = Listing.query.filter_by(user_id=user.id).all()
            
            # Get bookings for all of lister's listings
            listing_ids = [listing.id for listing in listings]
            if listing_ids:
                lister_bookings = Booking.query.filter(
                    Booking.listing_id.in_(listing_ids)
                ).order_by(desc(Booking.created_at)).all()
        
        # Combine bookings if user is both a customer and lister
        all_bookings = lister_bookings + user_bookings
        # Sort combined bookings by date
        all_bookings.sort(key=lambda x: x.booking_date, reverse=True)
        
        return render_template('dashboard.html',
                            username=user.username,
                            user=user,
                            listings=listings,
                            bookings=all_bookings,  # Send combined bookings
                            is_lister_booking=lambda x: x in lister_bookings,  # Helper function
                            today=datetime.now().date())
                            
    except Exception as e:
        logger.error(f"Dashboard error: {str(e)}")
        flash('Error loading dashboard', 'error')
        return redirect(url_for('index'))

@app.route('/pricing')
def pricing():
    try:
        existing_user_email = None
        if 'user_id' in session:
            user = User.query.get(session['user_id'])
            if user and user.role == 'lister' and user.verified:
                flash('You already have a lister account', 'info')
                return redirect(url_for('dashboard'))
            elif user:
                existing_user_email = user.email

        plans = [
            {
                'name': 'Promotional',
                'price': 3,
                'duration': '10 days',
                'features': ['1 listing', 'Basic support']
            },
            {
                'name': 'Basic',
                'price': 5,
                'duration': '30 days',
                'features': ['Up to 5 listings', 'Email support']
            },
            {
                'name': 'Premium',
                'price': 8,
                'duration': '60 days',
                'features': ['Unlimited listings', 'Priority support']
            }
        ]
        
        return render_template('pricing.html', 
                             username=session.get('username'),
                             existing_user_email=existing_user_email,
                             plans=plans,
                             now=datetime.now())
                             
    except Exception as e:
        logger.error(f"Error in pricing route: {str(e)}")
        flash('Error loading pricing page', 'error')
        return redirect(url_for('index'))

# Routes - Payment Processing
@app.route('/create-checkout-session')
def create_checkout_session():
    plan = request.args.get('plan', 'basic').lower()
    email = request.args.get('email')
    
    if not email:
        flash('Email is required for lister registration', 'error')
        return redirect(url_for('pricing'))
    
    amounts = {
        'promotional': 300,  # $3.00
        'basic': 500,       # $5.00
        'premium': 800      # $8.00
    }
    
    try:
        checkout_session = stripe.checkout.Session.create(
            payment_method_types=['card'],
            line_items=[{
                'price_data': {
                    'currency': 'usd',
                    'product_data': {
                        'name': f'{plan.title()} Plan',
                    },
                    'unit_amount': amounts.get(plan, amounts['basic']),
                },
                'quantity': 1,
            }],
            mode='payment',
            success_url=url_for('success', _external=True) + f"?session_id={{CHECKOUT_SESSION_ID}}&email={email}",
            cancel_url=url_for('cancel', _external=True),
            metadata={
                'plan': plan,
                'email': email
            }
        )
        
        return redirect(checkout_session.url, code=303)
    except Exception as e:
        logger.error(f"Error creating checkout session: {str(e)}")
        flash('Error processing payment request', 'error')
        return redirect(url_for('pricing'))

@app.route('/success')
def success():
    try:
        print("=== Starting Success Route ===")
        session_id = request.args.get('session_id')
        email = request.args.get('email')
        
        print(f"Session ID: {session_id}")
        print(f"Email: {email}")
        
        if not session_id or not email:
            print("Missing session_id or email")
            flash('Invalid session or missing email', 'error')
            return redirect(url_for('index'))

        # Verify Stripe payment
        print("Verifying Stripe payment...")
        checkout_session = stripe.checkout.Session.retrieve(session_id)
        if checkout_session.payment_status != 'paid':
            print("Payment not completed")
            flash('Payment not completed', 'error')
            return redirect(url_for('pricing'))

        print("Checking for existing user...")
        # Check for existing user
        user = User.query.filter_by(email=email).first()
        if user:
            print(f"Updating existing user: {user.email}")
            # Upgrade existing user to lister
            user.role = 'lister'
            user.verified = False  # Need to verify email for lister privileges
            db.session.commit()
        else:
            print(f"Creating new user with email: {email}")
            # Create new user
            user = User(
                username=email.split('@')[0],  # Temporary username
                email=email,
                password=generate_password_hash('temporary'),  # Temporary password
                role='lister',
                verified=False
            )
            db.session.add(user)
            db.session.commit()

        # Send verification email
        print("Attempting to send verification email...")
        print(f"Mail Settings: SERVER={app.config.get('MAIL_SERVER')}, PORT={app.config.get('MAIL_PORT')}")
        print(f"Username: {app.config.get('MAIL_USERNAME')}")
        if send_verification_email(email):
            print("Email sent successfully!")
            flash('Payment successful! Please check your email to verify your lister account.', 'success')
            return render_template('success.html', email=email)
        else:
            print("Email sending failed!")
            flash('Error sending verification email. Please contact support.', 'error')
            return redirect(url_for('index'))

    except Exception as e:
        print(f"Error in success route: {str(e)}")
        logger.error(f"Error in success route: {str(e)}")
        flash('Error processing payment success', 'error')
        return redirect(url_for('index'))

@app.route('/cancel')
def cancel():
    flash('Payment cancelled', 'info')
    return redirect(url_for('pricing'))

# Routes - Listings and Bookings
@app.route('/create-listing', methods=['GET', 'POST'])
def create_listing():
    if not session.get('user_id'):
        flash('Please log in to create listings', 'error')
        return redirect(url_for('sign_in'))
        
    user = User.query.get(session['user_id'])
    if not user or not user.is_lister():
        flash('Access denied. Only verified service providers can create listings.', 'error')
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        try:
            saved_images = []
            if 'images' in request.files:
                files = request.files.getlist('images')
                for file in files:
                    if file and allowed_file(file.filename):
                        filename = secure_filename(file.filename)
                        filename = f"{int(time.time())}_{filename}"
                        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                        file.save(filepath)
                        saved_images.append(filename)

            business_hours = {}
            days = ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday']
            for day in days:
                open_time = request.form.get(f'{day}_open')
                close_time = request.form.get(f'{day}_close')
                if open_time and close_time:
                    business_hours[day] = {'open': open_time, 'close': close_time}

            listing = Listing(
                user_id=user.id,
                title=request.form['title'],
                category=request.form['category'],
                description=request.form['description'],
                address=request.form['address'],
                city=request.form['city'],
                state=request.form['state'],
                zip_code=request.form['zip_code'],
                phone=request.form['phone'],
                email=request.form['email'],
                website=request.form.get('website', ''),
                price_range=request.form.get('price_range', '$'),
                business_hours=json.dumps(business_hours),
                images=json.dumps(saved_images) if saved_images else None,
                status='active'
            )
            
            db.session.add(listing)
            db.session.commit()
            
            flash('Listing created successfully!', 'success')
            return redirect(url_for('view_listing', listing_id=listing.id))
            
        except Exception as e:
            db.session.rollback()
            logger.error(f"Error creating listing: {str(e)}")
            flash('Error creating listing. Please try again.', 'error')
            return redirect(url_for('create_listing'))
    
    return render_template('create_listing.html', 
                         username=user.username,
                         form={'csrf_token': generate_csrf()})

@app.route('/listing/<int:listing_id>')
def view_listing(listing_id):
    listing = Listing.query.get_or_404(listing_id)
    return render_template('listing_detail.html', 
                         listing=listing,
                         is_owner=session.get('user_id') == listing.user_id)

@app.route('/book-listing/<int:listing_id>/available-slots', methods=['GET'])
def get_available_slots(listing_id):
    try:
        date_str = request.args.get('date')
        if not date_str:
            return jsonify({'error': 'Date is required'}), 400

        booking_date = datetime.strptime(date_str, '%Y-%m-%d').date()
        listing = Listing.query.get_or_404(listing_id)
        
        existing_bookings = Booking.query.filter_by(
            listing_id=listing_id,
            booking_date=booking_date,
            status='confirmed'
        ).all()
        
        if not listing.business_hours:
            return jsonify({'slots': []}), 200
            
        business_hours = json.loads(listing.business_hours)
        day_name = booking_date.strftime('%A').lower()
        
        if day_name not in business_hours:
            return jsonify({'slots': []}), 200
            
        booked_times = [booking.booking_time for booking in existing_bookings]
        
        day_hours = business_hours[day_name]
        open_time = datetime.strptime(day_hours['open'], '%H:%M').time()
        close_time = datetime.strptime(day_hours['close'], '%H:%M').time()
        
        available_slots = []
        current_time = datetime.combine(booking_date, open_time)
        end_time = datetime.combine(booking_date, close_time)
        
        while current_time < end_time:
            time_str = current_time.strftime('%H:%M')
            if time_str not in booked_times:
                available_slots.append(time_str)
            current_time += timedelta(minutes=30)
        
        return jsonify({'slots': available_slots}), 200
        
    except Exception as e:
        logger.error(f"Error getting available slots: {str(e)}")
        return jsonify({'slots': []}), 200

@app.route('/book-listing/<int:listing_id>', methods=['POST'])
def book_listing(listing_id):
    if not session.get('user_id'):
        return jsonify({'error': 'Please sign in to book'}), 401
        
    try:
        data = request.get_json()
        booking_date = datetime.strptime(data['date'], '%Y-%m-%d').date()
        booking_time = data['time']
        phone = data.get('phone', '')
        
        # Create notes with phone
        notes = f"Contact Phone: {phone}"
        if data.get('notes'):
            notes += f"\n{data.get('notes')}"
        
        booking = Booking(
            listing_id=listing_id,
            user_id=session['user_id'],
            booking_date=booking_date,
            booking_time=booking_time,
            notes=notes
        )
        
        db.session.add(booking)
        db.session.commit()
        
        listing = Listing.query.get(listing_id)
        send_booking_notification(listing.user_id, booking)
        
        return jsonify({'message': 'Booking successful!'}), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error creating booking: {str(e)}")
        return jsonify({'error': 'Error creating booking'}), 500

@app.route('/manage-booking/<int:booking_id>/<action>')
def manage_booking(booking_id, action):
    if not session.get('user_id'):
        flash('Please sign in', 'error')
        return redirect(url_for('sign_in'))
        
    booking = Booking.query.get_or_404(booking_id)
    listing = Listing.query.get(booking.listing_id)
    
    if listing.user_id != session['user_id']:
        flash('Unauthorized access', 'error')
        return redirect(url_for('dashboard'))
        
    try:
        if action == 'confirm':
            booking.status = 'confirmed'
            flash('Booking confirmed', 'success')
        elif action == 'cancel':
            booking.status = 'cancelled'
            flash('Booking cancelled', 'success')
            
        db.session.commit()
        send_booking_status_notification(booking)
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error managing booking: {str(e)}")
        flash('Error updating booking', 'error')
        
    return redirect(url_for('dashboard'))

@app.route('/search')
def search_listings():
    keyword = request.args.get('keyword', '')
    category = request.args.get('category', '')
    location = request.args.get('location', '')
    
    query = Listing.query.filter_by(status='active')
    
    if keyword:
        query = query.filter(
            or_(
                Listing.title.ilike(f'%{keyword}%'),
                Listing.description.ilike(f'%{keyword}%')
            )
        )
    
    if category:
        query = query.filter(Listing.category == category)
        
    if location:
        query = query.filter(
            or_(
                Listing.city.ilike(f'%{location}%'),
                Listing.state.ilike(f'%{location}%'),
                Listing.zip_code.ilike(f'%{location}%')
            )
        )
        
    listings = query.order_by(Listing.created_at.desc()).all()
    return render_template('listings.html', listings=listings)

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    logger.error(f"404 error: {str(error)}")
    flash('Page not found', 'error')
    return redirect(url_for('index'))

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"500 error: {str(error)}")  # Changed 'e' to 'error'
    db.session.rollback()
    flash('An internal server error occurred', 'error')
    return redirect(url_for('index'))

# Template filters
@app.template_filter('fromjson')
def fromjson_filter(value):
    try:
        return json.loads(value) if value else None
    except:
        return None
@app.template_filter('format_time')
def format_time_filter(time_str):
    try:
        if not time_str:
            return ''
        time_obj = datetime.strptime(time_str, '%H:%M')
        return time_obj.strftime('%I:%M %p').lstrip('0')  # Remove leading zero
    except Exception as e:
        logger.error(f"Error formatting time: {str(e)}")
        return time_str

# Application initialization
def init_app():
    with app.app_context():
        try:
            print("Creating database tables...")
            db.create_all()
            print("Tables created successfully")
            
            # Create test user
            if not User.query.first():
                test_user = User(
                    username='admin',
                    email='admin@example.com',
                    password=generate_password_hash('admin123'),
                    role='admin',
                    verified=True
                )
                db.session.add(test_user)
                db.session.commit()
                print("Test user created")
            
            return True
        except Exception as e:
            print(f"Error in init_app: {str(e)}")
            return False

if __name__ == '__main__':
    if init_app():
        app.run(debug=True)
    else:
        print("Failed to initialize application")
        print(f"Database URI: {app.config['SQLALCHEMY_DATABASE_URI']}")