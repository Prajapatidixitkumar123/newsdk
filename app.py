from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
from werkzeug.utils import secure_filename
import PyPDF2
from docx import Document
import openai
from dotenv import load_dotenv
import time
import random
import string
from twilio.rest import Client

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///news.db'

# Load environment variables
load_dotenv()

# Configure Twilio credentials
TWILIO_ACCOUNT_SID = os.getenv('TWILIO_ACCOUNT_SID')
TWILIO_AUTH_TOKEN = os.getenv('TWILIO_AUTH_TOKEN')
TWILIO_PHONE_NUMBER = os.getenv('TWILIO_PHONE_NUMBER')

# Initialize Twilio client
try:
    twilio_client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
    print("Twilio client initialized successfully")
    print(f"Using Twilio phone number: {TWILIO_PHONE_NUMBER}")
except Exception as e:
    print(f"Error initializing Twilio client: {str(e)}")
    print(f"Account SID: {TWILIO_ACCOUNT_SID}")
    print(f"Phone Number: {TWILIO_PHONE_NUMBER}")
    twilio_client = None

# Configure upload folder
UPLOAD_FOLDER = os.path.join('static', 'uploads')
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Ensure upload directory exists
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Configure allowed file extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

# Add to your existing UPLOAD_FOLDER configuration
ALLOWED_DOCUMENT_EXTENSIONS = {'pdf', 'doc', 'docx', 'txt'}

# Configure OpenAI API key from environment variable
openai.api_key = os.getenv('OPENAI_API_KEY')

# Configure OpenAI API settings
openai.api_base = "https://api.openai.com/v1"
openai.api_type = "open_ai"
openai.api_version = None

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def allowed_document(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_DOCUMENT_EXTENSIONS

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    mobile_number = db.Column(db.String(15), unique=True, nullable=False)
    is_verified = db.Column(db.Boolean, default=False)
    is_admin = db.Column(db.Boolean, default=False)

class News(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    image = db.Column(db.String(200))
    category = db.Column(db.String(50), nullable=False)
    author = db.Column(db.String(100), nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    views = db.Column(db.Integer, default=0)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def home():
    # Get all news articles ordered by date
    news = News.query.order_by(News.date_posted.desc()).all()
    
    # Get all categories for the navigation
    categories = db.session.query(News.category).distinct().all()
    categories = [category[0] for category in categories if category[0]]
    
    return render_template('index.html', 
                         news=news,
                         categories=categories)

@app.route('/news/<int:news_id>')
def news_detail(news_id):
    if not current_user.is_authenticated:
        return redirect(url_for('register'))
    
    news = News.query.get_or_404(news_id)
    news.views += 1
    db.session.commit()
    
    # Get related news (same category)
    related_news = News.query.filter(
        News.category == news.category,
        News.id != news.id
    ).order_by(News.date_posted.desc()).limit(3).all()
    
    return render_template('news_detail.html', news=news, related_news=related_news)

@app.route('/category/<category>')
def category_news(category):
    if not current_user.is_authenticated:
        return redirect(url_for('register'))
    
    # Get all news articles in this category
    news = News.query.filter_by(category=category).order_by(News.date_posted.desc()).all()
    
    # Get all categories for navigation
    categories = db.session.query(News.category).distinct().all()
    categories = [cat[0] for cat in categories if cat[0]]
    
    return render_template('category.html', 
                         news=news, 
                         category=category, 
                         categories=categories)

@app.route('/search')
def search():
    query = request.args.get('q', '').strip()
    if not query:
        flash('Please enter a search term', 'warning')
        return redirect(url_for('home'))
    
    # Search in title, content, category, and author
    news = News.query.filter(
        db.or_(
            News.title.ilike(f'%{query}%'),
            News.content.ilike(f'%{query}%'),
            News.category.ilike(f'%{query}%'),
            News.author.ilike(f'%{query}%')
        )
    ).order_by(News.date_posted.desc()).all()
    
    # Get categories for the sidebar
    categories = db.session.query(News.category).distinct().all()
    
    return render_template('search_results.html', 
                         news=news, 
                         query=query, 
                         categories=categories)

@app.route('/admin')
@login_required
def admin():
    # Check if user is admin
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('home'))
        
    # Get all news articles
    news = News.query.order_by(News.date_posted.desc()).all()
    
    # Get unique categories
    categories = list(set([item.category for item in news]))
    
    # Calculate total views
    total_views = sum(item.views for item in news)
    
    # Count popular articles (views > 100)
    popular_count = sum(1 for item in news if item.views > 100)
    
    return render_template('admin.html',
                         news=news,
                         categories=categories,
                         total_views=total_views,
                         popular_count=popular_count)

@app.route('/admin/news/<int:news_id>')
@login_required
def admin_news_detail(news_id):
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('home'))
    return redirect(url_for('news_detail', news_id=news_id, admin=1))

@app.route('/admin/category/<category>')
@login_required
def admin_category(category):
    if not current_user.is_admin:
        flash('Access denied. Admin privileges required.', 'danger')
        return redirect(url_for('home'))
    return redirect(url_for('category_news', category=category, admin=1))

@app.route('/add_news', methods=['POST'])
@login_required
def add_news():
    if not current_user.is_admin:
        return redirect(url_for('home'))
    
    try:
        # Get form data
        title = request.form.get('title')
        content = request.form.get('content')
        category = request.form.get('category')
        image = request.files.get('image')
        
        print(f"Debug - Title: {title}")
        print(f"Debug - Category: {category}")
        print(f"Debug - Image file: {image}")
        
        # Validate required fields
        if not title or not content or not category:
            flash('Please fill in all required fields', 'error')
            return redirect(url_for('admin'))
        
        # Handle image upload
        image_filename = None
        if image and image.filename:
            print(f"Debug - Processing image: {image.filename}")
            if not os.path.exists(app.config['UPLOAD_FOLDER']):
                os.makedirs(app.config['UPLOAD_FOLDER'])
            
            # Generate unique filename
            filename = secure_filename(image.filename)
            unique_filename = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{filename}"
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            
            print(f"Debug - Saving image to: {image_path}")
            # Save image
            image.save(image_path)
            image_filename = unique_filename
            print(f"Debug - Image saved as: {image_filename}")
        
        # Create new news article
        new_news = News(
            title=title,
            content=content,
            category=category,
            image=image_filename,
            author=current_user.username
        )
        
        print(f"Debug - Creating news article with image: {image_filename}")
        # Add to database
        db.session.add(new_news)
        db.session.commit()
        
        flash('News article added successfully!', 'success')
        return redirect(url_for('admin'))
        
    except Exception as e:
        print(f"Debug - Error: {str(e)}")
        db.session.rollback()
        flash(f'Error adding news article: {str(e)}', 'error')
        return redirect(url_for('admin'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('admin'))
        flash('Invalid username or password')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/edit_news/<int:news_id>', methods=['GET', 'POST'])
@login_required
def edit_news(news_id):
    if not current_user.is_admin:
        return redirect(url_for('home'))
    
    news = News.query.get_or_404(news_id)
    
    if request.method == 'POST':
        news.title = request.form.get('title')
        news.content = request.form.get('content')
        news.category = request.form.get('category')
        news.author = request.form.get('author')
        
        # Handle image upload
        if 'image' in request.files:
            file = request.files['image']
            if file and file.filename and allowed_file(file.filename):
                try:
                    # Delete old image if it exists
                    if news.image:
                        old_image_path = os.path.join('static', news.image)
                        if os.path.exists(old_image_path):
                            os.remove(old_image_path)
                    
                    # Save new image
                    filename = secure_filename(file.filename)
                    filename = f"{datetime.now().strftime('%Y%m%d_%H%M%S')}_{filename}"
                    
                    # Create uploads directory if it doesn't exist
                    if not os.path.exists(UPLOAD_FOLDER):
                        os.makedirs(UPLOAD_FOLDER)
                    
                    file_path = os.path.join(UPLOAD_FOLDER, filename)
                    file.save(file_path)
                    
                    # Store the path relative to static folder
                    news.image = os.path.join('uploads', filename).replace('\\', '/')
                    print(f"Debug - Updated image saved at: {file_path}")
                    print(f"Debug - Updated image path stored in db: {news.image}")
                    
                except Exception as e:
                    print(f"Error updating image: {e}")
                    flash('Error uploading new image', 'error')
                    return redirect(url_for('edit_news', news_id=news_id))
        
        try:
            db.session.commit()
            flash('News article updated successfully!', 'success')
            return redirect(url_for('admin'))
        except Exception as e:
            print(f"Error updating news: {e}")
            db.session.rollback()
            flash('Error updating news article', 'error')
    
    return render_template('edit_news.html', news=news)

@app.route('/delete_news/<int:news_id>')
@login_required
def delete_news(news_id):
    if not current_user.is_admin:
        return redirect(url_for('home'))
    
    news = News.query.get_or_404(news_id)
    
    # Delete associated image if it exists
    if news.image:
        image_path = os.path.join('static', news.image)
        if os.path.exists(image_path):
            os.remove(image_path)
    
    try:
        db.session.delete(news)
        db.session.commit()
        flash('News article deleted successfully!', 'success')
    except Exception as e:
        print(f"Error deleting news: {e}")
        db.session.rollback()
        flash('Error deleting news article', 'error')
    
    return redirect(url_for('admin'))

def extract_text_from_pdf(file_path):
    text = ""
    with open(file_path, 'rb') as file:
        pdf_reader = PyPDF2.PdfReader(file)
        for page in pdf_reader.pages:
            text += page.extract_text()
    return text

def extract_text_from_docx(file_path):
    doc = Document(file_path)
    text = []
    for paragraph in doc.paragraphs:
        text.append(paragraph.text)
    return '\n'.join(text)

def extract_text_from_file(file_path):
    extension = file_path.rsplit('.', 1)[1].lower()
    if extension == 'pdf':
        return extract_text_from_pdf(file_path)
    elif extension in ['doc', 'docx']:
        return extract_text_from_docx(file_path)
    elif extension == 'txt':
        with open(file_path, 'r', encoding='utf-8') as file:
            return file.read()
    return ""

def generate_article_content(text):
    try:
        if not openai.api_key or openai.api_key == 'your-openai-api-key-here':
            raise openai.error.AuthenticationError("OpenAI API key is not configured. Please add your API key.")

        print("Starting content generation with text length:", len(text))  # Debug log
        
        # Generate title
        print("Generating title...")  # Debug log
        title_response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a professional news editor. Generate a concise and engaging title for this article."},
                {"role": "user", "content": f"Generate a title for this text:\n{text[:1000]}..."}
            ],
            max_tokens=100,
            temperature=0.7
        )
        title = title_response.choices[0].message.content.strip()
        print(f"Generated title: {title}")  # Debug log

        # Generate category
        print("Generating category...")  # Debug log
        category_response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a news categorization expert. Suggest a single category for this article."},
                {"role": "user", "content": f"Suggest a category for this text:\n{text[:1000]}..."}
            ],
            max_tokens=50,
            temperature=0.7
        )
        category = category_response.choices[0].message.content.strip()
        print(f"Generated category: {category}")  # Debug log

        # Generate formatted content
        print("Generating formatted content...")  # Debug log
        content_response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a professional news writer. Format the given text into a well-structured news article with proper HTML formatting, headings, and paragraphs."},
                {"role": "user", "content": f"Format this text into a news article:\n{text}"}
            ],
            max_tokens=2000,
            temperature=0.7
        )
        content = content_response.choices[0].message.content.strip()
        print(f"Generated content length: {len(content)}")  # Debug log

        result = {
            "title": title,
            "category": category,
            "content": content
        }
        print("Content generation successful!")  # Debug log
        return result

    except openai.error.AuthenticationError as e:
        print(f"OpenAI Authentication Error: {str(e)}")  # Debug log
        return None
    except openai.error.APIError as e:
        print(f"OpenAI API Error: {str(e)}")  # Debug log
        return None
    except Exception as e:
        print(f"Error in generate_article_content: {str(e)}")  # Debug log
        return None

@app.route('/process_document', methods=['POST'])
@login_required
def process_document():
    if not current_user.is_admin:
        return jsonify({"error": "Unauthorized"}), 403

    if 'document' not in request.files:
        return jsonify({"error": "No document uploaded"}), 400

    file = request.files['document']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400

    if not allowed_document(file.filename):
        return jsonify({"error": "File type not allowed. Please upload PDF, DOC, DOCX, or TXT files."}), 400

    temp_path = None
    try:
        # Create a unique filename to avoid conflicts
        filename = secure_filename(file.filename)
        temp_path = os.path.join(UPLOAD_FOLDER, f'temp_{int(time.time())}_{filename}')
        
        # Save the uploaded file
        file.save(temp_path)
        print(f"File saved to: {temp_path}")  # Debug log

        # Extract text from the document
        text = extract_text_from_file(temp_path)
        if not text:
            return jsonify({"error": "Could not extract text from document. The file might be empty or corrupted."}), 400

        print(f"Extracted text length: {len(text)}")  # Debug log

        # Generate article content using AI
        result = generate_article_content(text)
        if not result:
            return jsonify({"error": "Failed to generate content. Please check if your OpenAI API key is valid and has sufficient credits."}), 500

        print("Successfully processed document and generated content")  # Debug log
        return jsonify(result)

    except openai.error.AuthenticationError as e:
        error_msg = "Invalid OpenAI API key. Please check your API key configuration."
        print(f"Authentication Error: {str(e)}")  # Debug log
        return jsonify({"error": error_msg}), 401

    except openai.error.RateLimitError as e:
        error_msg = "OpenAI API rate limit exceeded. Please try again later."
        print(f"Rate Limit Error: {str(e)}")  # Debug log
        return jsonify({"error": error_msg}), 429

    except openai.error.InvalidRequestError as e:
        error_msg = f"Invalid request to OpenAI API: {str(e)}"
        print(f"Invalid Request Error: {str(e)}")  # Debug log
        return jsonify({"error": error_msg}), 400

    except openai.error.APIError as e:
        error_msg = "OpenAI API is currently unavailable. Please try again later."
        print(f"API Error: {str(e)}")  # Debug log
        return jsonify({"error": error_msg}), 503

    except Exception as e:
        error_msg = f"Error processing document: {str(e)}"
        print(f"Error processing document: {error_msg}")  # Debug log
        return jsonify({"error": error_msg}), 500

    finally:
        # Clean up the temporary file
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
                print(f"Temporary file deleted: {temp_path}")  # Debug log
            except Exception as e:
                print(f"Warning: Could not delete temporary file: {str(e)}")  # Debug log

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('home'))
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        mobile_number = request.form.get('mobile_number')
        
        # Validate username
        if not username or len(username) < 3:
            flash('Username must be at least 3 characters long', 'error')
            return redirect(url_for('register'))
            
        # Validate password
        if not password or len(password) < 6:
            flash('Password must be at least 6 characters long', 'error')
            return redirect(url_for('register'))
            
        # Validate mobile number
        if not mobile_number or not mobile_number.isdigit() or len(mobile_number) != 10:
            flash('Please enter a valid 10-digit mobile number', 'error')
            return redirect(url_for('register'))
            
        # Check if username exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists. Please choose another one.', 'error')
            return redirect(url_for('register'))
            
        # Check if mobile number exists
        if User.query.filter_by(mobile_number=mobile_number).first():
            flash('Mobile number already registered. Please use another number.', 'error')
            return redirect(url_for('register'))
            
        try:
            # Generate OTP
            otp = ''.join([str(random.randint(0, 9)) for _ in range(6)])
            
            # Store registration data in session
            session['registration_data'] = {
                'username': username,
                'password': password,
                'mobile_number': mobile_number,
                'otp': otp
            }
            
            # Debug log
            print(f"Generated OTP: {otp}")
            print(f"Stored session data: {session['registration_data']}")
            
            # Send OTP via Twilio
            try:
                # Get Twilio credentials
                account_sid = os.getenv('TWILIO_ACCOUNT_SID')
                auth_token = os.getenv('TWILIO_AUTH_TOKEN')
                from_number = os.getenv('TWILIO_PHONE_NUMBER')
                
                # Validate Twilio credentials
                if not all([account_sid, auth_token, from_number]):
                    raise ValueError("Missing Twilio credentials in environment variables")
                
                print(f"Using Twilio credentials:")
                print(f"Account SID: {account_sid}")
                print(f"From number: {from_number}")
                
                # Initialize Twilio client
                twilio_client = Client(account_sid, auth_token)
                
                # Format the phone number correctly
                to_number = f"+91{mobile_number}"  # For Indian numbers
                
                # Log the attempt
                print(f"Attempting to send OTP to {to_number} from {from_number}")
                
                # Send the message
                message = twilio_client.messages.create(
                    body=f'Your OTP for registration is: {otp}',
                    from_=from_number.strip(),
                    to=to_number
                )
                
                # Log success
                print(f"OTP sent successfully. Message SID: {message.sid}")
                
                flash('OTP has been sent to your mobile number', 'success')
                return redirect(url_for('verify_otp'))
                
            except Exception as e:
                # Log detailed error information
                print(f"Twilio error details: {str(e)}")
                print(f"Account SID: {os.getenv('TWILIO_ACCOUNT_SID')}")
                print(f"From number: {os.getenv('TWILIO_PHONE_NUMBER')}")
                flash('Failed to send OTP. Please check your Twilio configuration.', 'error')
                return redirect(url_for('register'))
                
        except Exception as e:
            flash('An error occurred during registration. Please try again.', 'error')
            print(f"Registration error: {str(e)}")
            return redirect(url_for('register'))
            
    return render_template('register.html')

@app.route('/verify-otp', methods=['GET', 'POST'])
def verify_otp():
    # Debug log
    print("Accessing verify-otp route")
    print(f"Session data: {session.get('registration_data')}")
    
    if 'registration_data' not in session:
        flash('Registration session expired. Please register again.', 'error')
        return redirect(url_for('register'))
        
    if request.method == 'POST':
        user_otp = request.form.get('otp')
        stored_otp = session['registration_data']['otp']
        
        print(f"User entered OTP: {user_otp}")
        print(f"Stored OTP: {stored_otp}")
        
        if user_otp == stored_otp:
            try:
                # Create new user
                new_user = User(
                    username=session['registration_data']['username'],
                    mobile_number=session['registration_data']['mobile_number']
                )
                new_user.set_password(session['registration_data']['password'])
                
                db.session.add(new_user)
                db.session.commit()
                
                # Clear session data
                session.pop('registration_data', None)
                
                # Automatically log in the user
                login_user(new_user)
                
                flash('Registration successful! Welcome to the news website.', 'success')
                return redirect(url_for('home'))
                
            except Exception as e:
                flash('Failed to create account. Please try again.', 'error')
                print(f"User creation error: {str(e)}")
                return redirect(url_for('register'))
        else:
            flash('Invalid OTP. Please try again.', 'error')
            return redirect(url_for('verify_otp'))
            
    return render_template('verify_otp.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True) 