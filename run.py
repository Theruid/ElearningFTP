from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
from datetime import datetime
from functools import wraps
import sys

# Get the absolute path of the current directory
basedir = os.path.abspath(os.path.dirname(__file__))

app = Flask(__name__, 
    template_folder=os.path.join(basedir, 'templates'),
    static_folder=os.path.join(basedir, 'static')
)
app.config['SECRET_KEY'] = 'your-secret-key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///ems.db'
app.config['UPLOAD_FOLDER'] = os.path.join(basedir, 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 1024  # 1GB max file size
ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx', 'ppt', 'pptx', 'txt', 'mp4', 'zip'}

# Create uploads directory if it doesn't exist
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Role definitions
ROLE_ADMIN = 'admin'
ROLE_SUPERVISOR = 'supervisor'
ROLE_EMPLOYEE = 'employee'

# Team Model
class Team(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    members = db.relationship('User', back_populates='team', lazy=True)

# User Model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(20), nullable=False, default=ROLE_EMPLOYEE)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    team_id = db.Column(db.Integer, db.ForeignKey('team.id'))
    team = db.relationship('Team', back_populates='members')
    contents = db.relationship('Content', back_populates='author', lazy=True)
    supervised_categories = db.relationship('Category', secondary='category_supervisors', 
        back_populates='supervisors')
    progress_items = db.relationship('UserProgress', back_populates='user', lazy=True)
    quiz_scores = db.relationship('QuizAttempt', back_populates='user', lazy=True)
    created_quizzes = db.relationship('Quiz', back_populates='creator', lazy=True)
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def is_admin(self):
        return self.role == ROLE_ADMIN
    
    def is_supervisor(self):
        return self.role == ROLE_SUPERVISOR
    
    def can_edit_content(self, content):
        return self.is_admin() or self.id == content.user_id or \
            (self.is_supervisor() and content.category in self.supervised_categories)
    
    def can_manage_category(self, category):
        return self.is_admin() or \
            (self.is_supervisor() and category in self.supervised_categories)

# Category supervisors association table
category_supervisors = db.Table('category_supervisors',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('category_id', db.Integer, db.ForeignKey('category.id'), primary_key=True)
)

# Category Model
class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    parent_id = db.Column(db.Integer, db.ForeignKey('category.id'))
    contents = db.relationship('Content', back_populates='category', lazy=True)
    supervisors = db.relationship('User', secondary='category_supervisors', 
        back_populates='supervised_categories')
    subcategories = db.relationship(
        'Category',
        backref=db.backref('parent', remote_side=[id]),
        lazy=True
    )
    quizzes = db.relationship('Quiz', back_populates='category', lazy=True)

# Content Model
class Content(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    filename = db.Column(db.String(255), nullable=False)
    file_type = db.Column(db.String(10), nullable=False)
    upload_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    views = db.Column(db.Integer, default=0)
    completion_time = db.Column(db.Integer, default=0)  # Estimated completion time in minutes
    required = db.Column(db.Boolean, default=False)  # Is this content mandatory?
    author = db.relationship('User', back_populates='contents')
    category = db.relationship('Category', back_populates='contents')
    progress_records = db.relationship('UserProgress', back_populates='content', lazy=True)

# Progress Tracking Models
class UserProgress(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content_id = db.Column(db.Integer, db.ForeignKey('content.id'), nullable=False)
    status = db.Column(db.String(20), default='not_started')
    completion_date = db.Column(db.DateTime)
    time_spent = db.Column(db.Integer, default=0)
    last_accessed = db.Column(db.DateTime)
    user = db.relationship('User', back_populates='progress_items')
    content = db.relationship('Content', back_populates='progress_records')

class Quiz(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    category_id = db.Column(db.Integer, db.ForeignKey('category.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    passing_score = db.Column(db.Integer, default=70)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    category = db.relationship('Category', back_populates='quizzes', lazy=True)
    creator = db.relationship('User', back_populates='created_quizzes', lazy=True)
    questions = db.relationship('QuizQuestion', back_populates='quiz', lazy=True, cascade='all, delete-orphan')
    attempts = db.relationship('QuizAttempt', back_populates='quiz', lazy=True)

class QuizQuestion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'), nullable=False)
    question_text = db.Column(db.Text, nullable=False)
    question_type = db.Column(db.String(20), nullable=False)
    correct_answer = db.Column(db.Text, nullable=False)
    options = db.Column(db.Text)
    points = db.Column(db.Integer, default=1)
    quiz = db.relationship('Quiz', back_populates='questions')
    answers = db.relationship('QuizAnswer', back_populates='question', lazy=True)

class QuizAttempt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id'), nullable=False)
    score = db.Column(db.Float, nullable=False)
    passed = db.Column(db.Boolean, default=False)
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    user = db.relationship('User', back_populates='quiz_scores')
    quiz = db.relationship('Quiz', back_populates='attempts')
    answers = db.relationship('QuizAnswer', back_populates='attempt', lazy=True, cascade='all, delete-orphan')

class QuizAnswer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    attempt_id = db.Column(db.Integer, db.ForeignKey('quiz_attempt.id'), nullable=False)
    question_id = db.Column(db.Integer, db.ForeignKey('quiz_question.id'), nullable=False)
    user_answer = db.Column(db.Text, nullable=False)
    is_correct = db.Column(db.Boolean, nullable=False)
    points_earned = db.Column(db.Integer, nullable=False)
    attempt = db.relationship('QuizAttempt', back_populates='answers')
    question = db.relationship('QuizQuestion', back_populates='answers')

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def generate_unique_filename(original_filename, content_id=None):
    """Generate a unique filename while preserving the original name and extension."""
    name, ext = os.path.splitext(original_filename)
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    if content_id:
        return f"{name}_{content_id}{ext}"
    return f"{name}_{timestamp}{ext}"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def admin_or_supervisor_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin() and not current_user.is_supervisor():
            flash('Access denied. Only administrators and supervisors can upload content.', 'error')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Progress Tracking Routes
@app.route('/progress_dashboard')
@login_required
def progress_dashboard():
    # Calculate overall progress
    user_progress = UserProgress.query.filter_by(user_id=current_user.id).all()
    total_content = Content.query.count()
    completed_items = len([p for p in user_progress if p.status == 'completed'])
    overall_progress = (completed_items / total_content * 100) if total_content > 0 else 0

    # Calculate average quiz score
    quiz_attempts = QuizAttempt.query.filter_by(user_id=current_user.id).all()
    avg_quiz_score = sum(attempt.score for attempt in quiz_attempts) / len(quiz_attempts) if quiz_attempts else 0

    # Calculate total time spent
    total_time_spent = sum(p.time_spent for p in user_progress) / 60  # Convert minutes to hours

    # Get category progress data
    categories = Category.query.all()
    category_progress = []
    for category in categories:
        category_content = Content.query.filter_by(category_id=category.id).all()
        if category_content:
            completed_in_category = len([p for p in user_progress 
                if p.status == 'completed' and p.content in category_content])
            progress = (completed_in_category / len(category_content) * 100)
            category_progress.append({
                'name': category.name,
                'progress': progress
            })

    # Get recent activities
    recent_activities = []
    for progress in sorted(user_progress, key=lambda x: x.last_accessed or datetime.min, reverse=True)[:5]:
        if progress.last_accessed:
            activity = {
                'date': progress.last_accessed.strftime('%Y-%m-%d %H:%M'),
                'title': progress.content.title,
                'description': f"Spent {progress.time_spent} minutes on this content"
            }
            recent_activities.append(activity)

    # Create serializable progress items
    progress_data = []
    for item in user_progress:
        progress_item = {
            'title': item.content.title,
            'category': item.content.category.name,
            'file_type': item.content.file_type,
            'status': item.status,
            'time_spent': item.time_spent,
            'completion_date': item.completion_date.strftime('%Y-%m-%d') if item.completion_date else None,
            'score': None  # Add quiz score if available
        }
        # Get the latest quiz score for this content if exists
        quiz_attempt = QuizAttempt.query.filter_by(
            user_id=current_user.id,
            quiz_id=item.content.id
        ).order_by(QuizAttempt.completed_at.desc()).first()
        if quiz_attempt:
            progress_item['score'] = quiz_attempt.score
        progress_data.append(progress_item)

    return render_template('progress_dashboard.html',
        overall_progress=round(overall_progress, 1),
        completed_items=completed_items,
        avg_quiz_score=round(avg_quiz_score, 1),
        total_time_spent=round(total_time_spent, 1),
        category_progress=category_progress,
        recent_activities=recent_activities,
        progress_items=user_progress,  # For template display
        progress_data=progress_data    # For JSON export
    )

@app.route('/supervisor_dashboard')
@login_required
def supervisor_dashboard():
    if not current_user.is_supervisor() and not current_user.is_admin():
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))

    # Get supervised categories
    supervised_categories = current_user.supervised_categories

    # Get team members (users who have content in supervised categories)
    team_members_query = db.session.query(User).distinct().join(UserProgress)\
        .join(Content).join(Category)\
        .filter(Category.id.in_([cat.id for cat in supervised_categories]))
    
    team_members = []
    for member in team_members_query:
        member_progress = UserProgress.query.filter_by(user_id=member.id).all()
        member_quizzes = QuizAttempt.query.filter_by(user_id=member.id).all()
        
        completed = len([p for p in member_progress if p.status == 'completed'])
        in_progress = len([p for p in member_progress if p.status == 'in_progress'])
        total = len(member_progress)
        progress = (completed / total * 100) if total > 0 else 0
        
        quiz_avg = sum(q.score for q in member_quizzes) / len(member_quizzes) if member_quizzes else 0
        last_activity = max([p.last_accessed for p in member_progress if p.last_accessed] or [datetime.min])
        
        team_members.append({
            'id': member.id,
            'username': member.username,
            'progress': round(progress, 1),
            'completed_items': completed,
            'in_progress_items': in_progress,
            'quiz_average': round(quiz_avg, 1),
            'last_activity': last_activity
        })

    # Calculate team statistics
    team_progress = []
    for category in supervised_categories:
        category_content = Content.query.filter_by(category_id=category.id).all()
        if category_content:
            progress_records = UserProgress.query.join(Content)\
                .filter(Content.category_id == category.id).all()
            completion_rate = len([p for p in progress_records if p.status == 'completed']) \
                / (len(category_content) * team_members_query.count()) * 100
            team_progress.append({
                'category': category.name,
                'completion_rate': round(completion_rate, 1)
            })

    # Get quiz performance data
    quiz_performance = []
    for quiz in Quiz.query.filter(Quiz.category_id.in_([cat.id for cat in supervised_categories])):
        attempts = QuizAttempt.query.filter_by(quiz_id=quiz.id).all()
        if attempts:
            avg_score = sum(a.score for a in attempts) / len(attempts)
            quiz_performance.append({
                'quiz_name': quiz.title,
                'avg_score': round(avg_score, 1)
            })

    # Get required content completion data
    required_content = []
    for content in Content.query.filter_by(required=True)\
            .filter(Content.category_id.in_([cat.id for cat in supervised_categories])):
        progress_records = UserProgress.query.filter_by(content_id=content.id).all()
        completion_rate = len([p for p in progress_records if p.status == 'completed']) \
            / team_members_query.count() * 100
        avg_score = 0
        if content.quizzes:
            quiz_attempts = QuizAttempt.query.join(Quiz)\
                .filter(Quiz.category_id == content.category_id).all()
            if quiz_attempts:
                avg_score = sum(a.score for a in quiz_attempts) / len(quiz_attempts)
        
        required_content.append({
            'title': content.title,
            'category': content.category.name,
            'completion_rate': round(completion_rate, 1),
            'avg_score': round(avg_score, 1),
            'due_date': datetime.now(),  # You might want to add a due_date field to Content model
            'status': 'completed' if completion_rate == 100 else 'in_progress' if completion_rate > 0 else 'not_started'
        })

    # Calculate team averages
    team_stats = {
        'avg_progress': sum(m['progress'] for m in team_members) / len(team_members) if team_members else 0,
        'completion_rate': sum(c['completion_rate'] for c in required_content) / len(required_content) if required_content else 0,
        'avg_quiz_score': sum(q['avg_score'] for q in quiz_performance) / len(quiz_performance) if quiz_performance else 0,
        'active_users': len([m for m in team_members if m['last_activity'].date() == datetime.now().date()])
    }

    return render_template('supervisor_dashboard.html',
        team_members=team_members,
        team_progress=team_progress,
        quiz_performance=quiz_performance,
        required_content=required_content,
        team_avg_progress=round(team_stats['avg_progress'], 1),
        completion_rate=round(team_stats['completion_rate'], 1),
        team_avg_quiz_score=round(team_stats['avg_quiz_score'], 1),
        active_users=team_stats['active_users']
    )

@app.route('/view_member_progress/<int:user_id>')
@login_required
def view_member_progress(user_id):
    if not current_user.is_supervisor() and not current_user.is_admin():
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))

    member = User.query.get_or_404(user_id)
    return redirect(url_for('progress_dashboard', user_id=user_id))

@app.route('/export_team_report/<format>')
@login_required
def export_team_report(format):
    if not current_user.is_supervisor() and not current_user.is_admin():
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))

    # Implementation for report generation will be added later
    flash('Report export feature coming soon!', 'info')
    return redirect(url_for('supervisor_dashboard'))

# Update the view_content route to track progress
@app.route('/content/<int:content_id>')
@login_required
def view_content(content_id):
    try:
        content = Content.query.get_or_404(content_id)
        
        # Get or create progress record
        progress = UserProgress.query.filter_by(
            user_id=current_user.id,
            content_id=content_id
        ).first()
        
        if not progress:
            progress = UserProgress(
                user_id=current_user.id,
                content_id=content_id,
                status='in_progress'
            )
            db.session.add(progress)
        else:
            # Allow rewatching by setting status back to in_progress if completed
            if progress.status == 'completed':
                progress.status = 'in_progress'
        
        # Update last accessed time
        progress.last_accessed = datetime.utcnow()
        
        # Increment view count
        content.views += 1
        db.session.commit()
        
        # Get quiz attempt if exists
        quiz_attempt = None
        quizzes = Quiz.query.filter_by(category_id=content.category_id).all()
        if quizzes:
            quiz_attempt = QuizAttempt.query.filter_by(
                user_id=current_user.id,
                quiz_id=quizzes[0].id
            ).order_by(QuizAttempt.completed_at.desc()).first()
        
        return render_template('content.html', 
                             content=content, 
                             progress=progress,
                             quiz_attempt=quiz_attempt)
    except Exception as e:
        app.logger.error(f'Error viewing content: {str(e)}')
        flash('Error loading content', 'error')
        return redirect(url_for('dashboard'))

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            flash('Logged in successfully.', 'success')
            return redirect(url_for('dashboard'))
        flash('Invalid username or password.', 'error')
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'error')
            return redirect(url_for('register'))
            
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'error')
            return redirect(url_for('register'))
            
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/dashboard')
@login_required
def dashboard():
    # Get categories
    categories = Category.query.all()
    
    # Get recent progress
    recent_progress = UserProgress.query.filter_by(user_id=current_user.id)\
        .order_by(UserProgress.last_accessed.desc())\
        .limit(5).all()
    
    # Calculate category progress
    category_progress = {}
    for category in categories:
        category_content = Content.query.filter_by(category_id=category.id).all()
        if category_content:
            progress_records = UserProgress.query.join(Content)\
                .filter(Content.category_id == category.id,
                       UserProgress.user_id == current_user.id).all()
            completed = len([p for p in progress_records if p.status == 'completed'])
            progress = (completed / len(category_content) * 100) if category_content else 0
            category_progress[category.id] = round(progress, 1)
    
    # Get required content
    required_content = Content.query.filter_by(required=True).all()
    
    # Get content progress
    content_progress = {}
    progress_records = UserProgress.query.filter_by(user_id=current_user.id).all()
    for progress in progress_records:
        content_progress[progress.content_id] = {
            'status': progress.status,
            'time_spent': progress.time_spent,
            'completion_date': progress.completion_date
        }
    
    return render_template('dashboard.html',
        categories=categories,
        recent_progress=recent_progress,
        category_progress=category_progress,
        required_content=required_content,
        content_progress=content_progress
    )

@app.route('/category/<int:category_id>')
@login_required
def category(category_id):
    category = Category.query.get_or_404(category_id)
    return render_template('category.html', category=category)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
@admin_or_supervisor_required
def upload():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file selected', 'error')
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash('No file selected', 'error')
            return redirect(request.url)
        
        if '.' not in file.filename:
            flash('File must have an extension', 'error')
            return redirect(request.url)
            
        file_extension = file.filename.rsplit('.', 1)[1].lower()
        if not allowed_file(file.filename):
            flash(f'File type .{file_extension} is not allowed. Allowed types are: {", ".join(ALLOWED_EXTENSIONS)}', 'error')
            return redirect(request.url)
        
        try:
            # Create content record first to get the ID
            content = Content(
                title=request.form['title'],
                description=request.form.get('description', ''),
                filename='',  # Will update after saving file
                file_type=file_extension,
                category_id=request.form['category'],
                user_id=current_user.id,
                completion_time=request.form.get('completion_time', type=int, default=0),
                required=request.form.get('required') == 'on'
            )
            db.session.add(content)
            db.session.flush()  # This assigns an ID to content

            # Generate unique filename using content ID
            original_filename = secure_filename(file.filename)
            unique_filename = generate_unique_filename(original_filename, content.id)
            
            # Save file with unique name
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
            file.save(file_path)
            
            # Update content record with the filename
            content.filename = unique_filename
            
            # Create quiz if requested
            if request.form.get('add_quiz') == 'on':
                quiz = Quiz(
                    title=request.form.get('quiz_title', content.title + ' Quiz'),
                    description=request.form.get('quiz_description', ''),
                    category_id=request.form['category'],
                    created_by=current_user.id,
                    passing_score=request.form.get('passing_score', type=int, default=70)
                )
                db.session.add(quiz)
                db.session.commit()
                
                process_quiz_questions(request.form)
            
            db.session.commit()
            flash('Content uploaded successfully!', 'success')
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error uploading file: {str(e)}', 'error')
            return redirect(request.url)
    
    categories = Category.query.all()
    return render_template('upload.html', allowed_extensions=ALLOWED_EXTENSIONS, categories=categories)

@app.route('/edit-content/<int:content_id>', methods=['GET', 'POST'])
@login_required
@admin_or_supervisor_required
def edit_content(content_id):
    content = Content.query.get_or_404(content_id)
    
    if request.method == 'POST':
        try:
            content.title = request.form['title']
            content.description = request.form.get('description', '')
            content.category_id = request.form['category']
            content.completion_time = request.form.get('completion_time', type=int, default=0)
            content.required = request.form.get('required') == 'on'
            
            # Handle file upload if new file is provided
            if 'file' in request.files and request.files['file'].filename:
                file = request.files['file']
                if '.' not in file.filename:
                    flash('File must have an extension', 'error')
                    return redirect(request.url)
                    
                file_extension = file.filename.rsplit('.', 1)[1].lower()
                if not allowed_file(file.filename):
                    flash(f'File type .{file_extension} is not allowed. Allowed types are: {", ".join(ALLOWED_EXTENSIONS)}', 'error')
                    return redirect(request.url)
                
                # Delete old file if it exists
                old_file_path = os.path.join(app.config['UPLOAD_FOLDER'], content.filename)
                if os.path.exists(old_file_path):
                    os.remove(old_file_path)
                
                # Generate new filename using content ID
                original_filename = secure_filename(file.filename)
                new_filename = generate_unique_filename(original_filename, content.id)
                
                # Save new file
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], new_filename)
                file.save(file_path)
                
                # Update content record
                content.filename = new_filename
                content.file_type = file_extension
            
            db.session.commit()
            flash('Content updated successfully!', 'success')
            return redirect(url_for('manage_content'))
            
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating content: {str(e)}', 'error')
            return redirect(request.url)
    
    categories = Category.query.all()
    return render_template('admin/edit_content.html', content=content, categories=categories, allowed_extensions=ALLOWED_EXTENSIONS)

@app.route('/content/<int:content_id>/quiz', methods=['GET', 'POST'])
@login_required
def take_quiz(content_id):
    content = Content.query.get_or_404(content_id)
    quizzes = Quiz.query.filter_by(category_id=content.category_id).all()
    if not quizzes:
        flash('No quiz available for this content', 'error')
        return redirect(url_for('view_content', content_id=content_id))
    
    if request.method == 'POST':
        # Calculate score
        total_points = 0
        earned_points = 0
        quiz_attempt = QuizAttempt(
            user_id=current_user.id,
            quiz_id=quizzes[0].id,
            started_at=datetime.utcnow()
        )
        
        for question in quizzes[0].questions:
            answer = request.form.get(f'answer_{question.id}')
            if not answer:
                continue
            
            total_points += question.points
            is_correct = False
            
            if question.question_type == 'multiple_choice':
                is_correct = answer.strip() == question.correct_answer.strip()
            elif question.question_type == 'true_false':
                is_correct = answer.lower() == question.correct_answer.lower()
            else:  # text answer
                is_correct = answer.strip().lower() == question.correct_answer.strip().lower()
            
            points_earned = question.points if is_correct else 0
            earned_points += points_earned
            
            quiz_answer = QuizAnswer(
                question_id=question.id,
                user_answer=answer,
                is_correct=is_correct,
                points_earned=question.points if is_correct else 0
            )
            quiz_attempt.answers.append(quiz_answer)
        
        # Calculate percentage score
        score = (earned_points / total_points * 100) if total_points > 0 else 0
        quiz_attempt.score = score
        quiz_attempt.passed = score >= quizzes[0].passing_score
        quiz_attempt.completed_at = datetime.utcnow()
        
        db.session.add(quiz_attempt)
        
        # Update progress if quiz is passed
        if quiz_attempt.passed:
            progress = UserProgress.query.filter_by(
                user_id=current_user.id,
                content_id=content_id
            ).first()
            if progress:
                progress.status = 'completed'
                progress.completion_date = datetime.utcnow()
        
        db.session.commit()
        
        flash(f'Quiz submitted! Your score: {score:.1f}%', 'success' if quiz_attempt.passed else 'warning')
        return redirect(url_for('view_content', content_id=content_id))
    
    return render_template('quiz.html', content=content, quiz=quizzes[0])

@app.route('/download/<int:content_id>')
@login_required
def download_content(content_id):
    content = Content.query.get_or_404(content_id)
    return send_from_directory(
        app.config['UPLOAD_FOLDER'],
        content.filename,
        as_attachment=True,
        download_name=content.filename
    )

@app.route('/search')
@login_required
def search():
    query = request.args.get('q', '')
    if query:
        contents = Content.query.filter(
            (Content.title.ilike(f'%{query}%')) |
            (Content.description.ilike(f'%{query}%'))
        ).all()
    else:
        contents = []
    return render_template('search.html', contents=contents, query=query)

# Admin routes for category management
@app.route('/manage/categories', methods=['GET', 'POST'])
@login_required
def manage_categories():
    if not current_user.is_admin():
        flash('You do not have permission to access this page.', 'error')
        return redirect(url_for('index'))
    
    categories = Category.query.all()
    
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        parent_id = request.form.get('parent_id')
        
        if parent_id:
            parent_id = int(parent_id)
        else:
            parent_id = None
            
        new_category = Category(
            name=name,
            description=description,
            parent_id=parent_id
        )
        db.session.add(new_category)
        
        try:
            db.session.commit()
            flash('Category added successfully!', 'success')
        except:
            db.session.rollback()
            flash('Error adding category. Please try again.', 'error')
            
    return render_template('manage_categories.html', categories=categories)

@app.route('/category/<int:category_id>/edit', methods=['POST'])
@login_required
def edit_category(category_id):
    if not current_user.is_admin():
        flash('You do not have permission to perform this action.', 'error')
        return redirect(url_for('index'))
    
    category = Category.query.get_or_404(category_id)
    
    name = request.form.get('name')
    description = request.form.get('description')
    parent_id = request.form.get('parent_id')
    
    if parent_id:
        parent_id = int(parent_id)
    else:
        parent_id = None
        
    category.name = name
    category.description = description
    category.parent_id = parent_id
    
    try:
        db.session.commit()
        flash('Category updated successfully!', 'success')
    except:
        db.session.rollback()
        flash('Error updating category. Please try again.', 'error')
        
    return redirect(url_for('manage_categories'))

@app.route('/category/<int:category_id>/delete', methods=['POST'])
@login_required
def delete_category(category_id):
    if not current_user.is_admin():
        flash('You do not have permission to perform this action.', 'error')
        return redirect(url_for('index'))
    
    category = Category.query.get_or_404(category_id)
    
    # Check if category has any content
    if category.contents:
        flash('Cannot delete category that contains content.', 'error')
        return redirect(url_for('manage_categories'))
    
    # Check if category has any subcategories
    if category.subcategories:
        flash('Cannot delete category that has subcategories.', 'error')
        return redirect(url_for('manage_categories'))
    
    try:
        db.session.delete(category)
        db.session.commit()
        flash('Category deleted successfully!', 'success')
    except:
        db.session.rollback()
        flash('Error deleting category. Please try again.', 'error')
        
    return redirect(url_for('manage_categories'))

@app.route('/admin/categories', methods=['GET', 'POST'])
@login_required
def manage_categories_admin():
    if current_user.role != ROLE_ADMIN:
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        parent_id = request.form.get('parent_id')
        
        if parent_id and parent_id != '0':
            parent_id = int(parent_id)
        else:
            parent_id = None
            
        category = Category(name=name, description=description, parent_id=parent_id)
        db.session.add(category)
        db.session.commit()
        flash('Category created successfully!', 'success')
        return redirect(url_for('manage_categories_admin'))
        
    categories = Category.query.all()
    return render_template('admin/categories.html', categories=categories)

@app.route('/admin/users')
@login_required
def manage_users():
    if not current_user.is_admin():
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))
    users = User.query.all()
    return render_template('admin/users.html', users=users)

@app.route('/admin/user/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    if not current_user.is_admin():
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))
    
    user = User.query.get_or_404(user_id)
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        role = request.form.get('role')
        is_active = request.form.get('is_active') == 'on'
        
        if User.query.filter(User.username == username, User.id != user_id).first():
            flash('Username already exists', 'error')
        elif User.query.filter(User.email == email, User.id != user_id).first():
            flash('Email already exists', 'error')
        else:
            user.username = username
            user.email = email
            user.role = role
            user.is_active = is_active
            
            if role == ROLE_SUPERVISOR:
                category_ids = request.form.getlist('supervised_categories')
                supervised_categories = Category.query.filter(Category.id.in_(category_ids)).all()
                user.supervised_categories = supervised_categories
            else:
                user.supervised_categories = []
            
            db.session.commit()
            flash('User updated successfully', 'success')
            return redirect(url_for('manage_users'))
    
    categories = Category.query.all()
    return render_template('admin/edit_user.html', user=user, categories=categories)

@app.route('/admin/user/<int:user_id>/delete', methods=['POST'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin():
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))
    
    if current_user.id == user_id:
        flash('Cannot delete your own account', 'error')
        return redirect(url_for('manage_users'))
    
    user = User.query.get_or_404(user_id)
    db.session.delete(user)
    db.session.commit()
    flash('User deleted successfully', 'success')
    return redirect(url_for('manage_users'))

@app.route('/supervisor/categories')
@login_required
def supervisor_categories():
    if not current_user.is_supervisor():
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))
    return render_template('supervisor/categories.html', 
                         categories=current_user.supervised_categories)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/quizzes')
@login_required
def manage_quizzes():
    if not current_user.is_admin():
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('dashboard'))
    
    quizzes = Quiz.query.all()
    categories = Category.query.all()
    return render_template('manage_quizzes.html', quizzes=quizzes, categories=categories)

@app.route('/quiz/add', methods=['POST'])
@login_required
def add_quiz():
    if not current_user.is_admin():
        flash('Access denied', 'error')
        return redirect(url_for('manage_quizzes'))
    
    print("Form data:", request.form)  # Debug print
    
    try:
        # Create the quiz first
        quiz = Quiz(
            title=request.form.get('title', '').strip(),
            description=request.form.get('description', '').strip(),
            category_id=request.form.get('category'),
            created_by=current_user.id,
            passing_score=request.form.get('passing_score', type=int, default=70)
        )
        
        print("Quiz object created:", quiz.title)  # Debug print
        
        # Validate quiz data
        if not quiz.title or not quiz.category_id:
            raise ValueError("Quiz title and category are required")
            
        db.session.add(quiz)
        db.session.flush()  # Get the quiz ID without committing
        
        # Process and add questions
        questions_data = process_quiz_questions(request.form)
        print("Questions data:", questions_data)  # Debug print
        
        if not questions_data:
            raise ValueError("At least one valid question is required")
            
        for q_data in questions_data:
            question = QuizQuestion(
                quiz_id=quiz.id,
                question_text=q_data['text'],
                question_type=q_data['type'],
                correct_answer=q_data['answer'],
                options=q_data.get('options'),
                points=q_data['points']
            )
            db.session.add(question)
            print(f"Added question: {question.question_text}")  # Debug print
        
        db.session.commit()
        flash('Quiz created successfully', 'success')
        
    except ValueError as ve:
        db.session.rollback()
        flash(str(ve), 'error')
        print("Validation error:", str(ve))  # Debug print
    except Exception as e:
        db.session.rollback()
        flash(f'Error creating quiz: {str(e)}', 'error')
        print("Error creating quiz:", str(e))  # Debug print
    
    return redirect(url_for('manage_quizzes'))

@app.route('/quiz/<int:quiz_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_quiz(quiz_id):
    if not current_user.is_admin():
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('dashboard'))
    
    quiz = Quiz.query.get_or_404(quiz_id)
    
    if request.method == 'POST':
        try:
            quiz.title = request.form['title']
            quiz.description = request.form.get('description', '')
            quiz.category_id = request.form['category']
            quiz.passing_score = request.form.get('passing_score', type=int, default=70)
            
            # Remove existing questions
            QuizQuestion.query.filter_by(quiz_id=quiz.id).delete()
            
            # Add new questions
            questions_data = process_quiz_questions(request.form)
            for q_data in questions_data:
                question = QuizQuestion(
                    quiz_id=quiz.id,
                    question_text=q_data['text'],
                    question_type=q_data['type'],
                    correct_answer=q_data['answer'],
                    options=q_data.get('options'),
                    points=q_data['points']
                )
                db.session.add(question)
            
            db.session.commit()
            flash('Quiz updated successfully', 'success')
            return redirect(url_for('manage_quizzes'))
        except Exception as e:
            db.session.rollback()
            flash('Error updating quiz: ' + str(e), 'error')
    
    categories = Category.query.all()
    return render_template('edit_quiz.html', quiz=quiz, categories=categories)

@app.route('/quiz/<int:quiz_id>/delete', methods=['POST'])
@login_required
def delete_quiz(quiz_id):
    if not current_user.is_admin():
        return jsonify({'error': 'Access denied'}), 403
    
    quiz = Quiz.query.get_or_404(quiz_id)
    
    try:
        db.session.delete(quiz)
        db.session.commit()
        flash('Quiz deleted successfully', 'success')
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/quiz/<int:quiz_id>')
@login_required
def take_quiz_standalone(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    
    # Check if user has already attempted this quiz
    previous_attempt = QuizAttempt.query.filter_by(
        user_id=current_user.id,
        quiz_id=quiz.id
    ).order_by(QuizAttempt.completed_at.desc()).first()
    
    return render_template('quiz.html', quiz=quiz, previous_attempt=previous_attempt)

@app.route('/quiz/<int:quiz_id>/submit', methods=['POST'])
@login_required
def submit_quiz(quiz_id):
    quiz = Quiz.query.get_or_404(quiz_id)
    
    # Create quiz attempt
    quiz_attempt = QuizAttempt(
        user_id=current_user.id,
        quiz_id=quiz_id,
        score=0,
        started_at=datetime.utcnow(),
        completed_at=datetime.utcnow()
    )
    db.session.add(quiz_attempt)
    db.session.flush()  # Get the attempt ID
    
    total_points = 0
    earned_points = 0
    
    # Process each answer
    for question in quiz.questions:
        answer = request.form.get(f'answer_{question.id}', '').strip()
        is_correct = False
        
        if question.question_type == 'multiple_choice':
            is_correct = answer == question.correct_answer
        elif question.question_type == 'true_false':
            is_correct = answer.lower() == question.correct_answer.lower()
        else:  # text answer
            is_correct = answer.lower() == question.correct_answer.lower()
        
        if is_correct:
            earned_points += question.points
        total_points += question.points
        
        # Create answer record
        quiz_answer = QuizAnswer(
            attempt_id=quiz_attempt.id,
            question_id=question.id,
            user_answer=answer,
            is_correct=is_correct,
            points_earned=question.points if is_correct else 0
        )
        db.session.add(quiz_answer)
    
    # Calculate final score and update attempt
    if total_points > 0:
        final_score = (earned_points / total_points) * 100
    else:
        final_score = 0
    
    quiz_attempt.score = final_score
    quiz_attempt.passed = final_score >= quiz.passing_score
    
    try:
        db.session.commit()
        flash('Quiz submitted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash('Error submitting quiz: ' + str(e), 'error')
        return redirect(url_for('take_quiz_standalone', quiz_id=quiz_id))
    
    return redirect(url_for('view_quiz_results', attempt_id=quiz_attempt.id))

@app.route('/quiz/attempt/<int:attempt_id>')
@login_required
def view_quiz_results(attempt_id):
    attempt = QuizAttempt.query.get_or_404(attempt_id)
    
    # Ensure user can only view their own results
    if attempt.user_id != current_user.id and not current_user.is_admin():
        flash('Access denied', 'error')
        return redirect(url_for('dashboard'))
    
    return render_template('quiz_results.html', attempt=attempt)

# Content Management Routes
@app.route('/manage-content')
@login_required
@admin_or_supervisor_required
def manage_content():
    contents = Content.query.all()
    return render_template('admin/manage_content.html', contents=contents)

@app.route('/delete-content/<int:content_id>', methods=['POST'])
@login_required
@admin_or_supervisor_required
def delete_content(content_id):
    content = Content.query.get_or_404(content_id)
    try:
        # Delete the file
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], content.filename)
        if os.path.exists(file_path):
            os.remove(file_path)
        
        # Delete associated quiz if exists
        quiz = Quiz.query.filter_by(title=content.title + ' Quiz').first()
        if quiz:
            db.session.delete(quiz)
        
        # Delete the content
        db.session.delete(content)
        db.session.commit()
        flash('Content deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting content: {str(e)}', 'error')
    
    return redirect(url_for('manage_content'))

# Team Management Routes
@app.route('/admin/teams', methods=['GET', 'POST'])
@login_required
def manage_teams():
    if not current_user.is_admin():
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description')
        
        if name:
            team = Team(name=name, description=description)
            db.session.add(team)
            db.session.commit()
            flash('Team created successfully.', 'success')
        return redirect(url_for('manage_teams'))
    
    teams = Team.query.all()
    return render_template('manage_teams.html', teams=teams)

@app.route('/admin/teams/<int:team_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_team(team_id):
    if not current_user.is_admin():
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    
    team = Team.query.get_or_404(team_id)
    
    if request.method == 'POST':
        team.name = request.form.get('name')
        team.description = request.form.get('description')
        db.session.commit()
        flash('Team updated successfully.', 'success')
        return redirect(url_for('manage_teams'))
    
    return render_template('edit_team.html', team=team)

@app.route('/admin/teams/<int:team_id>/delete', methods=['POST'])
@login_required
def delete_team(team_id):
    if not current_user.is_admin():
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    
    team = Team.query.get_or_404(team_id)
    db.session.delete(team)
    db.session.commit()
    flash('Team deleted successfully.', 'success')
    return redirect(url_for('manage_teams'))

@app.route('/admin/teams/<int:team_id>/members', methods=['GET', 'POST'])
@login_required
def manage_team_members(team_id):
    if not current_user.is_admin():
        flash('Access denied.', 'error')
        return redirect(url_for('dashboard'))
    
    team = Team.query.get_or_404(team_id)
    
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        action = request.form.get('action')
        
        if user_id and action:
            user = User.query.get(user_id)
            if user:
                if action == 'add':
                    user.team_id = team.id
                elif action == 'remove':
                    user.team_id = None
                db.session.commit()
                flash('Team membership updated successfully.', 'success')
    
    # Get all users not in any team
    available_users = User.query.filter_by(team_id=None).all()
    return render_template('manage_team_members.html', team=team, available_users=available_users)

if __name__ == '__main__':
    with app.app_context():
        # Only create tables if they don't exist
        db.create_all()
        
        # Create default admin user only if no users exist
        if not User.query.first():
            admin_user = User(
                username='admin',
                email='admin@example.com',
                role=ROLE_ADMIN,
                is_active=True
            )
            admin_user.set_password('1qw23er4')
            db.session.add(admin_user)
            db.session.commit()
            print('Default admin user created!')
        
    # Production configuration
    app.config['DEBUG'] = False
    app.config['ENV'] = 'production'
    
    # Run the app on port 80, accessible from any network interface
    try:
        app.run(host='0.0.0.0', port=8080)
    except PermissionError:
        print("Error: Port 80 requires administrator privileges.")
        print("Please run the application as administrator or use a different port.")
        print("Alternatively, you can use this command: python run.py")
        sys.exit(1)
