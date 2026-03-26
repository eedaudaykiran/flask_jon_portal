import os
import re
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.utils import secure_filename
from sqlalchemy import or_

# -------------------- App Configuration --------------------
app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///jobportal.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'static/uploads/resumes'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.config['ALLOWED_EXTENSIONS'] = {'pdf', 'doc', 'docx'}  # restrict file types

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'

# -------------------- Helper Functions --------------------
def allowed_file(filename):
    """Check if the file has an allowed extension."""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def is_strong_password(password):
    """Check password strength: min 8 chars, at least one uppercase, one lowercase, one digit, one special char."""
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

def role_required(role):
    """Decorator to restrict access to users with specific role."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not current_user.is_authenticated or current_user.role != role:
                flash('Access denied.', 'danger')
                return redirect(url_for('dashboard'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def save_resume(file, user_id):
    """Save uploaded resume and return filename if valid."""
    if file and file.filename and allowed_file(file.filename):
        filename = secure_filename(f"{user_id}_{datetime.now().strftime('%Y%m%d%H%M%S')}_{file.filename}")
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return filename
    return None

# -------------------- Database Models --------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False)  # 'candidate' or 'recruiter'
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    candidate = db.relationship('Candidate', backref='user', uselist=False)
    recruiter = db.relationship('Recruiter', backref='user', uselist=False)

    def set_password(self, password):
        import bcrypt
        salt = bcrypt.gensalt()
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

    def check_password(self, password):
        import bcrypt
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))

class Candidate(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True)
    full_name = db.Column(db.String(100), nullable=False)
    phone = db.Column(db.String(20))
    skills = db.Column(db.Text)
    resume_filename = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    applications = db.relationship('Application', backref='candidate', lazy=True)

class Recruiter(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), unique=True)
    company_name = db.Column(db.String(100), nullable=False)
    company_description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    jobs = db.relationship('Job', backref='recruiter', lazy=True)

class Job(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    location = db.Column(db.String(100))
    posted_date = db.Column(db.DateTime, default=datetime.utcnow)
    recruiter_id = db.Column(db.Integer, db.ForeignKey('recruiter.id'))

    applications = db.relationship('Application', backref='job', lazy=True)

class Application(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.Integer, db.ForeignKey('job.id'))
    candidate_id = db.Column(db.Integer, db.ForeignKey('candidate.id'))
    applied_date = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='pending')  # pending, reviewed, rejected

@login_manager.user_loader
def load_user(user_id):
    try:
        return User.query.get(int(user_id))
    except (ValueError, TypeError):
        return None

# -------------------- Routes --------------------
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        role = request.form.get('role')
        
        if not email or not password or not role:
            flash('All fields are required.', 'danger')
            return redirect(url_for('signup'))
        
        if password != confirm_password:
            flash('Passwords do not match.', 'danger')
            return redirect(url_for('signup'))
        
        if not is_strong_password(password):
            flash('Password must be at least 8 characters long, contain uppercase, lowercase, digit and special character.', 'danger')
            return redirect(url_for('signup'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'danger')
            return redirect(url_for('signup'))
        
        user = User(email=email, role=role)
        user.set_password(password)
        db.session.add(user)
        db.session.flush()  # get user.id
        
        if role == 'candidate':
            full_name = request.form.get('full_name')
            phone = request.form.get('phone')
            skills = request.form.get('skills')
            if not full_name:
                flash('Full name is required for candidates.', 'danger')
                db.session.rollback()
                return redirect(url_for('signup'))
            candidate = Candidate(user_id=user.id, full_name=full_name, phone=phone, skills=skills)
            db.session.add(candidate)
        else:  # recruiter
            company_name = request.form.get('company_name')
            company_description = request.form.get('company_description')
            if not company_name:
                flash('Company name is required for recruiters.', 'danger')
                db.session.rollback()
                return redirect(url_for('signup'))
            recruiter = Recruiter(user_id=user.id, company_name=company_name, company_description=company_description)
            db.session.add(recruiter)
        
        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            flash(f'Registration failed: {str(e)}', 'danger')
            return redirect(url_for('signup'))
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            login_user(user)
            flash(f'Welcome back, {email}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password.', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.role == 'candidate':
        return redirect(url_for('candidate_dashboard'))
    else:
        return redirect(url_for('recruiter_dashboard'))

# -------------------- Candidate Routes --------------------
@app.route('/candidate/dashboard')
@login_required
@role_required('candidate')
def candidate_dashboard():
    candidate = current_user.candidate
    jobs = Job.query.order_by(Job.posted_date.desc()).all()
    applied_job_ids = [app.job_id for app in candidate.applications]
    return render_template('candidate_dashboard.html', candidate=candidate, jobs=jobs, applied_job_ids=applied_job_ids)

@app.route('/candidate/profile', methods=['GET', 'POST'])
@login_required
@role_required('candidate')
def candidate_profile():
    candidate = current_user.candidate
    if request.method == 'POST':
        candidate.full_name = request.form.get('full_name')
        candidate.phone = request.form.get('phone')
        candidate.skills = request.form.get('skills')
        
        if 'resume' in request.files:
            file = request.files['resume']
            if file and file.filename:
                filename = save_resume(file, current_user.id)
                if filename:
                    candidate.resume_filename = filename
                    flash('Resume uploaded successfully.', 'success')
                else:
                    flash('Invalid file type. Allowed: PDF, DOC, DOCX.', 'danger')
        
        try:
            db.session.commit()
            flash('Profile updated successfully.', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating profile: {str(e)}', 'danger')
        return redirect(url_for('candidate_profile'))
    
    return render_template('candidate_profile.html', candidate=candidate)

@app.route('/job/<int:job_id>/apply', methods=['POST'])
@login_required
@role_required('candidate')
def apply_job(job_id):
    candidate = current_user.candidate
    job = Job.query.get_or_404(job_id)
    
    existing = Application.query.filter_by(job_id=job_id, candidate_id=candidate.id).first()
    if existing:
        flash('You have already applied for this job.', 'warning')
        return redirect(url_for('candidate_dashboard'))
    
    if not candidate.resume_filename:
        flash('Please upload your resume in profile before applying.', 'danger')
        return redirect(url_for('candidate_profile'))
    
    application = Application(job_id=job_id, candidate_id=candidate.id)
    db.session.add(application)
    try:
        db.session.commit()
        flash('Application submitted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error applying: {str(e)}', 'danger')
    return redirect(url_for('candidate_dashboard'))

@app.route('/candidate/applications')
@login_required
@role_required('candidate')
def candidate_applications():
    candidate = current_user.candidate
    applications = Application.query.filter_by(candidate_id=candidate.id).order_by(Application.applied_date.desc()).all()
    return render_template('candidate_applications.html', applications=applications)

@app.route('/search/jobs')
@login_required
@role_required('candidate')
def search_jobs():
    query = request.args.get('q', '')
    if query:
        jobs = Job.query.filter(
            or_(
                Job.title.ilike(f'%{query}%'),
                Job.description.ilike(f'%{query}%'),
                Job.location.ilike(f'%{query}%')
            )
        ).order_by(Job.posted_date.desc()).all()
    else:
        jobs = Job.query.order_by(Job.posted_date.desc()).all()
    applied_job_ids = [app.job_id for app in current_user.candidate.applications]
    return render_template('candidate_dashboard.html', candidate=current_user.candidate, jobs=jobs, applied_job_ids=applied_job_ids)

# -------------------- Recruiter Routes --------------------
@app.route('/recruiter/dashboard')
@login_required
@role_required('recruiter')
def recruiter_dashboard():
    recruiter = current_user.recruiter
    jobs = Job.query.filter_by(recruiter_id=recruiter.id).order_by(Job.posted_date.desc()).all()
    return render_template('recruiter_dashboard.html', recruiter=recruiter, jobs=jobs)

@app.route('/recruiter/post_job', methods=['GET', 'POST'])
@login_required
@role_required('recruiter')
def post_job():
    if request.method == 'POST':
        title = request.form.get('title')
        description = request.form.get('description')
        location = request.form.get('location')
        
        if not title or not description:
            flash('Title and description are required.', 'danger')
            return redirect(url_for('post_job'))
        
        job = Job(
            title=title,
            description=description,
            location=location,
            recruiter_id=current_user.recruiter.id
        )
        db.session.add(job)
        try:
            db.session.commit()
            flash('Job posted successfully!', 'success')
        except Exception as e:
            db.session.rollback()
            flash(f'Error posting job: {str(e)}', 'danger')
        return redirect(url_for('recruiter_dashboard'))
    
    return render_template('post_job.html')

@app.route('/recruiter/job/<int:job_id>/applicants')
@login_required
@role_required('recruiter')
def view_applicants(job_id):
    job = Job.query.filter_by(id=job_id, recruiter_id=current_user.recruiter.id).first_or_404()
    applications = Application.query.filter_by(job_id=job_id).all()
    return render_template('view_applicants.html', job=job, applications=applications)

@app.route('/recruiter/search_candidates')
@login_required
@role_required('recruiter')
def search_candidates():
    query = request.args.get('q', '')
    candidates = []
    if query:
        candidates = Candidate.query.filter(
            or_(
                Candidate.full_name.ilike(f'%{query}%'),
                Candidate.skills.ilike(f'%{query}%')
            )
        ).all()
    else:
        candidates = Candidate.query.all()
    return render_template('search_candidates.html', candidates=candidates, query=query)

@app.route('/download/resume/<int:candidate_id>')
@login_required
@role_required('recruiter')
def download_resume(candidate_id):
    candidate = Candidate.query.get_or_404(candidate_id)
    if candidate.resume_filename:
        # Compatibility with Flask < 2.0 and >= 2.0
        try:
            # Flask 2.0+ uses download_name
            return send_from_directory(
                app.config['UPLOAD_FOLDER'],
                candidate.resume_filename,
                as_attachment=True,
                download_name=f"{candidate.full_name}_resume.pdf"
            )
        except TypeError:
            # Fallback for older Flask versions (1.x)
            return send_from_directory(
                app.config['UPLOAD_FOLDER'],
                candidate.resume_filename,
                as_attachment=True,
                attachment_filename=f"{candidate.full_name}_resume.pdf"
            )
    else:
        flash('No resume uploaded.', 'warning')
        return redirect(request.referrer or url_for('search_candidates'))

# -------------------- Run Application --------------------
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)