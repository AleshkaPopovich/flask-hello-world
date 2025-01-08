# Import statements and initial setup
import matplotlib
matplotlib.use('Agg')  # Use a non-GUI backend for Matplotlib (suitable for server environments)
import matplotlib.pyplot as plt
import plotly.graph_objects as go
from flask import Flask, render_template, request, redirect, url_for, json, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, date
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import io
import base64
import requests
import os
import csv

#Configuration of Flask application
app = Flask(__name__)
app.secret_key = 'my_super_secret_key'  # Secret key for secure session handling

# Configure the SQLite database URI, ensuring we store data in instance/grades.db
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(app.instance_path, 'grades.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Make sure the instance folder exists so grades.db can be created
os.makedirs(app.instance_path, exist_ok=True)

# Initialize the database object via SQLAlchemy
db = SQLAlchemy(app)

# model definition in SQLAlchemy

class User(db.Model):
    """
    Stores user accounts for authentication.
    Each user has a unique username and a hashed password.
    """
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)

    def set_password(self, password):
        """
        Hashes the provided password using PBKDF2-SHA256 and stores it
        in password_hash. This ensures no plaintext password is stored.
        """
        self.password_hash = generate_password_hash(password, method='pbkdf2:sha256')

    def check_password(self, password):
        """
        Verifies a password attempt against the stored password_hash.
        Returns True if correct, False otherwise.
        """
        return check_password_hash(self.password_hash, password)


class Class(db.Model):
    """
    Represents a 'class' or 'year group' entity, e.g. "Year 12 - Maths AA HL".
    Each class belongs to a specific User (user_id).
    """
    id = db.Column(db.Integer, primary_key=True)
    year_group = db.Column(db.Integer)
    subject = db.Column(db.String(100))

    # Relationship: one Class can have multiple Students
    students = db.relationship(
        'Student',
        backref='class_',
        lazy=True,
        cascade="all, delete-orphan"
    )

    # Foreign Key which refernces which user owns this class
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='classes', lazy=True)


class Student(db.Model):
    """
    Represents an individual student within a specific class.
    Stores basic info like name and surname, and references:
    - class_id => the Class they belong to
    - user_id => which User created this student entry
    """
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(20), nullable=False)
    surname = db.Column(db.String(20), nullable=False)
    class_id = db.Column(db.Integer, db.ForeignKey('class.id'), nullable=False)

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='students', lazy=True)

    # Relationship: a Student can have many Grades
    grades = db.relationship('Grade', backref='student', lazy=True, cascade="all, delete-orphan")


class Grade(db.Model):
    """
    Represents a single grade record for a Student.
    Stores assessment_name (Paper 1, Paper 2, etc.), the numeric score, and the date.
    Also references user_id for ownership.
    """
    id = db.Column(db.Integer, primary_key=True)
    assessment_name = db.Column(db.String(100))
    score = db.Column(db.Float)
    date = db.Column(db.Date)
    student_id = db.Column(db.Integer, db.ForeignKey('student.id'), nullable=False)

    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='grades', lazy=True)


class GradeBoundary(db.Model):
    """
    Stores grade boundaries for a particular Class.
    For example, subject= 'Maths AA HL', grade=7, lower_bound=90.0, upper_bound=100.0
    class_id => references which class these boundaries apply to
    """
    id = db.Column(db.Integer, primary_key=True)
    subject = db.Column(db.String(100))
    grade = db.Column(db.Integer)
    lower_bound = db.Column(db.Float)
    upper_bound = db.Column(db.Float)
    class_id = db.Column(db.Integer, db.ForeignKey('class.id'), nullable=False)

    class_ = db.relationship('Class', backref='grade_boundaries', lazy=True)



# utility function
    
def get_ib_grade(class_id, score):
    """
    Given a class_id (to identify the subject boundaries) and a numeric score,
    returns the IB grade matching the boundaries in GradeBoundary.
    If no boundary matches, returns None.
    """
    grade_boundaries = GradeBoundary.query.filter_by(class_id=class_id).order_by(GradeBoundary.lower_bound).all()
    for boundary in grade_boundaries:
        if boundary.lower_bound <= score <= boundary.upper_bound:
            return boundary.grade
    return None



# decorator for authentication

def login_required(f):
    """
    A decorator to ensure a route is only accessible to logged-in users.
    Redirects to login if 'user_id' not found in session.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function



# register, login, logout --> authentication routes

@app.route('/register', methods=['GET', 'POST'])
def register():
    """
    Handles user registration. On POST, checks form fields:
    - username, password, confirm_password
    - ensures no duplicates
    - stores hashed password
    """
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()
        confirm_password = request.form['confirm_password'].strip()

        # Basic validation if blank space is left
        if not username or not password or not confirm_password:
            error = "All fields are required."
            return render_template('register.html', error=error)

        if password != confirm_password:
            error = "Passwords do not match."
            return render_template('register.html', error=error)

        # Check if user already exists in the database
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            error = "Username already taken."
            return render_template('register.html', error=error)

        # Create new user and hash the entered password
        new_user = User(username=username)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        # Redirect to login page after successful registration 
        return redirect(url_for('login'))
    # If GET, just show the registration form
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Handles user login. If credentials match, store user_id in session.
    Otherwise, display an error.
    """
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()

        # Check if a user with entered username exists in the data base
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            # in case of valid login, user ID is stored
            session['user_id'] = user.id
            return redirect(url_for('index'))
        # if login is invalid, an error is being showed
        error = "Invalid username or password."
        return render_template('login.html', error=error)
    # If GET, just show the login page
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    """
    Logs out the current user by clearing the session.
    """
    session.pop('user_id', None)
    return redirect(url_for('login'))



# main home route

@app.route('/')
@login_required
def index():
    """
    Displays a list of all classes belonging to the logged-in user.
    This is the main 'dashboard' once logged in.
    """
    current_user_id = session['user_id']
    classes = Class.query.filter_by(user_id=current_user_id).all()
    return render_template('index.html', classes=classes)


# class management routes

@app.route('/add_class', methods=['GET', 'POST'])
@login_required
def add_class():
    """
    Allows the user to create a new class/year group.
    Validates year_group is an integer between 1 and 13,
    and subject is one of the allowed strings.
    """
    if request.method == 'POST':
        try:
            year_group = int(request.form['year_group'])
            if year_group < 1 or year_group > 13:
                raise ValueError
        except ValueError:
            error = "Year group must be an integer between 1 and 13."
            return render_template('add_class.html', error=error)

        subject = request.form['subject']
        if subject not in ["Maths AA SL", "Maths AA HL"]:
            error = "Invalid subject selected."
            return render_template('add_class.html', error=error)

        current_user_id = session['user_id']
        new_class = Class(year_group=year_group, subject=subject, user_id=current_user_id)
        db.session.add(new_class)
        db.session.commit()
        return redirect(url_for('index'))
    return render_template('add_class.html')


@app.route('/edit_class/<int:class_id>', methods=['GET', 'POST'])
@login_required
def edit_class(class_id):
    """
    Edits an existing class if it belongs to the current user.
    Validates new year_group and subject as well.
    """
    current_user_id = session['user_id']
    class_ = Class.query.filter_by(id=class_id, user_id=current_user_id).first_or_404()

    if request.method == 'POST':
        try:
            year_group = int(request.form['year_group'])
            if year_group < 1 or year_group > 13:
                raise ValueError
            class_.year_group = year_group
        except ValueError:
            error = "Year group must be an integer between 1 and 13."
            return render_template('edit_class.html', class_=class_, error=error)

        subject = request.form['subject']
        if subject not in ["Maths AA SL", "Maths AA HL"]:
            error = "Invalid subject selected."
            return render_template('edit_class.html', class_=class_, error=error)
        class_.subject = subject

        db.session.commit()
        return redirect(url_for('view_class', class_id=class_id))
    return render_template('edit_class.html', class_=class_)


@app.route('/delete_class/<int:class_id>', methods=['POST'])
@login_required
def delete_class(class_id):
    """
    Deletes a class record if owned by the current user.
    """
    current_user_id = session['user_id']
    class_ = Class.query.filter_by(id=class_id, user_id=current_user_id).first_or_404()
    db.session.delete(class_)
    db.session.commit()
    return redirect(url_for('index'))


@app.route('/class/<int:class_id>')
@login_required
def view_class(class_id):
    """
    Shows details of a single class: all its students,
    plus a progress chart of average scores over time.
    """
    current_user_id = session['user_id']
    class_ = Class.query.filter_by(id=class_id, user_id=current_user_id).first_or_404()
    students = class_.students  #all the students are shown in this class

    # Build a dictionary of date -> [scores], to compute daily averages building a dictionary of date 
    class_grades = {}
    for student in students:
        for grade in student.grades:
            if grade.date not in class_grades:
                class_grades[grade.date] = []
            class_grades[grade.date].append(grade.score)

    # Sort dates and compute average for each date
    sorted_dates = sorted(class_grades.keys())
    average_scores = [sum(scores) / len(scores) for scores in class_grades.values()]

    # Prepare data for the chart
    if sorted_dates:
        plot_data = [{
            'x': sorted_dates,
            'y': average_scores,
            'type': 'scatter',
            'mode': 'lines+markers',
            'name': 'Class Average Scores',
            'line': {'shape': 'spline', 'color': 'green'}
        }]

        plot_layout = {
            'title': f"Class Progress Over Time - Year {class_.year_group} {class_.subject}",
            'xaxis': {'title': 'Date'},
            'yaxis': {'title': 'Average Score', 'range': [0, 100]}
        }

        # Convert data/layout to JSON for Plotly rendering in the template
        plot_data_json = json.dumps(plot_data)
        plot_layout_json = json.dumps(plot_layout)
    else:
        # No data => no chart
        plot_data_json = None
        plot_layout_json = None

    # Overall class average across all dates
    class_average = sum(average_scores) / len(average_scores) if average_scores else None
    # Derive an IB grade for the overall average, if it exists
    class_ib_grade = get_ib_grade(class_id, class_average) if class_average is not None else None

    return render_template('view_class.html',
                           class_=class_,
                           class_average=class_average,
                           class_ib_grade=class_ib_grade,
                           plot_data=plot_data_json,
                           plot_layout=plot_layout_json)


# ---------------------------------------------
# STUDENT MANAGEMENT ROUTES
# ---------------------------------------------
@app.route('/class/<int:class_id>/add_student', methods=['GET', 'POST'])
@login_required
def add_student(class_id):
    """
    Adds a new student to the specified class, if user is authorized.
    Checks name length <= 20 chars, ensures not empty.
    """
    current_user_id = session['user_id']
    class_ = Class.query.filter_by(id=class_id, user_id=current_user_id).first_or_404()

    if request.method == 'POST':
        name = request.form['name'].strip()
        surname = request.form['surname'].strip()

        # Basic validations
        if not name or not surname:
            error = "Name and Surname are required."
            return render_template('add_student.html', class_=class_, error=error)
        if len(name) > 20 or len(surname) > 20:
            error = "Name and Surname must be 20 characters or fewer."
            return render_template('add_student.html', class_=class_, error=error)

        new_student = Student(name=name, surname=surname, class_id=class_id, user_id=current_user_id)
        db.session.add(new_student)
        db.session.commit()
        return redirect(url_for('view_class', class_id=class_id))
    return render_template('add_student.html', class_=class_)


@app.route('/edit_student/<int:student_id>', methods=['GET', 'POST'])
@login_required
def edit_student(student_id):
    """
    Edits an existing student if they belong to the user's class.
    """
    current_user_id = session['user_id']
    student = Student.query.filter_by(id=student_id, user_id=current_user_id).first_or_404()

    if request.method == 'POST':
        name = request.form['name'].strip()
        surname = request.form['surname'].strip()

        if not name or not surname:
            error = "Name and Surname are required."
            return render_template('edit_student.html', student=student, error=error)
        if len(name) > 20 or len(surname) > 20:
            error = "Name and Surname must be 20 characters or fewer."
            return render_template('edit_student.html', student=student, error=error)

        # Update fields and commit
        student.name = name
        student.surname = surname
        db.session.commit()
        return redirect(url_for('view_student', student_id=student_id))
    return render_template('edit_student.html', student=student)


@app.route('/delete_student/<int:student_id>', methods=['POST'])
@login_required
def delete_student(student_id):
    """
    Deletes a Student record if owned by the user's class.
    """
    current_user_id = session['user_id']
    student = Student.query.filter_by(id=student_id, user_id=current_user_id).first_or_404()
    class_id = student.class_id  # To redirect back to class page
    db.session.delete(student)
    db.session.commit()
    return redirect(url_for('view_class', class_id=class_id))


# ---------------------------------------------
# GRADE MANAGEMENT ROUTES
# ---------------------------------------------
@app.route('/student/<int:student_id>/add_grade', methods=['GET', 'POST'])
@login_required
def add_grade(student_id):
    """
    Allows adding a new grade to a specific student.
    Validates:
     - assessment_name in valid_assessments
     - score must be 0-100
     - date not in future
    """
    current_user_id = session['user_id']
    student = Student.query.filter_by(id=student_id, user_id=current_user_id).first_or_404()

    if request.method == 'POST':
        assessment_name = request.form['assessment_name']
        score = request.form['score']
        date_str = request.form['date']

        valid_assessments = ["Paper 1", "Paper 2", "Paper 3", "Cycle Test"]
        if assessment_name not in valid_assessments:
            error = "Invalid assessment name selected."
            return render_template('add_grade.html', student=student, error=error, max_date=date.today().strftime('%Y-%m-%d'))

        # Validate numeric score range
        try:
            score = float(score)
            if score < 0 or score > 100:
                raise ValueError
        except ValueError:
            error = "Score must be a number between 0 and 100."
            return render_template('add_grade.html', student=student, error=error, max_date=date.today().strftime('%Y-%m-%d'))

        # Validate date
        try:
            test_date = datetime.strptime(date_str, '%Y-%m-%d').date()
            if test_date > date.today():
                error = "Date cannot be in the future."
                return render_template('add_grade.html', student=student, error=error, max_date=date.today().strftime('%Y-%m-%d'))
        except ValueError:
            error = "Invalid date format."
            return render_template('add_grade.html', student=student, error=error, max_date=date.today().strftime('%Y-%m-%d'))

        # Create new Grade record
        new_grade = Grade(
            assessment_name=assessment_name,
            score=score,
            date=test_date,
            student_id=student_id,
            user_id=current_user_id
        )
        db.session.add(new_grade)
        db.session.commit()
        return redirect(url_for('view_student', student_id=student_id))

    return render_template('add_grade.html', student=student, max_date=date.today().strftime('%Y-%m-%d'))


@app.route('/edit_grade/<int:grade_id>', methods=['GET', 'POST'])
@login_required
def edit_grade(grade_id):
    """
    Edits an existing grade record (if user is authorized).
    Re-uses similar validation checks for assessment_name, score, and date.
    """
    current_user_id = session['user_id']
    grade = Grade.query.filter_by(id=grade_id, user_id=current_user_id).first_or_404()
    student = grade.student

    if request.method == 'POST':
        assessment_name = request.form['assessment_name']
        score = request.form['score']
        date_str = request.form['date']

        valid_assessments = ["Paper 1", "Paper 2", "Paper 3", "Cycle Test"]
        if assessment_name not in valid_assessments:
            error = "Invalid assessment name selected."
            return render_template('edit_grade.html', grade=grade, error=error, max_date=date.today().strftime('%Y-%m-%d'))

        try:
            score = float(score)
            if score < 0 or score > 100:
                raise ValueError
        except ValueError:
            error = "Score must be a number between 0 and 100."
            return render_template('edit_grade.html', grade=grade, error=error, max_date=date.today().strftime('%Y-%m-%d'))

        try:
            test_date = datetime.strptime(date_str, '%Y-%m-%d').date()
            if test_date > date.today():
                error = "Date cannot be in the future."
                return render_template('edit_grade.html', grade=grade, error=error, max_date=date.today().strftime('%Y-%m-%d'))
        except ValueError:
            error = "Invalid date format."
            return render_template('edit_grade.html', grade=grade, error=error, max_date=date.today().strftime('%Y-%m-%d'))

        # Update the existing grade record
        grade.assessment_name = assessment_name
        grade.score = score
        grade.date = test_date
        db.session.commit()
        return redirect(url_for('view_student', student_id=student.id))

    return render_template('edit_grade.html', grade=grade, max_date=date.today().strftime('%Y-%m-%d'))


@app.route('/delete_grade/<int:grade_id>', methods=['POST'])
@login_required
def delete_grade(grade_id):
    """
    Deletes a Grade if it belongs to the current user.
    """
    current_user_id = session['user_id']
    grade = Grade.query.filter_by(id=grade_id, user_id=current_user_id).first_or_404()
    student_id = grade.student_id
    db.session.delete(grade)
    db.session.commit()
    return redirect(url_for('view_student', student_id=student_id))


# ---------------------------------------------
# VIEW A SPECIFIC STUDENT'S GRADE PROGRESS
# ---------------------------------------------
@app.route('/student/<int:student_id>')
@login_required
def view_student(student_id):
    """
    Shows an individual student's data, including average of their grades
    and a line chart of progress over time. Also determines IB grade if
    boundaries exist for the class.
    """
    current_user_id = session['user_id']
    student = Student.query.filter_by(id=student_id, user_id=current_user_id).first_or_404()
    grades = student.grades

    # Compute average if any grades exist
    total_scores = sum(grade.score for grade in grades)
    total_grades = len(grades)
    student_average = total_scores / total_grades if total_grades > 0 else None

    # Compute IB grade by referencing the student's class
    class_id = student.class_id
    ib_grade = get_ib_grade(class_id, student_average) if student_average is not None else None

    # Prepare data for progress chart
    dates = [grade.date for grade in grades]
    scores = [grade.score for grade in grades]

    if dates:
        plot_data = [{
            'x': dates,
            'y': scores,
            'type': 'scatter',
            'mode': 'lines+markers',
            'name': 'Scores over Time',
            'line': {'shape': 'spline', 'color': 'blue'}
        }]

        plot_layout = {
            'title': f"Progress of {student.name} {student.surname}",
            'xaxis': {'title': 'Date'},
            'yaxis': {'title': 'Score', 'range': [0, 100]}
        }

        plot_data_json = json.dumps(plot_data)
        plot_layout_json = json.dumps(plot_layout)
    else:
        plot_data_json = None
        plot_layout_json = None

    return render_template('view_student.html',
                           student=student,
                           student_average=student_average,
                           ib_grade=ib_grade,
                           plot_data=plot_data_json,
                           plot_layout=plot_layout_json)


# ---------------------------------------------
# UPLOAD GRADE BOUNDARIES ROUTE
# ---------------------------------------------
@app.route('/class/<int:class_id>/upload_grade_boundaries', methods=['GET', 'POST'])
@login_required
def upload_grade_boundaries_for_class(class_id):
    """
    Allows uploading a CSV with grade boundaries for a particular class.
    CSV format:
      First row: [subject]
      Subsequent rows: [grade, lower_bound, upper_bound]
    Any mismatch or invalid data => show error. If valid, old boundaries are replaced.
    """
    current_user_id = session['user_id']
    class_ = Class.query.filter_by(id=class_id, user_id=current_user_id).first_or_404()

    if request.method == 'POST':
        if 'file' not in request.files:
            error = "No file part"
            return render_template('upload_grade_boundaries.html', class_=class_, error=error)
        file = request.files['file']
        if file.filename == '':
            error = "No selected file"
            return render_template('upload_grade_boundaries.html', class_=class_, error=error)
        if file:
            try:
                # Decode CSV content and parse it
                stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
                csv_input = csv.reader(stream)

                rows = list(csv_input)
                if not rows:
                    error = "CSV file is empty."
                    return render_template('upload_grade_boundaries.html', class_=class_, error=error)

                # First row should contain only the subject name
                subject_row = rows[0]
                if len(subject_row) != 1:
                    error = "The first row should contain only the subject name."
                    return render_template('upload_grade_boundaries.html', class_=class_, error=error)
                subject = subject_row[0].strip()

                # Cross-check that CSV subject matches the class subject
                if subject != class_.subject:
                    error = f"CSV subject '{subject}' does not match the class's subject '{class_.subject}'."
                    return render_template('upload_grade_boundaries.html', class_=class_, error=error)

                # Remove existing boundaries for this class to avoid duplicates
                GradeBoundary.query.filter_by(class_id=class_id).delete()
                db.session.commit()

                # Process subsequent rows for [grade, lower_bound, upper_bound]
                for row in rows[1:]:
                    if len(row) != 3:
                        error = "Each grade boundary row must have three values: grade, lower_bound, upper_bound."
                        return render_template('upload_grade_boundaries.html', class_=class_, error=error)
                    grade, lower_bound, upper_bound = row
                    grade_boundary = GradeBoundary(
                        subject=subject,
                        grade=int(grade),
                        lower_bound=float(lower_bound),
                        upper_bound=float(upper_bound),
                        class_id=class_id
                    )
                    db.session.add(grade_boundary)

                db.session.commit()
                success = f"Grade boundaries for '{subject}' (Class ID: {class_id}) uploaded successfully."
                return render_template('upload_grade_boundaries.html', class_=class_, success=success)
            except Exception as e:
                # Catch any parsing or conversion errors
                error = f"An error occurred while processing the CSV file: {e}"
                return render_template('upload_grade_boundaries.html', class_=class_, error=error)

    return render_template('upload_grade_boundaries.html', class_=class_)


# ---------------------------------------------
# MAIN ENTRY POINT
# ---------------------------------------------
if __name__ == '__main__':
    # Create DB tables if they don't exist
    with app.app_context():
        db.create_all()
    # Run app in debug mode for development
    app.run(debug=True)
