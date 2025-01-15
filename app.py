#import everything needed for the initial setup
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


#set secrte keys for session, database pathways and others
app = Flask(__name__)
app.secret_key = 'FLASK_SECRET_KEY'


app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(app.instance_path, 'grades.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False


os.makedirs(app.instance_path, exist_ok=True)
db = SQLAlchemy(app)


#model definitions in sqlalchemy (tables)
class ApplicationUser(db.Model):


#    that table stores user accounts for the authentication, so
#    each user whould have a unique loginName and hashed password


   __tablename__ = 'application_user' #defining the name of the table


   id = db.Column(db.Integer, primary_key=True)
   loginName = db.Column(db.String(64), unique=True, nullable=False)
   userPassHash = db.Column(db.String(128), nullable=False)


   def setLoginPassword(self, plainTextPassword):
       #hashing the user of the application password for it to be securely stored in the data base
       self.userPassHash = generate_password_hash(plainTextPassword, method='pbkdf2:sha256')


   def checkLoginPassword(self, plainTextPassword):
      #this function checks if the provided password matches the hashed password
       return check_password_hash(self.userPassHash, plainTextPassword)




class CourseGroup(db.Model):
#   table representing a course group, where each one belongs
#    to the ApplicationUser 
   __tablename__ = 'course_group'


   id = db.Column(db.Integer, primary_key=True)
   classLevel = db.Column(db.Integer)  # e.g. 12, 13
   courseSubject = db.Column(db.String(100))  # e.g. "Maths AA HL"


   #A relationship is demonstrated here: a course group can have multiple learners
   learners = db.relationship(
       'Learner',
       backref='courseGroup',
       lazy=True,
       cascade="all, delete-orphan"
   )


   # Foreign key references which ApplicationUser created this exact coursegroup
   owner_id = db.Column(db.Integer, db.ForeignKey('application_user.id'), nullable=False)
   owner = db.relationship('ApplicationUser', backref='courseGroups', lazy=True)




class Learner(db.Model):
#   An individual learner in a CourseGroup, which has attributes
#   such as firstName, lastName and references to group_id and owner_id
  
   __tablename__ = 'learner'


   id = db.Column(db.Integer, primary_key=True)
   firstName = db.Column(db.String(20), nullable=False)
   lastName = db.Column(db.String(20), nullable=False)


   group_id = db.Column(db.Integer, db.ForeignKey('course_group.id'), nullable=False)
   owner_id = db.Column(db.Integer, db.ForeignKey('application_user.id'), nullable=False)
   owner = db.relationship('ApplicationUser', backref='allLearners', lazy=True)


   # a one to many relationship is shown here, as one Learner can have many LearnerGrades
   learnerGrades = db.relationship(
       'LearnerGrade',
       backref='learner',
       lazy=True,
       cascade="all, delete-orphan"
   )




class LearnerGrade(db.Model):
#   table for grade records for an individual learner which specifies things like
#   examTitile and numericGrade.   
   __tablename__ = 'learner_grade'


   id = db.Column(db.Integer, primary_key=True)
   examTitle = db.Column(db.String(100))  # e.g. "Paper 1"
   numericGrade = db.Column(db.Float)     # e.g. 75.0
   date = db.Column(db.Date)


   learner_id = db.Column(db.Integer, db.ForeignKey('learner.id'), nullable=False)
   owner_id = db.Column(db.Integer, db.ForeignKey('application_user.id'), nullable=False)
   owner = db.relationship('ApplicationUser', backref='allGrades', lazy=True)




class BoundaryRule(db.Model):
#   table for grade boundaries for a particular CourseGroup
   __tablename__ = 'boundary_rule'


   id = db.Column(db.Integer, primary_key=True)
   boundarySubject = db.Column(db.String(100))  # e.g. "Maths AA HL"
   grade = db.Column(db.Integer)
   lowerBound = db.Column(db.Float)
   upperBound = db.Column(db.Float)


   group_id = db.Column(db.Integer, db.ForeignKey('course_group.id'), nullable=False)
   courseGroup = db.relationship('CourseGroup', backref='boundarySet', lazy=True)


# different utility functions
def computeIbGrade(courseGroup_id, numericGrade):
#   this functions goes through boundry rules for a CourseGroup to
#   find if the grade is between lower and upper bounds and returns that grade.
   boundaries = BoundaryRule.query.filter_by(group_id=courseGroup_id).order_by(BoundaryRule.lowerBound).all()
   for rule in boundaries:
       if rule.lowerBound <= numericGrade <= rule.upperBound:
           return rule.grade
   return None


#authentication security
def loginRequired(f):
#   function means that only users who are logged in would have access,
#   otherwise, they would be redirected to /logi       
   @wraps(f)
   def security_measure_function(*args, **kwargs):
       if 'user_identification_number' not in session:
           return redirect(url_for('login'))
       return f(*args, **kwargs)
   return security_measure_function


#routes used for authentication
@app.route('/register', methods=['GET', 'POST'])
def register():
#   function crates a new ApplicationUser by collecting username and password
#   As well it checks if username already exists in the database, hashes the password
   if request.method == 'POST':
       nameForLogin = request.form['username'].strip()
       plainPassword = request.form['password'].strip()
       confirmPassword = request.form['confirm_password'].strip()


       if not nameForLogin or not plainPassword or not confirmPassword:
           error = "All fields are required."
           return render_template('register.html', error=error)


       if plainPassword != confirmPassword:
           error = "Passwords do not match."
           return render_template('register.html', error=error)


       already_created_User = ApplicationUser.query.filter_by(loginName=nameForLogin).first()
       if already_created_User:
           error = "Username already taken."
           return render_template('register.html', error=error)


       newUser = ApplicationUser(loginName=nameForLogin)
       newUser.setLoginPassword(plainPassword)  # hashed
       db.session.add(newUser)
       db.session.commit()


       return redirect(url_for('login'))
   return render_template('register.html')




@app.route('/login', methods=['GET', 'POST'])
def login():
#   If credentials inputted match the ones in the database (ApplicationUser),
#   'user_identification_number' is stored in the current session
   if request.method == 'POST':
       nameForLogin = request.form['username'].strip()
       plainPassword = request.form['password'].strip()


       already_created_User = ApplicationUser.query.filter_by(loginName=nameForLogin).first()
       if already_created_User and already_created_User.checkLoginPassword(plainPassword):
           session['user_identification_number'] = already_created_User.id
           return redirect(url_for('homePage'))
       error = "Either username or password are incorrect, try again please."
       return render_template('login.html', error=error)
   return render_template('login.html')


@app.route('/logout')
@loginRequired
def logout():


#   functon clears 'user_identification_number', loggin out the user
   session.pop('user_identification_number', None)
   return redirect(url_for('login'))


#homepage route
@app.route('/')
@loginRequired
def homePage():
#   this function shows all CourseGroups that are currently avaiable
#    or were recently created by the logged-in ApplicationUser
   current_user_identification_number = session['user_identification_number']
   groups = CourseGroup.query.filter_by(owner_id=current_user_identification_number).all()
   return render_template('index.html', groups=groups)


# routes which are assissting in the managing of CourseGroups
@app.route('/add_group', methods=['GET', 'POST'])
@loginRequired
def addGroup():
#   function which collects data to create a new CourseGroup


   if request.method == 'POST':
       try:
           lvl = int(request.form['year_group'])
           if lvl < 1 or lvl > 13:
               raise ValueError
       except ValueError:
           error = "Year group must be an integer between 1 and 13."
           return render_template('add_group.html', error=error)


       sbj = request.form['subject']
       if sbj not in ["Maths AA SL", "Maths AA HL"]:
           error = "Invalid subject selected."
           return render_template('add_group.html', error=error)


       newGroup = CourseGroup(
           classLevel=lvl,
           courseSubject=sbj,
           owner_id=session['user_identification_number']
       )
       db.session.add(newGroup)
       db.session.commit()
       return redirect(url_for('homePage'))
   return render_template('add_group.html')




@app.route('/edit_group/<int:group_id>', methods=['GET', 'POST'])
@loginRequired
def editGroup(group_id):
#   function which lets an existing CourseGroup's attrivutes such as
#   class level and subject to change, if the user is authorized
   groupObj = CourseGroup.query.filter_by(
       id=group_id,
       owner_id=session['user_identification_number']
   ).first_or_404()


   if request.method == 'POST':
       try:
           lvl = int(request.form['year_group'])
           if lvl < 1 or lvl > 13:
               raise ValueError
           groupObj.classLevel = lvl
       except ValueError:
           error = "Year group must be 1-13."
           return render_template('edit_group.html', group_=groupObj, error=error)


       sbj = request.form['subject']
       if sbj not in ["Maths AA SL", "Maths AA HL"]:
           error = "Invalid subject selected."
           return render_template('edit_group.html', group_=groupObj, error=error)
       groupObj.courseSubject = sbj


       db.session.commit()
       return redirect(url_for('viewGroup', group_id=group_id))
   return render_template('edit_group.html', group_=groupObj)




@app.route('/delete_group/<int:group_id>', methods=['POST'])
@loginRequired
def deleteGroup(group_id):
#   function which lets user to remove his entire
#   CourseGroup if he is the owner
  
   groupObj = CourseGroup.query.filter_by(
       id=group_id,
       owner_id=session['user_identification_number']
   ).first_or_404()
   db.session.delete(groupObj)
   db.session.commit()
   return redirect(url_for('homePage'))




@app.route('/group/<int:group_id>')
@loginRequired
def viewGroup(group_id):
#   function which shows details for an individual CourseGroup
#   including chart created using Plotly, if user is logged in
   groupObj = CourseGroup.query.filter_by(
       id=group_id,
       owner_id=session['user_identification_number']
   ).first_or_404()


   learnersList = groupObj.learners
   groupGrades = {}
   #puts numericGrade in order by date
   for lrn in learnersList:
       for eachGrade in lrn.learnerGrades:
           groupGrades.setdefault(eachGrade.date, []).append(eachGrade.numericGrade)


   sorted_dates = sorted(groupGrades.keys())
   average_scores = [sum(scores) / len(scores) for scores in groupGrades.values()]


   #prepares plotply data if any of the dates are availiable
   if sorted_dates:
       chart_data = [{
           'x': sorted_dates,
           'y': average_scores,
           'type': 'scatter',
           'mode': 'lines+markers',
           'name': 'Group Average Scores',
           'line': {'shape': 'spline', 'color': 'green'}
       }]
       chart_layout = {
           'title': f"Group Progress Over Time - Year {groupObj.classLevel} {groupObj.courseSubject}",
           'xaxis': {'title': 'Date'},
           'yaxis': {'title': 'Average Score', 'range': [0, 100]}
       }
       plot_data_json = json.dumps(chart_data)
       plot_layout_json = json.dumps(chart_layout)
   else:
       plot_data_json = None
       plot_layout_json = None


   group_average = sum(average_scores) / len(average_scores) if average_scores else None
   ibGrade = computeIbGrade(group_id, group_average) if group_average is not None else None


   return render_template(
       'view_class.html',
       group_=groupObj,
       group_average=group_average,
       group_ib_grade=ibGrade,
       plot_data=plot_data_json,
       plot_layout=plot_layout_json
   )


#routes which assist anything related to Learner
@app.route('/group/<int:group_id>/add_learner', methods=['GET', 'POST'])
@loginRequired
def addLearner(group_id):
#   function which lets user create a new Learning in the CourseGroup he has chosen
#   but only if he is the owner
   groupObj = CourseGroup.query.filter_by(
       id=group_id,
       owner_id=session['user_identification_number']
   ).first_or_404()


   if request.method == 'POST':
       first = request.form['name'].strip()
       last = request.form['surname'].strip()


       if not first or not last:
           error = "First Name and Last Name are required."
           return render_template('add_learner.html', group_=groupObj, error=error)
       if len(first) > 20 or len(last) > 20:
           error = "Name must be 20 chars or fewer."
           return render_template('add_learner.html', group_=groupObj, error=error)


       newLearner = Learner(
           firstName=first,
           lastName=last,
           group_id=group_id,
           owner_id=session['user_identification_number']
       )
       db.session.add(newLearner)
       db.session.commit()
       return redirect(url_for('viewGroup', group_id=group_id))
   return render_template('add_learner.html', group_=groupObj)




@app.route('/edit_learner/<int:learner_id>', methods=['GET', 'POST'])
@loginRequired
def editLearner(learner_id):
#   existing Learner can be edited, if user is the owner
   lrn = Learner.query.filter_by(
       id=learner_id,
       owner_id=session['user_identification_number']
   ).first_or_404()


   if request.method == 'POST':
       first = request.form['name'].strip()
       last = request.form['surname'].strip()


       if not first or not last:
           error = "First and Last Name required."
           return render_template('edit_learner.html', learner=lrn, error=error)
       if len(first) > 20 or len(last) > 20:
           error = "Name must be 20 chars or fewer."
           return render_template('edit_learner.html', learner=lrn, error=error)


       lrn.firstName = first
       lrn.lastName = last
       db.session.commit()
       return redirect(url_for('viewLearner', learner_id=lrn.id))
   return render_template('edit_learner.html', learner=lrn)




@app.route('/delete_learner/<int:learner_id>', methods=['POST'])
@loginRequired
def deleteLearner(learner_id):
#   with the use of this function user can remove any
#   Learner from his CourseGroup
   lrn = Learner.query.filter_by(id=learner_id, owner_id=session['user_identification_number']).first_or_404()
   group_id = lrn.group_id
   db.session.delete(lrn)
   db.session.commit()
   return redirect(url_for('viewGroup', group_id=group_id))


#routes which assist managing grades of learners
@app.route('/learner/<int:learner_id>/add_grade', methods=['GET', 'POST'])
@loginRequired
def addLearnerGrade(learner_id):
#   creates a grade for a learner and makes sure
#   that the date is not in the future


   lrn = Learner.query.filter_by(id=learner_id, owner_id=session['user_identification_number']).first_or_404()


   if request.method == 'POST':
       exam = request.form['assessment_name']
       gradeVal = request.form['score']
       date_str = request.form['date']


       validExams = ["Paper 1", "Paper 2", "Paper 3", "Cycle Test"]
       if exam not in validExams:
           error = "Invalid exam name selected."
           return render_template('add_grade.html', learner=lrn, error=error, max_date=date.today().strftime('%Y-%m-%d'))


       try:
           gradeVal = float(gradeVal)
           if gradeVal < 0 or gradeVal > 100:
               raise ValueError
       except ValueError:
           error = "Grade added shoud be between 0 and 100."
           return render_template('add_grade.html', learner=lrn, error=error, max_date=date.today().strftime('%Y-%m-%d'))


       try:
           test_date = datetime.strptime(date_str, '%Y-%m-%d').date()
           if test_date > date.today():
               error = "Future dates cannot be inputted."
               return render_template('add_grade.html', learner=lrn, error=error, max_date=date.today().strftime('%Y-%m-%d'))
       except ValueError:
           error = "Date format is invalid, try again please."
           return render_template('add_grade.html', learner=lrn, error=error, max_date=date.today().strftime('%Y-%m-%d'))


       newGrade = LearnerGrade(
           examTitle=exam,
           numericGrade=gradeVal,
           date=test_date,
           learner_id=lrn.id,
           owner_id=session['user_identification_number']
       )
       db.session.add(newGrade)
       db.session.commit()
       return redirect(url_for('viewLearner', learner_id=lrn.id))


   return render_template('add_grade.html', learner=lrn, max_date=date.today().strftime('%Y-%m-%d'))




@app.route('/edit_learner_grade/<int:grade_id>', methods=['GET', 'POST'])
@loginRequired
def editLearnerGrade(grade_id):
#   function which updates already existing grade of the Learner
#   if user is authorized
   gradeObj = LearnerGrade.query.filter_by(id=grade_id, owner_id=session['user_identification_number']).first_or_404()
   lrn = gradeObj.learner


   if request.method == 'POST':
       exam = request.form['assessment_name']
       gradeVal = request.form['score']
       date_str = request.form['date']


       validExams = ["Paper 1", "Paper 2", "Paper 3", "Cycle Test"]
       if exam not in validExams:
           error = "Invalid exam name selected."
           return render_template('edit_grade.html', grade=gradeObj, error=error, max_date=date.today().strftime('%Y-%m-%d'))


       try:
           gradeVal = float(gradeVal)
           if gradeVal < 0 or gradeVal > 100:
               raise ValueError
       except ValueError:
           error = "Grade added shoud be between 0 and 100."
           return render_template('edit_grade.html', grade=gradeObj, error=error, max_date=date.today().strftime('%Y-%m-%d'))


       try:
           test_date = datetime.strptime(date_str, '%Y-%m-%d').date()
           if test_date > date.today():
               error = "Date format is invalid, try again please."
               return render_template('edit_grade.html', grade=gradeObj, error=error, max_date=date.today().strftime('%Y-%m-%d'))
       except ValueError:
           error = "Invalid date format."
           return render_template('edit_grade.html', grade=gradeObj, error=error, max_date=date.today().strftime('%Y-%m-%d'))


       gradeObj.examTitle = exam
       gradeObj.numericGrade = gradeVal
       gradeObj.date = test_date
       db.session.commit()
       return redirect(url_for('viewLearner', learner_id=lrn.id))


   return render_template('edit_grade.html', grade=gradeObj, max_date=date.today().strftime('%Y-%m-%d'))




@app.route('/delete_learner_grade/<int:grade_id>', methods=['POST'])
@loginRequired
def deleteLearnerGrade(grade_id):
#   If user is the owner, this function rmove a LearnerGrade
   gradeObj = LearnerGrade.query.filter_by(id=grade_id, owner_id=session['user_identification_number']).first_or_404()
   lrn_id = gradeObj.learner_id
   db.session.delete(gradeObj)
   db.session.commit()
   return redirect(url_for('viewLearner', learner_id=lrn_id))




#routes which allow specific Learners to viewed by the user
@app.route('/learner/<int:learner_id>')
@loginRequired
def viewLearner(learner_id):
#   Function which shows detail page about an individual Learner
#   e.g. (average, IB grade, chart generated by Plotly)
   lrn = Learner.query.filter_by(id=learner_id, owner_id=session['user_identification_number']).first_or_404()
   theirGrades = lrn.learnerGrades


   totalSum = sum(g.numericGrade for g in theirGrades)
   totalCount = len(theirGrades)
   learnerAverage = totalSum / totalCount if totalCount > 0 else None


   groupId = lrn.group_id
   ibResult = computeIbGrade(groupId, learnerAverage) if learnerAverage is not None else None


   dates = [g.date for g in theirGrades]
   scores = [g.numericGrade for g in theirGrades]


   if dates:
       chart_data = [{
           'x': dates,
           'y': scores,
           'type': 'scatter',
           'mode': 'lines+markers',
           'name': 'Scores over Time',
           'line': {'shape': 'spline', 'color': 'blue'}
       }]
       chart_layout = {
           'title': f"Progress of {lrn.firstName} {lrn.lastName}",
           'xaxis': {'title': 'Date'},
           'yaxis': {'title': 'Score', 'range': [0, 100]}
       }
       plot_data = json.dumps(chart_data)
       plot_layout = json.dumps(chart_layout)
   else:
       plot_data = None
       plot_layout = None


   return render_template(
       'view_student.html',
       learner=lrn,
       learner_average=learnerAverage,
       ib_grade=ibResult,
       plot_data=plot_data,
       plot_layout=plot_layout
   )


#route which lets grade boundaries to be uploaded
@app.route('/group/<int:group_id>/upload_boundaries', methods=['GET', 'POST'])
@loginRequired
def uploadBoundaries(group_id):
#   function which allows user to upload a CSV file with pre-specified boundaries
#   for a chosen CourseGroup
   groupObj = CourseGroup.query.filter_by(id=group_id, owner_id=session['user_identification_number']).first_or_404()


   if request.method == 'POST':
       if 'file' not in request.files:
           error = "try another file, this file cannot be read"
           return render_template('upload_grade_boundaries.html', group_=groupObj, error=error)
       file = request.files['file']
       if file.filename == '':
           error = "No selected file"
           return render_template('upload_grade_boundaries.html', group_=groupObj, error=error)


       try:
           stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
           csv_input = csv.reader(stream)
           rows = list(csv_input)
           if not rows:
               error = "CSV file is empty."
               return render_template('upload_grade_boundaries.html', group_=groupObj, error=error)


           # The first row must be exactly one type of subject (e.g. Maths HL)
           subjectRow = rows[0]
           if len(subjectRow) != 1:
               error = "The first row should contain only the subject name."
               return render_template('upload_grade_boundaries.html', group_=groupObj, error=error)
           boundarySubject = subjectRow[0].strip()


           if boundarySubject != groupObj.courseSubject:
               error = (
                   f"CSV subject '{boundarySubject}' "
                   f"does not match the group's subject '{groupObj.courseSubject}'."
               )
               return render_template('upload_grade_boundaries.html', group_=groupObj, error=error)


           # already existing boundaries for this CourseGroup are removed
           BoundaryRule.query.filter_by(group_id=group_id).delete()
           db.session.commit()


           # every row that comes after this should have this structure
           # [grade, lowerBound, upperBound]
           for row in rows[1:]:
               if len(row) != 3:
                   error = "Each grade boundary row must have three values: grade, lowerBound, upperBound."
                   return render_template('upload_grade_boundaries.html', group_=groupObj, error=error)
               rowGrade, lb, ub = row
               newRule = BoundaryRule(
                   boundarySubject=boundarySubject,
                   grade=int(rowGrade),
                   lowerBound=float(lb),
                   upperBound=float(ub),
                   group_id=group_id
               )
               db.session.add(newRule)


           db.session.commit()
           success = f"Boundaries for '{boundarySubject}' (Group ID: {group_id}) uploaded successfully."
           return render_template('upload_grade_boundaries.html', group_=groupObj, success=success)
       except Exception as e:
           error = f"CSV file cannot be processed due to an error: {e}"
           return render_template('upload_grade_boundaries.html', group_=groupObj, error=error)


   return render_template('upload_grade_boundaries.html', group_=groupObj)


#main entry
if __name__ == '__main__':
   # Creates Data base tables when they are needed
   with app.app_context():
       db.create_all()
   # runs in debug mode when code is in the developement
   app.run(debug=True)



