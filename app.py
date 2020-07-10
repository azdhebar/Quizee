from datetime import datetime

import bcrypt

from flask import Flask, render_template, request, redirect, session
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import backref

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///quizee.db"
app.secret_key = "hello"
db = SQLAlchemy(app)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    uname = db.Column(db.Text, unique=True, nullable=False)
    is_admin = db.Column(db.Integer, nullable=False, default=0)
    password = db.Column(db.Text, nullable=False)
    email = db.Column(db.Text, nullable=False, unique=True)
    recovery_code = db.Column(db.Integer, nullable=True, default="")
    fname = db.Column(db.Text, nullable=False)
    lname = db.Column(db.Text, nullable=False)
    Quizes = db.relationship('Quiz', backref=backref('user',passive_deletes=True), lazy=True)
    Score = db.relationship('Score', backref=backref('user', passive_deletes=True), lazy=True)

    def __repr__(self):
        return str(self.id)


class Quiz(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    qname = db.Column(db.Text, nullable=False, unique=True)
    qcode = db.Column(db.Text, nullable=False, unique=True)
    lock = db.Column(db.Integer, nullable=False, default=0)
    created_time = db.Column(db.Text, nullable=False, default=datetime.utcnow().date())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id',ondelete="CASCADE"), nullable=True)
    questions = db.relationship('Question', backref=backref('quiz',passive_deletes=True), lazy=True)
    options = db.relationship('Options', backref=backref('quiz', passive_deletes=True), lazy=True)
    Score = db.relationship('Score', backref=backref('quiz',passive_deletes=True), lazy=True)

    def __repr__(self):
        return str(self.id)


class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question = db.Column(db.Text, nullable=False)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id',ondelete="CASCADE"), nullable=True)
    options = db.relationship('Options', backref=backref('question',passive_deletes=True), lazy=True)
    def __repr__(self):
        return str(self.id)


class Options(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    option = db.Column(db.Text, nullable=False)
    correct = db.Column(db.Integer, nullable=False, default=0)
    question_id = db.Column(db.Integer, db.ForeignKey('question.id',ondelete="CASCADE"), nullable=True)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id', ondelete="CASCADE"), nullable=True)
    def __repr__(self):
        return str(self.id)

class Score(db.Model):
    id =db.Column(db.Integer,primary_key=True)
    score = db.Column(db.Integer,nullable=False)
    total= db.Column(db.Integer,nullable=False)
    quiz_id = db.Column(db.Integer, db.ForeignKey('quiz.id', ondelete="CASCADE"), nullable=True)
    created_time = db.Column(db.Text, nullable=False, default=datetime.utcnow().date())
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete="CASCADE"),nullable=True)
    def __repr__(self):
        return str(self.id)


def getQuizes():
    quizes = Quiz.query.filter_by(user_id=session["id"]).all()
    return quizes


# password hashing
def hashed_password(password):
    print(password)
    password = password.encode('utf8')
    print(password)
    key = bcrypt.kdf(password=password, salt=b'salt', desired_key_bytes=32, rounds=100)
    return key


# without login Routes
@app.route('/')
def index():
    if "user" not in session:
        return render_template('index.html')
    else:
        return redirect('/dashboard')


@app.route('/login', methods=["GET", "POST"])
def login():
    if "user" in session:
        return redirect('/dashboard')
    else:
        if request.method == "POST":
            uname = request.form["uname"]
            password = request.form["password"]
            hashedpassword = hashed_password(password)
            try:
                user = User.query.filter_by(uname=uname).first()

                if str(user.password) == str(hashedpassword):
                    session["user"] = user.uname
                    session["id"] = user.id
                    if user.is_admin == 0:
                        return redirect('/dashboard')

                else:
                    error = 'Password Is Wrong'
                    return render_template('login.html', error=error)
            except:
                error = 'Something Went Wrong'
                return render_template('login.html', error=error)
        else:
            return render_template('login.html')


@app.route('/register', methods=["GET", "POST"])
def register():
    if "user" in session:
        return redirect('/dashboard')
    else:
        if request.method == "POST":
            fname = request.form["fname"]
            lname = request.form["lname"]
            uname = request.form["uname"]
            email = request.form["email"]
            password = request.form["password"]
            hashedpassword = hashed_password(password)
            try:
                db.session.add(User(fname=fname, lname=lname, uname=uname, email=email, password=str(hashedpassword)))
                db.session.commit()
                return redirect('/login')
            except:
                error = 'Username Or Email Is Already Registred!!'
                return render_template('register.html', error=error)
        else:
            return render_template('register.html')


# with login Routes for user
@app.route('/dashboard')
def dashboard():
    if "user" not in session:
        return redirect("/login")
    else:
        return render_template('dashboard.html')


@app.route('/logout')
def logout():
    if "user" not in session:
        return redirect("/login")
    else:
        session.pop("user", None)
        return redirect('/login')


@app.route('/profile', methods=["GET", "POST"])
def profile():

    if "user" not in session:
        return redirect("/login")
    else:
        user = User.query.filter_by(uname=session["user"]).first()
        if request.method == "GET":
            return render_template('profile.html', user=user)
        if request.method == "POST":
            user.fname = request.form["fname"]
            user.lname = request.form["lname"]
            db.session.commit()
            return redirect('/profile')


@app.route('/Quiz/create', methods=["GET", "POST"])
def createQuiz():
    if "user" not in session:
        return redirect("/login")
    else:
        if request.method == "POST":
            qname = request.form["qname"]
            code = request.form["code"]
            try:
                db.session.add(Quiz(qname=qname, qcode=code, user_id=int(session["id"])))
                db.session.commit()
                return redirect('/')

            except:
                error = "Quize Name Or Code Already Registered Please Try Another"
                return render_template('createQuiz.html', error=error)
            return render_template('createQuiz.html')
        else:
            return render_template('createQuiz.html')


@app.route('/Quiz/display')
def displayQuiz():
    if "user" not in session:
        return redirect("/login")
    else:
        quizes = getQuizes()
        return render_template('displayQuizList.html', quizes=quizes)


@app.route('/deleteQuiz/<int:id>')
def deleteQuiz(id):
    if "user" not in session:
        return redirect("/login")
    else:

        try:
            quiz = Quiz.query.filter_by(id=int(id)).first()
            db.session.delete(quiz)
            db.session.commit()
            return redirect('/Quiz/display')
        except Exception as e:
            return str(e)


@app.route('/addQuestions/<int:id>')
def addQuestion(id):
    if "user" not in session:
        return redirect("/login")
    else:
        try:
            quiz = Quiz.query.filter_by(id=int(id)).first()
            question = Question.query.filter_by(quiz_id=int(id))
            print("Questrion {}".format(question))
            return render_template('addQuestions.html', questions=question, quiz=quiz)
        except:
            return render_template('404.html')


@app.route('/add/<int:id>', methods=["GET", "POST"])

def addnewquestion(id):
    if "user" not in session:
        return redirect("/login")
    else:
        if request.method == "GET":
            return render_template('addQuestion.html',id=id)
        else:
            c1=0
            c2=0
            c3=0
            c4=0
            question = request.form["question"]
            option1 = request.form["option1"]
            option2 = request.form["option2"]
            option3 = request.form["option3"]
            option4 = request.form["option4"]
            correct = request.form["correct"]
            if correct == "option1":
                c1=1
            if correct == "option2":
                c2 =1
            if correct == "option3":
                c3=1
            if correct == "option4":
                c4=1
            q=Question(question=question,quiz_id=id)
            db.session.add(q)
            db.session.flush()


            db.session.add(Options(correct=c1,option=option1,question_id=q.id,quiz_id=id))
            db.session.add(Options(correct=c2,option=option2,question_id=q.id,quiz_id=id))
            db.session.add(Options(correct=c3,option=option3,question_id=q.id,quiz_id=id))
            db.session.add(Options(correct=c4,option=option4,question_id=q.id,quiz_id=id))
            db.session.commit()
            return redirect('/addQuestions/{}'.format(id))

@app.route('/edit/<int:id>', methods=["GET", "POST"])#question Id
def editquestion(id):
    if "user" not in session:
        return redirect("/login")
    else:
        try:
            if request.method == "GET":
                q = Question.query.filter_by(id=id).first()

                return render_template('editQuestion.html',question=q)
            else:
                c= [0,0,0,0]
                option=[]
                question = request.form["question"]
                option.append(request.form["option1"])
                option.append(request.form["option2"])
                option.append(request.form["option3"])
                option.append(request.form["option4"])
                correct = request.form["correct"]
                if correct == "option1":
                    c[0]=1
                if correct == "option2":
                    c[1] =1
                if correct == "option3":
                    c[2]=1
                if correct == "option4":
                    c[3]=1
                q=Question.query.filter_by(id=id).first()
                q.question = question
                options = Options.query.filter_by(question_id=id).all()
                for i in range(len(options)):
                    o = Options.query.filter_by(id=options[i].id).first()
                    o.correct= c[i]
                    o.option=option[i]
                    db.session.commit()
                db.session.commit()

                return redirect('/addQuestions/{}'.format(q.quiz_id))
        except Exception as e:
            #return redirect('/addQuestions/{}'.format(q.quiz_id))
            return str(e)

@app.route('/delete/<int:id>/<int:qid>') #qid is for quiz id
def deletequestion(id,qid):
    if "user" not in session:
        return redirect("/login")
    else:
        try:
            options = Options.query.filter_by(question_id=id).all()
            print(options)
            if len(options)>0:
                delete_options= Options.__table__.delete().where(Options.question_id==id)
                db.session.execute(delete_options)
                db.session.commit()
            question =  Question.query.filter_by(id = id,quiz_id=qid).first()
            print(question.id)
            db.session.delete(question)
            db.session.commit()
            return redirect("/addQuestions/{}".format(qid))
        except:
            return redirect("/addQuestions/{}".format(qid))

#enable disable quiz
@app.route('/endquiz/<int:id>')
def endQuiz(id):
    if "user" not in session:
        return redirect("/login")
    else:
        try:
            quiz = Quiz.query.filter_by(id=id).first()
            if(quiz.lock==0):
                quiz.lock = 1
            else:
                quiz.lock=0
            db.session.commit()
            return redirect("/addQuestions/{}".format(id))
        except:
            return redirect("/addQuestions/{}".format(id))


@app.route('/joinquiz',methods=["GET","POST"])
def joinQuiz():
    if "user" not in session:
        return redirect("/login")
    else:
        if request.method=="GET":
            return render_template('joinQuiz.html')
        else:
            qcode = request.form["qcode"]
            try:
                quiz = Quiz.query.filter_by(qcode=qcode).first()
                print(quiz.id)
                score = Score.query.filter_by(user_id=int(session["id"]), quiz_id=quiz.id).all()
                if score==[]:
                   if quiz.lock == 0:
                        return render_template('attemptQuiz.html',quiz=quiz)
                   else:
                        error="Quiz Is Over"
                        return render_template('joinQuiz.html',error=error)
                else:
                    error = "You Have Already Given The Quiz"
                    return render_template('joinQuiz.html', error=error)
            except Exception as e:
                error = "Quiz Code Is Invalid"
                return render_template('joinQuiz.html', error=error)


@app.route('/result/<int:id>',methods=["POST"])
def result(id):
    if "user" not in session:
        return redirect("/login")
    else:
        if request.method=="POST":
            try:
                quiz = Quiz.query.filter_by(id=id).first()
                score = Score.query.filter_by(user_id=int(session["id"]),quiz_id=quiz.id).all()
                if(score==[]):

                    ans = []

                    questions = Question.query.filter_by(quiz_id=quiz.id).all()
                    for i in range(len(questions)):
                        ans.append(int(request.form[str(questions[i].id)]))
                    print(ans)

                    correct = []
                    correct1 = Options.query.filter_by(quiz_id=quiz.id,correct =1).all()
                    for i in range(len(correct1)):
                        correct.append(correct1[i].id)

                    print(correct)
                    c=0
                    print(c)

                    for j in range(len(ans)):
                        print(type(ans[j]))
                        print(type(correct[j]))
                        if ans[j]==correct[j]:
                            c=c+1
                    db.session.add(Score(score=c,total=len(correct),quiz_id=quiz.id,user_id=session["id"]))
                    db.session.commit()

                    return render_template('result.html',all = len(correct),correct=c)
                else:
                    error = "You Have Already Given The Quiz"
                    return render_template('joinQuiz.html', error=error)



            except Exception as e:
                return str(e)

@app.route('/seeResult')
def seeResult():
    if "user" not in session:
        return redirect("/login")
    else:
        score = Score.query.filter_by(user_id=int(session["id"])).all()
        return render_template('seeResult.html',score=score)

@app.route('/seeResult/<int:id>')
def seeResultQuiz(id):
    if "user" not in session:
        return redirect("/login")
    else:
        score = Score.query.filter_by(quiz_id=id).all()
        return render_template('seeResultQuiz.html', score=score)
