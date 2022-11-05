from cs50 import SQL
from flask import Flask, render_template, flash, request, redirect, session
from flask_session import Session
from werkzeug.security import generate_password_hash, check_password_hash

from helper import login_required, valid_password


app = Flask(__name__)


app.config["TEMPLATES_AUTO_RELOAD"] = True


app.config["SESSION_PERMENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)


db = SQL("sqlite:///save.db")


@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

@app.route("/login", methods=["GET", "POST"])
def login():
    session.clear()
    if request.method == "POST":
        user = request.form.get("username")
        password = request.form.get("password")
        if not user:
            flash("Must provide username.")
            return render_template("login.html")
        elif not password:
            flash("Must provide password.")
            return render_template("login.html")
        accounts = db.execute("SELECT * FROM accounts WHERE username = ?", user)
        if len(accounts) != 1 or not check_password_hash(accounts[0]["hash"], password):
            flash("invalid username and/or password")
            return render_template("login.html")
        session["user_id"] = accounts[0]["id"]
        name = accounts[0]["name"]
        flash(f"Hello! {name}")
        return redirect("/")
    else:
        return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name")
        user = request.form.get("username")
        password = request.form.get("password")
        con_password = request.form.get("confirmation")
        username_dict = db.execute("SELECT username FROM accounts")
        username_list = [sub['username'] for sub in username_dict]
        if not user or not name or not password or not con_password:
            flash("YOU MUST FILL ALL FORM.")
            return render_template("register.html")
        elif user in username_list:
            flash("Username already exit! Please choose different username.")
            return render_template("register.html")
        elif not valid_password(password):
            flash("Must provide strong password according to instruction.")
            return render_template("register.html")
        elif password != con_password:
            flash("Must provide same password.")
            return render_template("register.html")
        else:
            hash = generate_password_hash(password, method='pbkdf2:sha256', salt_length=16)
            db.execute("INSERT INTO accounts (name, username, hash) VALUES(?, ?, ?)", name, user, hash)
            accounts = db.execute("SELECT * FROM accounts WHERE username = ?", user)
            session["user_id"] = accounts[0]["id"]
            flash(f"Hello! {name}")
            return redirect("/")
    return render_template("register.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    user_id = session["user_id"]
    if request.method == "POST":
        folder = request.form.get("folder_name")
        text = request.form.get("text")
        if not text or not folder:
            flash("Please fill the form to save the text.")
            return redirect("/")
        else:
            db.execute("INSERT INTO datas (user_id, foldername, data) VALUES(?, ?, ?)", user_id, folder, text)
            return redirect("/")
    else:
        datas = []
        length1 = []
        folder_dict = db.execute("SELECT DISTINCT foldername FROM datas WHERE user_id = ?", user_id)
        folder_list = [sub['foldername'] for sub in folder_dict]
        length = len(folder_list)
        for i in range(length):
            name = folder_list[i]
            data = db.execute("SELECT data FROM datas WHERE user_id = ? AND foldername = ?", user_id, name)
            data_list = [sub['data'] for sub in data]
            lengt = len(data_list)
            length1.append(lengt)
            datas.append(data_list)
        return render_template("index.html", datas=datas, folder_list=folder_list, length=length, length1=length1)


@app.route("/index")
@app.route("/delete", methods=["GET", "POST"])
@login_required
def delete():
    if request.method == "POST":
        data = request.form.get("data")
        db.execute("DELETE FROM datas WHERE data = ?", data)
        return redirect("/")
    return redirect("/")


@app.route("/acc_setting")
@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    user_id = session["user_id"]
    if request.method == "POST":
        old = request.form.get("old_password")
        new = request.form.get("new_password")
        con = request.form.get("confirmation")
        accounts = db.execute("SELECT * FROM accounts WHERE id = ?", user_id)
        if not old or not new or not con:
            flash("YOU MUST FILL ALL FORM.")
            return render_template("acc_setting.html")
        elif len(accounts) != 1 or not check_password_hash(accounts[0]["hash"], old):
            flash("invalid password")
            return render_template("acc_setting.html")
        elif new != con:
            flash("Must provide same password.")
            return render_template("acc_setting.html")
        elif not valid_password(new):
            flash("Must provide strong password according to instruction.")
            return render_template("acc_setting.html")
        else:
            hash = generate_password_hash(new, method='pbkdf2:sha256', salt_length=16)
            db.execute("UPDATE accounts SET hash=? WHERE id=?", hash, user_id)
            flash("Password successfully changed!")
            return redirect("/")
    return render_template("acc_setting.html")


@app.route("/acc_setting")
@app.route("/delete_acc", methods=["GET", "POST"])
@login_required
def delete_acc():
    user_id = session["user_id"]
    if request.method == "POST":
        password = request.form.get("password")
        accounts = db.execute("SELECT * FROM accounts WHERE id = ?", user_id)
        if not password:
            flash("Please provide password.")
            return render_template("acc_setting.html")
        elif len(accounts) != 1 or not check_password_hash(accounts[0]["hash"], password):
            flash("invalid password")
            return render_template("acc_setting.html")
        else:
            db.execute("DELETE FROM datas WHERE user_id = ?", user_id)
            db.execute("DELETE FROM accounts WHERE id = ?", user_id)
            flash("Your account has been successfully deleted.")
            session.clear()
            return redirect("/")
    return render_template("acc_setting.html")