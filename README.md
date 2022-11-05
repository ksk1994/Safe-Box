# SAFE BOX

#### Video Demo: https://youtu.be/xrktf28-hsE

#### Decription:
This web application lets you cipher and decipher texts on client site. And you can open an account to store those texts in database. This web app can be used to store passwords, bank information, crypto currency wallet and etc. The main function in this web app is client-site cipher. At first, I was using AES cipher in crypto.js. I changed my mind not to use that and decided to write my own code. I got inspiration from a youtube video about how enigma machine from ww2 works. I wanted to write a code that use some parts of that machine's function, even if not full function. I was struggling for a few hours when I started writing but I managed to get through it and got a functioning code. The cipher takes three number-codes and a plain text as arguments and return ciphered text. It loops through each letter of the text, move certain number of places using number-code and increment the number by one each loop. If the first code reach 83, it will be assigned as 0 and the second code will be incremented by 1. If the second code reach 83, it will be assigned as 0 and the third code will be incremented by 1. This web app can also decipher the ciphered texts using the three codes which was used to ciphred the text. It can also save those texts for users. User can change password and delete account. User can also delete any saved text. Check below to learn how each code section works:

## Directory Structure:
 This web app has two folders:
- static
- templates

And four files in main folder:
- app.py
- helper.py
- README.md
- save.db

## static
In static folder, there are .ico file and .png files created using Adobe Expess and style.css which is a stylesheet.

## templates
In templates folder, there are five html templates:
- layout.html
- register.html
- login.html
- acc_setting.html
- index.html

## layout.html
This template contains layout for the web app such as:
## head, bootstrap and stylesheet
```htm
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <link crossorigin="anonymous" href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" integrity="sha384-1BmE4kWBq78iYhFldvKuhfTAU6auU8tT94WrHftjDbrCEXSU1oBoqyl2QvZ6jIW3" rel="stylesheet">
    <script crossorigin="anonymous" src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js" integrity="sha384-ka7Sk0Gln4gmtz2MlQnikT1wXgYsOg+OMhuP+IlRH9sENBO0LRn5q+8nbTov4+1p"></script>
    <link href="/static/icon.ico" rel="icon">
    <link href="/static/styles.css" rel="stylesheet">
    <title>Safe Box: {% block title %}{% endblock %}</title>
 </head>
```


## nav bar
In this nav-bar, html will show Log Out link and Account Setting link if account is in session. Or it will show Register link and Log In link.
```htm
<nav class="navbar navbar-expand-md navbar-light">
    <div class="container-fluid">
        <a class="navbar-brand" href="/">
            <img src="/static/icon1.png" alt="safe box" width="30" height="30">
            <span class="blue">S</span><span class="light">A</span><span class="blue">F</span><span class="light">E</span> <span class="blue">BOX</span>
        </a>
        <button aria-controls="navbar" aria-expanded="false" aria-label="Toggle navigation" class="navbar-toggler" data-bs-target="#navbar" data-bs-toggle="collapse" type="button">
            <span class="navbar-toggler-icon"></span>
        </button>
        <div class="collapse navbar-collapse" id="navbar">
            {% if session["user_id"] %}
                <ul class="navbar-nav ms-auto mt-2">
                    <li class="nav-item"><a class="nav-link" href="/logout">Log Out</a></li>
                    <li class="nav-item"><a class="nav-link" href="/acc_setting">Account Setting</a></li>
                </ul>
            {% else %}
                <ul class="navbar-nav ms-auto mt-2">
                    <li class="nav-item"><a class="nav-link" href="/register">Register</a></li>
                    <li class="nav-item"><a class="nav-link" href="/login">Log In</a></li>
                </ul>
            {% endif %}
        </div>
    </div>
</nav>
```

## flash massage
```htm
{% if get_flashed_messages() %}
    <header>
        <div class="alert alert-primary mb-0 text-center" role="alert">
            {{ get_flashed_messages() | join(" ") }}
        </div>
    </header>
{% endif %}
```


## main body
```htm
<main class="container-fluid py-5 text-center" style="background-color: #5CDB95">
    {% block main %}{% endblock %}
</main>
```


## register.html
This template contains form to register account and logo for safe box. If user tries to register, password have to be fill accodring to description or the page will reload itself and show flash massage.
## registration form
```htm
<form action="/register" method="post">
    <div class="mb-3">
        <input autocomplete="off" autofocus class="form-control mx-auto w-auto" id="name" name="name" placeholder="Full Name" type="text">
    </div>
    <div class="mb-3">
        <input autocomplete="off" autofocus class="form-control mx-auto w-auto" id="username" name="username" placeholder="Username" type="text">
    </div>
    <div class="mb-3">
        <input class="form-control mx-auto w-auto" id="password" name="password" placeholder="Password" type="password">
    </div>
    <div class="mb-3">
        <input class="form-control mx-auto w-auto" id="confirmation" name="confirmation" placeholder="confirm Password" type="password">
    </div>
    <p id="passwordHelpInline" class="form-text">Strong password must have minimum 8 charactors including at least one uppercase letter, one lowercase letter and one digit.</p>
    <button class="btn btn-outline-primary" type="submit">Register</button>
</form>
```


## logo
```htm
<div class="col" class="img-fluid rounded float-end" style="padding: 50px">
    <img src="/static/main1.png" alt="safe box" class="img-fluid" width="auto" height="auto">
</div>
```



## login.html
This template contains form to login and logo.
## form
```htm
<form action="/login" method="post">
    <div class="mb-3">
        <input autocomplete="off" autofocus class="form-control mx-auto w-auto" id="username" name="username" placeholder="Username" type="text">
    </div>
    <div class="mb-3">
        <input class="form-control mx-auto w-auto" id="password" name="password" placeholder="Password" type="password">
    </div>
    <button class="btn btn-outline-primary" type="submit">Log In</button>
</form>
```

## acc_setting.html
This template contains two functions:
If user tries to change password, new password have to be fill accodring to description or the page will reload itself and show flash massage.
## Change Password:
```htm
<form action="/change_password" method="post">
    <div class="mb-3">
        <input class="form-control mx-auto w-auto" id="old_password" name="old_password" placeholder="Old Password" type="password">
    </div>
    <div class="mb-3">
        <input class="form-control mx-auto w-auto" id="new_password" name="new_password" placeholder="New Password" type="password">
    </div>
    <div class="mb-3">
        <input class="form-control mx-auto w-auto" id="confirmation" name="confirmation" placeholder="confirm Password" type="password">
    </div>
        <p id="passwordHelpInline" class="form-text">Strong password must have minimum 8 charactors including at least one uppercase letter, one lowercase letter and one digit.</p>
    <button class="btn btn-outline-primary" type="submit">Change Password</button>
</form>
```

## Delete Account:
If user tries to delete account, pop up alert will warn user and gets confirmation to delete account.
```htm
<form action="/delete_acc" method="post">
    <div class="mb-3">
        <input class="form-control mx-auto w-auto" id="password" name="password" placeholder="Password" type="password">
    </div>
    <button class="btn btn-outline-primary" type="button" data-bs-toggle="modal" data-bs-target="#staticBackdrop">Delete Account</button>
    <div class="modal fade" id="staticBackdrop" data-bs-backdrop="static" data-bs-keyboard="false" tabindex="-1" aria-labelledby="staticBackdropLabel" aria-hidden="true">
        <div class="modal-dialog">
        <div class="modal-content">
            <div class="modal-header">
            <h5 class="modal-title" id="staticBackdropLabel">Warning</h5>
            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
            </div>
            <div class="modal-body">
            All your saved meterials will be deleted.
            </div>
            <div class="modal-footer">
            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
            <button type="button submit" class="btn btn-primary">Understood</button>
            </div>
        </div>
        </div>
    </div>
</form>
```

## index.html
This template contains:
- client-site cipher
- client-site decipher
- save
- showing saved texts
- deleting saved texts

## client-site cipher
This is a javascript function that takes three number-codes and text as arguments and return ciphered text.
```htm
<div class="col-6">
        <button id="encrypt_text" class="btn stybutton" type="button" data-bs-toggle="collapse" data-bs-target="#collapseWidthExample" aria-expanded="false" aria-controls="collapseWidthExample">
            Encrypt Your Note
        </button>
        <div class=" container-fluid py-5 text-center" style="min-height: 120px;">
            <div class="collapse collapse-vertical" id="collapseWidthExample">
                <div style="width: auto;">
                <form>
                    <div class="mb-3">
                        <label for="encryption-code" class="col-form-label">Encryption Code:</label>
                        <div class="row">
                            <div class="col-sm"><input style="background-color: #EDF5E1" type="number" class="form-control" id="encryption-code1"></div>
                            <div class="col-sm"><input style="background-color: #EDF5E1" type="number" class="form-control" id="encryption-code2"></div>
                            <div class="col-sm"><input style="background-color: #EDF5E1" type="number" class="form-control" id="encryption-code3"></div>
                        </div>
                        <p id="code_alert"></p>
                    </div>
                    <div class="mb-3">
                        <label for="text_to_encrypt" class="col-form-label">Message:</label>
                        <textarea class="form-control style" type="text" id="text_to_encrypt"></textarea>
                        <p id="text_alert"></p>
                        <button type="button" id="encrypt" class="btn stybutton">Encrypt</button>
                        <div class="form-floating">
                            <textarea class="form-control style" placeholder="Encrypted Text" id="encrypted_text" style="height: 100px"></textarea>
                            <label for="floatingTextarea2">Encrypted Text</label>
                        </div>
                    </div>
                </form>
            </div>
        </div>
    </div>
</div>
```
```javascript
function encrypt(text, code1, code2, code3) {
    let te = text.value.toString();
    const t = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', ',', '.', '?', '<', '>', '/', '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '-', '_', '=', '+', ' ']
    let myarray = te.split("");
    let length = te.length;
    let c1 = (code1.value) % 83;
    let c2 = (code2.value) % 83;
    let c3 = (code3.value) % 83;
    let enc = [];
    for (let i = 0; i < length; i++) {
    if (t.includes(myarray[i])) {
        let index = t.indexOf(myarray[i]);
        let enindex1 = (index + c1) % 83;
        let enindex2 = (enindex1 + c2) % 83;
        let enindex3 = (enindex2 + c3) % 83;
        c1 += 1;
        if ((c1 % 83) == 0 & c1 != 0) {
        c1 = 0;
        c2 += 1;
        }
        if ((c2 % 83) == 0 & c2 != 0) {
        c2 = 0;
        c3 += 1;
        }
        if ((c3 % 83) == 0) {
        c3 = 0;
        }
        enc[i] = t[enindex3];
    } else {
        enc[i] = myarray[i];
    }
    }
    let encrypted = enc.join("");
    return encrypted;
}
```

## client-site decipher
This is a javascript function that takes three number-codes and ciphered text as arguments and return original text.
```htm
<div class="col-6">
    <button id="decrypt_text" class="btn stybutton" type="button" data-bs-toggle="collapse" data-bs-target="#collapseWidthExample2" aria-expanded="false" aria-controls="collapseWidthExample2">
        Decrypt Your Note
    </button>
    <div class=" container-fluid py-5 text-center" style="min-height: 120px;">
        <div class="collapse collapse-vertical" id="collapseWidthExample2">
            <div  style="width: auto;">
                <form>
                    <div class="mb-3">
                        <label for="decryption-code"class="col-form-label">Decryption Code: </label>
                        <div class="row">
                         <div class="col-sm"><input style="background-color: #EDF5E1" type="number" class="form-control" id="decryption_code1"></div>
                        <div class="col-sm"><input style="background-color: #EDF5E1" type="number" class="form-control" id="decryption_code2"></div>
                        <div class="col-sm"><input style="background-color: #EDF5E1" type="number" class="form-control" id="decryption_code3"></div>
                        </div>
                        <p id="de_code_alert"></p>
                    </div>
                    <div class="mb-3">
                        <label for="text_to_decrypt" class="col-form-label">Text To Decrypt: </label>
                        <textarea class="form-control style" type="text" id="text_to_decrypt"></textarea>
                        <p id="de_text_alert"></p>
                        <button type="button" id="decrypt" class="btn stybutton">Decrypt</button>
                        <div class="form-floating">
                        <textarea class="form-control style" placeholder="Decrypted Text" id="decrypted_text" style="height: 100px"></textarea>
                        <label for="floatingTextarea2">Decrypted Text</label>
                        </div>
                    </div>
                </form>
            </div>
        </div>
    </div>
</div>
```

```javascript
function decrypt(text, code1, code2, code3) {
    let te = text.value.toString();
    const t = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', ',', '.', '?', '<', '>', '/', '!', '@', '#', '$', '%', '^', '&', '*', '(', ')', '-', '_', '=', '+', ' ']
    let myarray = te.split("");
    let length = te.length;
    let c1 = (code1.value) % 83;
    let c2 = (code2.value) % 83;
    let c3 = (code3.value) % 83;
    let decr = [];
    for (let i = 0; i < length; i++) {
    if (t.includes(myarray[i])) {
        let index = t.indexOf(myarray[i]);
        let deindex1 = (index - c1 + 83) % 83;
        let deindex2 = (deindex1 - c2 + 83) % 83;
        let deindex3 = (deindex2 - c3 + 83) % 83;
        c1 += 1;
        if ((c1 % 83) == 0 & c1 != 0) {
        c1 = 0;
        c2 += 1;
        }
        if ((c2 % 83) == 0 & c2 != 0) {
        c2 = 0;
        c3 += 1;
        }
        if ((c3 % 83) == 0) {
        c3 = 0;
        }
        decr[i] = t[deindex3];
    } else {
        decr[i] = myarray[i];
    }
    }
    let decrypted = decr.join("");
    return decrypted;
}
```


## save
User can name a folder and save some texts.
```htm
<div class="container-fluid">
    <form action="/" method="post">
        <div class="mb-3">
            <input class="style" autocomplete="off" autofocus class="form-control mx-auto w-auto" id="folder_name" name="folder_name" placeholder="Folder Name" type="text">
        </div>
        <div class="mb-3">
        <div class="form-floating">
            <textarea class="form-control mb-3 style" placeholder="Text" type="text" name="text" style="height: 100px"></textarea>
            <label for="floatingTextarea2">Note to save</label>
        </div>
        <button type="submit" id="save" class="btn stybutton">SAVE</button>
        </div>
    </form>
</div>
```

## showing saved texts
User will be showed saved texts grouped by folder name.
## deleting saved texts
User can delete each texts.
```htm
<div class="accordion accordion-flush style">
    {% for i in range(length) %}
        <div class="accordion-item">
            <h2 class="accordion-header" id="headingOne">
            <button class="dataheader accordion-button collapsed" type="button" data-bs-toggle="collapse" data-bs-target="#collapse{{ i }}" aria-expanded="false" aria-controls="collapse{{ i }}">
              {{ folder_list[i] }}
            </button>
            </h2>
        {% for y in range(length1[i]) %}
          <div id="collapse{{ i }}" class="accordion-collapse collapse dataarea" aria-labelledby="headingOne" data-bs-parent="#accordionExample">
            <div class="accordion-body container">
              <div class="row">
                <div class="col-8" style="text-align: left;">{{ datas[i][y] }}</div>
                <div class="gap-2 d-md-flex justify-content-md-end">
                  <button id="{{ i }}{{ y }}_decrypt_text" type="button" class="btn stybutton" data-bs-toggle="modal" data-bs-target="#staticBackdrop{{ i }}{{ y }}">
                    Decrypt
                  </button>
                  <div class="modal fade" id="staticBackdrop{{ i }}{{ y }}" data-bs-backdrop="static" data-bs-keyboard="false" tabindex="-1" aria-labelledby="staticBackdropLabel" aria-hidden="true">
                    <div class="modal-dialog">
                      <div class="modal-content">
                        <div class="modal-header">
                          <h5 class="modal-title">Decryption Code</h5>
                          <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                        </div>
                        <div class="modal-body">
                          <form>
                            <div class="mb-3">
                                <label class="col-form-label">Decryption Code: </label>
                                <div class="row">
                                  <div class="col-sm"><input style="background-color: #EDF5E1" type="number" class="form-control" id="decryption_code1_{{ i }}{{ y }}"></div>
                                  <div class="col-sm"><input style="background-color: #EDF5E1" type="number" class="form-control" id="decryption_code2_{{ i }}{{ y }}"></div>
                                  <div class="col-sm"><input style="background-color: #EDF5E1" type="number" class="form-control" id="decryption_code3_{{ i }}{{ y }}"></div>
                                </div>
                                <p id="{{ i }}{{ y }}_de_code_alert"></p>
                            </div>
                            <div class="mb-3">
                                <label for="text_to_decrypt" class="col-form-label">Text To Decrypt: </label>
                                <textarea class="form-control style" type="text" id="{{ i }}{{ y }}_text_to_decrypt" disabled>{{ datas[i][y] }}</textarea>
                                <p id="{{ i }}{{ y }}_de_text_alert"></p>
                                <div class="form-floating">
                                  <textarea class="form-control style" placeholder="Decrypted Text" id="{{ i }}{{ y }}_decrypted_text" style="height: 100px"></textarea>
                                  <label for="floatingTextarea2">Decrypted Text</label>
                                </div>
                            </div>
                        </form>
                        </div>
                        <div class="modal-footer">
                          <button type="button" class="btn stybutton" data-bs-dismiss="modal">Close</button>
                          <button type="button" id="{{ i }}{{ y }}_decrypt" class="btn stybutton">Decrypt</button>
                        </div>
                      </div>
                    </div>
                  </div>
                  <form action="/delete" method="post">
                  <input type="hidden" id="data" name="data" value="{{ datas[i][y] }}">
                  <button type="button" class="btn stybutton" data-bs-toggle="modal" data-bs-target="#delete_confirm{{ i }}{{ y }}">Delete</button>
                  <div class="modal fade" id="delete_confirm{{ i }}{{ y }}" data-bs-backdrop="static" data-bs-keyboard="false" tabindex="-1" aria-labelledby="staticBackdropLabel" aria-hidden="true">
                    <div class="modal-dialog modal-dialog-centered">
                      <div class="modal-content">
                        <div class="modal-header">
                          <h5 class="modal-title" id="staticBackdropLabel">Confirm Delete</h5>
                          <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
                        </div>
                        <div class="modal-body">
                          Are you sure you want to delete this?
                        </div>
                        <div class="modal-footer">
                          <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
                          <button type="submit" class="btn stybutton">Delete</button>
                        </div>
                      </div>
                    </div>
                  </div>
                </form>
                </div>
            </div>
        </div>
    </div>
        {% endfor %}
    </div>
    {% endfor %}
</div>
```

## app.py
This is a backend python application that handles all html templates.

## "/register"
This function handles register.html. All datas from http request will be checked and store in accounts table of save.db.
```python
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
```

## "/login"
This function handles login.html. It check username and hashed password from http request with username and hash from database. And if matched, logs user in.
```python
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
```

## "/acc_setting/change_password"
This function handles change_password form in acc_setting.html. It takes old password from http request, hashs it and checks with hash stored in save.db. It checks new password with confirmation.If all is OK, old hash will be updated with new hash in save.db.
```python
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
```

## "/acc_setting/delete_acc"
This function handles delete_acc in acc_setting. It takes password from http request, hashs it and checks with hash stored in save.db. If all OK, it will delete all data relating with user_id from save.db.
```python
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
```

## "/index"
This function handles index.html. It saves data from http-request into save.db. And it sends data relating user_id stored in save.db.
```python
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
```

## "/delete"
This function handle delete in index.html.
```python
@app.route("/index")
@app.route("/delete", methods=["GET", "POST"])
@login_required
def delete():
    if request.method == "POST":
        data = request.form.get("data")
        db.execute("DELETE FROM datas WHERE data = ?", data)
        return redirect("/")
    return redirect("/")
```


## helper.py
This is a python application to assist in some function for app.py.
## login_required function:
This function makes sure user is in session for certain function in app.py.
```python
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function
```

## valid_password function:
This function checks password validity.
```python
def valid_password(password):
    l, u, d = 0, 0, 0
    passw = password
    for i in passw:
        if (i.islower()):
            l += 1
        if (i.isupper()):
            u += 1
        if (i.isdigit()):
            d += 1
    if len(passw) >= 8 and l >= 1 and u >= 1 and d >= 1:
        return True
    else:
        return False
```

## save.db
This file is a database to store accounts and datas.
It was created using code below:
```sql
CREATE TABLE accounts (
id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
name TEXT NOT NULL,
username TEXT NOT NULL,
hash TEXT NOT NULL
);
CREATE TABLE sqlite_sequence(name,seq);
CREATE TABLE datas (
id INTEGER PRIMARY KEY NOT NULL,
user_id INTEGER NOT NULL,
foldername TEXT NOT NULL,
data TEXT NOT NULL,
FOREIGN KEY(user_id) REFERENCES accounts(id)
);
```
