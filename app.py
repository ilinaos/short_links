from flask import Flask, request, redirect, jsonify
from flask_jwt_extended import create_access_token, JWTManager, get_jwt_identity, jwt_required
import sqlite3, uuid, hashlib
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = "super-secret"  # Change this!
jwt = JWTManager(app)

accesses=['public', 'general', 'private']


@app.route('/', methods=['POST'])
def hello_world():
    return request.json.get('login', None)

@app.route('/registration', methods=['POST'])
def register():
    username=str(request.json.get("login", None))
    password = str(request.json.get("password", None))
    salt_generation = str(uuid.uuid4().hex)
    hash_password = str(generate_password_hash(password + salt_generation))
    try:
        connect = sqlite3.connect('data.db')
        cursor = connect.cursor()
        user=cursor.execute('''SELECT login FROM users WHERE login=?''',(username,)).fetchall()
        if len(user)!=0:
            return jsonify("Такой пользователь уже есть")
        else:
            cursor.execute('''INSERT INTO users (login, password, salt)
                    VALUES (?, ?, ?)''', (username, hash_password, salt_generation,))
            connect.commit()
            return jsonify("Пользователь зарегистирован")
    except sqlite3.Error:
        print('не удалось зарегистрироваться')
    finally:
        connect.close()

@app.route('/auth', methods=['GET'])
def auth():
    username = str(request.json.get("login", None))
    password = str(request.json.get("password", None))
    try:
        connect = sqlite3.connect('data.db')
        cursor = connect.cursor()
        user = cursor.execute('''SELECT login FROM users WHERE login=?''', (username,)).fetchall()
        hash = cursor.execute('''SELECT password FROM users WHERE login=?''', (username,)).fetchall()
        if len(hash)!=0: hash=hash[0][0]
        salt_in_base = cursor.execute('''SELECT salt FROM users WHERE login=?''', (username,)).fetchall()
        if len(salt_in_base)!=0: salt_in_base=salt_in_base[0][0]
        #если пользователя с таким именем в базе нет
        #или пароль юзера из базы не совпадает с введенным
        if len(user)==0 or check_password_hash(hash, password + salt_in_base)==False:
            return jsonify("Bad username or password")
        access_token = create_access_token(identity=username)
        return jsonify(access_token=access_token)
    except sqlite3.Error:
        print('не удалось авторизоваться')
    finally:
        connect.close()

@app.route("/protected", methods=["GET"])
@jwt_required()
def protected():
    # Access the identity of the current user with get_jwt_identity
    current_user = get_jwt_identity()
    print(current_user)
    return jsonify(logged_in_as=current_user), 200

@app.route('/lk', methods=['GET','POST', 'PUT', 'DELETE']) #личный кабинет
@jwt_required()
def lk():
    current_user = str(get_jwt_identity())
    print (current_user)
    if request.method =='POST':
    #генератор ссылок
        adress=request.json.get("full_link")
        user_adress=str(request.json.get("user_link"))
        access=str(request.json.get("access"))
        if access == "": access = "public"
        if access not in accesses:
            return jsonify("невозможно установить такой тип доступа")
        if user_adress=="": user_adress=hashlib.md5(adress.encode()).hexdigest()[:10]
        if adress=="": return jsonify("не указана ссылка")
        try:
            connect = sqlite3.connect('data.db')
            cursor = connect.cursor()
            link_in_base=cursor.execute('''SELECT id from links WHERE long_link=?''',(adress,)).fetchall()
            if len(link_in_base)!=0:
                link_for_user=cursor.execute('''SELECT long_link FROM links
        JOIN user_link ON links.id=link_id
        JOIN users ON users.id=user_id
        WHERE login=? AND long_link=?''', (current_user,adress,)).fetchall()
                user_links=[]
                for i in link_for_user:
                    user_links.append(i[0])
                if adress in user_links:
                    return jsonify("для вас уже есть такая ссылка")
                access_in_base = cursor.execute('''SELECT access from links WHERE long_link=?''', (adress,)).fetchall()[0][0]
                if access_in_base==access:
                    cursor.execute('''INSERT INTO user_link (link_id, user_id) VALUES (
                                (SELECT id from links WHERE long_link=?), 
                                (SELECT id FROM users WHERE login=?))''', (adress, current_user,))
                    connect.commit()
                    return jsonify("ссылка добавлена")
            cursor.execute('''INSERT INTO links (long_link, short_link, access) VALUES (?, ?, ?)''',
                           (adress, user_adress, access,))
            connect.commit()
            cursor.execute('''INSERT INTO user_link (link_id, user_id) VALUES (
                        (SELECT id from links WHERE long_link=?), 
                        (SELECT id FROM users WHERE login=?))''', (adress, current_user,))
            connect.commit()
            return jsonify("ссылка добавлена")

        except sqlite3.Error:
            print('ошибка подключения к базе при создании ссылки')
        finally:
            connect.close()
    elif request.method=='PUT':#редактирование
        edit_link = str(request.json.get("full_link"))
        new_short = str(request.json.get("user_link"))
        generate=str(request.json.get("generate"))
        new_access = str(request.json.get("access"))
        flag=False
        try:
            connect = sqlite3.connect('data.db')
            cursor = connect.cursor()
            id_link = cursor.execute('''SELECT links.id from links
                    JOIN user_link ON links.id=link_id
                    JOIN users ON users.id=user_id WHERE long_link=? AND login=?''', (edit_link, current_user,)).fetchall()
            if len(id_link)==0: return jsonify("Такой ссылки в базе нет")
            # id_link=int(id_link[0][0])
            # id_user = cursor.execute('''SELECT id FROM users WHERE login=?''', (current_user,)).fetchall()[0][0]
            if generate=="True": new_short=hashlib.md5(edit_link.encode()).hexdigest()[:10]
            if new_short=="" and generate!="True": return jsonify('надо ввести короткий адресс')
            cursor.execute('''UPDATE links
                    SET short_link=?
                    WHERE links.id=
                    (SELECT links.id FROM links
                    JOIN user_link ON links.id=link_id
                    JOIN users ON users.id=user_id
                    WHERE users.login=? AND links.long_link=?)''', (new_short, current_user, edit_link,))
            connect.commit()
            flag=True
            if new_access!="" and new_access in accesses:
                cursor.execute('''UPDATE links
    SET access=?
    WHERE links.id=
    (SELECT links.id FROM links
    JOIN user_link ON links.id=link_id
    JOIN users ON users.id=user_id
    WHERE users.login=? AND links.long_link=?)''', (new_access, current_user, edit_link,))
                connect.commit()
                flag=True
            if flag==True:
                return jsonify("Ссылка отредактирована")
            return jsonify('почему-то не отредактировали')

        except sqlite3.Error:
            print('ошибка подключения к базе при редактировании')
        finally:
            connect.close()
    elif request.method=='DELETE':#удаление
        del_link = str(request.json.get("full_link"))
        try:
            connect = sqlite3.connect('data.db')
            cursor = connect.cursor()
            info=cursor.execute('''SELECT long_link FROM links
        JOIN user_link ON links.id=link_id
        JOIN users ON users.id=user_id
        WHERE login=?''', (current_user,)).fetchall()
            links=[]
            for i in info:
                links.append(i[0])
            if del_link in links:
                id_link=cursor.execute('''SELECT links.id from links
        JOIN user_link ON links.id=link_id
        JOIN users ON users.id=user_id WHERE long_link=? AND login=?''', (del_link, current_user,)).fetchall()[0][0]
                id_user=cursor.execute('''SELECT id FROM users WHERE login=?''', (current_user,)).fetchall()[0][0]
                cursor.execute(''' DELETE FROM user_link
       WHERE user_id=?
       AND link_id=?''', (id_user, id_link,))
                connect.commit()
                cursor.execute('''DELETE FROM links WHERE id=?''', (id_link,))
                connect.commit()
                return jsonify("ссылка удалена")
            else:
                return jsonify("невозможно удалить, нет такой ссылки")
        except sqlite3.Error:
            print('ошибка подключения к базе при удалении')
        finally:
            connect.close()
    elif request.method=='GET': #просмотр ссылок
        try:
            connect = sqlite3.connect('data.db')
            cursor = connect.cursor()
            info = cursor.execute('''SELECT long_link, short_link FROM links
        JOIN user_link ON links.id=link_id
        JOIN users ON users.id=user_id
        WHERE login=?''', (current_user,)).fetchall()
            result=dict()
            for i in info:
                result[f'{i[0]}']=f'{i[1]}'
            return jsonify(result)
        except sqlite3.Error:
            print('ошибка подключения к базе при чтении')
        finally:
            connect.close()
    else:
        print ('error')
        return jsonify('я такого метода не знаю')

link='https://www.google.ru/'
@app.route('/redirect', methods=['GET'])
def red():
    return redirect(link)


if __name__ == '__main__':
    try:
        connect = sqlite3.connect('data.db')
        cursor = connect.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS "users" (
	"id"	INTEGER NOT NULL,
	"login"	TEXT NOT NULL,
	"password"	TEXT NOT NULL,
	"salt"	TEXT,
	PRIMARY KEY("id" AUTOINCREMENT)
);''')
        connect.commit()

        cursor.execute('''CREATE TABLE IF NOT EXISTS "links" (
	"id"	INTEGER NOT NULL,
	"long_link"	TEXT NOT NULL,
	"short_link"	TEXT NOT NULL,
	"access"	TEXT NOT NULL,
	PRIMARY KEY("id" AUTOINCREMENT)
);''')
        connect.commit()

        cursor.execute('''CREATE TABLE IF NOT EXISTS "user_link" (
	"user_id"	INTEGER NOT NULL,
	"link_id"	INTEGER NOT NULL
);''')
        connect.commit()

        cursor.execute('''CREATE TABLE IF NOT EXISTS "accesses" (
	"id"	TEXT NOT NULL,
	PRIMARY KEY("id")
);''')
        connect.commit()
        data=cursor.execute('''SELECT * FROM accesses''').fetchall()
        words=[]
        for j in data:
            words.append(j[0])
        for i in accesses:
            if i not in words:
                cursor.execute('''INSERT INTO accesses (id) VALUES (?)''',(i,))
                connect.commit()


        print('база благополучно открыта')
    except sqlite3.Error:
        print('ошибка подключения к базе на старте')
    finally:
        connect.close()
        app.run()
