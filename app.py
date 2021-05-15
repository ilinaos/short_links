from flask import Flask, request, jsonify
import sqlite3, uuid, hashlib
from werkzeug.security import generate_password_hash, check_password_hash
app = Flask(__name__)

@app.route('/', methods=['POST'])
def hello_world():
    return request.json.get('login', None)

@app.route('/registration', methods=['POST'])
def register():
    login=request.get_json('логин')
    password = request.get_json('пароль')
    salt_generation = uuid.uuid4().hex
    hash_passworda = generate_password_hash(password + salt_generation)
    username='test'
    try:
        connect = sqlite3.connect('data.db')
        cursor = connect.cursor()
        cursor.execute(''' INSERT
    INTO
    users(login, password, salt)
    VALUES(?, ?, ?)''', username,hash_passworda,salt_generation)
        connect.commit()
    except sqlite3.Error:
        print('не удалось зарегистрироваться')
    finally:
        connect.close()

@app.route('/auth', methods=['GET'])
def auth():
    username = 'test'
    try:
        connect = sqlite3.connect('data.db')
        cursor = connect.cursor()
        hash='test' #то, что ввел пользователь
        password = cursor.execute('''SELECT password FROM users WHERE login=?''', username).fetchall()[0]
        print(password)
        salt_in_base =cursor.execute('''SELECT salt FROM users WHERE login=?''', username).fetchall()[0]
        check_password_hash(hash, password + salt_in_base)
    except sqlite3.Error:
        print('не удалось авторизоваться')
    finally:
        connect.close()

@app.route('/lk/<username>/links', methods=['GET','POST', 'PUT', 'DELETE']) #личный кабинет
def new_link(): #генерация ссылок
    if request.method =='POST':
    #генератор ссылок
        adress='vk.com'
        a=hashlib.md5(adress.encode()).hexdigest()[:10]
        access='public'
        username='test'
        try:
            connect = sqlite3.connect('data.db')
            cursor = connect.cursor()
            cursor.execute('''INSERT INTO links (long_link, short_link, access) VALUES (?, ?, ?)''',adress,a,access)
            connect.commit()
            cursor.execute('''INSERT INTO user_link (link_id, user_id) VALUES (
            (SELECT id from links WHERE long_link=?), 
            (SELECT id FROM users WHERE login=?))''', adress, username)
        except sqlite3.Error:
            print('ошибка подключения к базе при создании ссылки')
        finally:
            connect.close()


def read_link(): #просмотр ссылок
    if request.method=='GET':
        username = 'test'
        try:
            connect = sqlite3.connect('data.db')
            cursor = connect.cursor()
            info=cursor.execute('''SELECT long_link FROM links
JOIN user_link ON links.id=link_id
JOIN users ON users.id=user_id
WHERE login=?''', username).fetchall()
            print(info[0])
        except sqlite3.Error:
            print('ошибка подключения к базе при чтении')
        finally:
            connect.close()

def edit_link(): #редактирование
    '''UPDATE links
SET access='private'
WHERE links.id=
(SELECT links.id FROM links
JOIN user_link ON links.id=link_id
JOIN users ON users.id=user_id
WHERE users.login='ann' AND links.long_link='google.com')'''

    '''UPDATE links
SET short_link='wowwowowo'
WHERE links.id=
(SELECT links.id FROM links
JOIN user_link ON links.id=link_id
JOIN users ON users.id=user_id
WHERE users.login='ann' AND links.long_link='google.com')'''
    pass

def delete_link(): #удаление
    '''удалить ссылку для пользователя
DELETE FROM user_link
WHERE user_id=2
AND link_id=1

DELETE FROM links
WHERE id=1'''
    pass




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
        accesses=['public', 'private', 'general']
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
