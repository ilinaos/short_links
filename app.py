from flask import Flask, request, redirect, jsonify
from flask_jwt_extended import create_access_token, JWTManager, get_jwt_identity, jwt_required
import sqlite3, uuid, hashlib, random
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = "super-secret"  # Change this!
jwt = JWTManager(app)

accesses=['public', 'general', 'private']


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
        return jsonify('не удалось зарегистрироваться')
    finally:
        connect.close()

@app.route('/auth', methods=['POST'])
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
        return jsonify('не удалось авторизоваться')
    finally:
        connect.close()

@app.route('/lk', methods=['GET','POST', 'PUT', 'DELETE']) #личный кабинет
@jwt_required()
def lk():
    current_user = str(get_jwt_identity())
    if request.method =='POST':
    #генератор ссылок
        adress=str(request.json.get("full_link"))
        user_adress=str(request.json.get("user_link"))
        access=str(request.json.get("access"))
        if access == "" or access not in accesses: access = "private" #по умолчанию или в случае ошибки
        #если не указан человекочитаемый псевдоним, то генерируем
        if user_adress=="": user_adress=hashlib.md5(adress.encode()).hexdigest()[:random.randint(8,12)]
        if adress=="": return jsonify("не указана ссылка")
        try:
            connect = sqlite3.connect('data.db')
            cursor = connect.cursor()
            #получить список ссылок этого пользователя, совпадения по логину и длинной ссылке
            link_for_user=cursor.execute('''SELECT long_link FROM links
        JOIN user_link ON links.id=link_id
        JOIN users ON users.id=user_id
        WHERE login=? AND long_link=?''', (current_user,adress,)).fetchall()
            user_links=[]
            for i in link_for_user:
                user_links.append(i[0])
            #если список не пустой
            if adress in user_links:
                return jsonify("для вас уже есть такая ссылка")
            #а если пустой, то выбираем из базы все короткие ссылки и смотрим, чтоб не совпадали псевдонимы
            shorts = cursor.execute('SELECT short_link from links').fetchall()
            short_links_in_base = []
            for i in shorts:
                short_links_in_base.append(i[0])
            if user_adress in short_links_in_base:
                return jsonify('Такая короткая ссылка в базе уже есть, задайте новый псевдоним')
            #и только после этого добавляем в базу
            cursor.execute('''INSERT INTO links (long_link, short_link, access, count_of_redirection) VALUES (?, ?, ?, 0)''',
                           (adress, user_adress, access,))
            connect.commit()
            cursor.execute('''INSERT INTO user_link (link_id, user_id) VALUES (
                        (SELECT id from links WHERE long_link=?), 
                        (SELECT id FROM users WHERE login=?))''', (adress, current_user,))
            connect.commit()
            return jsonify(r"ссылка добавлена: http://127.0.0.1:5000/"+f"{user_adress}")

        except sqlite3.Error:
            return jsonify('ошибка подключения к базе при создании ссылки')
        finally:
            connect.close()
    elif request.method=='PUT':#редактирование
        edit_link = str(request.json.get("full_link"))
        new_short = str(request.json.get("user_link"))
        #будем ли мы генерировать короткую ссылку случайно
        generate=str(request.json.get("generate"))
        new_access = str(request.json.get("access"))
        try:
            connect = sqlite3.connect('data.db')
            cursor = connect.cursor()
            #найти, есть ли у пользователя такая ссылка
            id_link = cursor.execute('''SELECT links.id from links
                    JOIN user_link ON links.id=link_id
                    JOIN users ON users.id=user_id WHERE long_link=? AND login=?''', (edit_link, current_user,)).fetchall()
            if len(id_link)==0:
                return jsonify("Такой ссылки в базе нет")
            else:
                id_link=int(id_link[0][0])
            #если хотим изменить короткую ссылку на случайную
            if generate=="True":
                new_short=hashlib.md5(edit_link.encode()).hexdigest()[:random.randint(8,12)]
            #если в итоге короткая ссылка (новая) не пустая, т.е. пользователь ввел псевдоним или ссылка сгенерировалась случайно
            if new_short!="":
            #сначала проверить, чтобы она не совпадала ни с чем в базе, чтобы не возникало конфликтов
                shorts=cursor.execute('SELECT short_link from links').fetchall()
                short_links_in_base=[]
                for i in shorts:
                    short_links_in_base.append(i[0])
                if new_short in short_links_in_base:
                    return jsonify('Такая ссылка в базе уже есть, задайте новый псевдоним')
            #и если таких коротких ссылок в базе нет
                cursor.execute('''UPDATE links
                    SET short_link=?
                    WHERE links.id=?''', (new_short, id_link,))
                connect.commit()
                flag=True
            #если пользователь указал подходящий тип доступа
            if new_access!="" and new_access in accesses:
                cursor.execute('''UPDATE links
                    SET access=?
                    WHERE links.id=?''', (new_access, id_link,))
                connect.commit()
                flag=True
            if flag==True:
                return jsonify("Ссылка отредактирована")
            return jsonify("Не отредактировали ссылку, скорей всего вы не выбрали что будем менять")

        except sqlite3.Error:
            return jsonify('ошибка подключения к базе при редактировании')
        finally:
            connect.close()
    elif request.method=='DELETE':#удаление
        del_link = str(request.json.get("full_link"))
        try:
            connect = sqlite3.connect('data.db')
            cursor = connect.cursor()
            #получить все ссылки пользователя
            info=cursor.execute('''SELECT long_link FROM links
        JOIN user_link ON links.id=link_id
        JOIN users ON users.id=user_id
        WHERE login=?''', (current_user,)).fetchall()
            #сформировать из них список
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
            return jsonify('ошибка подключения к базе при удалении')
        finally:
            connect.close()
    elif request.method=='GET': #просмотр ссылок
        try:
            connect = sqlite3.connect('data.db')
            cursor = connect.cursor()
            info = cursor.execute('''SELECT long_link, short_link, access, count_of_redirection FROM links
        JOIN user_link ON links.id=link_id
        JOIN users ON users.id=user_id
        WHERE login=?''', (current_user,)).fetchall()
            if len(info)!=0:
                result=dict()
                for i in info:
                    result[f'{i[0]}']=f'{i[1]}, {i[2]}, переходов: {i[3]}'
                return jsonify(result)
            else:
                return jsonify('У вас пока нет ссылок')
        except sqlite3.Error:
            return jsonify('ошибка подключения к базе при чтении')
        finally:
            connect.close()
    else:
        return jsonify('я такого метода не знаю')

@app.route('/<short>', methods=['GET'])
@jwt_required(optional=True)
def red(short):
    try:
        connect = sqlite3.connect('data.db')
        cursor = connect.cursor()
        #получаем длинную ссылку по введенной короткой
        inf=cursor.execute('''SELECT long_link FROM links WHERE short_link=?''',(short,)).fetchall()
        #если такая ссылка была найдена
        if len(inf)!=0:
            link = inf[0][0]
        #нужно проверить доступ
        # и логин пользователя, чья это ссылка
            access=cursor.execute('''SELECT access FROM links WHERE short_link=?''',(short,)).fetchall()[0][0]
            user=cursor.execute('''SELECT login FROM users
JOIN user_link ON users.id=user_id
JOIN links ON link_id=links.id
WHERE short_link=?''',(short,)).fetchall()[0][0]
            current_user = str(get_jwt_identity())
            print(current_user)
            if access=='public' or access=='general' and current_user is not None or access=='private' and user==current_user:
                return redirect(link)
            elif current_user is None:
                return jsonify('Нужно авторизоваться')
            elif current_user!=user:
                return jsonify('Вам эта ссылка недоступна')
        else:
            return jsonify('Ссылка не существует или недоступна из-за уровня защиты')

    except sqlite3.Error:
        print('ошибка подключения к базе при переходе')
    finally:
        connect.close()

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
	"count_of_redirection"	INTEGER NOT NULL,
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
