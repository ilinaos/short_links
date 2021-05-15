from flask import Flask
import sqlite3
app = Flask(__name__)

@app.route('/')
def hello_world():
    return 'Hello, World!'


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