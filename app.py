import sqlite3
from flask import Flask, render_template, request, redirect

app = Flask(__name__)

def init_db():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS calculs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            x1 REAL,
            x2 REAL,
            P_bulle REAL,
            y1 REAL,
            y2 REAL
        )
    ''')

    conn.commit()
    conn.close()

init_db()


@app.route('/', methods=['GET', 'POST'])
def home():
    result = None
    error = None
    details = None

    p1 = 101.3
    p2 = 40

    if request.method == 'POST':
        try:
            x1 = float(request.form['x1'])
            x2 = float(request.form['x2'])

            if x1 < 0 or x2 < 0:
                error = "Les fractions doivent être positives."

            elif abs(x1 + x2 - 1) > 0.01:
                error = "La somme x1 + x2 doit être égale à 1."

            else:
                P_bulle = (p1 * x1) + (p2 * x2)
                y1 = (x1 * p1) / P_bulle
                y2 = (x2 * p2) / P_bulle
                somme = y1 + y2

                result = (
                    round(P_bulle, 3),
                    round(y1, 3),
                    round(y2, 3),
                    round(somme, 3)
                )

                details = {
                    "application": [
                        f"P_bulle = {x1}×101.3 + {x2}×40 = {round(P_bulle,3)}",
                        f"y1 = ({x1}×101.3) / {round(P_bulle,3)} = {round(y1,3)}",
                        f"y2 = ({x2}×40) / {round(P_bulle,3)} = {round(y2,3)}",
                        f"{round(y1,3)} + {round(y2,3)} = {round(somme,3)}"
                    ]
                }

                conn = sqlite3.connect('database.db')
                cursor = conn.cursor()

                cursor.execute('''
                    INSERT INTO calculs (x1, x2, P_bulle, y1, y2)
                    VALUES (?, ?, ?, ?, ?)
                ''', (x1, x2, P_bulle, y1, y2))

                conn.commit()
                conn.close()

        except:
            error = "Valeurs invalides"

    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()

    cursor.execute('SELECT * FROM calculs ORDER BY id DESC LIMIT 10')
    historique = cursor.fetchall()

    conn.close()

    return render_template(
        'index.html',
        result=result,
        error=error,
        historique=historique,
        details=details
    )


@app.route('/delete_history')
def delete_history():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('DELETE FROM calculs')
    conn.commit()
    conn.close()
    return redirect('/')


if __name__ == '__main__':
    app.run(debug=True)
