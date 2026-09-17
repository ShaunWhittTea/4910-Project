import os

from dotenv import load_dotenv
from flask import Flask, render_template, request
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import URL, text

load_dotenv()

app = Flask(__name__)

app.config["SQLALCHEMY_DATABASE_URI"] = URL.create(
    drivername="mysql+pymysql",
    username=os.environ["DB_USER"],
    password=os.environ["DB_PASSWORD"],
    host=os.environ["DB_HOST"],
    port=int(os.getenv("DB_PORT", "3306")),
    database=os.environ["DB_NAME"],
)

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)


@app.route("/", methods=["GET", "POST"])
def home():
    message = None

    if request.method == "POST":
        name = request.form.get("name", "").strip()

        if name:
            message = f"Welcome, {name}!"
        else:
            message = "Please enter your name."

    return render_template("index.html", message=message)


@app.get("/db-check")
def database_check():
    try:
        database_name = db.session.execute(
            text("SELECT DATABASE()")
        ).scalar_one()

        table_count = db.session.execute(
            text(
                """
                SELECT COUNT(*)
                FROM information_schema.tables
                WHERE table_schema = :schema_name
                """
            ),
            {"schema_name": database_name},
        ).scalar_one()

        return {
            "connected": True,
            "database": database_name,
            "table_count": table_count,
        }

    except Exception:
        app.logger.exception("Database connection failed")

        return {
            "connected": False,
            "message": "Database connection failed",
        }, 500


if __name__ == "__main__":
    app.run(debug=True)