import os

from dotenv import load_dotenv
from flask import Flask, render_template, request, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import URL, text
from werkzeug.security import check_password_hash
from functools import wraps

load_dotenv()

app = Flask(__name__)

app.config["SECRET_KEY"] = os.getenv(
    "SECRET_KEY",
    "development-secret-key"
)

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


# 25133 - Sponsor Account Security and Access Protection

def sponsor_required(function):
    @wraps(function)
    def protected_function(*args, **kwargs):

        # User must be logged in
        if session.get("user_id") is None:
            return redirect(url_for("sponsor_login"))

        # User must have the SPONSOR role
        if session.get("role") != "SPONSOR":
            return "Access denied.", 403

        return function(*args, **kwargs)

    return protected_function


def driver_required(function):
    """Allow only authenticated driver accounts to access a route."""

    @wraps(function)
    def protected_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect(url_for("driver_login"))

        if session.get("role") != "DRIVER":
            return "Access denied.", 403

        return function(*args, **kwargs)

    return protected_function


# 25132 & 25134 - Implement Sponsor Login Functionality & Update and Improve Sponsor Login Functionality

@app.route("/sponsor/login", methods=["GET", "POST"])
def sponsor_login():
    message = None

    if request.method == "POST":
        session.clear()

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not email or not password:
            message = "Please enter both an email and password."
            return render_template("sponsor_login.html", message=message)

        try:
            user = db.session.execute(
                text(
                    """
                    SELECT user_id, email, password_hash,
                           first_name, last_name, sponsor_org_id
                    FROM app_user
                    WHERE email = :email
                      AND role = 'SPONSOR'
                      AND status = 'ACTIVE'
                    """
                ),
                {"email": email},
            ).mappings().first()

        except Exception:
            app.logger.exception("Sponsor login database error")
            db.session.rollback()

            message = "Unable to process login right now. Please try again."
            return render_template("sponsor_login.html", message=message)

        if (
            user is not None
            and user["password_hash"] is not None
            and check_password_hash(user["password_hash"], password)
        ):
            session["user_id"] = user["user_id"]
            session["role"] = "SPONSOR"
            session["sponsor_org_id"] = user["sponsor_org_id"]

            return redirect(url_for("sponsor_dashboard"))

        message = "Invalid email or password."

    return render_template("sponsor_login.html", message=message)

@app.get("/sponsor/dashboard")
@sponsor_required
def sponsor_dashboard():
    return render_template("sponsor_dashboard.html")


# 25135 - User Profile Editing and Saving

@app.route("/sponsor/profile", methods=["GET", "POST"])
@sponsor_required
def sponsor_profile():
    message = None

    if request.method == "POST":
        first_name = request.form.get("first_name", "").strip()
        last_name = request.form.get("last_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        phone = request.form.get("phone", "").strip()

        if not first_name or not last_name or not email:
            message = "First name, last name, and email are required."
        else:
            try:
                db.session.execute(
                    text(
                        """
                        UPDATE app_user
                        SET first_name = :first_name,
                            last_name = :last_name,
                            email = :email,
                            phone = :phone
                        WHERE user_id = :user_id
                          AND role = 'SPONSOR'
                        """
                    ),
                    {
                        "first_name": first_name,
                        "last_name": last_name,
                        "email": email,
                        "phone": phone if phone else None,
                        "user_id": session["user_id"],
                    },
                )

                db.session.commit()
                message = "Profile updated successfully."

            except Exception:
                db.session.rollback()
                app.logger.exception("Sponsor profile update failed")
                message = "Unable to update profile. Please try again."

    user = db.session.execute(
        text(
            """
            SELECT user_id, email, first_name, last_name, phone
            FROM app_user
            WHERE user_id = :user_id
              AND role = 'SPONSOR'
            """
        ),
        {"user_id": session["user_id"]},
    ).mappings().first()

    if user is None:
        session.clear()
        return redirect(url_for("sponsor_login"))

    return render_template(
        "sponsor_profile.html",
        user=user,
        message=message
    )


# 25136 - Organization Profile Editing and Saving

@app.route("/sponsor/organization", methods=["GET", "POST"])
@sponsor_required
def sponsor_organization():
    message = None

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        contact_email = request.form.get("contact_email", "").strip().lower()
        phone = request.form.get("phone", "").strip()

        if not name or not contact_email:
            message = "Organization name and contact email are required."
        else:
            try:
                db.session.execute(
                    text(
                        """
                        UPDATE sponsor_org
                        SET name = :name,
                            contact_email = :contact_email,
                            phone = :phone
                        WHERE sponsor_org_id = :sponsor_org_id
                        """
                    ),
                    {
                        "name": name,
                        "contact_email": contact_email,
                        "phone": phone if phone else None,
                        "sponsor_org_id": session["sponsor_org_id"],
                    },
                )

                db.session.commit()
                message = "Organization profile updated successfully."

            except Exception:
                db.session.rollback()
                app.logger.exception("Sponsor organization update failed")
                message = "Unable to update organization profile. Please try again."

    organization = db.session.execute(
        text(
            """
            SELECT sponsor_org_id, name, contact_email,
                   phone, point_dollar_value, status
            FROM sponsor_org
            WHERE sponsor_org_id = :sponsor_org_id
            """
        ),
        {"sponsor_org_id": session["sponsor_org_id"]},
    ).mappings().first()

    if organization is None:
        return "Organization not found.", 404

    return render_template(
        "sponsor_organization.html",
        organization=organization,
        message=message
    )

@app.get("/sponsor/logout")
def sponsor_logout():
    session.clear()

    return redirect(url_for("sponsor_login"))


# 21752 & 22364 - Driver sign in and safe login-failure feedback

@app.route("/driver/login", methods=["GET", "POST"])
def driver_login():
    message = None
    email = ""

    if request.method == "POST":
        session.clear()

        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not email or not password:
            message = "Please enter both an email and password."
            return render_template(
                "driver_login.html",
                message=message,
                email=email,
            )

        try:
            user = db.session.execute(
                text(
                    """
                    SELECT u.user_id, u.password_hash,
                           d.sponsor_org_id
                    FROM app_user AS u
                    JOIN driver_profile AS d
                      ON d.user_id = u.user_id
                    WHERE u.email = :email
                      AND u.role = 'DRIVER'
                      AND u.status = 'ACTIVE'
                    """
                ),
                {"email": email},
            ).mappings().first()
        except Exception:
            app.logger.exception("Driver login database error")
            db.session.rollback()
            message = "Unable to sign in right now. Please try again."
            return render_template(
                "driver_login.html",
                message=message,
                email=email,
            )

        if (
            user is not None
            and user["password_hash"] is not None
            and check_password_hash(user["password_hash"], password)
        ):
            session["user_id"] = user["user_id"]
            session["role"] = "DRIVER"
            session["sponsor_org_id"] = user["sponsor_org_id"]
            return redirect(url_for("driver_dashboard"))

        # Keep the response identical for unknown, inactive, non-driver, and
        # incorrect-password accounts so the page does not reveal membership.
        message = "Invalid email or password."

    return render_template(
        "driver_login.html",
        message=message,
        email=email,
    )


@app.get("/driver/dashboard")
@driver_required
def driver_dashboard():
    return render_template("driver_dashboard.html")


# 22367 & 22368 - View and update the authenticated driver's profile

@app.route("/driver/profile", methods=["GET", "POST"])
@driver_required
def driver_profile():
    message = None

    if request.method == "POST":
        first_name = request.form.get("first_name", "").strip()
        last_name = request.form.get("last_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        phone = request.form.get("phone", "").strip()
        shipping_address = request.form.get("shipping_address", "").strip()

        if not first_name or not last_name or not email:
            message = "First name, last name, and email are required."
        elif "@" not in email:
            message = "Please enter a valid email address."
        elif (
            len(first_name) > 80
            or len(last_name) > 80
            or len(email) > 255
            or len(phone) > 40
            or len(shipping_address) > 400
        ):
            message = "One or more profile fields are too long."
        else:
            try:
                db.session.execute(
                    text(
                        """
                        UPDATE app_user
                        SET first_name = :first_name,
                            last_name = :last_name,
                            email = :email,
                            phone = :phone
                        WHERE user_id = :user_id
                          AND role = 'DRIVER'
                        """
                    ),
                    {
                        "first_name": first_name,
                        "last_name": last_name,
                        "email": email,
                        "phone": phone if phone else None,
                        "user_id": session["user_id"],
                    },
                )
                db.session.execute(
                    text(
                        """
                        UPDATE driver_profile
                        SET shipping_address = :shipping_address
                        WHERE user_id = :user_id
                        """
                    ),
                    {
                        "shipping_address": (
                            shipping_address if shipping_address else None
                        ),
                        "user_id": session["user_id"],
                    },
                )
                db.session.commit()
                message = "Profile updated successfully."
            except Exception:
                db.session.rollback()
                app.logger.exception("Driver profile update failed")
                message = "Unable to update profile. Please try again."

    try:
        user = db.session.execute(
            text(
                """
                SELECT u.user_id, u.email, u.first_name, u.last_name,
                       u.phone, d.shipping_address, d.point_balance,
                       s.name AS sponsor_name
                FROM app_user AS u
                JOIN driver_profile AS d
                  ON d.user_id = u.user_id
                JOIN sponsor_org AS s
                  ON s.sponsor_org_id = d.sponsor_org_id
                WHERE u.user_id = :user_id
                  AND u.role = 'DRIVER'
                """
            ),
            {"user_id": session["user_id"]},
        ).mappings().first()
    except Exception:
        app.logger.exception("Driver profile database error")
        db.session.rollback()
        return "Unable to load profile.", 500

    if user is None:
        session.clear()
        return redirect(url_for("driver_login"))

    return render_template(
        "driver_profile.html",
        user=user,
        message=message,
    )


# 22358 - Sign out of a driver account

@app.route("/driver/logout", methods=["GET", "POST"])
def driver_logout():
    session.clear()
    return redirect(url_for("driver_login"))

if __name__ == "__main__":
    app.run(debug=True)
