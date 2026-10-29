import hashlib
import hmac
import os
import click

from dotenv import load_dotenv
from flask import Flask, flash, render_template, request, session, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import URL, text
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps
from product_api import (
    EbayApiError,
    EbayProductApiClient,
    FixtureProductApiClient,
)

load_dotenv()

app = Flask(__name__)

app.config["PRODUCT_API_PROVIDER"] = os.getenv(
    "PRODUCT_API_PROVIDER", "fixture"
).strip().lower()

app.config["EBAY_CLIENT_ID"] = os.getenv("EBAY_CLIENT_ID", "").strip()
app.config["EBAY_CLIENT_SECRET"] = os.getenv("EBAY_CLIENT_SECRET", "").strip()
app.config["EBAY_SANDBOX"] = os.getenv(
    "EBAY_SANDBOX", "true"
).strip().lower() == "true"

# 23319 - Protect stored passwords / sessions
app.config["SECRET_KEY"] = os.environ["SECRET_KEY"]
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["PASSWORD_RESET_MAX_AGE"] = int(
    os.getenv("PASSWORD_RESET_MAX_AGE", "1800")
)
app.config["PASSWORD_RESET_SHOW_LINK"] = os.getenv(
    "PASSWORD_RESET_SHOW_LINK", "false"
).strip().lower() == "true"

app.config["SQLALCHEMY_DATABASE_URI"] = URL.create(
    drivername="mysql+pymysql",
    username=os.environ["DB_USER"],
    password=os.environ["DB_PASSWORD"],
    host=os.environ["DB_HOST"],
    port=int(os.getenv("DB_PORT", "3306")),
    database=os.environ["DB_NAME"],
)

# 23362 - Connect AWS-hosted database (keep connections alive)
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {"pool_pre_ping": True, "pool_recycle": 280}

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)


ACCOUNT_UNAVAILABLE_MESSAGE = (
    "Your driver account is not currently available. "
    "Contact your sponsor administrator for help."
)
PASSWORD_MIN_LENGTH = 12
PASSWORD_RESET_SALT = "driver-password-reset-v1"
PASSWORD_RESET_REQUEST_MESSAGE = (
    "If an active driver account matches that email, a password-reset "
    "link has been prepared."
)
INVALID_RESET_LINK_MESSAGE = (
    "This password-reset link is invalid, expired, or has already been "
    "used. Request a new link to continue."
)


def get_password_validation_errors(password):
    """Return each unmet password-complexity requirement."""

    errors = []

    if len(password) < PASSWORD_MIN_LENGTH:
        errors.append(f"at least {PASSWORD_MIN_LENGTH} characters")
    if not any(character.isupper() for character in password):
        errors.append("an uppercase letter")
    if not any(character.islower() for character in password):
        errors.append("a lowercase letter")
    if not any(character.isdigit() for character in password):
        errors.append("a number")
    if not any(
        not character.isalnum() and not character.isspace()
        for character in password
    ):
        errors.append("a special character")

    return errors


def format_password_validation_errors(errors):
    """Return clear feedback while keeping the policy in one place."""

    return "Password must include " + ", ".join(errors) + "."


def get_password_requirements():
    """Return the password rules for driver-facing forms."""

    return [
        f"At least {PASSWORD_MIN_LENGTH} characters",
        "At least one uppercase letter",
        "At least one lowercase letter",
        "At least one number",
        "At least one special character",
    ]


def get_password_reset_serializer():
    return URLSafeTimedSerializer(
        app.config["SECRET_KEY"],
        salt=PASSWORD_RESET_SALT,
    )


def get_password_hash_fingerprint(password_hash):
    """Bind a reset token to the current password without exposing it."""

    return hashlib.sha256(password_hash.encode("utf-8")).hexdigest()


def create_password_reset_token(user_id, password_hash):
    return get_password_reset_serializer().dumps(
        {
            "user_id": user_id,
            "password_fingerprint": get_password_hash_fingerprint(
                password_hash
            ),
        }
    )


def get_password_reset_payload(token):
    """Return a verified reset payload, or None for invalid/expired data."""

    try:
        payload = get_password_reset_serializer().loads(
            token,
            max_age=app.config["PASSWORD_RESET_MAX_AGE"],
        )
    except (BadSignature, SignatureExpired):
        return None

    if not isinstance(payload, dict):
        return None
    if not isinstance(payload.get("user_id"), int):
        return None
    if not isinstance(payload.get("password_fingerprint"), str):
        return None

    return payload


def deliver_password_reset_link(user, reset_url):
    """Deliver through an injected sender; local testing may show the URL."""

    sender = app.extensions.get("password_reset_sender")
    if sender is not None:
        sender(
            email=user["email"],
            first_name=user["first_name"],
            reset_url=reset_url,
        )
        return

    app.logger.warning(
        "Password reset requested for driver user_id=%s, but no "
        "password_reset_sender is configured.",
        user["user_id"],
    )


@app.get("/")
def home():
    try:
        info = db.session.execute(
            text(
                """
                SELECT
                    team_number,
                    version_number,
                    release_date,
                    product_name,
                    product_description
                FROM about_info
                ORDER BY about_id DESC
                LIMIT 1
                """
            )
        ).mappings().first()

    except Exception:
        app.logger.exception("About information database error")
        db.session.rollback()
        info = None

    return render_template("index.html", info=info)

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
            return redirect(url_for("login"))

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

        try:
            active_driver = db.session.execute(
                text(
                    """
                    SELECT 1
                    FROM app_user AS u
                    JOIN driver_profile AS d
                      ON d.user_id = u.user_id
                    JOIN sponsor_org AS s
                      ON s.sponsor_org_id = d.sponsor_org_id
                    WHERE u.user_id = :user_id
                      AND u.role = 'DRIVER'
                      AND u.status = 'ACTIVE'
                      AND s.status = 'ACTIVE'
                    """
                ),
                {"user_id": session["user_id"]},
            ).first()
        except Exception:
            db.session.rollback()
            app.logger.exception("Driver account verification failed")
            return "Unable to verify driver account right now.", 500

        if active_driver is None:
            session.clear()
            return ACCOUNT_UNAVAILABLE_MESSAGE, 403

        return function(*args, **kwargs)

    return protected_function

# 22356 & 22355 - Log in with credentials and automatically determine user type
ROLE_HOME_PAGES = {
    "DRIVER": "driver_dashboard",
    "SPONSOR": "sponsor_dashboard",
    # The admin dashboard has not been implemented yet. Keep authenticated
    # admins on the existing home page until that route is available.
    "ADMIN": "admin_home",
}

@app.route("/login", methods=["GET", "POST"])
def login():
     # If an admin is already logged in, send them back to the admin page
    if session.get("user_id") and session.get("role") == "ADMIN":
        return redirect(url_for("admin_home"))
    message = None
    if request.args.get("password_reset") == "success":
        message = "Your password was reset successfully. You can now sign in."
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
                    SELECT u.user_id, u.role, u.password_hash, u.status,
                           CASE
                               WHEN u.role = 'DRIVER'
                                   THEN d.sponsor_org_id
                               ELSE u.sponsor_org_id
                           END AS sponsor_org_id
                    FROM app_user AS u
                    LEFT JOIN driver_profile AS d
                      ON d.user_id = u.user_id
                    WHERE u.email = :email
                    """
                ),
                {"email": email},
            ).mappings().first()
        except Exception:
            app.logger.exception("Login database error")
            db.session.rollback()
            message = "Unable to sign in right now. Please try again."
            return render_template(
                "driver_login.html",
                message=message,
                email=email,
            )

        home_page = ROLE_HOME_PAGES.get(user["role"]) if user else None
        credentials_are_valid = (
            user is not None
            and home_page is not None
            and user["password_hash"] is not None
            and check_password_hash(user["password_hash"], password)
        )

        if credentials_are_valid and user["status"] != "ACTIVE":

            if user["role"] == "DRIVER":
                # Check whether this driver has submitted an application.
                application = db.session.execute(
                    text(
                        """
                        SELECT status
                        FROM driver_application
                        WHERE driver_user_id = :user_id
                        ORDER BY created_at DESC
                        LIMIT 1
                        """
                    ),
                    {
                        "user_id": user["user_id"]
                    },
                ).mappings().first()

                if application is not None and application["status"] in ("PENDING", "REJECTED"):
                    session["user_id"] = user["user_id"]
                    session["role"] = user["role"]

                    if user["sponsor_org_id"] is not None:
                        session["sponsor_org_id"] = user["sponsor_org_id"]

                    return redirect(url_for("application_status"))

                message = ACCOUNT_UNAVAILABLE_MESSAGE

            else:
                message = "Invalid email or password."

        elif credentials_are_valid:
            session["user_id"] = user["user_id"]
            session["role"] = user["role"]

            if user["sponsor_org_id"] is not None:
                session["sponsor_org_id"] = user["sponsor_org_id"]

            return redirect(url_for(home_page))

        # Use one response for unknown, inactive, and incorrect-password
        # accounts so the form does not reveal whether an email is registered.
        if not credentials_are_valid:
            message = "Invalid email or password."

    return render_template(
        "driver_login.html",
        message=message,
        email=email,
    )


# 22359, 22360 & 22361 - Driver password-reset workflow

@app.route("/driver/password/forgot", methods=["GET", "POST"])
def driver_forgot_password():
    message = None
    email = ""
    reset_link = None

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        if not email:
            message = "Please enter your email address."
        else:
            try:
                user = db.session.execute(
                    text(
                        """
                        SELECT u.user_id, u.email, u.first_name,
                               u.password_hash
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
                db.session.rollback()
                app.logger.exception("Password-reset request database error")
                return render_template(
                    "driver_forgot_password.html",
                    message=(
                        "Unable to process the request right now. "
                        "Please try again."
                    ),
                    email=email,
                    reset_link=None,
                ), 500

            if user is not None and user["password_hash"]:
                token = create_password_reset_token(
                    user["user_id"],
                    user["password_hash"],
                )
                generated_link = url_for(
                    "driver_reset_password",
                    token=token,
                    _external=True,
                )
                try:
                    deliver_password_reset_link(user, generated_link)
                except Exception:
                    app.logger.exception("Password-reset delivery failed")

                if (
                    app.config["PASSWORD_RESET_SHOW_LINK"]
                    or app.config.get("TESTING")
                ):
                    reset_link = generated_link

            # Always use the same public response so account membership is
            # not disclosed to someone submitting arbitrary email addresses.
            message = PASSWORD_RESET_REQUEST_MESSAGE

    return render_template(
        "driver_forgot_password.html",
        message=message,
        email=email,
        reset_link=reset_link,
    )


@app.route("/driver/password/reset/<token>", methods=["GET", "POST"])
def driver_reset_password(token):
    payload = get_password_reset_payload(token)
    if payload is None:
        return render_template(
            "driver_reset_password.html",
            valid_link=False,
            message=INVALID_RESET_LINK_MESSAGE,
            password_requirements=get_password_requirements(),
        )

    try:
        user = db.session.execute(
            text(
                """
                SELECT u.user_id, u.password_hash
                FROM app_user AS u
                JOIN driver_profile AS d
                  ON d.user_id = u.user_id
                WHERE u.user_id = :user_id
                  AND u.role = 'DRIVER'
                  AND u.status = 'ACTIVE'
                """
            ),
            {"user_id": payload["user_id"]},
        ).mappings().first()
    except Exception:
        db.session.rollback()
        app.logger.exception("Password-reset validation database error")
        return "Unable to validate this reset link right now.", 500

    token_matches_current_password = (
        user is not None
        and user["password_hash"]
        and hmac.compare_digest(
            payload["password_fingerprint"],
            get_password_hash_fingerprint(user["password_hash"]),
        )
    )
    if not token_matches_current_password:
        return render_template(
            "driver_reset_password.html",
            valid_link=False,
            message=INVALID_RESET_LINK_MESSAGE,
            password_requirements=get_password_requirements(),
        )

    message = None
    password_errors = []
    if request.method == "POST":
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not new_password or not confirm_password:
            message = "Please enter and confirm your new password."
        elif new_password != confirm_password:
            message = "New passwords do not match."
        else:
            password_errors = get_password_validation_errors(new_password)
            if password_errors:
                message = format_password_validation_errors(password_errors)
            elif check_password_hash(user["password_hash"], new_password):
                message = "Choose a password different from your current password."
            else:
                new_password_hash = generate_password_hash(new_password)
                try:
                    update_result = db.session.execute(
                        text(
                            """
                            UPDATE app_user
                            SET password_hash = :new_password_hash
                            WHERE user_id = :user_id
                              AND role = 'DRIVER'
                              AND password_hash = :current_password_hash
                            """
                        ),
                        {
                            "new_password_hash": new_password_hash,
                            "user_id": user["user_id"],
                            "current_password_hash": user["password_hash"],
                        },
                    )
                    if update_result.rowcount != 1:
                        db.session.rollback()
                        return render_template(
                            "driver_reset_password.html",
                            valid_link=False,
                            message=INVALID_RESET_LINK_MESSAGE,
                            password_requirements=get_password_requirements(),
                        )

                    db.session.execute(
                        text(
                            """
                            INSERT INTO audit_log
                                (category, actor_user_id, target_user_id,
                                 success, reason)
                            VALUES
                                ('PASSWORD_CHANGE', :user_id, :user_id,
                                 TRUE, :reason)
                            """
                        ),
                        {
                            "user_id": user["user_id"],
                            "reason": "Driver completed password reset",
                        },
                    )
                    db.session.commit()
                except Exception:
                    db.session.rollback()
                    app.logger.exception("Driver password reset failed")
                    message = (
                        "Unable to reset your password right now. "
                        "Please try again."
                    )
                else:
                    session.clear()
                    return redirect(url_for("login", password_reset="success"))

    return render_template(
        "driver_reset_password.html",
        valid_link=True,
        message=message,
        password_errors=password_errors,
        password_requirements=get_password_requirements(),
    )

@app.route("/logout", methods=["GET", "POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


# 25132 & 25134 - Implement Sponsor Login Functionality ...

# 25132 & 25134 - Implement Sponsor Login Functionality & Update and Improve Sponsor Login Functionality


@app.get("/sponsor/dashboard")
@sponsor_required
def sponsor_dashboard():
    return render_template("sponsor_dashboard.html")

def get_product_search_client():
    cached_client = app.extensions.get("product_search_client")
    if cached_client is not None:
        return cached_client

    provider = app.config["PRODUCT_API_PROVIDER"]

    if provider == "fixture":
        client = FixtureProductApiClient()
    elif provider == "ebay":
        client = EbayProductApiClient(
            app.config["EBAY_CLIENT_ID"],
            app.config["EBAY_CLIENT_SECRET"],
            sandbox=app.config["EBAY_SANDBOX"],
        )
    else:
        raise ValueError("Unsupported product API provider")

    app.extensions["product_search_client"] = client
    return client


@app.get("/sponsor/products/search")
@sponsor_required
def sponsor_product_search():
    try:
        sponsor = db.session.execute(
            text(
                """
                SELECT u.user_id
                FROM app_user AS u
                JOIN sponsor_org AS so
                    ON so.sponsor_org_id = u.sponsor_org_id
                WHERE u.user_id = :user_id
                  AND u.role = 'SPONSOR'
                  AND u.status = 'ACTIVE'
                  AND so.status = 'ACTIVE'
                """
            ),
            {"user_id": session["user_id"]},
        ).first()
    except Exception:
        db.session.rollback()
        app.logger.error("Sponsor search authorization lookup failed")
        return "Unable to verify sponsor access right now.", 503

    if sponsor is None:
        return "Access denied.", 403

    query = request.args.get("q", "").strip()
    products = []
    error = None
    searched = False
    status = 200

    provider = app.config["PRODUCT_API_PROVIDER"]
    source_label = (
        "Fixture development data"
        if provider == "fixture"
        else (
            "eBay Sandbox"
            if app.config["EBAY_SANDBOX"]
            else "eBay Production"
        )
    )

    if len(query) > 100:
        error = "Please use a search query of 100 characters or fewer."
        status = 400
    elif query:
        try:
            products = get_product_search_client().search(query)
            searched = True
        except (EbayApiError, ValueError):
            app.logger.error(
                "Product search failed for provider %s", provider
            )
            error = "Product search is unavailable. Please try again later."
            status = 503

    return render_template(
        "sponsor_product_search.html",
        query=query,
        products=products,
        error=error,
        searched=searched,
        source_label=source_label,
    ), status

# - admin can login
@app.get("/admin/home")
def admin_home():
    if session.get("user_id") is None:
        return redirect(url_for("login"))

    if session.get("role") != "ADMIN":
        return "Access denied.", 403

    return render_template("admin_home.html")

@app.route("/admin/profile", methods=["GET", "POST"])
def admin_profile():
    if session.get("user_id") is None:
        return redirect(url_for("login"))

    if session.get("role") != "ADMIN":
        return "Access denied.", 403

    user_id = session["user_id"]
    message = None

    # Only allow the phone number to be updated
    if request.method == "POST":
        phone = request.form.get("phone", "").strip()

        db.session.execute(
            text(
                """
                UPDATE app_user
                SET phone = :phone
                WHERE user_id = :user_id
                  AND role = 'ADMIN'
                """
            ),
            {
                "phone": phone or None,
                "user_id": user_id
            }
        )

        db.session.commit()
        message = "Phone number updated successfully."

    # Get the admin's profile information
    user = db.session.execute(
        text(
            """
            SELECT
                user_id,
                first_name,
                last_name,
                email,
                phone
            FROM app_user
            WHERE user_id = :user_id
              AND role = 'ADMIN'
            """
        ),
        {"user_id": user_id}
    ).mappings().first()

    if user is None:
        return "Admin profile not found.", 404

    return render_template(
        "admin_profile.html",
        user=user,
        message=message
    )

@app.route("/admin/update", methods=["GET", "POST"])
def admin_update():
    if session.get("user_id") is None:
        return redirect(url_for("login"))

    if session.get("role") != "ADMIN":
        return "Access denied.", 403

    user_id = session["user_id"]
    message = None

    if request.method == "POST":
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        # Get the current password hash for this admin
        user = db.session.execute(
            text(
                """
                SELECT password_hash
                FROM app_user
                WHERE user_id = :user_id
                  AND role = 'ADMIN'
                """
            ),
            {"user_id": user_id}
        ).mappings().first()

        if user is None:
            return "Admin account not found.", 404

        # Check the current password
        if not check_password_hash(
            user["password_hash"],
            current_password
        ):
            message = "Current password is incorrect."

        # Make sure the new password is long enough
        elif len(new_password) < 8:
            message = "New password must be at least 8 characters."

        # Make sure both new passwords match
        elif new_password != confirm_password:
            message = "New passwords do not match."

        else:
            # Hash the new password
            new_password_hash = generate_password_hash(new_password)

            # Store the new hash in the database
            db.session.execute(
                text(
                    """
                    UPDATE app_user
                    SET password_hash = :password_hash
                    WHERE user_id = :user_id
                      AND role = 'ADMIN'
                    """
                ),
                {
                    "password_hash": new_password_hash,
                    "user_id": user_id
                }
            )

            db.session.commit()

            message = "Password updated successfully."

    return render_template(
        "admin_update.html",
        message=message
    )
    

@app.route("/admin/users")
def admin_user_index():
    if session.get("user_id") is None:
        return redirect(url_for("login"))

    if session.get("role") != "ADMIN":
        return "Access denied.", 403

    users = db.session.execute(
        text(
            """
            SELECT
                u.user_id,
                u.role,
                u.first_name,
                u.last_name,
                u.email,
                so.sponsor_org_id,
                so.name AS organization_name

            FROM app_user AS u

            LEFT JOIN driver_profile AS dp
                ON u.user_id = dp.user_id
                AND u.role = 'DRIVER'

            LEFT JOIN sponsor_org AS so
                ON so.sponsor_org_id =
                    CASE
                        WHEN u.role = 'DRIVER'
                            THEN dp.sponsor_org_id
                        WHEN u.role = 'SPONSOR'
                            THEN u.sponsor_org_id
                        ELSE NULL
                    END

            ORDER BY
                u.last_name ASC,
                u.first_name ASC,
                u.email ASC
            """
        )
    ).mappings().all()

    return render_template(
        "admin_user_index.html",
        users=users
    )


@app.route("/admin/users/<int:user_id>")
def admin_user_detail(user_id):
    if session.get("user_id") is None:
        return redirect(url_for("login"))

    if session.get("role") != "ADMIN":
        return "Access denied.", 403

    user = db.session.execute(
        text(
            """
            SELECT
                u.user_id,
                u.role,
                u.first_name,
                u.last_name,
                u.email,
                u.phone,
                u.status,
                u.created_at,

                dp.point_balance,
                dp.shipping_address,

                so.sponsor_org_id,
                so.name AS organization_name

            FROM app_user AS u

            LEFT JOIN driver_profile AS dp
                ON u.user_id = dp.user_id
                AND u.role = 'DRIVER'

            LEFT JOIN sponsor_org AS so
                ON so.sponsor_org_id =
                    CASE
                        WHEN u.role = 'DRIVER'
                            THEN dp.sponsor_org_id
                        WHEN u.role = 'SPONSOR'
                            THEN u.sponsor_org_id
                        ELSE NULL
                    END

            WHERE u.user_id = :user_id
            """
        ),
        {"user_id": user_id}
    ).mappings().first()

    if user is None:
        return "User not found.", 404

    return render_template(
        "admin_user_detail.html",
        user=user
    )


@app.route("/admin/organizations/<int:sponsor_org_id>")
def admin_organization_detail(sponsor_org_id):
    if session.get("user_id") is None:
        return redirect(url_for("login"))

    if session.get("role") != "ADMIN":
        return "Access denied.", 403

    organization = db.session.execute(
        text(
            """
            SELECT
                sponsor_org_id,
                name,
                contact_email,
                phone,
                point_dollar_value,
                created_at

            FROM sponsor_org

            WHERE sponsor_org_id = :sponsor_org_id
            """
        ),
        {"sponsor_org_id": sponsor_org_id}
    ).mappings().first()

    if organization is None:
        return "Sponsor organization not found.", 404

    return render_template(
        "admin_organization_detail.html",
        organization=organization
    )

@app.route("/admin/create-driver", methods=["GET", "POST"])
def admin_create_driver():
    if session.get("user_id") is None:
        return redirect(url_for("login"))

    if session.get("role") != "ADMIN":
        return "Access denied.", 403

    message = None

    # Get all active sponsor organizations for the dropdown
    sponsors = db.session.execute(
        text(
            """
            SELECT sponsor_org_id, name
            FROM sponsor_org
            WHERE status = 'ACTIVE'
            ORDER BY name
            """
        )
    ).mappings().all()

    if request.method == "POST":
        first_name = request.form.get("first_name", "").strip()
        last_name = request.form.get("last_name", "").strip()
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()
        password = request.form.get("password", "")
        shipping_address = request.form.get("shipping_address", "").strip()
        sponsor_org_id = request.form.get("sponsor_org_id")

        # Make sure the email is not already being used
        existing_user = db.session.execute(
            text(
                """
                SELECT user_id
                FROM app_user
                WHERE email = :email
                """
            ),
            {"email": email}
        ).mappings().first()

        if existing_user:
            message = "An account with that email already exists."

        elif len(password) < 8:
            message = "Password must be at least 8 characters."

        else:
            password_hash = generate_password_hash(password)

            try:
                # Create the app_user account
                result = db.session.execute(
                    text(
                        """
                        INSERT INTO app_user
                            (role, email, password_hash, first_name,
                             last_name, phone, status)
                        VALUES
                            ('DRIVER', :email, :password_hash, :first_name,
                             :last_name, :phone, 'ACTIVE')
                        """
                    ),
                    {
                        "email": email,
                        "password_hash": password_hash,
                        "first_name": first_name,
                        "last_name": last_name,
                        "phone": phone or None
                    }
                )

                # Get the new driver's user_id
                new_user_id = result.lastrowid

                # Create the driver's profile
                db.session.execute(
                    text(
                        """
                        INSERT INTO driver_profile
                            (user_id, sponsor_org_id, point_balance,
                             shipping_address)
                        VALUES
                            (:user_id, :sponsor_org_id, 0,
                             :shipping_address)
                        """
                    ),
                    {
                        "user_id": new_user_id,
                        "sponsor_org_id": sponsor_org_id,
                        "shipping_address": shipping_address or None
                    }
                )

                db.session.commit()
                message = "Driver created successfully."

            except Exception:
                db.session.rollback()
                app.logger.exception("Error creating driver")
                message = "Unable to create driver."

    return render_template(
        "admin_create_driver.html",
        sponsors=sponsors,
        message=message
    )
    
@app.route("/admin/create-admin", methods=["GET", "POST"])
def admin_create_admin():
    if session.get("user_id") is None:
        return redirect(url_for("login"))

    if session.get("role") != "ADMIN":
        return "Access denied.", 403

    message = None

    if request.method == "POST":
        first_name = request.form.get("first_name", "").strip()
        last_name = request.form.get("last_name", "").strip()
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()
        password = request.form.get("password", "")

        # Check whether the email already exists
        existing_user = db.session.execute(
            text(
                """
                SELECT user_id
                FROM app_user
                WHERE email = :email
                """
            ),
            {"email": email}
        ).mappings().first()

        if existing_user:
            message = "An account with that email already exists."

        elif len(password) < 8:
            message = "Password must be at least 8 characters."

        else:
            password_hash = generate_password_hash(password)

            try:
                db.session.execute(
                    text(
                        """
                        INSERT INTO app_user
                            (role, email, password_hash,
                             first_name, last_name, phone, status)
                        VALUES
                            ('ADMIN', :email, :password_hash,
                             :first_name, :last_name, :phone, 'ACTIVE')
                        """
                    ),
                    {
                        "email": email,
                        "password_hash": password_hash,
                        "first_name": first_name,
                        "last_name": last_name,
                        "phone": phone or None
                    }
                )

                db.session.commit()
                message = "Admin created successfully."

            except Exception:
                db.session.rollback()
                app.logger.exception("Error creating admin")
                message = "Unable to create admin."

    return render_template(
        "admin_create_admin.html",
        message=message
    )

@app.route("/admin/create-sponsor", methods=["GET", "POST"])
def admin_create_sponsor():
    if session.get("user_id") is None:
        return redirect(url_for("login"))

    if session.get("role") != "ADMIN":
        return "Access denied.", 403

    message = None

    # Get existing active sponsor organizations
    organizations = db.session.execute(
        text(
            """
            SELECT sponsor_org_id, name
            FROM sponsor_org
            WHERE status = 'ACTIVE'
            ORDER BY name
            """
        )
    ).mappings().all()

    if request.method == "POST":
        first_name = request.form.get("first_name", "").strip()
        last_name = request.form.get("last_name", "").strip()
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()
        password = request.form.get("password", "")
        organization_option = request.form.get("organization_option")

        existing_user = db.session.execute(
            text(
                """
                SELECT user_id
                FROM app_user
                WHERE email = :email
                """
            ),
            {"email": email}
        ).mappings().first()

        if existing_user:
            message = "An account with that email already exists."

        elif len(password) < 8:
            message = "Password must be at least 8 characters."

        else:
            password_hash = generate_password_hash(password)

            try:
                # Create a new organization if NEW was selected
                if organization_option == "NEW":
                    organization_name = request.form.get(
                        "organization_name", ""
                    ).strip()

                    point_dollar_value = request.form.get(
                        "point_dollar_value", "0.0100"
                    )

                    if not organization_name:
                        return render_template(
                            "admin_create_sponsor.html",
                            organizations=organizations,
                            message="Organization name is required."
                        )

                    result = db.session.execute(
                        text(
                            """
                            INSERT INTO sponsor_org
                                (name, contact_email, phone,
                                 point_dollar_value, status)
                            VALUES
                                (:name, :contact_email, :phone,
                                 :point_dollar_value, 'ACTIVE')
                            """
                        ),
                        {
                            "name": organization_name,
                            "contact_email": email,
                            "phone": phone or None,
                            "point_dollar_value": point_dollar_value
                        }
                    )

                    sponsor_org_id = result.lastrowid

                else:
                    # Use the existing organization
                    sponsor_org_id = organization_option

                # Create the Sponsor account
                db.session.execute(
                    text(
                        """
                        INSERT INTO app_user
                            (role, email, password_hash,
                             first_name, last_name, phone,
                             status, sponsor_org_id)
                        VALUES
                            ('SPONSOR', :email, :password_hash,
                             :first_name, :last_name, :phone,
                             'ACTIVE', :sponsor_org_id)
                        """
                    ),
                    {
                        "email": email,
                        "password_hash": password_hash,
                        "first_name": first_name,
                        "last_name": last_name,
                        "phone": phone or None,
                        "sponsor_org_id": sponsor_org_id
                    }
                )

                db.session.commit()
                message = "Sponsor created successfully."

            except Exception:
                db.session.rollback()
                app.logger.exception("Error creating sponsor")
                message = "Unable to create sponsor."

    return render_template(
        "admin_create_sponsor.html",
        organizations=organizations,
        message=message
    )
# 25135 - User Profile Editing and Saving

@app.route("/sponsor/profile", methods=["GET", "POST"])
@sponsor_required
def sponsor_profile():
    message = None
    edit_mode = request.args.get("edit") == "1"

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
        return redirect(url_for("login"))

    return render_template(
        "sponsor_profile.html",
        user=user,
        message=message,
        edit_mode=edit_mode
    )


# 25136 - Organization Profile Editing and Saving

@app.route("/sponsor/organization", methods=["GET", "POST"])
@sponsor_required
def sponsor_organization():
    message = None
    edit_mode = request.args.get("edit") == "1"

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
        message=message,
        edit_mode=edit_mode
    )

@app.get("/sponsor/logout")
def sponsor_logout():
    session.clear()

    return redirect(url_for("login"))

# 25137 - Sponsor Create New Driver
@app.route("/sponsor/drivers/create", methods=["GET", "POST"])
@sponsor_required
def sponsor_create_driver():
    message = None

    if request.method == "POST":
        first_name = request.form.get("first_name", "").strip()
        last_name = request.form.get("last_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        phone = request.form.get("phone", "").strip()
        password = request.form.get("password", "")
        shipping_address = request.form.get("shipping_address", "").strip()

        if not first_name or not last_name or not email or not password:
            message = "First name, last name, email, and password are required."

        elif len(password) < 8:
            message = "Password must be at least 8 characters."

        else:
            try:
                # Make sure the email is not already being used.
                existing_user = db.session.execute(
                    text(
                        """
                        SELECT user_id
                        FROM app_user
                        WHERE email = :email
                        """
                    ),
                    {"email": email},
                ).first()

                if existing_user is not None:
                    message = "A user with that email already exists."

                else:
                    # Create the driver's user account.
                    result = db.session.execute(
                        text(
                            """
                            INSERT INTO app_user
                                (role,
                                 email,
                                 password_hash,
                                 first_name,
                                 last_name,
                                 phone,
                                 status,
                                 sponsor_org_id)
                            VALUES
                                ('DRIVER',
                                 :email,
                                 :password_hash,
                                 :first_name,
                                 :last_name,
                                 :phone,
                                 'ACTIVE',
                                 :sponsor_org_id)
                            """
                        ),
                        {
                            "email": email,
                            "password_hash": generate_password_hash(password),
                            "first_name": first_name,
                            "last_name": last_name,
                            "phone": phone if phone else None,
                            "sponsor_org_id": session["sponsor_org_id"],
                        },
                    )

                    driver_user_id = result.lastrowid

                    # Create the driver's profile and connect it to this sponsor.
                    db.session.execute(
                        text(
                            """
                            INSERT INTO driver_profile
                                (user_id,
                                 sponsor_org_id,
                                 point_balance,
                                 shipping_address)
                            VALUES
                                (:user_id,
                                 :sponsor_org_id,
                                 0,
                                 :shipping_address)
                            """
                        ),
                        {
                            "user_id": driver_user_id,
                            "sponsor_org_id": session["sponsor_org_id"],
                            "shipping_address": (
                                shipping_address if shipping_address else None
                            ),
                        },
                    )

                    db.session.commit()
                    message = "Driver created successfully."

            except Exception:
                db.session.rollback()
                app.logger.exception("Driver creation failed")
                message = "Unable to create driver. Please try again."

    return render_template(
        "sponsor_create_driver.html",
        message=message
    )

# 25139 - Sponsor Create Another Sponsor User
@app.route("/sponsor/users/create", methods=["GET", "POST"])
@sponsor_required
def sponsor_create_user():
    message = None

    if request.method == "POST":
        first_name = request.form.get("first_name", "").strip()
        last_name = request.form.get("last_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        phone = request.form.get("phone", "").strip()
        password = request.form.get("password", "")

        if not first_name or not last_name or not email or not password:
            message = "First name, last name, email, and password are required."

        elif len(password) < 8:
            message = "Password must be at least 8 characters."

        else:
            try:
                existing_user = db.session.execute(
                    text(
                        """
                        SELECT user_id
                        FROM app_user
                        WHERE email = :email
                        """
                    ),
                    {"email": email},
                ).first()

                if existing_user is not None:
                    message = "A user with that email already exists."

                else:
                    db.session.execute(
                        text(
                            """
                            INSERT INTO app_user
                                (role,
                                 email,
                                 password_hash,
                                 first_name,
                                 last_name,
                                 phone,
                                 status,
                                 sponsor_org_id)
                            VALUES
                                ('SPONSOR',
                                 :email,
                                 :password_hash,
                                 :first_name,
                                 :last_name,
                                 :phone,
                                 'ACTIVE',
                                 :sponsor_org_id)
                            """
                        ),
                        {
                            "email": email,
                            "password_hash": generate_password_hash(password),
                            "first_name": first_name,
                            "last_name": last_name,
                            "phone": phone if phone else None,
                            "sponsor_org_id": session["sponsor_org_id"],
                        },
                    )

                    db.session.commit()
                    message = "Sponsor user created successfully."

            except Exception:
                db.session.rollback()
                app.logger.exception("Sponsor user creation failed")
                message = "Unable to create sponsor user. Please try again."

    return render_template(
        "sponsor_create_user.html",
        message=message
    )

# Driver Application
@app.route("/apply", methods=["GET", "POST"])
def driver_apply():
    message = None

    organizations = db.session.execute(
        text(
            """
            SELECT sponsor_org_id, name
            FROM sponsor_org
            WHERE status = 'ACTIVE'
            ORDER BY name
            """
        )
    ).mappings().all()

    if request.method == "POST":
        first_name = request.form.get("first_name", "").strip()
        last_name = request.form.get("last_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        phone = request.form.get("phone", "").strip()
        has_license = request.form.get("has_license", "")
        sponsor_org_id = request.form.get("sponsor_org_id", "")
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if (
            not first_name
            or not last_name
            or not email
            or not phone
            or not has_license
            or not sponsor_org_id
            or not password
            or not confirm_password
        ):
            message = "Please complete all fields."

        elif password != confirm_password:
            message = "Passwords do not match."

        elif get_password_validation_errors(password):
            message = format_password_validation_errors(
                get_password_validation_errors(password)
            )

        else:
            try:
                existing_user = db.session.execute(
                    text(
                        """
                        SELECT user_id
                        FROM app_user
                        WHERE email = :email
                        """
                    ),
                    {"email": email},
                ).first()

                if existing_user is not None:
                    message = "An account with that email already exists."

                else:
                    # Create the applicant's pending driver account.
                    result = db.session.execute(
                        text(
                            """
                            INSERT INTO app_user
                                (role,
                                 email,
                                 password_hash,
                                 first_name,
                                 last_name,
                                 phone,
                                 status,
                                 sponsor_org_id)
                            VALUES
                                ('DRIVER',
                                 :email,
                                 :password_hash,
                                 :first_name,
                                 :last_name,
                                 :phone,
                                 'PENDING',
                                 :sponsor_org_id)
                            """
                        ),
                        {
                            "email": email,
                            "password_hash": generate_password_hash(password),
                            "first_name": first_name,
                            "last_name": last_name,
                            "phone": phone,
                            "sponsor_org_id": sponsor_org_id,
                        },
                    )

                    driver_user_id = result.lastrowid

                    # Create the pending application.
                    db.session.execute(
                        text(
                            """
                            INSERT INTO driver_application
                                (driver_user_id,
                                 sponsor_org_id,
                                 status,
                                 reason)
                            VALUES
                                (:driver_user_id,
                                 :sponsor_org_id,
                                 'PENDING',
                                 :reason)
                            """
                        ),
                        {
                            "driver_user_id": driver_user_id,
                            "sponsor_org_id": sponsor_org_id,
                            "reason": (
                                "Valid driver's license: "
                                + has_license
                            ),
                        },
                    )

                    db.session.commit()

                    message = (
                        "Application submitted successfully. "
                        "You can now use your login information "
                        "to check your application status."
                    )

            except Exception:
                db.session.rollback()
                app.logger.exception("Driver application submission failed")
                message = "Unable to submit application. Please try again."

    return render_template(
        "driver_apply.html",
        organizations=organizations,
        message=message,
        password_requirements=get_password_requirements(),
    )

@app.route("/application/status")
def application_status():

    if "user_id" not in session:
        return redirect(url_for("login"))

    application = db.session.execute(
        text(
            """
            SELECT a.status,
                   o.name AS organization_name
            FROM driver_application a
            JOIN sponsor_org o
              ON a.sponsor_org_id = o.sponsor_org_id
            WHERE a.driver_user_id = :user_id
            ORDER BY a.created_at DESC
            LIMIT 1
            """
        ),
        {
            "user_id": session["user_id"]
        },
    ).mappings().first()

    if application is None:
        return redirect(url_for("login"))

    # Approved drivers should use the normal driver dashboard.
    if application["status"] == "APPROVED":
        return redirect(url_for("driver_dashboard"))

    return render_template(
        "application_status.html",
        application=application
    )

# 25141 / 25142 - Sponsor Driver Application Management
@app.route("/sponsor/applications")
@sponsor_required
def sponsor_applications():

    applications = db.session.execute(
        text(
            """
            SELECT a.application_id,
                   a.status AS application_status,
                   a.reason,
                   a.created_at,
                   u.first_name,
                   u.last_name,
                   u.email,
                   u.phone
            FROM driver_application a
            JOIN app_user u
              ON a.driver_user_id = u.user_id
            WHERE a.sponsor_org_id = :sponsor_org_id
            ORDER BY a.created_at DESC
            """
        ),
        {
            "sponsor_org_id": session["sponsor_org_id"]
        },
    ).mappings().all()

    return render_template(
        "sponsor_applications.html",
        applications=applications
    )

# 25141 - Approve Driver Application
@app.post("/sponsor/applications/<int:application_id>/approve")
@sponsor_required
def sponsor_approve_application(application_id):

    application = db.session.execute(
        text(
            """
            SELECT application_id, driver_user_id
            FROM driver_application
            WHERE application_id = :application_id
              AND sponsor_org_id = :sponsor_org_id
              AND status = 'PENDING'
            """
        ),
        {
            "application_id": application_id,
            "sponsor_org_id": session["sponsor_org_id"],
        },
    ).mappings().first()

    if application is None:
        return "Application not found.", 404

    try:
        # Approve the application.
        db.session.execute(
            text(
                """
                UPDATE driver_application
                SET status = 'APPROVED',
                    decided_by = :decided_by,
                    decided_at = CURRENT_TIMESTAMP
                WHERE application_id = :application_id
                """
            ),
            {
                "decided_by": session["user_id"],
                "application_id": application_id,
            },
        )

        # Create the driver's profile so they can use normal driver features.
        db.session.execute(
            text(
                """
                INSERT INTO driver_profile
                    (user_id,
                     sponsor_org_id,
                     point_balance)
                VALUES
                    (:driver_user_id,
                     :sponsor_org_id,
                     0)
                """
            ),
            {
                "driver_user_id": application["driver_user_id"],
                "sponsor_org_id": session["sponsor_org_id"],
            },
        )

        # Activate the driver's account.
        db.session.execute(
            text(
                """
                UPDATE app_user
                SET status = 'ACTIVE'
                WHERE user_id = :driver_user_id
                  AND role = 'DRIVER'
                """
            ),
            {
                "driver_user_id": application["driver_user_id"]
            },
        )

        db.session.commit()

    except Exception:
        db.session.rollback()
        app.logger.exception("Driver application approval failed")
        return "Unable to approve application.", 500

    return redirect(url_for("sponsor_applications"))


# 25142 - Reject Driver Application
@app.post("/sponsor/applications/<int:application_id>/reject")
@sponsor_required
def sponsor_reject_application(application_id):

    application = db.session.execute(
        text(
            """
            SELECT application_id, driver_user_id
            FROM driver_application
            WHERE application_id = :application_id
              AND sponsor_org_id = :sponsor_org_id
              AND status = 'PENDING'
            """
        ),
        {
            "application_id": application_id,
            "sponsor_org_id": session["sponsor_org_id"],
        },
    ).mappings().first()

    if application is None:
        return "Application not found.", 404

    try:
        db.session.execute(
            text(
                """
                UPDATE driver_application
                SET status = 'REJECTED',
                    decided_by = :decided_by,
                    decided_at = CURRENT_TIMESTAMP
                WHERE application_id = :application_id
                """
            ),
            {
                "decided_by": session["user_id"],
                "application_id": application_id,
            },
        )

        db.session.commit()

    except Exception:
        db.session.rollback()
        app.logger.exception("Driver application rejection failed")
        return "Unable to reject application.", 500

    return redirect(url_for("sponsor_applications"))

# 25158 - Sponsor Management and Points - Driver Data
@app.get("/sponsor/drivers")
@sponsor_required
def sponsor_drivers():
    drivers = db.session.execute(
        text(
            """
            SELECT u.user_id,
                   u.first_name,
                   u.last_name,
                   u.email,
                   u.phone,
                   u.status,
                   d.point_balance,
                   d.shipping_address
            FROM app_user u
            JOIN driver_profile d
              ON u.user_id = d.user_id
            WHERE d.sponsor_org_id = :sponsor_org_id
              AND u.role = 'DRIVER'
            ORDER BY u.last_name, u.first_name
            """
        ),
        {
            "sponsor_org_id": session["sponsor_org_id"]
        },
    ).mappings().all()

    return render_template(
        "sponsor_drivers.html",
        drivers=drivers
    )

# 25143 - Sponsor Edit Driver Information
@app.route("/sponsor/drivers/<int:driver_user_id>/edit", methods=["GET", "POST"])
@sponsor_required
def sponsor_edit_driver(driver_user_id):
    message = None

    # Make sure the driver belongs to the logged-in sponsor.
    driver = db.session.execute(
        text(
            """
            SELECT u.user_id,
                   u.first_name,
                   u.last_name,
                   u.email,
                   u.phone,
                   d.shipping_address
            FROM app_user u
            JOIN driver_profile d
              ON u.user_id = d.user_id
            WHERE u.user_id = :driver_user_id
              AND d.sponsor_org_id = :sponsor_org_id
              AND u.role = 'DRIVER'
            """
        ),
        {
            "driver_user_id": driver_user_id,
            "sponsor_org_id": session["sponsor_org_id"],
        },
    ).mappings().first()

    if driver is None:
        return "Driver not found.", 404

    if request.method == "POST":
        first_name = request.form.get("first_name", "").strip()
        last_name = request.form.get("last_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        phone = request.form.get("phone", "").strip()
        shipping_address = request.form.get("shipping_address", "").strip()

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
                        WHERE user_id = :driver_user_id
                          AND role = 'DRIVER'
                        """
                    ),
                    {
                        "first_name": first_name,
                        "last_name": last_name,
                        "email": email,
                        "phone": phone if phone else None,
                        "driver_user_id": driver_user_id,
                    },
                )

                db.session.execute(
                    text(
                        """
                        UPDATE driver_profile
                        SET shipping_address = :shipping_address
                        WHERE user_id = :driver_user_id
                          AND sponsor_org_id = :sponsor_org_id
                        """
                    ),
                    {
                        "shipping_address": (
                            shipping_address if shipping_address else None
                        ),
                        "driver_user_id": driver_user_id,
                        "sponsor_org_id": session["sponsor_org_id"],
                    },
                )

                db.session.commit()

                return redirect(url_for("sponsor_drivers"))

            except Exception:
                db.session.rollback()
                app.logger.exception("Sponsor driver update failed")
                message = "Unable to update driver. Please try again."

    return render_template(
        "sponsor_edit_driver.html",
        driver=driver,
        message=message
    )

# 25161 - Sponsor Remove Driver From Organization
@app.post("/sponsor/drivers/<int:driver_user_id>/remove")
@sponsor_required
def sponsor_remove_driver(driver_user_id):
    sponsor_org_id = session["sponsor_org_id"]

    # Make sure this driver belongs to the logged-in sponsor organization.
    driver = db.session.execute(
        text(
            """
            SELECT u.user_id
            FROM app_user u
            JOIN driver_profile d
              ON d.user_id = u.user_id
            WHERE u.user_id = :driver_user_id
              AND d.sponsor_org_id = :sponsor_org_id
              AND u.role = 'DRIVER'
              AND u.status = 'ACTIVE'
            """
        ),
        {
            "driver_user_id": driver_user_id,
            "sponsor_org_id": sponsor_org_id,
        },
    ).mappings().first()

    if driver is None:
        return "Driver not found.", 404

    try:
        # Keep the driver's records, but prevent further participation.
        db.session.execute(
            text(
                """
                UPDATE app_user
                SET status = 'INACTIVE'
                WHERE user_id = :driver_user_id
                  AND role = 'DRIVER'
                """
            ),
            {
                "driver_user_id": driver_user_id
            },
        )

        db.session.commit()

    except Exception:
        db.session.rollback()
        app.logger.exception("Sponsor driver removal failed")
        return "Unable to remove driver. Please try again.", 500

    return redirect(url_for("sponsor_drivers"))

# 25150 - Sponsor Assume Driver Identity
@app.post("/sponsor/drivers/<int:driver_user_id>/impersonate")
@sponsor_required
def sponsor_impersonate_driver(driver_user_id):
    sponsor_org_id = session["sponsor_org_id"]

    # Make sure the driver belongs to this sponsor and is active.
    driver = db.session.execute(
        text(
            """
            SELECT u.user_id
            FROM app_user u
            JOIN driver_profile d
              ON d.user_id = u.user_id
            WHERE u.user_id = :driver_user_id
              AND d.sponsor_org_id = :sponsor_org_id
              AND u.role = 'DRIVER'
              AND u.status = 'ACTIVE'
            """
        ),
        {
            "driver_user_id": driver_user_id,
            "sponsor_org_id": sponsor_org_id,
        },
    ).mappings().first()

    if driver is None:
        return "Driver not found.", 404

    # Save the sponsor's identity so we can switch back later.
    session["original_sponsor_user_id"] = session["user_id"]
    session["original_sponsor_org_id"] = session["sponsor_org_id"]
    session["impersonating_driver"] = True

    # Temporarily make the session act like the selected driver.
    session["user_id"] = driver_user_id
    session["role"] = "DRIVER"

    return redirect(url_for("driver_dashboard"))

# 25150 - Stop Driver Impersonation and Return to Sponsor
@app.post("/sponsor/stop-impersonating")
def sponsor_stop_impersonating():
    if not session.get("impersonating_driver"):
        return redirect(url_for("login"))

    sponsor_user_id = session.get("original_sponsor_user_id")
    sponsor_org_id = session.get("original_sponsor_org_id")

    if not sponsor_user_id or not sponsor_org_id:
        session.clear()
        return redirect(url_for("login"))

    # Restore the original sponsor session.
    session["user_id"] = sponsor_user_id
    session["sponsor_org_id"] = sponsor_org_id
    session["role"] = "SPONSOR"

    # Remove the temporary impersonation information.
    session.pop("original_sponsor_user_id", None)
    session.pop("original_sponsor_org_id", None)
    session.pop("impersonating_driver", None)

    return redirect(url_for("sponsor_dashboard"))

# 25171 - Sponsor Management and Points - Point Management
@app.route("/sponsor/points", methods=["GET", "POST"])
@sponsor_required
def sponsor_points():
    message = None

    if request.method == "POST":
        driver_user_id = request.form.get("driver_user_id")
        action = request.form.get("action")
        reason = request.form.get("reason", "").strip()

        try:
            points = int(request.form.get("points", "0"))
        except ValueError:
            points = 0

        if points <= 0 or action not in ("add", "deduct") or not reason:
            message = "Please enter a valid point amount, action, and reason."
        else:
            try:
                # Make sure this driver actually belongs to this sponsor.
                driver = db.session.execute(
                    text(
                        """
                        SELECT point_balance
                        FROM driver_profile
                        WHERE user_id = :driver_user_id
                          AND sponsor_org_id = :sponsor_org_id
                        """
                    ),
                    {
                        "driver_user_id": driver_user_id,
                        "sponsor_org_id": session["sponsor_org_id"],
                    },
                ).mappings().first()

                if driver is None:
                    message = "Driver not found."
                else:
                    point_change = points if action == "add" else -points
                    new_balance = driver["point_balance"] + point_change

                    if new_balance < 0:
                        message = "A driver's point balance cannot be negative."
                    else:
                        # Update the driver's current balance.
                        db.session.execute(
                            text(
                                """
                                UPDATE driver_profile
                                SET point_balance = :new_balance
                                WHERE user_id = :driver_user_id
                                  AND sponsor_org_id = :sponsor_org_id
                                """
                            ),
                            {
                                "new_balance": new_balance,
                                "driver_user_id": driver_user_id,
                                "sponsor_org_id": session["sponsor_org_id"],
                            },
                        )

                        # Record the change in the point ledger.
                        db.session.execute(
                            text(
                                """
                                INSERT INTO point_change
                                    (driver_user_id,
                                     sponsor_org_id,
                                     actor_user_id,
                                     points,
                                     reason)
                                VALUES
                                    (:driver_user_id,
                                     :sponsor_org_id,
                                     :actor_user_id,
                                     :points,
                                     :reason)
                                """
                            ),
                            {
                                "driver_user_id": driver_user_id,
                                "sponsor_org_id": session["sponsor_org_id"],
                                "actor_user_id": session["user_id"],
                                "points": point_change,
                                "reason": reason,
                            },
                        )

                        db.session.commit()
                        message = "Point balance updated successfully."

            except Exception:
                db.session.rollback()
                app.logger.exception("Point management update failed")
                message = "Unable to update points. Please try again."

    drivers = db.session.execute(
        text(
            """
            SELECT u.user_id,
                   u.first_name,
                   u.last_name,
                   d.point_balance
            FROM app_user u
            JOIN driver_profile d
              ON u.user_id = d.user_id
            WHERE d.sponsor_org_id = :sponsor_org_id
              AND u.role = 'DRIVER'
              AND u.status = 'ACTIVE'
            ORDER BY u.last_name, u.first_name
            """
        ),
        {
            "sponsor_org_id": session["sponsor_org_id"]
        },
    ).mappings().all()

    return render_template(
        "sponsor_points.html",
        drivers=drivers,
        message=message
    )


# 25176 - Sponsor Management and Points - Point Tracking
@app.get("/sponsor/point-history")
@sponsor_required
def sponsor_point_history():
    drivers = db.session.execute(
        text(
            """
            SELECT u.user_id,
                   u.first_name,
                   u.last_name,
                   d.point_balance
            FROM app_user u
            JOIN driver_profile d
              ON u.user_id = d.user_id
            WHERE d.sponsor_org_id = :sponsor_org_id
              AND u.role = 'DRIVER'
            ORDER BY u.last_name, u.first_name
            """
        ),
        {
            "sponsor_org_id": session["sponsor_org_id"]
        },
    ).mappings().all()

    point_history = db.session.execute(
        text(
            """
            SELECT pc.point_change_id,
                   pc.driver_user_id,
                   pc.points,
                   pc.reason,
                   pc.created_at,
                   u.first_name,
                   u.last_name
            FROM point_change pc
            JOIN app_user u
              ON pc.driver_user_id = u.user_id
            WHERE pc.sponsor_org_id = :sponsor_org_id
            ORDER BY pc.created_at DESC
            """
        ),
        {
            "sponsor_org_id": session["sponsor_org_id"]
        },
    ).mappings().all()

    return render_template(
        "sponsor_point_history.html",
        drivers=drivers,
        point_history=point_history
    )


# 25175 - Sponsor Management and Points - Order Management
@app.get("/sponsor/orders")
@sponsor_required
def sponsor_orders():
    orders = db.session.execute(
        text(
            """
            SELECT po.order_id,
                   po.status,
                   po.total_points,
                   po.total_usd,
                   po.created_at,
                   u.first_name,
                   u.last_name
            FROM purchase_order po
            JOIN app_user u
              ON po.driver_user_id = u.user_id
            WHERE po.sponsor_org_id = :sponsor_org_id
            ORDER BY po.created_at DESC
            """
        ),
        {
            "sponsor_org_id": session["sponsor_org_id"]
        },
    ).mappings().all()

    return render_template(
        "sponsor_orders.html",
        orders=orders
    )


# 25156 - Sponsor Management and Points - Sponsor Communications
@app.get("/sponsor/communications")
@sponsor_required
def sponsor_communications():
    drivers = db.session.execute(
        text(
            """
            SELECT u.user_id,
                   u.first_name,
                   u.last_name,
                   u.email,
                   u.phone,
                   u.status
            FROM app_user u
            JOIN driver_profile d
              ON u.user_id = d.user_id
            WHERE d.sponsor_org_id = :sponsor_org_id
              AND u.role = 'DRIVER'
            ORDER BY u.last_name, u.first_name
            """
        ),
        {
            "sponsor_org_id": session["sponsor_org_id"]
        },
    ).mappings().all()

    return render_template(
        "sponsor_communications.html",
        drivers=drivers
    )


# 21752 & 22364 - Driver sign in and safe login-failure feedback

@app.route("/driver/login", methods=["GET", "POST"])
def driver_login():
    message = None
    if request.args.get("password_reset") == "success":
        message = "Your password was reset successfully. You can now sign in."
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
                    SELECT u.user_id, u.password_hash, u.status,
                           d.sponsor_org_id
                    FROM app_user AS u
                    JOIN driver_profile AS d
                      ON d.user_id = u.user_id
                    WHERE u.email = :email
                      AND u.role = 'DRIVER'
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

        credentials_are_valid = (
            user is not None
            and user["password_hash"] is not None
            and check_password_hash(user["password_hash"], password)
        )

        if credentials_are_valid and user["status"] != "ACTIVE":
            message = ACCOUNT_UNAVAILABLE_MESSAGE
        elif credentials_are_valid:
            session["user_id"] = user["user_id"]
            session["role"] = "DRIVER"
            session["sponsor_org_id"] = user["sponsor_org_id"]
            return redirect(url_for("driver_dashboard"))

        # Keep the response identical for unknown, inactive, non-driver, and
        # incorrect-password accounts so the page does not reveal membership.
        if not credentials_are_valid:
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


# 22362 & 22363 - Change password and explain complexity requirements

@app.route("/driver/password/change", methods=["GET", "POST"])
@driver_required
def driver_change_password():
    message = None
    password_errors = []

    if request.method == "POST":
        current_password = request.form.get("current_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        try:
            user = db.session.execute(
                text(
                    """
                    SELECT password_hash
                    FROM app_user
                    WHERE user_id = :user_id
                      AND role = 'DRIVER'
                    """
                ),
                {"user_id": session["user_id"]},
            ).mappings().first()
        except Exception:
            db.session.rollback()
            app.logger.exception("Driver password lookup failed")
            return "Unable to change your password right now.", 500

        if not current_password or not new_password or not confirm_password:
            message = "Complete all password fields."
        elif (
            user is None
            or not user["password_hash"]
            or not check_password_hash(
                user["password_hash"], current_password
            )
        ):
            message = "Current password is incorrect."
        elif new_password != confirm_password:
            message = "New passwords do not match."
        else:
            password_errors = get_password_validation_errors(new_password)
            if password_errors:
                message = format_password_validation_errors(password_errors)
            elif check_password_hash(user["password_hash"], new_password):
                message = "Choose a password different from your current password."
            else:
                try:
                    update_result = db.session.execute(
                        text(
                            """
                            UPDATE app_user
                            SET password_hash = :new_password_hash
                            WHERE user_id = :user_id
                              AND role = 'DRIVER'
                              AND password_hash = :current_password_hash
                            """
                        ),
                        {
                            "new_password_hash": generate_password_hash(
                                new_password
                            ),
                            "user_id": session["user_id"],
                            "current_password_hash": user["password_hash"],
                        },
                    )
                    if update_result.rowcount != 1:
                        raise RuntimeError("Driver password was not updated")

                    db.session.execute(
                        text(
                            """
                            INSERT INTO audit_log
                                (category, actor_user_id, target_user_id,
                                 success, reason)
                            VALUES
                                ('PASSWORD_CHANGE', :user_id, :user_id,
                                 TRUE, :reason)
                            """
                        ),
                        {
                            "user_id": session["user_id"],
                            "reason": "Driver changed password",
                        },
                    )
                    db.session.commit()
                except Exception:
                    db.session.rollback()
                    app.logger.exception("Driver password change failed")
                    message = (
                        "Unable to change your password right now. "
                        "Please try again."
                    )
                else:
                    flash("Password changed successfully.", "success")
                    return redirect(url_for("driver_profile"))

    return render_template(
        "driver_change_password.html",
        message=message,
        password_errors=password_errors,
        password_requirements=get_password_requirements(),
    )


# 22580, 23861, 23864, 23866 & 23868 - Driver point history

@app.get("/driver/point-history")
@driver_required
def driver_point_history():
    try:
        point_history = db.session.execute(
            text(
                """
                SELECT pc.point_change_id,
                       pc.points,
                       pc.reason,
                       pc.created_at,
                       s.name AS sponsor_name
                FROM point_change AS pc
                JOIN sponsor_org AS s
                  ON s.sponsor_org_id = pc.sponsor_org_id
                WHERE pc.driver_user_id = :driver_user_id
                ORDER BY pc.created_at DESC, pc.point_change_id DESC
                """
            ),
            {"driver_user_id": session["user_id"]},
        ).mappings().all()
    except Exception:
        db.session.rollback()
        app.logger.exception("Driver point history database error")
        return "Unable to load point history right now.", 500

    return render_template(
        "driver_point_history.html",
        point_history=point_history,
    )


# 23886, 23887, 23888, 23890 & 23892 - Driver purchase self-service

@app.get("/driver/orders")
@driver_required
def driver_orders():
    """Show the authenticated driver's complete purchase history."""

    try:
        orders = db.session.execute(
            text(
                """
                SELECT po.order_id,
                       po.status,
                       po.total_points,
                       po.total_usd,
                       po.created_at,
                       s.name AS sponsor_name
                FROM purchase_order AS po
                JOIN sponsor_org AS s
                  ON s.sponsor_org_id = po.sponsor_org_id
                WHERE po.driver_user_id = :driver_user_id
                ORDER BY po.created_at DESC, po.order_id DESC
                """
            ),
            {"driver_user_id": session["user_id"]},
        ).mappings().all()
    except Exception:
        db.session.rollback()
        app.logger.exception("Driver purchase history database error")
        return "Unable to load purchase history right now.", 500

    return render_template(
        "driver_orders.html",
        orders=orders,
    )


@app.get("/driver/orders/<int:order_id>")
@driver_required
def driver_order_detail(order_id):
    """Show one purchase and its line items when it belongs to the driver."""

    parameters = {
        "order_id": order_id,
        "driver_user_id": session["user_id"],
    }

    try:
        order = db.session.execute(
            text(
                """
                SELECT po.order_id,
                       po.status,
                       po.total_points,
                       po.total_usd,
                       po.created_at,
                       s.name AS sponsor_name
                FROM purchase_order AS po
                JOIN sponsor_org AS s
                  ON s.sponsor_org_id = po.sponsor_org_id
                WHERE po.order_id = :order_id
                  AND po.driver_user_id = :driver_user_id
                """
            ),
            parameters,
        ).mappings().first()

        if order is None:
            return "Order not found.", 404

        order_lines = db.session.execute(
            text(
                """
                SELECT ol.order_line_id,
                       ol.external_product_id,
                       ol.title,
                       ol.quantity,
                       ol.unit_price_usd,
                       ol.unit_points
                FROM order_line AS ol
                JOIN purchase_order AS po
                  ON po.order_id = ol.order_id
                WHERE ol.order_id = :order_id
                  AND po.driver_user_id = :driver_user_id
                ORDER BY ol.order_line_id ASC
                """
            ),
            parameters,
        ).mappings().all()
    except Exception:
        db.session.rollback()
        app.logger.exception("Driver purchase detail database error")
        return "Unable to load purchase details right now.", 500

    return render_template(
        "driver_order_detail.html",
        order=order,
        order_lines=order_lines,
    )


@app.post("/driver/orders/<int:order_id>/cancel")
@driver_required
def driver_cancel_order(order_id):
    """Cancel an owned order only while it is still in PLACED status."""

    parameters = {
        "order_id": order_id,
        "driver_user_id": session["user_id"],
    }

    try:
        order = db.session.execute(
            text(
                """
                SELECT order_id, status, total_points, sponsor_org_id
                FROM purchase_order
                WHERE order_id = :order_id
                  AND driver_user_id = :driver_user_id
                FOR UPDATE
                """
            ),
            parameters,
        ).mappings().first()

        if order is None:
            db.session.rollback()
            return "Order not found.", 404

        if order["status"] != "PLACED":
            db.session.rollback()
            flash(
                "This order can no longer be canceled because it is not in "
                "Placed status.",
                "error",
            )
            return redirect(
                url_for("driver_order_detail", order_id=order_id)
            )

        update_result = db.session.execute(
            text(
                """
                UPDATE purchase_order
                SET status = 'CANCELLED'
                WHERE order_id = :order_id
                  AND driver_user_id = :driver_user_id
                  AND status = 'PLACED'
                """
            ),
            parameters,
        )

        if update_result.rowcount != 1:
            db.session.rollback()
            flash(
                "The order could not be canceled because its status changed. "
                "Please review the current order status.",
                "error",
            )
            return redirect(
                url_for("driver_order_detail", order_id=order_id)
            )

        refund_parameters = {
            **parameters,
            "points": order["total_points"],
            "sponsor_org_id": order["sponsor_org_id"],
            "reason": f"Refund for canceled order #{order_id}",
        }
        refund_result = db.session.execute(
            text(
                """
                UPDATE driver_profile
                SET point_balance = point_balance + :points
                WHERE user_id = :driver_user_id
                """
            ),
            refund_parameters,
        )
        if refund_result.rowcount != 1:
            raise RuntimeError("Driver balance was not updated")

        db.session.execute(
            text(
                """
                INSERT INTO point_change
                    (driver_user_id, sponsor_org_id, actor_user_id,
                     points, reason)
                VALUES
                    (:driver_user_id, :sponsor_org_id, :driver_user_id,
                     :points, :reason)
                """
            ),
            refund_parameters,
        )

        db.session.commit()
    except Exception:
        db.session.rollback()
        app.logger.exception("Driver order cancellation failed")
        return "Unable to cancel this order right now.", 500

    flash(f"Order #{order_id} was canceled successfully.", "success")
    return redirect(url_for("driver_order_detail", order_id=order_id))


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

# Catalog browsing, sponsor isolation, secured catalog API

def get_positive_int(
    raw_value: str | None,
    default: int,
    maximum: int,
) -> int | None:
    """Return a bounded positive integer, or None for invalid input."""

    if raw_value is None or raw_value == "":
        return default

    try:
        value = int(raw_value)
    except ValueError:
        return None

    if value < 1 or value > maximum:
        return None

    return value


def get_driver_catalog_page(
    driver_user_id: int,
    page: int,
    page_size: int,
) -> tuple[list[dict], int]:
    """
    Load one page of the authenticated driver's active sponsor catalog.

    Sponsor scope is derived from driver_profile in SQL. It is never accepted
    from the query string or trusted from the browser session.
    """

    offset = (page - 1) * page_size

    filters = {
        "driver_user_id": driver_user_id,
    }

    total_items = db.session.execute(
        text(
            """
            SELECT COUNT(*) AS total_items
            FROM app_user AS u
            JOIN driver_profile AS dp
              ON dp.user_id = u.user_id
            JOIN sponsor_org AS so
              ON so.sponsor_org_id = dp.sponsor_org_id
            JOIN catalog_item AS ci
              ON ci.sponsor_org_id = dp.sponsor_org_id
            WHERE u.user_id = :driver_user_id
              AND u.role = 'DRIVER'
              AND u.status = 'ACTIVE'
              AND so.status = 'ACTIVE'
              AND ci.active = 1
            """
        ),
        filters,
    ).scalar_one()

    catalog_items = db.session.execute(
        text(
            """
            SELECT
                ci.catalog_item_id,
                ci.external_product_id,
                ci.title,
                ci.description,
                ci.price_usd,
                ci.image_url,
                CEILING(ci.price_usd / so.point_dollar_value) AS points_price
            FROM app_user AS u
            JOIN driver_profile AS dp
              ON dp.user_id = u.user_id
            JOIN sponsor_org AS so
              ON so.sponsor_org_id = dp.sponsor_org_id
            JOIN catalog_item AS ci
              ON ci.sponsor_org_id = dp.sponsor_org_id
            WHERE u.user_id = :driver_user_id
              AND u.role = 'DRIVER'
              AND u.status = 'ACTIVE'
              AND so.status = 'ACTIVE'
              AND ci.active = 1
            ORDER BY ci.catalog_item_id ASC
            LIMIT :page_size OFFSET :offset
            """
        ),
        {
            "driver_user_id": driver_user_id,
            "page_size": page_size,
            "offset": offset,
        },
    ).mappings().all()

    return [dict(item) for item in catalog_items], total_items


@app.get("/driver/catalog")
@driver_required
def driver_catalog():
    """Render the authenticated driver's paginated sponsor catalog."""

    page = get_positive_int(
        request.args.get("page"),
        default=1,
        maximum=1_000_000,
    )
    page_size = get_positive_int(
        request.args.get("pageSize"),
        default=12,
        maximum=50,
    )

    if page is None or page_size is None:
        return "page and pageSize must be positive integers.", 400

    try:
        catalog_items, total_items = get_driver_catalog_page(
            driver_user_id=session["user_id"],
            page=page,
            page_size=page_size,
        )
    except Exception:
        db.session.rollback()
        app.logger.exception("Driver catalog database error")
        return "Unable to load catalog right now.", 500

    total_pages = max(1, (total_items + page_size - 1) // page_size)

    if page > total_pages and total_items > 0:
        return redirect(
            url_for(
                "driver_catalog",
                page=total_pages,
                pageSize=page_size,
            )
        )

    return render_template(
        "driver_catalog.html",
        catalog_items=catalog_items,
        page=page,
        page_size=page_size,
        total_items=total_items,
        total_pages=total_pages,
    )


@app.post("/driver/catalog/<int:catalog_item_id>/purchase")
@driver_required
def driver_purchase_catalog_item(catalog_item_id):
    """Purchase one active item from the authenticated driver's catalog."""

    lookup_parameters = {
        "catalog_item_id": catalog_item_id,
        "driver_user_id": session["user_id"],
    }

    try:
        item = db.session.execute(
            text(
                """
                SELECT ci.catalog_item_id,
                       ci.external_product_id,
                       ci.title,
                       ci.price_usd,
                       dp.sponsor_org_id,
                       dp.point_balance,
                       CEILING(
                           ci.price_usd / so.point_dollar_value
                       ) AS points_price
                FROM driver_profile AS dp
                JOIN sponsor_org AS so
                  ON so.sponsor_org_id = dp.sponsor_org_id
                JOIN catalog_item AS ci
                  ON ci.sponsor_org_id = dp.sponsor_org_id
                WHERE dp.user_id = :driver_user_id
                  AND ci.catalog_item_id = :catalog_item_id
                  AND so.status = 'ACTIVE'
                  AND ci.active = 1
                FOR UPDATE
                """
            ),
            lookup_parameters,
        ).mappings().first()

        if item is None:
            db.session.rollback()
            return "Catalog item not found.", 404

        points_price = int(item["points_price"])
        if item["point_balance"] < points_price:
            db.session.rollback()
            flash(
                f"You need {points_price} points to purchase "
                f"{item['title']}, but your balance is "
                f"{item['point_balance']} points.",
                "error",
            )
            return redirect(url_for("driver_catalog"))

        purchase_parameters = {
            "driver_user_id": session["user_id"],
            "sponsor_org_id": item["sponsor_org_id"],
            "catalog_item_id": item["catalog_item_id"],
            "external_product_id": item["external_product_id"],
            "title": item["title"],
            "price_usd": item["price_usd"],
            "points_price": points_price,
            "reason": f"Catalog purchase: {item['title']}",
        }

        balance_result = db.session.execute(
            text(
                """
                UPDATE driver_profile
                SET point_balance = point_balance - :points_price
                WHERE user_id = :driver_user_id
                  AND sponsor_org_id = :sponsor_org_id
                  AND point_balance >= :points_price
                """
            ),
            purchase_parameters,
        )
        if balance_result.rowcount != 1:
            db.session.rollback()
            flash(
                "Your point balance changed before the purchase completed. "
                "Please review your balance and try again.",
                "error",
            )
            return redirect(url_for("driver_catalog"))

        order_result = db.session.execute(
            text(
                """
                INSERT INTO purchase_order
                    (driver_user_id, sponsor_org_id, placed_by_user_id,
                     status, total_points, total_usd)
                VALUES
                    (:driver_user_id, :sponsor_org_id, :driver_user_id,
                     'PLACED', :points_price, :price_usd)
                """
            ),
            purchase_parameters,
        )
        order_id = order_result.lastrowid
        if order_id is None:
            raise RuntimeError("Purchase order ID was not returned")

        line_parameters = {
            **purchase_parameters,
            "order_id": order_id,
        }
        db.session.execute(
            text(
                """
                INSERT INTO order_line
                    (order_id, external_product_id, title, quantity,
                     unit_price_usd, unit_points)
                VALUES
                    (:order_id, :external_product_id, :title, 1,
                     :price_usd, :points_price)
                """
            ),
            line_parameters,
        )
        db.session.execute(
            text(
                """
                INSERT INTO point_change
                    (driver_user_id, sponsor_org_id, actor_user_id,
                     points, reason)
                VALUES
                    (:driver_user_id, :sponsor_org_id, :driver_user_id,
                     -:points_price, :reason)
                """
            ),
            purchase_parameters,
        )
        db.session.commit()
    except Exception:
        db.session.rollback()
        app.logger.exception("Driver catalog purchase failed")
        return "Unable to complete this purchase right now.", 500

    flash(
        f"{item['title']} was purchased successfully for "
        f"{points_price} points.",
        "success",
    )
    return redirect(url_for("driver_order_detail", order_id=order_id))


@app.get("/api/catalog/items")
@driver_required
def catalog_items_api():
    """Return the same secured, sponsor-scoped page as JSON."""

    page = get_positive_int(
        request.args.get("page"),
        default=1,
        maximum=1_000_000,
    )
    page_size = get_positive_int(
        request.args.get("pageSize"),
        default=12,
        maximum=50,
    )

    if page is None or page_size is None:
        return {
            "message": "page and pageSize must be positive integers.",
        }, 400

    try:
        catalog_items, total_items = get_driver_catalog_page(
            driver_user_id=session["user_id"],
            page=page,
            page_size=page_size,
        )
    except Exception:
        db.session.rollback()
        app.logger.exception("Catalog API database error")
        return {
            "message": "Unable to load catalog right now.",
        }, 500

    total_pages = (
        (total_items + page_size - 1) // page_size
        if total_items > 0
        else 0
    )

    return {
        "items": catalog_items,
        "pagination": {
            "page": page,
            "pageSize": page_size,
            "totalItems": total_items,
            "totalPages": total_pages,
        },
    }

# 23319 - Protect stored passwords
@app.cli.command("set-password")
@click.argument("email")
def set_password(email):
    """Hash and store a password for an existing user."""
    password = click.prompt("New password", hide_input=True, confirmation_prompt=True)
    validation_errors = get_password_validation_errors(password)
    if validation_errors:
        requirements = ", ".join(validation_errors)
        raise click.ClickException(f"Password must include {requirements}.")

    result = db.session.execute(
        text("UPDATE app_user SET password_hash = :hash WHERE email = :email"),
        {"hash": generate_password_hash(password), "email": email.strip().lower()},
    )
    db.session.commit()
    click.echo("Password updated." if result.rowcount else "No user with that email.")


if __name__ == "__main__":
    app.run(debug=os.getenv("FLASK_DEBUG") == "1")


