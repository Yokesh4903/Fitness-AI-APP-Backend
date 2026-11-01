
import os
import sqlite3
from functools import wraps

from flask import Flask, jsonify, request, g
from flask_cors import CORS
from dotenv import load_dotenv
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from openai import OpenAI, OpenAIError

load_dotenv()

app = Flask(__name__)
CORS(app)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "users.db")
SECRET_KEY = os.getenv("FLASK_SECRET_KEY")

if not SECRET_KEY:
    raise RuntimeError(
        "FLASK_SECRET_KEY is missing. Add it to backend/.env"
    )

serializer = URLSafeTimedSerializer(SECRET_KEY, salt="fitness-auth")


# ---------------- DATABASE ----------------

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    with sqlite3.connect(DATABASE) as db:
        db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)


init_db()


# ---------------- AUTHENTICATION ----------------

def create_token(user_id):
    return serializer.dumps({"user_id": user_id})


def token_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        header = request.headers.get("Authorization", "")

        if not header.startswith("Bearer "):
            return jsonify({"error": "Please log in first."}), 401

        token = header[7:].strip()

        try:
            payload = serializer.loads(token, max_age=60 * 60 * 24 * 7)
        except SignatureExpired:
            return jsonify({"error": "Your session expired. Please log in again."}), 401
        except BadSignature:
            return jsonify({"error": "Invalid login session."}), 401

        user = get_db().execute(
            "SELECT id, name, email FROM users WHERE id = ?",
            (payload.get("user_id"),)
        ).fetchone()

        if user is None:
            return jsonify({"error": "Account not found. Please log in again."}), 401

        g.current_user = user
        return function(*args, **kwargs)

    return wrapper


@app.route("/", methods=["GET"])
def home():
    return jsonify({
        "message": "AI Fitness Coach API is running!",
        "status": "success"
    })


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "healthy"}), 200


@app.route("/signup", methods=["POST"])
def signup():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Please send a JSON request body."}), 400

    name = data.get("name", "")
    email = data.get("email", "")
    password = data.get("password", "")

    if not all(isinstance(v, str) for v in (name, email, password)):
        return jsonify({"error": "All fields must be text."}), 400

    name = name.strip()
    email = email.strip().lower()

    if not name or not email or not password:
        return jsonify({"error": "Name, email and password are required."}), 400

    if len(name) > 100 or len(email) > 254:
        return jsonify({"error": "Name or email is too long."}), 400

    if "@" not in email or "." not in email.rsplit("@", 1)[-1]:
        return jsonify({"error": "Enter a valid email address."}), 400

    if len(password) < 6:
        return jsonify({"error": "Password must contain at least 6 characters."}), 400

    db = get_db()

    existing = db.execute(
        "SELECT id FROM users WHERE email = ?",
        (email,)
    ).fetchone()

    if existing:
        return jsonify({
            "error": "An account with this email already exists. Please log in."
        }), 409

    try:
        cursor = db.execute(
            "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
            (name, email, generate_password_hash(password))
        )
        db.commit()

        user_id = cursor.lastrowid
        token = create_token(user_id)

        return jsonify({
            "status": "success",
            "message": "Account created successfully.",
            "token": token,
            "user": {
                "id": user_id,
                "name": name,
                "email": email
            }
        }), 201

    except sqlite3.IntegrityError:
        db.rollback()
        return jsonify({"error": "An account with this email already exists."}), 409


@app.route("/login", methods=["POST"])
def login():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Please send a JSON request body."}), 400

    email = data.get("email", "")
    password = data.get("password", "")

    if not isinstance(email, str) or not isinstance(password, str):
        return jsonify({"error": "Email and password must be text."}), 400

    email = email.strip().lower()

    if not email or not password:
        return jsonify({"error": "Enter your email and password."}), 400

    user = get_db().execute(
        "SELECT id, name, email, password_hash FROM users WHERE email = ?",
        (email,)
    ).fetchone()

    if user is None or not check_password_hash(user["password_hash"], password):
        return jsonify({"error": "Invalid email or password."}), 401

    return jsonify({
        "status": "success",
        "message": "Login successful.",
        "token": create_token(user["id"]),
        "user": {
            "id": user["id"],
            "name": user["name"],
            "email": user["email"]
        }
    }), 200


@app.route("/me", methods=["GET"])
@token_required
def me():
    return jsonify({
        "status": "success",
        "user": {
            "id": g.current_user["id"],
            "name": g.current_user["name"],
            "email": g.current_user["email"]
        }
    }), 200


# ---------------- AI WORKOUT PLAN ----------------

@app.route("/workout-plan", methods=["POST"])
@token_required
def workout_plan():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Please send a JSON request body."}), 400

    goal = data.get("goal", "general fitness")
    activity = data.get("activity", "beginner")
    workout = data.get("workout", "home workout")
    age = data.get("age", "")
    limitations = data.get("limitations", "")

    fields = [goal, activity, workout, age, limitations]

    if not all(isinstance(value, str) for value in fields):
        return jsonify({"error": "Fitness details must be text values."}), 400

    if not goal.strip() or not activity.strip() or not workout.strip():
        return jsonify({
            "error": "Goal, activity level and workout preference are required."
        }), 400

    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return jsonify({"error": "AI service is not configured."}), 500

    try:
        client = OpenAI(api_key=api_key)
        response = client.responses.create(
            model="gpt-4.1-mini",
            instructions=(
                "You are a careful fitness coach. Create a practical beginner-friendly "
                "workout plan. Include warm-up, exercises, sets, repetitions or duration, "
                "rest periods, cool-down and recovery days. Do not diagnose conditions. "
                "Advise professional guidance for injuries or medical limitations."
            ),
            input=(
                f"Fitness goal: {goal}\n"
                f"Activity level: {activity}\n"
                f"Workout preference: {workout}\n"
                f"Age: {age or 'Not provided'}\n"
                f"Limitations or injuries: {limitations or 'Not provided'}\n\n"
                "Create a one-week workout plan."
            )
        )

        return jsonify({
            "status": "success",
            "workout_plan": response.output_text
        }), 200

    except OpenAIError:
        app.logger.exception("Workout-plan request failed.")
        return jsonify({"error": "The AI service could not generate a plan."}), 502

    except Exception:
        app.logger.exception("Unexpected workout-plan error.")
        return jsonify({"error": "An unexpected server error occurred."}), 500


# ---------------- AI DIET PLAN ----------------

@app.route("/diet-plan", methods=["POST"])
@token_required
def diet_plan():
    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Please send a JSON request body."}), 400

    goal = data.get("goal", "general fitness")
    diet = data.get("diet", "balanced diet")
    age = data.get("age", "")
    weight = data.get("weight", "")
    limitations = data.get("limitations", "")

    fields = [goal, diet, age, weight, limitations]

    if not all(isinstance(value, str) for value in fields):
        return jsonify({"error": "Fitness details must be text values."}), 400

    if not goal.strip() or not diet.strip():
        return jsonify({"error": "Goal and diet preference are required."}), 400

    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return jsonify({"error": "AI service is not configured."}), 500

    try:
        client = OpenAI(api_key=api_key)
        response = client.responses.create(
            model="gpt-4.1-mini",
            instructions=(
                "You are a responsible nutrition coach. Create a practical one-week "
                "meal plan using affordable, commonly available foods. Include breakfast, "
                "lunch, dinner and snacks for each day. Avoid extreme calorie restriction "
                "and unsupported medical claims. Mention that allergies and medical "
                "conditions require individualized professional advice."
            ),
            input=(
                f"Fitness goal: {goal}\n"
                f"Diet preference: {diet}\n"
                f"Age: {age or 'Not provided'}\n"
                f"Current weight: {weight or 'Not provided'}\n"
                f"Limitations or allergies: {limitations or 'Not provided'}\n\n"
                "Generate a one-week meal plan with clear daily headings."
            )
        )

        return jsonify({
            "status": "success",
            "diet_plan": response.output_text
        }), 200

    except OpenAIError:
        app.logger.exception("Diet-plan request failed.")
        return jsonify({"error": "The AI service could not generate a diet plan."}), 502

    except Exception:
        app.logger.exception("Unexpected diet-plan error.")
        return jsonify({"error": "An unexpected server error occurred."}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
/
