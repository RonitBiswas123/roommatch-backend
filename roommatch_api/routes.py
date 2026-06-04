from fastapi import APIRouter, HTTPException
from roommatch_api.database import get_cursor
from roommatch_api.models import UserRegister, UserLogin, UserResponse, ProfileCreate
from passlib.context import CryptContext

router = APIRouter()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# ════════════════════════════════
# POST /register
# ════════════════════════════════
@router.post("/register")
def register(user: UserRegister):
    conn, cur = get_cursor()
    try:
        # Check if email already exists
        cur.execute("SELECT id FROM users WHERE email = %s", (user.email,))
        existing = cur.fetchone()
        if existing:
            raise HTTPException(status_code=400, detail="Email already registered")

        # Hash the password
        hashed_password = pwd_context.hash(user.password)

        # Insert new user
        cur.execute("""
            INSERT INTO users (name, email, password, branch, year, gender)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING id, name, email, branch, year, gender
        """, (user.name, user.email, hashed_password, user.branch, user.year, user.gender))

        new_user = cur.fetchone()
        conn.commit()

        return {
            "message": "User registered successfully",
            "user": {
                "id":     new_user[0],
                "name":   new_user[1],
                "email":  new_user[2],
                "branch": new_user[3],
                "year":   new_user[4],
                "gender": new_user[5]
            }
        }

    except HTTPException:
        raise
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close()
        conn.close()

# ════════════════════════════════
# GET /users
# ════════════════════════════════
@router.get("/users")
def get_users():
    conn, cur = get_cursor()
    try:
        cur.execute("""
            SELECT id, name, email, branch, year, gender
            FROM users
            ORDER BY created_at DESC
        """)
        rows = cur.fetchall()
        users = [
            {
                "id":     row[0],
                "name":   row[1],
                "email":  row[2],
                "branch": row[3],
                "year":   row[4],
                "gender": row[5]
            }
            for row in rows
        ]
        return {"users": users, "total": len(users)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close()
        conn.close()

# ════════════════════════════════
# GET /users/{user_id}
# ════════════════════════════════
@router.get("/users/{user_id}")
def get_user(user_id: int):
    conn, cur = get_cursor()
    try:
        cur.execute("""
            SELECT u.id, u.name, u.email, u.branch, u.year, u.gender,
                   p.sleep_time, p.wake_time, p.study_hours,
                   p.cleanliness, p.noise, p.guests, p.about
            FROM users u
            LEFT JOIN profiles p ON u.id = p.user_id
            WHERE u.id = %s
        """, (user_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="User not found")
        return {
            "id":          row[0],
            "name":        row[1],
            "email":       row[2],
            "branch":      row[3],
            "year":        row[4],
            "gender":      row[5],
            "sleep_time":  row[6],
            "wake_time":   row[7],
            "study_hours": row[8],
            "cleanliness": row[9],
            "noise":       row[10],
            "guests":      row[11],
            "about":       row[12]
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close()
        conn.close()