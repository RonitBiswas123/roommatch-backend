from fastapi import APIRouter, HTTPException, Depends, Header
from roommatch_api.database import get_cursor
from roommatch_api.models import UserRegister, UserLogin, ProfileCreate
from roommatch_api.auth import create_access_token, get_current_user
from passlib.context import CryptContext
from typing import Optional

router = APIRouter()
pwd_context = CryptContext(
    schemes=["bcrypt"],
    deprecated="auto",
    bcrypt__rounds=12
)

def hash_password(password: str) -> str:
    return pwd_context.hash(password[:72])

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain[:72], hashed)

# ════════════════════════════════
# POST /register
# ════════════════════════════════
@router.post("/register")
def register(user: UserRegister):
    conn, cur = get_cursor()
    try:
        cur.execute("SELECT id FROM users WHERE email = %s", (user.email,))
        if cur.fetchone():
            raise HTTPException(status_code=400, detail="Email already registered")

        hashed_password = hash_password(user.password)

        cur.execute("""
            INSERT INTO users (name, email, password, branch, year, gender)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING id, name, email, branch, year, gender
        """, (user.name, user.email, hashed_password, user.branch, user.year, user.gender))

        new_user = cur.fetchone()
        conn.commit()

        token = create_access_token({
            "user_id": new_user[0],
            "email":   new_user[2]
        })

        return {
            "message": "User registered successfully",
            "access_token": token,
            "token_type": "bearer",
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
# POST /login
# ════════════════════════════════
@router.post("/login")
def login(credentials: UserLogin):
    conn, cur = get_cursor()
    try:
        cur.execute("""
            SELECT id, name, email, password, branch, year, gender
            FROM users WHERE email = %s
        """, (credentials.email,))
        user = cur.fetchone()

        if not user:
            raise HTTPException(status_code=401, detail="Invalid email or password")

        if not verify_password(credentials.password, user[3]):
            raise HTTPException(status_code=401, detail="Invalid email or password")

        token = create_access_token({
            "user_id": user[0],
            "email":   user[2]
        })

        return {
            "message": "Login successful",
            "access_token": token,
            "token_type": "bearer",
            "user": {
                "id":     user[0],
                "name":   user[1],
                "email":  user[2],
                "branch": user[4],
                "year":   user[5],
                "gender": user[6]
            }
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close()
        conn.close()

# ════════════════════════════════
# GET /me — get current logged in user
# ════════════════════════════════
@router.get("/me")
def get_me(current_user = Depends(get_current_user)):
    conn, cur = get_cursor()
    try:
        cur.execute("""
            SELECT u.id, u.name, u.email, u.branch, u.year, u.gender,
                   p.sleep_time, p.wake_time, p.study_hours,
                   p.cleanliness, p.noise, p.guests, p.about
            FROM users u
            LEFT JOIN profiles p ON u.id = p.user_id
            WHERE u.id = %s
        """, (current_user["user_id"],))
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

# ════════════════════════════════
# GET /users
# ════════════════════════════════
@router.get("/users")
def get_users():
    conn, cur = get_cursor()
    try:
        cur.execute("""
            SELECT id, name, email, branch, year, gender
            FROM users ORDER BY created_at DESC
        """)
        rows = cur.fetchall()
        return {
            "users": [
                {"id": r[0], "name": r[1], "email": r[2],
                 "branch": r[3], "year": r[4], "gender": r[5]}
                for r in rows
            ],
            "total": len(rows)
        }
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
            "id": row[0], "name": row[1], "email": row[2],
            "branch": row[3], "year": row[4], "gender": row[5],
            "sleep_time": row[6], "wake_time": row[7],
            "study_hours": row[8], "cleanliness": row[9],
            "noise": row[10], "guests": row[11], "about": row[12]
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close()
        conn.close()

# ════════════════════════════════
# POST /profile/{user_id}
# ════════════════════════════════
@router.post("/profile/{user_id}")
def create_profile(user_id: int, profile: ProfileCreate):
    conn, cur = get_cursor()
    try:
        cur.execute("SELECT id FROM users WHERE id = %s", (user_id,))
        if not cur.fetchone():
            raise HTTPException(status_code=404, detail="User not found")

        cur.execute("SELECT id FROM profiles WHERE user_id = %s", (user_id,))
        existing = cur.fetchone()

        if existing:
            cur.execute("""
                UPDATE profiles
                SET sleep_time=%s, wake_time=%s, study_hours=%s,
                    cleanliness=%s, noise=%s, guests=%s, about=%s,
                    updated_at=CURRENT_TIMESTAMP
                WHERE user_id=%s
            """, (profile.sleep_time, profile.wake_time, profile.study_hours,
                  profile.cleanliness, profile.noise, profile.guests,
                  profile.about, user_id))
        else:
            cur.execute("""
                INSERT INTO profiles
                (user_id, sleep_time, wake_time, study_hours, cleanliness, noise, guests, about)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
            """, (user_id, profile.sleep_time, profile.wake_time,
                  profile.study_hours, profile.cleanliness,
                  profile.noise, profile.guests, profile.about))

        conn.commit()
        return {"message": "Profile saved successfully", "user_id": user_id}

    except HTTPException:
        raise
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close()
        conn.close()

# ════════════════════════════════
# GET /profile/{user_id}
# ════════════════════════════════
@router.get("/profile/{user_id}")
def get_profile(user_id: int):
    conn, cur = get_cursor()
    try:
        cur.execute("""
            SELECT u.id, u.name, u.email, u.branch, u.year, u.gender,
                   p.sleep_time, p.wake_time, p.study_hours,
                   p.cleanliness, p.noise, p.guests, p.about, p.updated_at
            FROM users u
            LEFT JOIN profiles p ON u.id = p.user_id
            WHERE u.id = %s
        """, (user_id,))
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="User not found")
        return {
            "id": row[0], "name": row[1], "email": row[2],
            "branch": row[3], "year": row[4], "gender": row[5],
            "sleep_time": row[6], "wake_time": row[7],
            "study_hours": row[8], "cleanliness": row[9],
            "noise": row[10], "guests": row[11],
            "about": row[12], "updated_at": str(row[13]) if row[13] else None
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close()
        conn.close()

# ════════════════════════════════
# GET /students
# ════════════════════════════════
@router.get("/students")
def get_students(
    branch: str = None,
    year:   int = None,
    gender: str = None
):
    conn, cur = get_cursor()
    try:
        query = """
            SELECT u.id, u.name, u.branch, u.year, u.gender,
                   p.sleep_time, p.wake_time, p.study_hours,
                   p.cleanliness, p.noise, p.guests, p.about
            FROM users u
            JOIN profiles p ON u.id = p.user_id
            WHERE 1=1
        """
        params = []
        if branch:
            query += " AND u.branch = %s"
            params.append(branch)
        if year:
            query += " AND u.year = %s"
            params.append(year)
        if gender:
            query += " AND u.gender = %s"
            params.append(gender)
        query += " ORDER BY u.name"

        cur.execute(query, tuple(params))
        rows = cur.fetchall()

        return {
            "students": [
                {
                    "id": r[0], "name": r[1], "branch": r[2],
                    "year": r[3], "gender": r[4],
                    "sleep_time": r[5], "wake_time": r[6],
                    "study_hours": r[7], "cleanliness": r[8],
                    "noise": r[9], "guests": r[10], "about": r[11]
                }
                for r in rows
            ],
            "total": len(rows)
        }
    except Exception as e:
        print(f"ERROR: {e}")
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close()
        conn.close()

# ════════════════════════════════
# DELETE /users/{user_id}
# ════════════════════════════════
@router.delete("/users/{user_id}")
def delete_user(user_id: int):
    conn, cur = get_cursor()
    try:
        cur.execute("SELECT id FROM users WHERE id = %s", (user_id,))
        if not cur.fetchone():
            raise HTTPException(status_code=404, detail="User not found")
        cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
        conn.commit()
        return {"message": "User deleted successfully"}
    except HTTPException:
        raise
    except Exception as e:
        conn.rollback()
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        cur.close()
        conn.close()