from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from pymongo import MongoClient, ReturnDocument
import bcrypt
import jwt
import datetime
import os
import sys
import certifi

app = FastAPI()

# React frontend nundi requests allow cheyadaniki CORS setup[cite: 1]
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SECRET_KEY = "senvra_super_secret_key"

# --- MONGODB CONNECTION SETUP ---
# Nee kotha file lo password 'sai' ani undi, adhe ikkada pedutunnanu
MONGO_URI = "mongodb+srv://saipraveenthandra99:sai@cluster0.9wmwes8.mongodb.net/?appName=Cluster0"

client = None
db = None
users_collection = None
counters_collection = None

try:
    # Syntax error ni ikkada fix chesa bava
    client = MongoClient(
        MONGO_URI, 
        serverSelectionTimeoutMS=5000,
        tls=True,
        tlsCAFile=certifi.where(),
        tlsAllowInvalidCertificates=False,
        connectTimeoutMS=20000,
        socketTimeoutMS=20000
    )
    # Connection check
    client.server_info() 
    
    db = client["senvra_db"]
    users_collection = db["users"]
    counters_collection = db["counters"]
    
    # Counter initialize cheyadam (Start from 0)
    if not counters_collection.find_one({"_id": "userid"}):
        counters_collection.insert_one({"_id": "userid", "seq": 0})
        
    print("Mawa, MongoDB Connected Successfully!")
except Exception as e:
    print(f"CRITICAL ERROR: Database connection failed: {e}")
    sys.exit(1)

# --- MODELS ---
class UserSignup(BaseModel):
    name: str
    email: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

# --- AUTO-INCREMENT LOGIC ---
def get_next_sequence_value():
    counter = counters_collection.find_one_and_update(
        {"_id": "userid"},
        {"$inc": {"seq": 1}},
        return_document=ReturnDocument.AFTER
    )
    return counter["seq"]

# --- ROUTES ---

@app.get("/")
def home():
    return {"message": "Senvra AI Backend is running!"}

@app.post("/api/auth/signup", status_code=status.HTTP_201_CREATED)
def signup(user: UserSignup):
    email = user.email.lower()
    
    existing_user = users_collection.find_one({"email": email})
    if existing_user:
        raise HTTPException(status_code=400, detail="User with this email already exists!")
    
    # Sequential ID generation (1, 2, 3...)
    new_id = get_next_sequence_value()
    
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(user.password.encode('utf-8'), salt)
    
    new_user = {
        "app_id": new_id,
        "name": user.name,
        "email": email,
        "password": hashed_password.decode('utf-8'),
        "role": "applicant" # Default role[cite: 1]
    }
    users_collection.insert_one(new_user)
    
    return {"message": "Signup successful!", "id": new_id}

@app.post("/api/auth/login")
def login(user: UserLogin):
    email = user.email.lower()
    db_user = users_collection.find_one({"email": email})
    
    if not db_user:
        raise HTTPException(status_code=400, detail="User not found!")
        
    if not bcrypt.checkpw(user.password.encode('utf-8'), db_user["password"].encode('utf-8')):
        raise HTTPException(status_code=400, detail="Incorrect password!")
        
    expiration = datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    token_payload = {
        "email": email,
        "name": db_user["name"],
        "role": db_user.get("role", "applicant"),
        "app_id": db_user.get("app_id"),
        "exp": expiration
    }
    
    token = jwt.encode(token_payload, SECRET_KEY, algorithm="HS256")
    
    return {
        "message": "Login successful!",
        "accessToken": token, 
        "user": {
            "app_id": db_user.get("app_id"),
            "name": db_user["name"],
            "email": email,
            "role": db_user.get("role", "applicant")
        }
    }