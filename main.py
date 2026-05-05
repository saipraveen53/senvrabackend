from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from pymongo import MongoClient
import bcrypt
import jwt
import datetime
import os
import sys

app = FastAPI()

# React frontend nundi requests allow cheyadaniki CORS setup[cite: 1]
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# JWT Token kosam secret key (Deenni safe ga pettukovali)
SECRET_KEY = "senvra_super_secret_key"

# --- MONGODB CONNECTION SETUP ---
# Password lo unna '@' ni '%40' ga marchanu parse error rakunda
MONGO_URI = "mongodb+srv://saipraveenthandra99:sai@cluster0.9wmwes8.mongodb.net/?appName=Cluster0"

# Variables ni None ga initialize chestunnam (NameError raakunda)
client = None
db = None
users_collection = None

try:
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    # Connection nijamga pani chestundo ledo check cheyadaniki
    client.server_info() 
    
    db = client["senvra_db"]
    users_collection = db["users"]
    print("Mawa, MongoDB Connected Successfully!")
except Exception as e:
    print(f"CRITICAL ERROR: Database connection failed: {e}")
    # Database lekunda APIs pani cheyavu kabatti stop chestunnam
    sys.exit(1)

# --- MODELS ---
class UserSignup(BaseModel):
    name: str
    email: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

# --- ROUTES ---

@app.get("/")
def home():
    return {"message": "Senvra AI Backend is running!"}

@app.post("/api/auth/signup", status_code=status.HTTP_201_CREATED)
def signup(user: UserSignup):
    email = user.email.lower()
    
    # 1. User already unnada ani check
    existing_user = users_collection.find_one({"email": email})
    if existing_user:
        raise HTTPException(status_code=400, detail="User with this email already exists!")
    
    # 2. Password Hash cheyadam
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(user.password.encode('utf-8'), salt)
    
    # 3. MongoDB lo save cheyadam (Frontend roles ki match ayyela)[cite: 1]
    new_user = {
        "name": user.name,
        "email": email,
        "password": hashed_password.decode('utf-8'),
        "role": "applicant"  # Default role from frontend logic[cite: 1]
    }
    users_collection.insert_one(new_user)
    
    return {"message": "Signup successful! Data saved in MongoDB."}

@app.post("/api/auth/login")
def login(user: UserLogin):
    email = user.email.lower()
    
    # 4. Database nundi user ni vethukudam
    db_user = users_collection.find_one({"email": email})
    
    if not db_user:
        raise HTTPException(status_code=400, detail="User not found!")
        
    # 5. Password correct ah kado verify cheyadam
    if not bcrypt.checkpw(user.password.encode('utf-8'), db_user["password"].encode('utf-8')):
        raise HTTPException(status_code=400, detail="Incorrect password!")
        
    # 6. JWT Token Generate cheyadam (Frontend expected fields tho)[cite: 1]
    expiration = datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    token_payload = {
        "email": email,
        "name": db_user["name"],
        "role": db_user.get("role", "applicant"), #[cite: 1]
        "exp": expiration
    }
    
    token = jwt.encode(token_payload, SECRET_KEY, algorithm="HS256")
    
    return {
        "message": "Login successful!",
        "accessToken": token, # Frontend handles 'accessToken'[cite: 1]
        "user": {
            "name": db_user["name"],
            "email": email,
            "role": db_user.get("role", "applicant")
        }
    }