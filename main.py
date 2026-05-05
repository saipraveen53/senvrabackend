from fastapi import FastAPI, HTTPException, status, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from pymongo import MongoClient, ReturnDocument
from bson import ObjectId
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
import bcrypt
import jwt
import datetime
import os
import sys
import certifi
import io
import random
import string
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email_validator import validate_email, EmailNotValidError

app = FastAPI()
auth_scheme = HTTPBearer()

# CORS Setup
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SECRET_KEY = "senvra_super_secret_key"
MONGO_URI = "mongodb+srv://saipraveenthandra99:sai@cluster0.9wmwes8.mongodb.net/?appName=Cluster0"

# ========== EMAIL SMTP CONFIGURATION ==========
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USER = "saipraveenthandra99@gmail.com"
SMTP_PASSWORD = "hqqpioauacdsjqgk"
SMTP_FROM_EMAIL = "saipraveenthandra99@gmail.com"

# ========== DATABASE CONNECTION ==========
client = None
db = None
users_collection = None
counters_collection = None
assessments_collection = None
otp_collection = None

try:
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000, tls=True, tlsCAFile=certifi.where())
    client.server_info() 
    db = client["senvra_db"]
    users_collection = db["users"]
    counters_collection = db["counters"]
    assessments_collection = db["assessments"]
    otp_collection = db["otp_codes"]
    
    if not counters_collection.find_one({"_id": "userid"}):
        counters_collection.insert_one({"_id": "userid", "seq": 0})
    print("MongoDB Connected Successfully!")
except Exception as e:
    print(f"CRITICAL ERROR: Database connection failed: {e}")
    sys.exit(1)

# ========== TOKEN VERIFICATION ==========
def verify_token(credentials: HTTPAuthorizationCredentials = Depends(auth_scheme)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
        return payload
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid or expired token!")

# ========== MODELS ==========
class UserSignup(BaseModel):
    name: str
    email: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

class ExamSubmit(BaseModel):
    exam_name: str
    total_questions: int
    correct_answers: int
    wrong_answers: int

class OTPRequest(BaseModel):
    assessment_id: str

class OTPVerifyRequest(BaseModel):
    assessment_id: str
    otp: str

class PasswordVerifyRequest(BaseModel):
    assessment_id: str
    password: str

class CertificateDownloadRequest(BaseModel):
    assessment_id: str
    method: str  # "otp" or "password"
    otp: str = None
    password: str = None

# ========== OTP FUNCTIONS ==========
def generate_alphanumeric_otp(length=6):
    """Generate 6-digit alphanumeric OTP"""
    characters = string.digits + string.ascii_uppercase
    otp = ''.join(random.choices(characters, k=length))
    return otp

def save_otp(email, otp, expiry_minutes=5):
    """Save OTP to database with expiry time"""
    expiry_time = datetime.datetime.utcnow() + datetime.timedelta(minutes=expiry_minutes)
    
    otp_collection.update_one(
        {"email": email},
        {"$set": {
            "otp": otp,
            "created_at": datetime.datetime.utcnow(),
            "expires_at": expiry_time,
            "is_used": False
        }},
        upsert=True
    )
    return expiry_time

def verify_otp(email, otp):
    """Verify OTP code"""
    otp_record = otp_collection.find_one({
        "email": email,
        "otp": otp,
        "is_used": False,
        "expires_at": {"$gt": datetime.datetime.utcnow()}
    })
    
    if otp_record:
        otp_collection.update_one(
            {"_id": otp_record["_id"]},
            {"$set": {"is_used": True}}
        )
        return True
    return False

def delete_otp(email):
    """Delete OTP record"""
    otp_collection.delete_one({"email": email})

def send_otp_email(to_email, otp, user_name=None):
    """Send OTP to user's email"""
    try:
        msg = MIMEMultipart()
        msg["From"] = SMTP_FROM_EMAIL
        msg["To"] = to_email
        msg["Subject"] = "Your Certificate Download OTP - Senvra"
        
        html_body = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{
                    font-family: Arial, sans-serif;
                    background-color: #f4f4f4;
                    margin: 0;
                    padding: 0;
                }}
                .container {{
                    max-width: 500px;
                    margin: 50px auto;
                    background: white;
                    border-radius: 10px;
                    box-shadow: 0 4px 8px rgba(0,0,0,0.1);
                    overflow: hidden;
                }}
                .header {{
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 30px;
                    text-align: center;
                }}
                .content {{
                    padding: 30px;
                    text-align: center;
                }}
                .otp-code {{
                    font-size: 36px;
                    font-weight: bold;
                    color: #667eea;
                    background: #f0f0f0;
                    padding: 15px;
                    border-radius: 8px;
                    letter-spacing: 5px;
                    margin: 20px 0;
                    font-family: monospace;
                }}
                .footer {{
                    background: #f8f9fa;
                    padding: 15px;
                    text-align: center;
                    font-size: 12px;
                    color: #666;
                }}
                .warning {{
                    color: #dc3545;
                    font-size: 12px;
                    margin-top: 15px;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h2>🔐 Certificate Download Verification</h2>
                </div>
                <div class="content">
                    <p>Hello <strong>{user_name or 'User'}</strong>,</p>
                    <p>You have requested to download your certificate. Use the OTP code below to verify:</p>
                    <div class="otp-code">{otp}</div>
                    <p>This OTP is valid for <strong>5 minutes</strong>.</p>
                    <div class="warning">
                        ⚠️ If you didn't request this, please ignore this email.
                    </div>
                </div>
                <div class="footer">
                    <p>© 2025 Senvra. All rights reserved.</p>
                </div>
            </div>
        </body>
        </html>
        """
        
        msg.attach(MIMEText(html_body, "html"))
        
        server = smtplib.SMTP(SMTP_HOST, SMTP_PORT)
        server.starttls()
        server.login(SMTP_USER, SMTP_PASSWORD)
        server.send_message(msg)
        server.quit()
        
        return True
        
    except Exception as e:
        print(f"Email sending failed: {e}")
        return False

# ========== UTILS ==========
def get_next_sequence_value():
    counter = counters_collection.find_one_and_update(
        {"_id": "userid"},
        {"$inc": {"seq": 1}},
        return_document=ReturnDocument.AFTER
    )
    return counter["seq"]

def generate_certificate_for_assessment(assessment_id, app_id, assessment_data, current_user_email=None):
    """Generate certificate for an assessment"""
    try:
        print(f"🔍 Generating certificate for assessment_id: {assessment_id}, app_id: {app_id}")
        
        if isinstance(app_id, str):
            app_id = int(app_id) if app_id.isdigit() else app_id
        
        user = users_collection.find_one({"app_id": app_id})
        
        if not user and current_user_email:
            user = users_collection.find_one({"email": current_user_email})
            
        if not user:
            print(f"❌ User not found for app_id: {app_id}")
            return None
        
        print(f"✅ User found: {user.get('name')} - {user.get('email')}")
        
        timestamp = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
        assessment_id_str = str(assessment_id)
        cert_id_part = assessment_id_str[-8:] if len(assessment_id_str) >= 8 else assessment_id_str
        certificate_id = f"CERT-{app_id}-{cert_id_part}-{timestamp}"
        
        certificate_data = {
            "certificate_id": certificate_id,
            "user_name": user.get("name"),
            "user_email": user.get("email"),
            "app_id": app_id,
            "assessment_id": assessment_id_str,
            "skill_domain": assessment_data.get("skillDomain"),
            "score": assessment_data.get("score"),
            "issue_date": datetime.datetime.utcnow(),
            "expiry_date": datetime.datetime.utcnow() + datetime.timedelta(days=365),
            "status": "active"
        }
        
        result = assessments_collection.update_one(
            {"_id": ObjectId(assessment_id) if isinstance(assessment_id, str) else assessment_id},
            {"$set": {
                "certificate_generated": True,
                "certificate_id": certificate_id,
                "certificate_info": certificate_data,
                "certificate_issue_date": datetime.datetime.utcnow()
            }}
        )
        
        if result.modified_count > 0:
            print(f"✅ Certificate generated: {certificate_id}")
            return certificate_data
        else:
            print(f"❌ Failed to update assessment")
            return None
            
    except Exception as e:
        print(f"❌ Certificate generation error: {e}")
        return None

def generate_pdf_certificate(certificate_data):
    """Generate PDF certificate"""
    try:
        pdf_buffer = io.BytesIO()
        
        doc = SimpleDocTemplate(
            pdf_buffer, 
            pagesize=landscape(A4),
            rightMargin=40,
            leftMargin=40,
            topMargin=40,
            bottomMargin=40
        )
        
        styles = getSampleStyleSheet()
        
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=36,
            textColor=colors.HexColor('#2c3e50'),
            alignment=1,
            spaceAfter=30,
            fontName='Helvetica-Bold'
        )
        
        subtitle_style = ParagraphStyle(
            'CustomSubtitle',
            parent=styles['Heading2'],
            fontSize=20,
            textColor=colors.HexColor('#34495e'),
            alignment=1,
            spaceAfter=20,
            fontName='Helvetica'
        )
        
        content_style = ParagraphStyle(
            'CustomContent',
            parent=styles['Normal'],
            fontSize=16,
            textColor=colors.HexColor('#2c3e50'),
            alignment=1,
            spaceAfter=15,
            fontName='Helvetica'
        )
        
        name_style = ParagraphStyle(
            'NameStyle',
            parent=styles['Normal'],
            fontSize=28,
            textColor=colors.HexColor('#27ae60'),
            alignment=1,
            spaceAfter=20,
            fontName='Helvetica-Bold'
        )
        
        story = []
        
        story.append(Paragraph("CERTIFICATE OF ACHIEVEMENT", title_style))
        story.append(Spacer(1, 20))
        story.append(Paragraph("This certificate is proudly presented to", subtitle_style))
        story.append(Spacer(1, 20))
        story.append(Paragraph(certificate_data.get('user_name', 'Student'), name_style))
        story.append(Spacer(1, 20))
        story.append(Paragraph("For successfully completing the course in", content_style))
        story.append(Spacer(1, 10))
        
        skill_text = f"<b>{certificate_data.get('skill_domain', 'Course').upper()}</b>"
        skill_style = ParagraphStyle(
            'SkillStyle',
            parent=content_style,
            fontSize=24,
            textColor=colors.HexColor('#e74c3c')
        )
        story.append(Paragraph(skill_text, skill_style))
        story.append(Spacer(1, 20))
        
        score = certificate_data.get('score', 0)
        grade = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D"
        
        score_data = [
            ["Score", f"{score}%"],
            ["Grade", grade],
            ["Certificate ID", certificate_data.get('certificate_id', 'N/A')]
        ]
        
        score_table = Table(score_data, colWidths=[150, 200])
        score_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('FONTNAME', (0, 0), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 0), (-1, -1), 14),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#2c3e50')),
            ('GRID', (0, 0), (-1, -1), 1, colors.HexColor('#bdc3c7')),
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#ecf0f1')),
            ('PADDING', (0, 0), (-1, -1), 10)
        ]))
        
        story.append(score_table)
        story.append(Spacer(1, 30))
        
        issue_date = certificate_data.get('issue_date')
        if isinstance(issue_date, datetime.datetime):
            date_str = issue_date.strftime('%B %d, %Y')
        else:
            date_str = str(issue_date)
            
        story.append(Paragraph(f"Issued on: {date_str}", content_style))
        story.append(Spacer(1, 40))
        
        signature_data = [
            ["_________________________", "_________________________"],
            ["Authorized Signatory", "Date"]
        ]
        
        signature_table = Table(signature_data, colWidths=[250, 250])
        signature_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.HexColor('#7f8c8d')),
        ]))
        
        story.append(signature_table)
        
        doc.build(story)
        
        pdf_buffer.seek(0)
        return pdf_buffer
        
    except Exception as e:
        print(f"PDF generation error: {e}")
        return None

def verify_user_password(email, password):
    """Verify user's login password"""
    user = users_collection.find_one({"email": email})
    if not user:
        return False
    return bcrypt.checkpw(password.encode('utf-8'), user["password"].encode('utf-8'))

# ========== AUTH ROUTES ==========
@app.post("/api/auth/signup", status_code=status.HTTP_201_CREATED)
def signup(user: UserSignup):
    email = user.email.lower()
    if users_collection.find_one({"email": email}):
        raise HTTPException(status_code=400, detail="User already exists!")
    
    new_id = get_next_sequence_value()
    hashed = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    
    users_collection.insert_one({
        "app_id": new_id, 
        "name": user.name, 
        "email": email, 
        "password": hashed, 
        "role": "applicant"
    })
    return {"message": "Signup successful!", "id": new_id}

@app.post("/api/auth/login")
def login(user: UserLogin):
    db_user = users_collection.find_one({"email": user.email.lower()})
    
    if not db_user or not bcrypt.checkpw(user.password.encode('utf-8'), db_user["password"].encode('utf-8')):
        raise HTTPException(status_code=400, detail="Invalid credentials!")
    
    user_id = db_user.get("app_id", 0)
    
    token = jwt.encode({
        "email": db_user["email"], 
        "name": db_user["name"], 
        "app_id": user_id, 
        "role": db_user.get("role", "applicant"),
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }, SECRET_KEY, algorithm="HS256")
    
    return {
        "accessToken": token, 
        "user": {
            "app_id": user_id, 
            "name": db_user["name"], 
            "email": db_user["email"],
            "role": db_user.get("role", "applicant")
        }
    }

# ========== EXAM SUBMISSION ==========
@app.post("/api/exam/submit")
def submit_exam(data: ExamSubmit, current_user: dict = Depends(verify_token)):
    score_percentage = round((data.correct_answers / data.total_questions) * 100) if data.total_questions > 0 else 0
    status_label = "Passed" if score_percentage >= 60 else "Failed"
    access_status = "Unlocked" if score_percentage >= 60 else "Locked"
    
    exam_record = {
        "app_id": current_user.get("app_id"),
        "skillDomain": data.exam_name,
        "score": score_percentage,
        "status": status_label,
        "total_q": data.total_questions,
        "correct": data.correct_answers,
        "wrong": data.wrong_answers,
        "date": datetime.datetime.utcnow(),
        "certificateStatus": "claimable" if score_percentage >= 60 else "locked",
        "access": access_status,
        "certificate_generated": False,
        "certificate_id": None,
        "certificate_info": None
    }
    
    result = assessments_collection.insert_one(exam_record)
    assessment_id = result.inserted_id
    
    certificate_info = None
    if score_percentage >= 60:
        certificate_info = generate_certificate_for_assessment(
            assessment_id, 
            current_user.get("app_id"), 
            exam_record,
            current_user.get("email")
        )
    
    return {
        "message": "Exam results saved!", 
        "score": score_percentage, 
        "status": status_label,
        "assessment_id": str(assessment_id),
        "certificate": certificate_info
    }

# ========== CERTIFICATE DOWNLOAD METHODS ==========

# Method 1: Send OTP
@app.post("/api/certificate/send-otp")
def send_certificate_otp(
    request: OTPRequest, 
    current_user: dict = Depends(verify_token)
):
    """Send OTP to user's registered email for certificate download"""
    
    try:
        assessment_object_id = ObjectId(request.assessment_id)
    except:
        raise HTTPException(status_code=400, detail="Invalid assessment ID format!")
    
    assessment = assessments_collection.find_one({
        "_id": assessment_object_id,
        "app_id": current_user.get("app_id")
    })
    
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found!")
    
    if not assessment.get("certificate_generated", False):
        raise HTTPException(status_code=400, detail="Certificate not generated for this assessment!")
    
    user_email = current_user.get("email")
    user_name = current_user.get("name")
    
    try:
        valid = validate_email(user_email)
        user_email = valid.email
    except EmailNotValidError:
        raise HTTPException(status_code=400, detail="Invalid email address!")
    
    otp = generate_alphanumeric_otp(6)
    expiry_time = save_otp(user_email, otp)
    
    email_sent = send_otp_email(user_email, otp, user_name)
    
    if not email_sent:
        raise HTTPException(status_code=500, detail="Failed to send OTP email!")
    
    return {
        "success": True,
        "message": "OTP sent to your registered email",
        "expires_in_minutes": 5,
        "email": user_email[:3] + "***" + user_email[user_email.index('@'):],
        "method": "otp"
    }

# Method 1: Verify OTP and Download
@app.post("/api/certificate/verify-otp")
def verify_otp_and_download(
    request: OTPVerifyRequest,
    current_user: dict = Depends(verify_token)
):
    """Verify OTP and download certificate"""
    
    try:
        assessment_object_id = ObjectId(request.assessment_id)
    except:
        raise HTTPException(status_code=400, detail="Invalid assessment ID format!")
    
    assessment = assessments_collection.find_one({
        "_id": assessment_object_id,
        "app_id": current_user.get("app_id")
    })
    
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found!")
    
    if not assessment.get("certificate_generated", False):
        raise HTTPException(status_code=400, detail="Certificate not generated!")
    
    user_email = current_user.get("email")
    is_valid = verify_otp(user_email, request.otp)
    
    if not is_valid:
        raise HTTPException(status_code=400, detail="Invalid or expired OTP!")
    
    delete_otp(user_email)
    
    certificate_data = {
        "certificate_id": assessment.get("certificate_id"),
        "user_name": current_user.get("name"),
        "user_email": user_email,
        "skill_domain": assessment.get("skillDomain"),
        "score": assessment.get("score"),
        "issue_date": assessment.get("certificate_issue_date"),
        "status": "active"
    }
    
    pdf_buffer = generate_pdf_certificate(certificate_data)
    
    if pdf_buffer:
        return StreamingResponse(
            pdf_buffer,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename=certificate_{assessment.get('certificate_id')}.pdf"
            }
        )
    else:
        raise HTTPException(status_code=500, detail="Failed to generate PDF")

# Method 2: Verify Password and Download
@app.post("/api/certificate/verify-password")
def verify_password_and_download(
    request: PasswordVerifyRequest,
    current_user: dict = Depends(verify_token)
):
    """Verify login password and download certificate"""
    
    try:
        assessment_object_id = ObjectId(request.assessment_id)
    except:
        raise HTTPException(status_code=400, detail="Invalid assessment ID format!")
    
    assessment = assessments_collection.find_one({
        "_id": assessment_object_id,
        "app_id": current_user.get("app_id")
    })
    
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found!")
    
    if not assessment.get("certificate_generated", False):
        raise HTTPException(status_code=400, detail="Certificate not generated!")
    
    user_email = current_user.get("email")
    
    # Verify password
    is_valid = verify_user_password(user_email, request.password)
    
    if not is_valid:
        raise HTTPException(status_code=400, detail="Invalid password!")
    
    certificate_data = {
        "certificate_id": assessment.get("certificate_id"),
        "user_name": current_user.get("name"),
        "user_email": user_email,
        "skill_domain": assessment.get("skillDomain"),
        "score": assessment.get("score"),
        "issue_date": assessment.get("certificate_issue_date"),
        "status": "active"
    }
    
    pdf_buffer = generate_pdf_certificate(certificate_data)
    
    if pdf_buffer:
        return StreamingResponse(
            pdf_buffer,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename=certificate_{assessment.get('certificate_id')}.pdf"
            }
        )
    else:
        raise HTTPException(status_code=500, detail="Failed to generate PDF")

# Combined endpoint - supports both methods
@app.post("/api/certificate/download")
def download_certificate(
    request: CertificateDownloadRequest,
    current_user: dict = Depends(verify_token)
):
    """Download certificate using either OTP or Password method"""
    
    try:
        assessment_object_id = ObjectId(request.assessment_id)
    except:
        raise HTTPException(status_code=400, detail="Invalid assessment ID format!")
    
    assessment = assessments_collection.find_one({
        "_id": assessment_object_id,
        "app_id": current_user.get("app_id")
    })
    
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found!")
    
    if not assessment.get("certificate_generated", False):
        raise HTTPException(status_code=400, detail="Certificate not generated!")
    
    user_email = current_user.get("email")
    
    # Verify based on method
    if request.method == "otp":
        if not request.otp:
            raise HTTPException(status_code=400, detail="OTP is required for OTP method!")
        is_valid = verify_otp(user_email, request.otp)
        if is_valid:
            delete_otp(user_email)
    elif request.method == "password":
        if not request.password:
            raise HTTPException(status_code=400, detail="Password is required for password method!")
        is_valid = verify_user_password(user_email, request.password)
    else:
        raise HTTPException(status_code=400, detail="Invalid method! Use 'otp' or 'password'")
    
    if not is_valid:
        raise HTTPException(status_code=400, detail="Verification failed! Invalid OTP or password.")
    
    certificate_data = {
        "certificate_id": assessment.get("certificate_id"),
        "user_name": current_user.get("name"),
        "user_email": user_email,
        "skill_domain": assessment.get("skillDomain"),
        "score": assessment.get("score"),
        "issue_date": assessment.get("certificate_issue_date"),
        "status": "active"
    }
    
    pdf_buffer = generate_pdf_certificate(certificate_data)
    
    if pdf_buffer:
        return StreamingResponse(
            pdf_buffer,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename=certificate_{assessment.get('certificate_id')}.pdf"
            }
        )
    else:
        raise HTTPException(status_code=500, detail="Failed to generate PDF")

# Resend OTP
@app.post("/api/certificate/resend-otp")
def resend_certificate_otp(
    request: OTPRequest,
    current_user: dict = Depends(verify_token)
):
    """Resend OTP to user's registered email"""
    
    try:
        assessment_object_id = ObjectId(request.assessment_id)
    except:
        raise HTTPException(status_code=400, detail="Invalid assessment ID format!")
    
    assessment = assessments_collection.find_one({
        "_id": assessment_object_id,
        "app_id": current_user.get("app_id")
    })
    
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found!")
    
    if not assessment.get("certificate_generated", False):
        raise HTTPException(status_code=400, detail="Certificate not generated!")
    
    user_email = current_user.get("email")
    user_name = current_user.get("name")
    
    otp = generate_alphanumeric_otp(6)
    save_otp(user_email, otp)
    
    email_sent = send_otp_email(user_email, otp, user_name)
    
    if not email_sent:
        raise HTTPException(status_code=500, detail="Failed to send OTP email!")
    
    return {
        "success": True,
        "message": "OTP resent to your registered email",
        "expires_in_minutes": 5
    }

# ========== DASHBOARD API ==========
@app.get("/api/user/dashboard")
def get_dashboard(current_user: dict = Depends(verify_token)):
    user_id = current_user.get("app_id")
    user_email = current_user.get("email")
    
    records = list(assessments_collection.find({"app_id": user_id}).sort("date", -1))
    
    if not records:
        return {
            "stats": {"averagePerformance": 0, "coursesAttempted": 0, "certificatesUnlocked": 0},
            "assessmentHistory": []
        }
    
    history = []
    certificates_unlocked = 0
    
    for record in records:
        assessment_id = record["_id"]
        score = record.get("score", 0)
        
        if score >= 60 and not record.get("certificate_generated", False):
            print(f"Generating certificate for assessment: {assessment_id}")
            generate_certificate_for_assessment(
                assessment_id, 
                user_id, 
                record,
                user_email
            )
            record = assessments_collection.find_one({"_id": assessment_id})
        
        has_certificate = record.get("certificate_generated", False)
        if has_certificate:
            certificates_unlocked += 1
        
        history.append({
            "id": str(record["_id"]),
            "skillDomain": record.get("skillDomain"),
            "score": record.get("score"),
            "status": record.get("status"),
            "certificateStatus": "claimable" if record.get("score", 0) >= 60 else "locked",
            "certificateFee": 49,
            "access": record.get("access"),
            "certificate_generated": has_certificate,
            "certificate_id": record.get("certificate_id") if has_certificate else None,
            "has_certificate": has_certificate,
            "assessment_id": str(record["_id"])
        })
    
    total_score = sum(r.get("score", 0) for r in records)
    attempted = len(records)
    avg_perf = round(total_score / attempted) if attempted > 0 else 0
    
    return {
        "stats": {
            "averagePerformance": avg_perf,
            "coursesAttempted": attempted,
            "certificatesUnlocked": certificates_unlocked
        },
        "assessmentHistory": history
    }

# ========== DIRECT CERTIFICATE DOWNLOAD ==========
@app.get("/api/certificate/{assessment_id}")
def get_certificate(assessment_id: str, download_pdf: bool = False, current_user: dict = Depends(verify_token)):
    """Get certificate for a specific assessment - can return JSON or PDF"""
    try:
        assessment_object_id = ObjectId(assessment_id)
    except:
        raise HTTPException(status_code=400, detail="Invalid assessment ID format!")
    
    assessment = assessments_collection.find_one({
        "_id": assessment_object_id,
        "app_id": current_user.get("app_id")
    })
    
    if not assessment:
        raise HTTPException(status_code=404, detail="Assessment not found!")
    
    if assessment.get("score", 0) >= 60 and not assessment.get("certificate_generated", False):
        generate_certificate_for_assessment(
            assessment_object_id, 
            current_user.get("app_id"), 
            assessment,
            current_user.get("email")
        )
        assessment = assessments_collection.find_one({"_id": assessment_object_id})
    
    if assessment.get("certificate_generated", False):
        certificate_data = {
            "certificate_id": assessment.get("certificate_id"),
            "user_name": current_user.get("name"),
            "user_email": current_user.get("email"),
            "skill_domain": assessment.get("skillDomain"),
            "score": assessment.get("score"),
            "issue_date": assessment.get("certificate_issue_date"),
            "status": "active"
        }
        
        if download_pdf:
            pdf_buffer = generate_pdf_certificate(certificate_data)
            if pdf_buffer:
                return StreamingResponse(
                    pdf_buffer,
                    media_type="application/pdf",
                    headers={
                        "Content-Disposition": f"attachment; filename=certificate_{assessment.get('certificate_id')}.pdf"
                    }
                )
            else:
                raise HTTPException(status_code=500, detail="Failed to generate PDF")
        
        return {
            "success": True,
            "certificate": certificate_data,
            "download_url": f"/api/certificate/{assessment_id}?download_pdf=true"
        }
    else:
        return {
            "success": False,
            "message": "Certificate not available. You need to score 60% or above."
        }

# ========== DIRECT FIX CERTIFICATES ==========
@app.post("/api/direct-fix-certificates")
def direct_fix_certificates(current_user: dict = Depends(verify_token)):
    user_id = current_user.get("app_id")
    user_email = current_user.get("email")
    
    user = users_collection.find_one({"app_id": user_id})
    if not user:
        user = users_collection.find_one({"email": user_email})
    
    if not user:
        return {"error": "User not found"}
    
    passed_assessments = list(assessments_collection.find({
        "app_id": user_id,
        "score": {"$gte": 60}
    }))
    
    updated_count = 0
    details = []
    
    for assessment in passed_assessments:
        if not assessment.get("certificate_generated", False):
            timestamp = datetime.datetime.now().strftime('%Y%m%d%H%M%S')
            cert_id = f"CERT-{user_id}-{str(assessment['_id'])[-8:]}-{timestamp}"
            
            result = assessments_collection.update_one(
                {"_id": assessment["_id"]},
                {"$set": {
                    "certificate_generated": True,
                    "certificate_id": cert_id,
                    "certificate_issue_date": datetime.datetime.utcnow(),
                    "certificate_info": {
                        "certificate_id": cert_id,
                        "user_name": user.get("name"),
                        "user_email": user.get("email"),
                        "app_id": user_id,
                        "assessment_id": str(assessment["_id"]),
                        "skill_domain": assessment.get("skillDomain"),
                        "score": assessment.get("score"),
                        "issue_date": datetime.datetime.utcnow(),
                        "status": "active"
                    }
                }}
            )
            
            if result.modified_count > 0:
                updated_count += 1
                details.append({
                    "assessment_id": str(assessment["_id"]),
                    "skill": assessment.get("skillDomain"),
                    "certificate_id": cert_id,
                    "status": "fixed"
                })
    
    return {
        "message": f"Directly fixed {updated_count} certificates",
        "total_processed": len(passed_assessments),
        "certificates_fixed": updated_count,
        "details": details
    }

# ========== HEALTH CHECK ==========
@app.get("/api/health")
def health_check():
    return {"status": "ok", "timestamp": datetime.datetime.utcnow().isoformat()}