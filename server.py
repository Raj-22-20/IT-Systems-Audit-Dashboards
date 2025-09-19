from fastapi import FastAPI, APIRouter, HTTPException, BackgroundTasks
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
import uuid
from datetime import datetime, timezone, timedelta
import random
from enum import Enum
import json
from emergentintegrations.llm.chat import LlmChat, UserMessage

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# LLM Integration
emergent_key = os.environ.get('EMERGENT_LLM_KEY')

# Create the main app without a prefix
app = FastAPI(title="IT Systems Audit & Risk Assessment Dashboard")

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Enums
class UserRole(str, Enum):
    ADMIN = "admin"
    USER = "user"
    MANAGER = "manager"
    AUDITOR = "auditor"
    GUEST = "guest"

class AccessResult(str, Enum):
    SUCCESS = "success"
    FAILED = "failed"
    SUSPICIOUS = "suspicious"

class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class ViolationType(str, Enum):
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    FAILED_AUTHENTICATION = "failed_authentication"
    UNUSUAL_ACTIVITY = "unusual_activity"
    SEGREGATION_DUTY_CONFLICT = "segregation_duty_conflict"

# Data Models
class UserAccessLog(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    username: str
    user_role: UserRole
    access_time: datetime
    ip_address: str
    location: str
    resource_accessed: str
    access_result: AccessResult
    session_duration_minutes: Optional[int] = None
    failed_attempts: int = 0
    privilege_changes: List[str] = []
    is_violation: bool = False
    violation_type: Optional[ViolationType] = None
    risk_score: float = 0.0
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class AccessViolation(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    log_id: str
    violation_type: ViolationType
    severity: RiskLevel
    description: str
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    resolved: bool = False

class RiskAssessment(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    assessment_date: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    overall_risk_score: float
    risk_level: RiskLevel
    risk_factors: List[str]
    recommendations: List[str]
    ai_analysis: Optional[str] = None

class DashboardStats(BaseModel):
    total_access_logs: int
    active_violations: int
    high_risk_users: int
    failed_logins_today: int
    privilege_escalations_week: int
    compliance_score: float

# Helper Functions
def calculate_risk_score(log: UserAccessLog) -> float:
    """Calculate risk score based on various factors"""
    score = 0.0
    
    # Base score for failed attempts
    score += log.failed_attempts * 0.2
    
    # Privilege changes increase risk
    score += len(log.privilege_changes) * 0.3
    
    # Failed access adds risk
    if log.access_result == AccessResult.FAILED:
        score += 0.5
    elif log.access_result == AccessResult.SUSPICIOUS:
        score += 0.8
    
    # Time-based risk (access outside business hours)
    hour = log.access_time.hour
    if hour < 7 or hour > 19:  # Outside 7 AM - 7 PM
        score += 0.3
    
    # Weekend access
    if log.access_time.weekday() >= 5:  # Saturday, Sunday
        score += 0.2
    
    return min(score, 1.0)  # Cap at 1.0

def determine_risk_level(score: float) -> RiskLevel:
    """Determine risk level based on score"""
    if score >= 0.8:
        return RiskLevel.CRITICAL
    elif score >= 0.6:
        return RiskLevel.HIGH
    elif score >= 0.3:
        return RiskLevel.MEDIUM
    else:
        return RiskLevel.LOW

async def generate_sample_data():
    """Generate comprehensive sample data for demo"""
    # Clear existing data
    await db.access_logs.delete_many({})
    await db.violations.delete_many({})
    await db.risk_assessments.delete_many({})
    
    # Sample users
    users = [
        {"id": "USR001", "username": "john.doe", "role": UserRole.ADMIN},
        {"id": "USR002", "username": "jane.smith", "role": UserRole.USER},
        {"id": "USR003", "username": "mike.johnson", "role": UserRole.MANAGER},
        {"id": "USR004", "username": "sarah.wilson", "role": UserRole.AUDITOR},
        {"id": "USR005", "username": "david.brown", "role": UserRole.USER},
        {"id": "USR006", "username": "emma.davis", "role": UserRole.MANAGER},
        {"id": "USR007", "username": "robert.clark", "role": UserRole.USER},
        {"id": "USR008", "username": "lisa.white", "role": UserRole.ADMIN},
        {"id": "USR009", "username": "james.taylor", "role": UserRole.USER},
        {"id": "USR010", "username": "maria.garcia", "role": UserRole.AUDITOR},
    ]
    
    # Sample IP addresses and locations
    ip_locations = [
        {"ip": "192.168.1.100", "location": "New York, NY"},
        {"ip": "192.168.1.101", "location": "San Francisco, CA"},
        {"ip": "192.168.1.102", "location": "Chicago, IL"},
        {"ip": "10.0.0.50", "location": "London, UK"},
        {"ip": "10.0.0.51", "location": "Tokyo, Japan"},
        {"ip": "172.16.0.10", "location": "Berlin, Germany"},
        {"ip": "203.0.113.1", "location": "Sydney, Australia"},
        {"ip": "198.51.100.1", "location": "Toronto, Canada"},
    ]
    
    # Sample resources
    resources = [
        "Financial Database", "HR System", "Customer CRM", 
        "Admin Panel", "Audit Logs", "Payroll System",
        "Document Management", "Email Server", "VPN Gateway",
        "Backup System", "Security Console", "Development Server"
    ]
    
    # Generate 1000+ access logs
    logs = []
    violations = []
    
    for i in range(1200):
        user = random.choice(users)
        ip_loc = random.choice(ip_locations)
        resource = random.choice(resources)
        
        # Create realistic time distribution
        base_time = datetime.now(timezone.utc) - timedelta(days=random.randint(0, 30))
        
        # Simulate business hours vs off-hours
        if random.random() < 0.7:  # 70% business hours
            hour = random.randint(8, 18)
        else:  # 30% off-hours
            hour = random.choice([6, 7, 19, 20, 21, 22, 23, 0, 1, 2])
        
        access_time = base_time.replace(hour=hour, minute=random.randint(0, 59))
        
        # Determine access result with realistic distribution
        access_result = random.choices(
            [AccessResult.SUCCESS, AccessResult.FAILED, AccessResult.SUSPICIOUS],
            weights=[85, 12, 3]  # 85% success, 12% failed, 3% suspicious
        )[0]
        
        # Failed attempts
        failed_attempts = 0
        if access_result == AccessResult.FAILED:
            failed_attempts = random.randint(1, 5)
        elif access_result == AccessResult.SUSPICIOUS:
            failed_attempts = random.randint(3, 8)
        
        # Privilege changes (rare but important)
        privilege_changes = []
        if random.random() < 0.05:  # 5% chance
            changes = ["elevated_to_admin", "access_granted_finance", "removed_hr_access"]
            privilege_changes = random.sample(changes, random.randint(1, 2))
        
        # Session duration
        session_duration = None
        if access_result == AccessResult.SUCCESS:
            session_duration = random.randint(5, 240)  # 5 minutes to 4 hours
        
        log = UserAccessLog(
            user_id=user["id"],
            username=user["username"],
            user_role=user["role"],
            access_time=access_time,
            ip_address=ip_loc["ip"],
            location=ip_loc["location"],
            resource_accessed=resource,
            access_result=access_result,
            session_duration_minutes=session_duration,
            failed_attempts=failed_attempts,
            privilege_changes=privilege_changes
        )
        
        # Calculate risk score
        log.risk_score = calculate_risk_score(log)
        
        # Determine if it's a violation
        if (log.risk_score > 0.6 or 
            failed_attempts > 3 or 
            len(privilege_changes) > 0 or 
            access_result == AccessResult.SUSPICIOUS):
            
            log.is_violation = True
            
            # Determine violation type
            if len(privilege_changes) > 0:
                log.violation_type = ViolationType.PRIVILEGE_ESCALATION
            elif failed_attempts > 3:
                log.violation_type = ViolationType.FAILED_AUTHENTICATION
            elif access_result == AccessResult.SUSPICIOUS:
                log.violation_type = ViolationType.UNUSUAL_ACTIVITY
            elif hour < 7 or hour > 19:
                log.violation_type = ViolationType.UNAUTHORIZED_ACCESS
            else:
                log.violation_type = ViolationType.SEGREGATION_DUTY_CONFLICT
            
            # Create violation record
            violation = AccessViolation(
                log_id=log.id,
                violation_type=log.violation_type,
                severity=determine_risk_level(log.risk_score),
                description=f"Risk Score: {log.risk_score:.2f}, Failed Attempts: {failed_attempts}, "
                           f"Privilege Changes: {len(privilege_changes)}, Access Result: {access_result.value}"
            )
            violations.append(violation.dict())
        
        logs.append(log.dict())
    
    # Insert data
    if logs:
        await db.access_logs.insert_many(logs)
    if violations:
        await db.violations.insert_many(violations)
    
    return len(logs), len(violations)

async def ai_analyze_patterns(logs: List[UserAccessLog]) -> str:
    """Use AI to analyze access patterns and generate insights"""
    try:
        # Prepare data summary for AI
        violation_logs = [log for log in logs if log.is_violation]
        
        data_summary = {
            "total_logs": len(logs),
            "violations": len(violation_logs),
            "failed_attempts": sum(log.failed_attempts for log in logs),
            "privilege_escalations": len([log for log in logs if log.privilege_changes]),
            "off_hours_access": len([log for log in logs if log.access_time.hour < 7 or log.access_time.hour > 19]),
            "high_risk_users": len(set(log.user_id for log in logs if log.risk_score > 0.6))
        }
        
        # Initialize LLM chat
        chat = LlmChat(
            api_key=emergent_key,
            session_id=f"audit-analysis-{uuid.uuid4()}",
            system_message="You are an expert IT security auditor specializing in access control analysis and risk assessment."
        ).with_model("openai", "gpt-4o-mini")
        
        # Create analysis prompt
        prompt = f"""
        Analyze the following IT access log data and provide security insights:
        
        Data Summary:
        - Total Access Logs: {data_summary['total_logs']}
        - Security Violations: {data_summary['violations']}
        - Failed Login Attempts: {data_summary['failed_attempts']}
        - Privilege Escalations: {data_summary['privilege_escalations']}
        - Off-Hours Access: {data_summary['off_hours_access']}
        - High-Risk Users: {data_summary['high_risk_users']}
        
        Provide a concise professional analysis including:
        1. Key security concerns identified
        2. Risk assessment summary
        3. Top 3 actionable recommendations
        
        Keep response under 300 words, formatted for an executive dashboard.
        """
        
        user_message = UserMessage(text=prompt)
        response = await chat.send_message(user_message)
        
        return response
        
    except Exception as e:
        logging.error(f"AI analysis failed: {str(e)}")
        return "AI analysis temporarily unavailable. Manual review recommended for comprehensive risk assessment."

# API Routes
@api_router.get("/")
async def root():
    return {"message": "IT Systems Audit & Risk Assessment Dashboard API"}

@api_router.post("/generate-sample-data")
async def generate_sample_data_endpoint(background_tasks: BackgroundTasks):
    """Generate comprehensive sample data for demo"""
    try:
        logs_count, violations_count = await generate_sample_data()
        return {
            "message": "Sample data generated successfully",
            "logs_generated": logs_count,
            "violations_generated": violations_count
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/dashboard/stats", response_model=DashboardStats)
async def get_dashboard_stats():
    """Get dashboard statistics"""
    try:
        # Aggregate data
        total_logs = await db.access_logs.count_documents({})
        active_violations = await db.violations.count_documents({"resolved": False})
        
        # High risk users (risk score > 0.6)
        high_risk_pipeline = [
            {"$match": {"risk_score": {"$gt": 0.6}}},
            {"$group": {"_id": "$user_id"}},
            {"$count": "unique_users"}
        ]
        high_risk_result = await db.access_logs.aggregate(high_risk_pipeline).to_list(1)
        high_risk_users = high_risk_result[0]["unique_users"] if high_risk_result else 0
        
        # Failed logins today
        today_start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
        failed_today = await db.access_logs.count_documents({
            "access_result": "failed",
            "access_time": {"$gte": today_start}
        })
        
        # Privilege escalations this week
        week_start = datetime.now(timezone.utc) - timedelta(days=7)
        escalations_week = await db.access_logs.count_documents({
            "privilege_changes": {"$ne": []},
            "access_time": {"$gte": week_start}
        })
        
        # Calculate compliance score (simplified)
        if total_logs > 0:
            compliance_score = max(0, (total_logs - active_violations) / total_logs * 100)
        else:
            compliance_score = 100.0
        
        return DashboardStats(
            total_access_logs=total_logs,
            active_violations=active_violations,
            high_risk_users=high_risk_users,
            failed_logins_today=failed_today,
            privilege_escalations_week=escalations_week,
            compliance_score=round(compliance_score, 1)
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/access-logs", response_model=List[UserAccessLog])
async def get_access_logs(
    limit: int = 100,
    skip: int = 0,
    violations_only: bool = False,
    risk_level: Optional[RiskLevel] = None
):
    """Get access logs with filtering options"""
    try:
        query = {}
        
        if violations_only:
            query["is_violation"] = True
            
        if risk_level:
            if risk_level == RiskLevel.CRITICAL:
                query["risk_score"] = {"$gte": 0.8}
            elif risk_level == RiskLevel.HIGH:
                query["risk_score"] = {"$gte": 0.6, "$lt": 0.8}
            elif risk_level == RiskLevel.MEDIUM:
                query["risk_score"] = {"$gte": 0.3, "$lt": 0.6}
            else:  # LOW
                query["risk_score"] = {"$lt": 0.3}
        
        logs = await db.access_logs.find(query).sort("access_time", -1).skip(skip).limit(limit).to_list(limit)
        return [UserAccessLog(**log) for log in logs]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/violations", response_model=List[AccessViolation])
async def get_violations(limit: int = 50, active_only: bool = True):
    """Get access violations"""
    try:
        query = {}
        if active_only:
            query["resolved"] = False
            
        violations = await db.violations.find(query).sort("detected_at", -1).limit(limit).to_list(limit)
        return [AccessViolation(**violation) for violation in violations]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.post("/violations/{violation_id}/resolve")
async def resolve_violation(violation_id: str):
    """Mark a violation as resolved"""
    try:
        result = await db.violations.update_one(
            {"id": violation_id},
            {"$set": {"resolved": True}}
        )
        
        if result.matched_count == 0:
            raise HTTPException(status_code=404, detail="Violation not found")
            
        return {"message": "Violation resolved successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/users/{user_id}/risk-assessment")
async def get_user_risk_assessment(user_id: str):
    """Get risk assessment for a specific user"""
    try:
        # Get recent logs for user
        week_ago = datetime.now(timezone.utc) - timedelta(days=7)
        logs = await db.access_logs.find({
            "user_id": user_id,
            "access_time": {"$gte": week_ago}
        }).to_list(100)
        
        if not logs:
            raise HTTPException(status_code=404, detail="No recent activity found for user")
        
        user_logs = [UserAccessLog(**log) for log in logs]
        
        # Calculate overall risk
        avg_risk_score = sum(log.risk_score for log in user_logs) / len(user_logs)
        risk_level = determine_risk_level(avg_risk_score)
        
        # Identify risk factors
        risk_factors = []
        if any(log.failed_attempts > 3 for log in user_logs):
            risk_factors.append("Multiple failed login attempts")
        if any(log.privilege_changes for log in user_logs):
            risk_factors.append("Recent privilege changes")
        if any(log.access_time.hour < 7 or log.access_time.hour > 19 for log in user_logs):
            risk_factors.append("Off-hours access detected")
        if len([log for log in user_logs if log.is_violation]) > 0:
            risk_factors.append("Recent security violations")
        
        # Generate AI analysis
        ai_analysis = await ai_analyze_patterns(user_logs)
        
        # Create recommendations
        recommendations = []
        if avg_risk_score > 0.6:
            recommendations.append("Implement additional authentication factors")
        if any(log.failed_attempts > 5 for log in user_logs):
            recommendations.append("Review account security and reset password")
        if len(risk_factors) > 2:
            recommendations.append("Conduct security awareness training")
        if not recommendations:
            recommendations.append("Continue monitoring user activity")
        
        assessment = RiskAssessment(
            user_id=user_id,
            overall_risk_score=avg_risk_score,
            risk_level=risk_level,
            risk_factors=risk_factors,
            recommendations=recommendations,
            ai_analysis=ai_analysis
        )
        
        # Save assessment
        await db.risk_assessments.insert_one(assessment.dict())
        
        return assessment
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.get("/analytics/trends")
async def get_analytics_trends():
    """Get access trends and patterns"""
    try:
        # Last 7 days trend
        trends = []
        for i in range(7):
            day_start = datetime.now(timezone.utc) - timedelta(days=i)
            day_start = day_start.replace(hour=0, minute=0, second=0, microsecond=0)
            day_end = day_start + timedelta(days=1)
            
            daily_count = await db.access_logs.count_documents({
                "access_time": {"$gte": day_start, "$lt": day_end}
            })
            
            violations_count = await db.access_logs.count_documents({
                "access_time": {"$gte": day_start, "$lt": day_end},
                "is_violation": True
            })
            
            trends.append({
                "date": day_start.date().isoformat(),
                "total_access": daily_count,
                "violations": violations_count
            })
        
        # Reverse to show oldest to newest
        trends.reverse()
        
        # Top violation types
        violation_pipeline = [
            {"$match": {"is_violation": True}},
            {"$group": {
                "_id": "$violation_type",
                "count": {"$sum": 1}
            }},
            {"$sort": {"count": -1}},
            {"$limit": 5}
        ]
        
        violation_types = await db.access_logs.aggregate(violation_pipeline).to_list(5)
        
        # Risk distribution
        risk_pipeline = [
            {"$bucket": {
                "groupBy": "$risk_score",
                "boundaries": [0, 0.3, 0.6, 0.8, 1.0],
                "default": "high",
                "output": {"count": {"$sum": 1}}
            }}
        ]
        
        risk_distribution = await db.access_logs.aggregate(risk_pipeline).to_list(4)
        
        return {
            "access_trends": trends,
            "top_violation_types": violation_types,
            "risk_distribution": risk_distribution
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

def serialize_mongodb_doc(doc):
    """Convert MongoDB document to JSON-serializable format"""
    if isinstance(doc, dict):
        return {key: serialize_mongodb_doc(value) for key, value in doc.items() if key != '_id'}
    elif isinstance(doc, list):
        return [serialize_mongodb_doc(item) for item in doc]
    elif hasattr(doc, 'isoformat'):  # datetime objects
        return doc.isoformat()
    else:
        return doc

@api_router.post("/sql-query")
async def execute_sql_query(query_request: Dict[str, Any]):
    """Execute predefined SQL-like queries for audit analysis"""
    try:
        query_type = query_request.get("query_type")
        
        if query_type == "unauthorized_access":
            # Find unauthorized access attempts
            results = await db.access_logs.find({
                "$or": [
                    {"access_result": "failed", "failed_attempts": {"$gt": 3}},
                    {"access_result": "suspicious"},
                    {"is_violation": True, "violation_type": "unauthorized_access"}
                ]
            }).sort("access_time", -1).limit(50).to_list(50)
            
        elif query_type == "privilege_escalation":
            # Find privilege escalation events
            results = await db.access_logs.find({
                "privilege_changes": {"$ne": []}
            }).sort("access_time", -1).limit(50).to_list(50)
            
        elif query_type == "segregation_conflicts":
            # Find potential segregation of duties conflicts
            results = await db.access_logs.find({
                "violation_type": "segregation_duty_conflict"
            }).sort("access_time", -1).limit(50).to_list(50)
            
        elif query_type == "failed_logins":
            # Find failed login patterns
            results = await db.access_logs.find({
                "access_result": "failed"
            }).sort("access_time", -1).limit(100).to_list(100)
            
        elif query_type == "off_hours_access":
            # Find off-hours access
            pipeline = [
                {"$addFields": {
                    "hour": {"$hour": "$access_time"}
                }},
                {"$match": {
                    "$or": [
                        {"hour": {"$lt": 7}},
                        {"hour": {"$gt": 19}}
                    ]
                }},
                {"$sort": {"access_time": -1}},
                {"$limit": 50}
            ]
            results = await db.access_logs.aggregate(pipeline).to_list(50)
            
        else:
            raise HTTPException(status_code=400, detail="Invalid query type")
        
        # Serialize results to handle MongoDB ObjectIds
        serialized_results = [serialize_mongodb_doc(result) for result in results]
        
        return {
            "query_type": query_type,
            "results_count": len(serialized_results),
            "results": serialized_results
        }
        
    except Exception as e:
        logging.error(f"SQL Query execution failed: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Query execution failed: {str(e)}")

# Include the router in the main app
app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()