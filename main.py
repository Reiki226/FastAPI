from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt, JWTError, ExpiredSignatureError
from passlib.context import CryptContext
from pydantic import BaseModel
from pymongo import MongoClient
from bson.objectid import ObjectId
from typing import List
import datetime
app = FastAPI() 



client = MongoClient("mongodb://localhost:27017/")
db = client["testdb"]
users = db["users"]
employees = db["employees"]


SECRET_KEY = "secret"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

class Employee(BaseModel):
    name: str
    role: str
    salary : float
    
def create_token(email:str):
    expire = datetime.datetime.utcnow() + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    return jwt.encode({"sub": email,"exp": expire}, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=404, detail="token is invaild")
        return email
    except ExpiredSignatureError:
        raise HTTPException(status_code=404, detail="token has been expired")
    except JWTError:
        raise HTTPException(status_code=404, detail="invalid token")
    
    
@app.post("/signup")
def signup(form: OAuth2PasswordRequestForm = Depends()): 
    if users.find_one({"email": form.username}): 
        raise HTTPException(status_code=409, detail="user already exist")
    
    hashed = pwd_context.hash(form.password)
    users.insert_one({"email": form.username, "password": hashed})
    return {"msg": "user has been created"}

@app.post("/login")
def login(form: OAuth2PasswordRequestForm = Depends()):
    user = users.find_one({"email": form.username}) 
    if not user or not pwd_context.verify(form.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_token(user["email"])
    return {"access_token": token, "token_type": "bearer"}
    
@app.post("/employees")
def create_employees(data: Employee, current_user: str = Depends(get_current_user)):
    employee = data.dict()
    employee["created_by"] = current_user
    result = employees.insert_one(employee)
    return {"msg": "Employee has been created", "id": str(result.inserted_id)}

@app.get("/employees")
def get_employees(current_user: str = Depends(get_current_user)):
    result = list(employees.find({"created_by": current_user}))
    for emp in result:
        emp["_id"] = str(emp["_id"])
    return result

@app.put("/employees/{emp_id}")
def update_employee(emp_id: str, data: Employee, current_user: str = Depends(get_current_user)):
    result = employees.update_one(
        {"_id": ObjectId(emp_id), "created_by": current_user},
        {"$set": data.dict()}
    )
    if result.modified_count == 0:
        raise HTTPException(status_code=404, detail="Employee not found or not authorized")
    return {"msg": "Employee updated"}


@app.delete("/employees/{emp_id}")
def delete_employee(emp_id: str, current_user: str = Depends(get_current_user)):
    result = employees.delete_one({"_id": ObjectId(emp_id), "created_by": current_user})
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Employee not found or not authorized")
    return {"msg": "Employee deleted"}