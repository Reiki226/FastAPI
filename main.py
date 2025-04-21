
from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt, JWTError
from passlib.context import CryptContext
from pydantic import BaseModel
from pymongo import MongoClient
from bson.objectid import ObjectId
import datetime 

app = FastAPI() 


# Connect to local MongoDB
client = MongoClient("mongodb://localhost:27017/")
db = client["testdb"]
users = db["users"]


SECRET_KEY = "secret"
ALGORITHM = "HS256"
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")


def CreatToken(email: str):
    return jwt.encode(
        {"sub": email, "exp": datetime.datetime.utcnow() + datetime.timedelta(minutes=10)},
        SECRET_KEY,
        algorithm=ALGORITHM
    )




def GetUser(token: str = Depends(oauth2_scheme)):
    try:
        data = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return data["sub"]
    except JWTError:
        raise HTTPException(status_code=404, detail="Invalid token. Try again")


@app.post("/signup")
def signup(form: OAuth2PasswordRequestForm = Depends()):
    if users.find_one({"email": form.username}):
        raise HTTPException(status_code=401, detail="User already exists")
    hashed_password = pwd_context.hash(form.password)
    users.insert_one({"email": form.username, "password": hashed_password})
    return {"msg": "User has been created"}


@app.post("/login")
def login(form: OAuth2PasswordRequestForm = Depends()):
    user = users.find_one({"email": form.username})
    if not user or not pwd_context.verify(form.password, user["password"]):
        raise HTTPException(status_code=401, detail="Invalid login info")
    token = CreatToken(user["email"])
    return {"access_token": token, "token_type": "bearer"}


@app.get("/secret")
def red_secret(user=Depends(GetUser)):
    return {"msg": f"Hello {user}, you are authorized"}