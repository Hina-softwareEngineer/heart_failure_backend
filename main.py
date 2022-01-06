from datetime import datetime, timedelta
from typing import Optional
import pprint
from fastapi import Depends, FastAPI, HTTPException, status, Form
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext

from Database import Database

from pydantic import BaseModel

SECRET_KEY = "33a6640eb3a4e6460d32613f8b65f6ba5f46c3776ef31522adeab71292ccd4a3"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440


app = FastAPI()
DB = Database()


class Token(BaseModel):
    username: str
    email: Optional[str]
    phone : Optional[str]
    access_token: str
    token_type: str


class User(BaseModel):
    username: str
    email: Optional[str] = None
    phone : Optional[str] = None
    password : Optional[str] = None


class UserInDB(User):
    _id : str
    exp : int


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

app = FastAPI()


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password):
    return pwd_context.hash(password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=1440)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        
        if payload['_id'] is None:
            raise credentials_exception
        user = payload

    except JWTError:
        raise credentials_exception
    
    return user


async def get_current_active_user(current_user: UserInDB = Depends(get_current_user)):
    if not current_user:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user


@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    
    user = form_data
    
    userExistCheck = DB.get_user(user.username)
    
    if userExistCheck:
        verifyPwd = verify_password(user.password, userExistCheck['password'])
        
        if verifyPwd:
            userExistCheck['_id'] = str(userExistCheck['_id'])
            userExistCheck['access_token'] = create_access_token(userExistCheck, expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
            userExistCheck['token_type'] = 'Bearer'

            del userExistCheck['password']

            return userExistCheck
    
    
    raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        ) 
    

@app.post("/v1/signup/")
async def signup_user(user: User):
    
    userExistCheck = DB.get_user(user.email)
    
    if userExistCheck:
        raise HTTPException(
            status_code = status.HTTP_404_NOT_FOUND,
            detail="User already exists.",
        )

    hashedPassword = get_password_hash(user.password)
    userobj = {
        'username' : user.username,
        'email' : user.email,
        'phone' : user.phone,
        'password' : hashedPassword
    }
    response = DB.createUserInDB(userobj)

    if not response.acknowledged:
        raise HTTPException(
            status_code = status.HTTP_404_NOT_FOUND,
            detail="Failed to create user.",
        )

    userobj['_id'] = str(response.inserted_id)
    userobj['token'] = create_access_token(userobj)

    return {"data" : userobj}


@app.post("/v1/login/")
async def login_user(email: str = Form(...), password: str = Form(...)):
    
    userExistCheck = DB.get_user(email)
    
    if userExistCheck:
        verifyPwd = verify_password(password, userExistCheck['password'])
        
        if verifyPwd:
            userExistCheck['_id'] = str(userExistCheck['_id'])
            userExistCheck['access_token'] = create_access_token(userExistCheck)
            userExistCheck['token_type'] = 'Bearer'

            del userExistCheck['password']

            return {'data' : userExistCheck}
    
    
    raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        ) 


@app.get("/users/me/", response_model=UserInDB)
async def read_users_me(current_user: UserInDB = Depends(get_current_active_user)):
    return current_user


@app.post("/rate-prediction", response_model=UserInDB)
async def heart_rate_prediction(current_user: UserInDB = Depends(get_current_active_user)):
    return {'data' : 1}