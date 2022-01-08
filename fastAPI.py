from Database import Database
from pydantic import BaseModel
from typing import Optional
from datetime import datetime, timedelta
from fastapi import Depends, FastAPI, HTTPException, status, Form
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext

import pickle
import warnings
import uvicorn
from dotenv import load_dotenv

warnings.filterwarnings("ignore")

SECRET_KEY = "33a6640eb3a4e6460d32613f8b65f6ba5f46c3776ef31522adeab71292ccd4a3"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 1440


app = FastAPI()
DB = Database()

load_dotenv()

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

class HeartData(BaseModel):
    age : int
    restingBP : int
    cholestrol : int
    fastingBS : int
    maxHR : int
    oldpeak : float
    sex : str
    chestPainType : str
    restingECG : str
    exerciseAngina : str
    st_slope: str

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

model = pickle.load(open("model.pkl", 'rb'))
ss = pickle.load(open('scaler.scl', 'rb'))


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

@app.get("/")
async def root_url():
    return {'message' : "Successfully Running the server..."}


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
        'password' : hashedPassword,
        'created_at' : datetime.now()
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


@app.post("/rate-prediction")
async def heart_rate_prediction(data : HeartData, current_user: UserInDB = Depends(get_current_active_user)):
    
    # for sex
    male = female = 0

    if data.sex == 'F':
        female = 1
    else:
        male = 1

    # for chestpaintype
    asy = ata = nap = ta = 0
    
    if data.chestPainType == 'ASY':
        asy = 1
    elif data.chestPainType == 'ATA':
        ata = 1
    elif data.chestPainType == 'NAP':
        nap = 1
    elif data.chestPainType == 'TA':
        ta = 1

    
    # for Resting ECG
    lvh = normal = st = 0
    
    if data.restingECG == 'LVH':
        lvh = 1
    elif data.restingECG == 'Normal':
        normal = 1
    elif data.restingECG == 'ST':
        st = 1

    
    # for exercise Angina
    ea_yes = ea_no = 0

    if data.exerciseAngina == 'Y':
        ea_yes = 1
    elif data.exerciseAngina == 'N':
        ea_no = 1


    # for st_slope
    st_down = st_flat = st_up = 0
    
    if data.st_slope == 'Down':
        st_down = 1
    elif data.st_slope == 'Flat':
        st_flat = 1
    elif data.st_slope == 'Up':
        st_up = 1


    hot_encoded_data = [data.age, data.restingBP, data.cholestrol,
                        data.fastingBS, data.maxHR, data.oldpeak, 
                        female, male, asy, ata, nap, ta, lvh, normal,
                        st, ea_no, ea_yes, st_down, st_flat, st_up]

    try:
        transformed_data = ss.transform([hot_encoded_data])

        response = model.predict(transformed_data)
        prediction = response.tolist()

        record_object = {
            'age' : data.age,
            'restingBP' : data.restingBP,
            'cholestrol' : data.cholestrol,
            'fastingBS' : data.fastingBS,
            'maxHR' : data.maxHR,
            'oldpeak' : data.oldpeak,
            'gender' : data.sex,
            'chestPainType' : data.chestPainType,
            'restingECG' : data.restingECG,
            'exerciseAngina' : data.exerciseAngina,
            'st_slope' : data.st_slope,
            'heartDisease' : prediction[0],
            'created_at' : datetime.now(),
            'user_id' : current_user['_id']
        }

        response = DB.user_create_predicted_result(record_object)

        if not response.acknowledged:
            raise HTTPException(
                status_code = status.HTTP_404_NOT_FOUND,
                detail="Failed to create record.",
            )

        record_object['_id'] = str(response.inserted_id)
        
        return {'data' : record_object}
    
    except Exception as err:
        print('Error in the Heart Rate Prediction function : ',err)
        HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail= { 'message' : 'Fail to Predict.', 'err' : err},
            headers={"WWW-Authenticate": "Bearer"},
        )


@app.get("/all-medical-records")
def all_medical_records(current_user: UserInDB = Depends(get_current_active_user)):
    
    records = DB.user_heart_history(current_user['_id'])
    all_records = []

    for record in records:
        record['_id'] = str(record['_id'])
        all_records.append(record)

    return {'data' : all_records}



@app.get("/week-medical-records")
def week_medical_records(current_user: UserInDB = Depends(get_current_active_user)):

    records = DB.week_heart_history(current_user['_id'])
    all_records = []

    for record in records:
        record['_id'] = str(record['_id'])
        all_records.append(record)

    return {'data' : all_records}
