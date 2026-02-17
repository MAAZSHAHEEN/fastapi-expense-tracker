from fastapi import FastAPI, Depends 
from pydantic import BaseModel
from sqlalchemy.orm import Session
from database import engine, Base, get_db, ExpenseDB
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
from database import UserDB
from fastapi.security import OAuth2PasswordBearer
from fastapi.security import OAuth2PasswordRequestForm

# Password hashing
pwd_context = CryptContext(schemes=["sha256_crypt"], deprecated="auto")

# JWT settings
SECRET_KEY = "your-secret-key-change-this-in-production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")
app = FastAPI()
Base.metadata.create_all(bind=engine)

class Expense(BaseModel):
    amount: float
    category: str
    description: str

class User(BaseModel):
    username: str
    password: str
class Token(BaseModel):
    access_token: str
    token_type: str

def hash_password(password: str):
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str):
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt
def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            return None
        user = db.query(UserDB).filter(UserDB.username == username).first()
        return user
    except JWTError:
        return None

@app.post("/register")
def register(user: User, db: Session = Depends(get_db)):
    # Check if username already exists
    existing_user = db.query(UserDB).filter(UserDB.username == user.username).first()
    if existing_user:
        return {"error": "Username already exists"}
    
    # Create new user with hashed password
    hashed_pw = hash_password(user.password)
    new_user = UserDB(username=user.username, hashed_password=hashed_pw)
    
    # Save to database
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    
    return {"message": "User created successfully", "username": new_user.username}
@app.post("/login")
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    # Find user in database
    db_user = db.query(UserDB).filter(UserDB.username == form_data.username).first()
    
    # Check if user exists and password is correct
    if not db_user or not verify_password(form_data.password, db_user.hashed_password):
        return {"error": "Invalid username or password"}
    
    # Create token
    access_token = create_access_token(data={"sub": db_user.username})
    
    return {"access_token": access_token, "token_type": "bearer"}



@app.post("/expenses")
def create_expense(expense: Expense, db: Session = Depends(get_db), current_user: UserDB = Depends(get_current_user)):
    if not current_user:
        return {"error": "Not authenticated"}
    
    expense_db = ExpenseDB(
        amount=expense.amount, 
        category=expense.category, 
        description=expense.description,
        user_id=current_user.id
    )
    db.add(expense_db)
    db.commit()
    db.refresh(expense_db)
    return expense_db
@app.get("/expenses")
def get_expenses(category: str = None, db: Session = Depends(get_db), current_user: UserDB = Depends(get_current_user)):
    if not current_user:
        return {"error": "Not authenticated"}
    
    if category:
        return db.query(ExpenseDB).filter(ExpenseDB.user_id == current_user.id, ExpenseDB.category == category).all()
    return db.query(ExpenseDB).filter(ExpenseDB.user_id == current_user.id).all()
@app.get("/expenses/{expense_id}")
def get_expense(expense_id: int, db: Session = Depends(get_db), current_user: UserDB = Depends(get_current_user)):
    if not current_user:
        return {"error": "Not authenticated"}
    
    expense_db = db.query(ExpenseDB).filter(ExpenseDB.id == expense_id, ExpenseDB.user_id == current_user.id).first()
    if expense_db:
        return expense_db
    return {"error": "Expense not found"}
@app.delete("/expenses/{expense_id}")
def delete_expense(expense_id: int, db: Session = Depends(get_db), current_user: UserDB = Depends(get_current_user)):
    if not current_user:
        return {"error": "Not authenticated"}
    
    expense_db = db.query(ExpenseDB).filter(ExpenseDB.id == expense_id, ExpenseDB.user_id == current_user.id).first()
    if expense_db:
        db.delete(expense_db)
        db.commit()
        return {"message": "Expense deleted successfully"}
    return {"error": "Expense not found"}
    
@app.put("/expenses/{expense_id}")
def update_expense(expense_id: int, expense: Expense, db: Session = Depends(get_db), current_user: UserDB = Depends(get_current_user)):
    if not current_user:
        return {"error": "Not authenticated"}
    
    expense_db = db.query(ExpenseDB).filter(ExpenseDB.id == expense_id, ExpenseDB.user_id == current_user.id).first()
    if expense_db:
        expense_db.amount = expense.amount
        expense_db.category = expense.category
        expense_db.description = expense.description
        db.commit()
        db.refresh(expense_db)
        return expense_db
    return {"error": "Expense not found"}
    