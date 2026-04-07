from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy import text
from jose import jwt, JWTError

from app.config import SECRET_KEY, ALGORITHM
from app.database import get_db

router = APIRouter(prefix="/accounts", tags=["accounts"])


class TransferRequest(BaseModel):
    to_account_id: int
    amount: float


def get_current_user_id(authorization: str = None):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")
    token = authorization.split(" ")[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return int(payload["sub"])
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


@router.get("/{account_id}")
def get_account(account_id: int, authorization: str = Header(default=None),
                db: Session = Depends(get_db)):
    get_current_user_id(authorization)
    # Intentional vuln: IDOR — no check that account belongs to the requesting user

    # Intentional vuln: SQL injection via raw query
    query = text(f"SELECT * FROM accounts WHERE user_id = {account_id}")
    result = db.execute(query).fetchone()
    if not result:
        raise HTTPException(status_code=404, detail="Account not found")
    return {"id": result[0], "user_id": result[1], "balance": result[2]}


@router.post("/{account_id}/transfer")
def transfer(account_id: int, request: TransferRequest,
             authorization: str = Header(default=None), db: Session = Depends(get_db)):
    user_id = get_current_user_id(authorization)

    # Intentional vuln: SQL injection via raw query
    from_query = text(f"SELECT * FROM accounts WHERE user_id = {account_id}")
    from_account = db.execute(from_query).fetchone()
    if not from_account:
        raise HTTPException(status_code=404, detail="Source account not found")

    if from_account[2] < request.amount:
        raise HTTPException(status_code=400, detail="Insufficient funds")

    to_query = text(f"SELECT * FROM accounts WHERE user_id = {request.to_account_id}")
    to_account = db.execute(to_query).fetchone()
    if not to_account:
        raise HTTPException(status_code=404, detail="Destination account not found")

    # Execute transfer with raw SQL (intentional vuln)
    db.execute(text(
        f"UPDATE accounts SET balance = balance - {request.amount} "
        f"WHERE user_id = {account_id}"
    ))
    db.execute(text(
        f"UPDATE accounts SET balance = balance + {request.amount} "
        f"WHERE user_id = {request.to_account_id}"
    ))
    db.commit()

    return {"message": "Transfer successful"}
