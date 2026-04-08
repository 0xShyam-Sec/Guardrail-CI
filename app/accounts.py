from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
import jwt
from jwt.exceptions import PyJWTError

from app.config import SECRET_KEY, ALGORITHM
from app.database import get_db
from app.models import Account

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
    except (PyJWTError, Exception):
        raise HTTPException(status_code=401, detail="Invalid token")


@router.get("/{account_id}")
def get_account(account_id: int, authorization: str = Header(default=None),
                db: Session = Depends(get_db)):
    user_id = get_current_user_id(authorization)

    # Fixed: use ORM query instead of raw SQL, enforce ownership
    account = db.query(Account).filter(Account.user_id == account_id).first()
    if not account:
        raise HTTPException(status_code=404, detail="Account not found")
    if account.user_id != user_id:
        raise HTTPException(status_code=403, detail="Access denied")
    return {"id": account.id, "user_id": account.user_id, "balance": account.balance}


@router.post("/{account_id}/transfer")
def transfer(account_id: int, request: TransferRequest,
             authorization: str = Header(default=None), db: Session = Depends(get_db)):
    user_id = get_current_user_id(authorization)

    # Fixed: use ORM queries
    from_account = db.query(Account).filter(Account.user_id == account_id).first()
    if not from_account:
        raise HTTPException(status_code=404, detail="Source account not found")
    if from_account.user_id != user_id:
        raise HTTPException(status_code=403, detail="Access denied")
    if from_account.balance < request.amount:
        raise HTTPException(status_code=400, detail="Insufficient funds")

    to_account = db.query(Account).filter(Account.user_id == request.to_account_id).first()
    if not to_account:
        raise HTTPException(status_code=404, detail="Destination account not found")

    from_account.balance -= request.amount
    to_account.balance += request.amount
    db.commit()

    return {"message": "Transfer successful"}
