from fastapi import APIRouter, Depends, HTTPException, status
import boto3
from db.db import get_db
from db.models.user import User
from helper.auth_helper import get_secret_hash
from pydantic_models.auth_models import SignupRequest, LoginRequest, ConfirmSignupRequest
from secret_keys import SecretKeys
from sqlalchemy.orm import Session

router = APIRouter()
secret_keys = SecretKeys()

COGNITO_CLIENT_ID = secret_keys.COGNITO_CLIENT_ID
COGNITO_CLIENT_SECRET = secret_keys.COGNITO_CLIENT_SECRET

cognito_client = boto3.client("cognito-idp", region_name=secret_keys.REGION_NAME)

@router.post("/signup")
def signup_user(
    data: SignupRequest,
    db: Session = Depends(get_db)
):
    try:
        secret_hash = get_secret_hash(data.email, COGNITO_CLIENT_ID, COGNITO_CLIENT_SECRET)

        cognito_response = cognito_client.sign_up(
            ClientId=COGNITO_CLIENT_ID,
            Username=data.email,
            Password=data.password,
            SecretHash=secret_hash,
            UserAttributes=[
                {
                    "Name": "email",
                    "Value": data.email
                },
                {
                    "Name": "name",
                    "Value": data.name
                }
            ]
        )

        cognito_sub = cognito_response.get("UserSub")

        if not cognito_sub:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail='Failed to get user sub'
            )

        new_user = User(
            name=data.name,
            email=data.email,
            cognito_sub=cognito_sub
        )

        db.add(new_user)
        db.commit()
        db.refresh(new_user)

        return {
            "message": "User signed up successfully, please check your email for verification code",
            "data": cognito_response
        }

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@router.post("/login")
def login_user(
    data: LoginRequest,
):
    try:
        secret_hash = get_secret_hash(
            data.email,
            COGNITO_CLIENT_ID,
            COGNITO_CLIENT_SECRET,
        )

        cognito_response = cognito_client.initiate_auth(
            ClientId=COGNITO_CLIENT_ID,
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={
                "USERNAME": data.email,
                "PASSWORD": data.password,
                "SECRET_HASH": secret_hash
            }
        )

        return {
            "message": "user logged in successfully",
            "data": cognito_response
        }

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )

@router.post("/confirm-signup")
def confirm_signup(
    data: ConfirmSignupRequest,
):
    try:
        secret_hash = get_secret_hash(
            data.email,
            COGNITO_CLIENT_ID,
            COGNITO_CLIENT_SECRET,
        )

        cognito_response = cognito_client.confirm_sign_up(
            ClientId=COGNITO_CLIENT_ID,
            Username=data.email,
            ConfirmationCode=data.confirmation_code,
            SecretHash=secret_hash,
        )

        return {
            "message": "User confirmed successfully",
            "data": cognito_response
        }

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
