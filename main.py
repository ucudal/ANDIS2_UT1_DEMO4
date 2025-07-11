from dotenv import load_dotenv
load_dotenv()

import os
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from jose.exceptions import JWTClaimsError, ExpiredSignatureError
import httpx
import asyncio
from typing import Dict, Optional
from datetime import datetime
import logging

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI()
security = HTTPBearer()

KEYCLOAK_URL = os.environ.get("KEYCLOAK_URL", "http://localhost:8080")
KEYCLOAK_REALM = os.environ.get("KEYCLOAK_REALM", "demo-realm")
KEYCLOAK_CLIENT_ID = os.environ.get("KEYCLOAK_CLIENT_ID", "demo-client")
KEYCLOAK_AUDIENCE = os.environ.get("KEYCLOAK_AUDIENCE", "account")
# KEYCLOAK_CLIENT_SECRET = os.environ.get("KEYCLOAK_CLIENT_SECRET", "demo-secret")



# Cache for public keys
public_keys_cache = {}
cache_timestamp = None
CACHE_DURATION = 3600  # Cache for 1 hour

async def get_keycloak_public_keys():
    """Fetch public keys from Keycloak's JWKS endpoint"""
    global public_keys_cache, cache_timestamp

    # Check if cache is still valid
    if cache_timestamp and (datetime.now().timestamp() - cache_timestamp) < CACHE_DURATION:
        return public_keys_cache

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/certs",
                timeout=10.0
            )
            response.raise_for_status()

            jwks = response.json()

            # Convert JWKS to a format suitable for jose
            public_keys = {}
            for key in jwks.get("keys", []):
                kid = key.get("kid")
                if kid:
                    public_keys[kid] = key

            public_keys_cache = public_keys
            cache_timestamp = datetime.now().timestamp()

            logger.info(f"Successfully fetched {len(public_keys)} public keys from Keycloak")
            return public_keys

    except Exception as e:
        logger.error(f"Error fetching public keys: {str(e)}")
        if public_keys_cache:
            logger.info("Using cached public keys")
            return public_keys_cache
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Unable to fetch public keys from Keycloak"
        )

async def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict:
    """Verify and decode JWT token"""
    token = credentials.credentials

    try:
        # Get the token header to find the key ID
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get("kid")

        if not kid:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token missing key ID"
            )

        # Get public keys from Keycloak
        public_keys = await get_keycloak_public_keys()

        if kid not in public_keys:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid key ID"
            )

        # Verify and decode the token using the correct audience
        payload = jwt.decode(
            token,
            public_keys[kid],
            algorithms=["RS256"],
            audience=KEYCLOAK_AUDIENCE,  # Use AUDIENCE instead of CLIENT_ID
            issuer=f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}"
        )

        # Additional validation: check that the token was issued by our client
        if payload.get("azp") != KEYCLOAK_CLIENT_ID:
            logger.warning(f"Token was issued by client '{payload.get('azp')}' but expected '{KEYCLOAK_CLIENT_ID}'")
            # This is a warning, not an error, since the signature is valid

        return payload

    except ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired"
        )
    except JWTClaimsError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token claims: {str(e)}"
        )
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid token: {str(e)}"
        )
    except Exception as e:
        logger.error(f"Unexpected error verifying token: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error"
        )

# Routes
@app.get("/")
async def root():
    """Root endpoint with API information"""
    return {
        "message": "Demo de conceptos de seguridad con Keycloak",
        "endpoints": {
            "/protected": "Protected endpoint requiring valid JWT",
            "/user-info": "Get user information from JWT token",
            "/token-info": "Get detailed token information"
        }
    }


# async def verify_token_flexible(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict:
#     """Verify and decode JWT token with flexible audience validation"""
#     token = credentials.credentials

#     try:
#         # Get the token header to find the key ID
#         unverified_header = jwt.get_unverified_header(token)
#         kid = unverified_header.get("kid")

#         if not kid:
#             raise HTTPException(
#                 status_code=status.HTTP_401_UNAUTHORIZED,
#                 detail="Token missing key ID"
#             )

#         # Get public keys from Keycloak
#         public_keys = await get_keycloak_public_keys()

#         if kid not in public_keys:
#             raise HTTPException(
#                 status_code=status.HTTP_401_UNAUTHORIZED,
#                 detail="Invalid key ID"
#             )

#         # First decode without audience validation to inspect the token
#         payload_debug = jwt.decode(
#             token,
#             public_keys[kid],
#             algorithms=["RS256"],
#             options={"verify_aud": False, "verify_iss": False}
#         )

#         # Check the audience claim and determine how to validate
#         token_audience = payload_debug.get('aud')

#         # Common Keycloak scenarios:
#         # 1. audience is "account" (common default)
#         # 2. audience is a list containing multiple services
#         # 3. audience matches your client_id

#         if isinstance(token_audience, list):
#             # If it's a list, try to find our client_id or use account
#             if CLIENT_ID in token_audience:
#                 audience_to_verify = CLIENT_ID
#             elif "account" in token_audience:
#                 audience_to_verify = "account"
#             else:
#                 audience_to_verify = token_audience[0]
#         else:
#             # Single audience value
#             audience_to_verify = token_audience

#         # Check issuer and build expected issuer
#         token_issuer = payload_debug.get('iss')
#         expected_issuer = f"{KEYCLOAK_URL}/realms/{REALM}"

#         logger.info(f"Token issuer: {token_issuer}")
#         logger.info(f"Expected issuer: {expected_issuer}")

#         # Try to determine the correct issuer format
#         if token_issuer:
#             # Use the issuer from the token if it looks valid
#             if "/realms/" in token_issuer and token_issuer.endswith(f"/realms/{REALM}"):
#                 issuer_to_verify = token_issuer
#             else:
#                 # Try our expected format
#                 issuer_to_verify = expected_issuer
#         else:
#             issuer_to_verify = expected_issuer

#         # Now verify with the determined audience and issuer
#         payload = jwt.decode(
#             token,
#             public_keys[kid],
#             algorithms=["RS256"],
#             audience=audience_to_verify,
#             issuer=issuer_to_verify
#         )

#         logger.info(f"Token validated successfully with audience: {audience_to_verify}")
#         return payload

#     except ExpiredSignatureError:
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED,
#             detail="Token has expired"
#         )
#     except JWTClaimsError as e:
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED,
#             detail=f"Invalid token claims: {str(e)}"
#         )
#     except JWTError as e:
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED,
#             detail=f"Invalid token: {str(e)}"
#         )
#     except Exception as e:
#         logger.error(f"Unexpected error verifying token: {str(e)}")
#         raise HTTPException(
#             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
#             detail="Internal server error"
#         )

# async def verify_token_debug(credentials: HTTPAuthorizationCredentials = Depends(security)) -> Dict:
#     """Verify and decode JWT token with minimal validation for debugging"""
#     token = credentials.credentials

#     try:
#         # Get the token header to find the key ID
#         unverified_header = jwt.get_unverified_header(token)
#         kid = unverified_header.get("kid")

#         if not kid:
#             raise HTTPException(
#                 status_code=status.HTTP_401_UNAUTHORIZED,
#                 detail="Token missing key ID"
#             )

#         # Get public keys from Keycloak
#         public_keys = await get_keycloak_public_keys()

#         if kid not in public_keys:
#             raise HTTPException(
#                 status_code=status.HTTP_401_UNAUTHORIZED,
#                 detail="Invalid key ID"
#             )

#         # Decode with minimal validation - only verify signature and expiration
#         payload = jwt.decode(
#             token,
#             public_keys[kid],
#             algorithms=["RS256"],
#             options={"verify_aud": False, "verify_iss": False}
#         )

#         # Manual expiration check
#         import time
#         current_time = time.time()
#         if payload.get('exp', 0) < current_time:
#             raise HTTPException(
#                 status_code=status.HTTP_401_UNAUTHORIZED,
#                 detail="Token has expired"
#             )

#         logger.info(f"Token validated with minimal checks - signature OK, not expired")
#         return payload

#     except ExpiredSignatureError:
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED,
#             detail="Token has expired"
#         )
#     except JWTError as e:
#         raise HTTPException(
#             status_code=status.HTTP_401_UNAUTHORIZED,
#             detail=f"Invalid token: {str(e)}"
#         )
#     except Exception as e:
#         logger.error(f"Unexpected error verifying token: {str(e)}")
#         raise HTTPException(
#             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
#             detail="Internal server error"
#         )
#
# @app.get("/protected-debug")
# async def protected_route_debug(token_data: Dict = Depends(verify_token_debug)):
#     """Protected route with minimal validation - only checks signature and expiration"""
#     return {
#         "message": "Access granted with minimal validation (signature + expiration only)",
#         "user": token_data.get("preferred_username", "Unknown"),
#         "roles": token_data.get("realm_access", {}).get("roles", []),
#         "token_audience": token_data.get("aud"),
#         "token_issuer": token_data.get("iss"),
#         "token_client": token_data.get("azp")
#     }
#
# async def protected_route_flexible(token_data: Dict = Depends(verify_token_flexible)):
#     """Protected route with flexible audience validation"""
#     return {
#         "message": "Access granted with flexible validation",
#         "user": token_data.get("preferred_username", "Unknown"),
#         "roles": token_data.get("realm_access", {}).get("roles", [])
#     }

@app.get("/protected")
async def protected_route(token_data: Dict = Depends(verify_token)):
    """Protected route that requires valid JWT token"""
    return {
        "message": "Access granted to protected resource",
        "user": token_data.get("preferred_username", "Unknown"),
        "roles": token_data.get("realm_access", {}).get("roles", [])
    }

@app.get("/user-info")
async def get_user_info(token_data: Dict = Depends(verify_token)):
    """Extract user information from JWT token"""
    return {
        "user_id": token_data.get("sub"),
        "username": token_data.get("preferred_username"),
        "email": token_data.get("email"),
        "first_name": token_data.get("given_name"),
        "last_name": token_data.get("family_name"),
        "roles": token_data.get("realm_access", {}).get("roles", []),
        "groups": token_data.get("groups", [])
    }

@app.get("/token-info")
async def get_token_info(token_data: Dict = Depends(verify_token)):
    """Get detailed information about the JWT token"""
    return {
        "issuer": token_data.get("iss"),
        "subject": token_data.get("sub"),
        "audience": token_data.get("aud"),
        "issued_at": datetime.fromtimestamp(token_data.get("iat", 0)).isoformat(),
        "expires_at": datetime.fromtimestamp(token_data.get("exp", 0)).isoformat(),
        "token_type": token_data.get("typ"),
        "session_id": token_data.get("sid"),
        "client_id": token_data.get("azp"),
        "scope": token_data.get("scope", "").split()
    }

# @app.get("/debug-token")
# async def debug_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
#     """Debug endpoint to see token contents without full validation"""
#     token = credentials.credentials

#     try:
#         # Get unverified header and payload
#         header = jwt.get_unverified_header(token)
#         payload = jwt.get_unverified_claims(token)

#         return {
#             "header": header,
#             "payload": payload,
#             "validation_comparison": {
#                 "audience": {
#                     "in_token": payload.get("aud"),
#                     "expected": AUDIENCE,  # Use AUDIENCE instead of CLIENT_ID
#                     "match": payload.get("aud") == AUDIENCE or (
#                         isinstance(payload.get("aud"), list) and AUDIENCE in payload.get("aud", [])
#                     )
#                 },
#                 "issuer": {
#                     "in_token": payload.get("iss"),
#                     "expected": f"{KEYCLOAK_URL}/realms/{REALM}",
#                     "match": payload.get("iss") == f"{KEYCLOAK_URL}/realms/{REALM}"
#                 },
#                 "client_id": {
#                     "in_token": payload.get("azp"),
#                     "expected": CLIENT_ID,
#                     "match": payload.get("azp") == CLIENT_ID
#                 }
#             },
#             "suggestions": {
#                 "if_audience_mismatch": f"Try setting AUDIENCE = '{payload.get('aud')}' in your config",
#                 "if_issuer_mismatch": f"Check if KEYCLOAK_URL should be '{payload.get('iss', '').replace(f'/realms/{REALM}', '') if payload.get('iss') else 'unknown'}'",
#                 "minimal_validation": "Use /protected-debug endpoint to skip audience/issuer validation"
#             }
#         }
#     except JWTError as e:
#         raise HTTPException(
#             status_code=status.HTTP_400_BAD_REQUEST,
#             detail=f"Invalid JWT token: {str(e)}"
#         )

@app.post("/decode-token")
async def decode_token_endpoint(token: str):
    """Decode a JWT token without verification (for debugging)"""
    try:
        # Get unverified header and payload
        header = jwt.get_unverified_header(token)
        payload = jwt.get_unverified_claims(token)

        return {
            "header": header,
            "payload": payload,
            "warning": "This token was not verified - use only for debugging"
        }
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid JWT token: {str(e)}"
        )


# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint"""
    try:
        # Test connection to Keycloak
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{KEYCLOAK_URL}/realms/{KEYCLOAK_REALM}",
                timeout=5.0
            )
            keycloak_status = "healthy" if response.status_code == 200 else "unhealthy"
    except:
        keycloak_status = "unhealthy"

    return {
        "status": "healthy",
        "keycloak_connection": keycloak_status,
        "cached_keys": len(public_keys_cache)
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
