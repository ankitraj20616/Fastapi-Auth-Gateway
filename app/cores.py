from fastapi import Request, Response, HTTPException, status
from fastapi.responses import JSONResponse, StreamingResponse
from .config import settings
import httpx
import json

async def forward_authenticated_user(
    request: Request,
    target_path: str,
    user: dict
):
    '''
    This internal method will forward the authenticated request to target URL

    Args:
        request: Original FastAPI request that needs to forward
        target_path: Path to append to the target base URL
        user: Verified user information from token
    
    Return:
        response received from the replayed request
    '''
    target_url = f"{settings.PROXY_TARGET_URL}/{target_path}"
    query_params = dict(request.query_params)
    headers = dict(request.headers)
    headers_to_remove = ['host', 'content-length', 'connection',  'accept-encoding']
    for header in headers_to_remove:
        headers.pop(header, None)

    headers['X-User-ID'] = str(user.get("sub", ""))
    headers['X-User-Email'] = str(user.get("email", ""))
    headers['X-User-Role'] = str(user.get("role", ""))

    body = await request.body()

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            async with client.stream(
                method=request.method,
                url=target_url,
                params=query_params,
                headers=headers,
                content=body,
                follow_redirects=True
            ) as response:
                
                content_type = response.headers.get("content-type", "")
                
                if "application/json" in content_type:
                    try:
                        await response.aread()
                        json_data = response.json()
                        return JSONResponse(
                            content=json_data,
                            status_code=response.status_code
                        )
                    except json.JSONDecodeError:
                        await response.aread()
                        return Response(
                            content=response.text,
                            status_code=response.status_code,
                            media_type=content_type
                        )
                
                # For binary/large responses, read all chunks and return
                chunks = []
                async for chunk in response.aiter_bytes():
                    chunks.append(chunk)
                
                return Response(
                    content=b''.join(chunks),
                    status_code=response.status_code,
                    media_type=content_type,
                    headers=dict(response.headers)
                )
    except httpx.TimeoutException:
        raise HTTPException(
            status_code= status.HTTP_504_GATEWAY_TIMEOUT,
            detail= "Target service did not respond in time."
        )
    except httpx.RequestError as e:
        raise HTTPException(
            status_code = status.HTTP_502_BAD_GATEWAY,
            detail= f"Failed to connect to the target service: {str(e)}"
        )
    except Exception as e:
        print(f"Proxy error: {str(e)}")
        raise HTTPException(
            status_code = status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail= f"Proxy error: {str(e)}"
        )
    
    
    