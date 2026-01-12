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
    headers_to_remove = ['host', 'content-lenght', 'connection',  'accept-encoding']
    for header in headers_to_remove:
        headers.pop(header, None)

    headers['X-User-ID'] = str(user.get("sub", ""))
    headers['X-User-Email'] = str(user.get("email", ""))
    headers['X-User-Role'] = str(user.get("role", ""))

    body = await request.body()

    try:
        # Default timeout of httpx is 5.0 sec so we need to exdent it's time for connection
        client = httpx.AsyncClient(timeout= 30.0)
        stream_response = await client.stream(
            method= request.method,
            url= target_url,
            params= query_params,
            headers= headers,
            content= body,
            # follow_redirects is True so that client will receive response and status code of final replay server so that client thinks that it's communicating with final server only not with the gatways
            follow_redirects= True
        )
        await stream_response.aread()
        content_type = stream_response.headers.get("content-type", "")
        if "application/json" in content_type:
            try:
                json_data = stream_response.json()
                await stream_response.aclose()
                await client.aclose()
                return JSONResponse(
                    content= json_data,
                    status_code= stream_response.status_code
                )
            except json.JSONDecodeError:
                await stream_response.aclose()
                await client.aclose()
                return Response(
                    content= stream_response.text,
                    status_code= stream_response.status_code,
                    media_type= content_type
                )
            # If data received in response is in binary then we should send it in chunks to the client
            async def generate():
                try:
                    async for chunk in stream_response.aiter_bytes():
                        yield chunk
                finally:
                    await stream_response.aclose()
                    await client.aclose()
            return StreamingResponse(
                generate(),
                status_code = stream_response.status_code,
                media_type= content_type,
                headers= dict(stream_response.headers)
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
    
    