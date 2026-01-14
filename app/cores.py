from fastapi import Request, Response, HTTPException, status
from fastapi.responses import JSONResponse, StreamingResponse
from opentelemetry import trace
from .config import settings
import httpx
import json

tracer = trace.get_tracer(__name__)

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
    with tracer.start_as_current_span("forward_authenticated_user") as span:
        target_url = f"{settings.PROXY_TARGET_URL}/{target_path}"
        
        span.set_attribute("http.method", request.method)
        span.set_attribute("http.url", target_url)
        span.set_attribute("user.id", user.get("sub", ""))
        span.set_attribute("user.email", user.get("email", ""))
        
        with tracer.start_as_current_span("prepare_request"):
            query_params = dict(request.query_params)
            headers = dict(request.headers)
            headers_to_remove = ['host', 'content-length', 'connection',  'accept-encoding']
            for header in headers_to_remove:
                headers.pop(header, None)

            headers['X-User-ID'] = str(user.get("sub", ""))
            headers['X-User-Email'] = str(user.get("email", ""))
            headers['X-User-Role'] = str(user.get("role", ""))

            body = await request.body()
            span.set_attribute("request.body_size", len(body))

        try:
            with tracer.start_as_current_span("http_client_request") as http_span:
                async with httpx.AsyncClient(timeout=30.0) as client:
                    async with client.stream(
                        
                        method=request.method,
                        url=target_url,
                        params=query_params,
                        headers=headers,
                        content=body,
                        follow_redirects=True
                    ) as response:
                        http_span.set_attribute("http.status_code", response.status_code)
                        content_type = response.headers.get("content-type", "")
                        http_span.set_attribute("http.content_type", content_type)
                        
                        with tracer.start_as_current_span("process_response") as process_span:
                            if "application/json" in content_type:
                                try:
                                    await response.aread()
                                    json_data = response.json()
                                    process_span.set_attribute("response.type", "json")
                                    return JSONResponse(
                                        content=json_data,
                                        status_code=response.status_code
                                    )
                                except json.JSONDecodeError:
                                    await response.aread()
                                    process_span.set_attribute("response.type", "text")
                                    return Response(
                                        content=response.text,
                                        status_code=response.status_code,
                                        media_type=content_type
                                    )
                            
                            # For binary/large responses, read all chunks and return
                            chunks = []
                            async for chunk in response.aiter_bytes():
                                chunks.append(chunk)
                            
                            total_size = sum(len(chunk) for chunk in chunks)
                            process_span.set_attribute("response.type", "binary")
                            process_span.set_attribute("response.size", total_size)
                            
                            return Response(
                                content=b''.join(chunks),
                                status_code=response.status_code,
                                media_type=content_type,
                                headers=dict(response.headers)
                            )
        except httpx.TimeoutException as e:
            span.set_attribute("error.type", "timeout")
            span.set_attribute("error.message", str(e))
            raise HTTPException(
                status_code= status.HTTP_504_GATEWAY_TIMEOUT,
                detail= "Target service did not respond in time."
            )
        except httpx.RequestError as e:
            span.set_attribute("error.type", "connection")
            span.set_attribute("error.message", str(e))
            raise HTTPException(
                status_code = status.HTTP_502_BAD_GATEWAY,
                detail= f"Failed to connect to the target service: {str(e)}"
            )
        except Exception as e:
            span.set_attribute("error.type", "unknown")
            span.set_attribute("error.message", str(e))
            print(f"Proxy error: {str(e)}")
            raise HTTPException(
                status_code = status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail= f"Proxy error: {str(e)}"
            )