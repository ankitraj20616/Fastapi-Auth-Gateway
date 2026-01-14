from fastapi import Request, Response
from opentelemetry import metrics
from opentelemetry.metrics import get_meter
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
import time
import logging

logger = logging.getLogger(__name__)

class MetricsMiddleware(BaseHTTPMiddleware):
    """
    This is custom middleware to capture detailed metrics about HTTP requests and responses.
    
    Metrics captured:
        - http_requests_total: Counter of total HTTP requests
        - http_request_duration_seconds: Histogram of request durations
        - http_requests_in_progress: UpDownCounter of concurrent requests
        - http_request_size_bytes: Histogram of request body sizes
        - http_response_size_bytes: Histogram of response body sizes
        - http_errors_total: Counter of error responses (4xx, 5xx)
    """
    
    def __init__(self, app: ASGIApp, service_name: str = "fastapi-auth-gateway"):
        super().__init__(app)
        self.meter = get_meter(__name__)
        
        self.request_counter = self.meter.create_counter(
            name="http_requests_total",
            description="Total number of HTTP requests",
            unit="requests"
        )
        
        self.request_duration = self.meter.create_histogram(
            name="http_request_duration_seconds",
            description="HTTP request duration in seconds",
            unit="s"
        )
        
        self.requests_in_progress = self.meter.create_up_down_counter(
            name="http_requests_in_progress",
            description="Number of HTTP requests currently in progress",
            unit="requests"
        )
        
        self.request_size = self.meter.create_histogram(
            name="http_request_size_bytes",
            description="HTTP request body size in bytes",
            unit="bytes"
        )
        
        self.response_size = self.meter.create_histogram(
            name="http_response_size_bytes",
            description="HTTP response body size in bytes",
            unit="bytes"
        )
        
        self.error_counter = self.meter.create_counter(
            name="http_errors_total",
            description="Total number of HTTP error responses",
            unit="errors"
        )
        
        self.auth_attempts = self.meter.create_counter(
            name="auth_attempts_total",
            description="Total number of authentication attempts",
            unit="attempts"
        )
        
        self.auth_failures = self.meter.create_counter(
            name="auth_failures_total",
            description="Total number of authentication failures",
            unit="failures"
        )
        
        self.proxy_requests = self.meter.create_counter(
            name="proxy_requests_total",
            description="Total number of proxied requests",
            unit="requests"
        )
        
    async def dispatch(self, request: Request, call_next):
        """
        This method process each request and capture metrics.
        """
        start_time = time.time()
        
        # Extract request metadata
        method = request.method
        path = request.url.path
        
        # Increment in-progress counter
        attributes = {
            "method": method,
            "path": path,
            "host": request.client.host if request.client else "unknown"
        }
        self.requests_in_progress.add(1, attributes)
        
        # Track request size
        content_length = request.headers.get("content-length", 0)
        try:
            request_size = int(content_length)
            self.request_size.record(request_size, attributes)
        except (ValueError, TypeError):
            request_size = 0
        
        # Track authentication endpoints
        if "/auth/login" in path or "/auth/signup" in path:
            self.auth_attempts.add(1, {"endpoint": path})
        
        # Track proxy requests
        if "/auth/proxy/" in path:
            self.proxy_requests.add(1, {"method": method})
        
        try:
            # Process the request
            response = await call_next(request)
            status_code = response.status_code
            
            # Calculate duration
            duration = time.time() - start_time
            
            # Update attributes with status code
            response_attributes = {
                **attributes,
                "status_code": str(status_code),
                "status_class": f"{status_code // 100}xx"
            }
            
            # Record metrics
            self.request_counter.add(1, response_attributes)
            self.request_duration.record(duration, response_attributes)
            
            # Track errors
            if status_code >= 400:
                error_attributes = {
                    **response_attributes,
                    "error_type": "client_error" if status_code < 500 else "server_error"
                }
                self.error_counter.add(1, error_attributes)
                
                # Track auth failures specifically
                if "/auth/" in path and status_code == 401:
                    self.auth_failures.add(1, {"endpoint": path, "reason": "unauthorized"})
            
            # Track response size
            response_content_length = response.headers.get("content-length", 0)
            try:
                response_size = int(response_content_length)
                self.response_size.record(response_size, response_attributes)
            except (ValueError, TypeError):
                pass
            
            logger.info(
                f"{method} {path} - {status_code} - {duration:.3f}s"
            )
            
            return response
            
        except Exception as e:
            # Handle exceptions and record metrics
            duration = time.time() - start_time
            error_attributes = {
                **attributes,
                "status_code": "500",
                "status_class": "5xx",
                "error_type": "exception",
                "exception_type": type(e).__name__
            }
            
            self.request_counter.add(1, error_attributes)
            self.request_duration.record(duration, error_attributes)
            self.error_counter.add(1, error_attributes)
            
            logger.error(f"Request failed: {method} {path} - {str(e)}")
            raise
            
        finally:
            # Decrement in-progress counter
            self.requests_in_progress.add(-1, attributes)