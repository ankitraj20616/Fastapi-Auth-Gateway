from .config import settings
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter, SimpleSpanProcessor
from opentelemetry import trace, metrics
from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import OTLPMetricExporter
from opentelemetry.sdk.metrics import MeterProvider
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.logging import LoggingInstrumentor
import logging


def setup_opentelemetry(app, service_name: str = "fastapi-auth-gateway"):
    '''
    This method will setup all configurations for Opentelemetry for our fastapi app
    Args:
        app- FastAPI app instance.
        service_name- Name of this service.
    '''
    environment = settings.APP_ENVIRONMENT
    resource = Resource.create({
        "service.name": service_name,
        "service.version": settings.APP_VERSION,
        "deployment.environment": environment
    })
    # gRPC expects host:port only
    otlp_endpoint = (
        settings.OTLP_URL
        .replace("http://", "")
        .replace("https://", "")
    )
    tracer_provider = TracerProvider(resource= resource)
    otlp_exporter = OTLPSpanExporter(
        endpoint= otlp_endpoint,
        insecure= True  # send data without encoding it in raw format, if we set it to false then we will first encode it using TLS then send it over network for safety in production
    )
    
    if environment == "development":
        tracer_provider.add_span_processor(SimpleSpanProcessor(otlp_exporter))
        tracer_provider.add_span_processor(SimpleSpanProcessor(ConsoleSpanExporter()))
    else:
        # Batch Processer we will be using it in production 
        span_processor = BatchSpanProcessor(otlp_exporter) 
        tracer_provider.add_span_processor(span_processor)
    
    
    
    trace.set_tracer_provider(tracer_provider)
    
    metric_reader = PeriodicExportingMetricReader(
        OTLPMetricExporter(
            endpoint= otlp_endpoint,
            insecure= True
        ),
        export_interval_millis= 5000  # export metrice after every 5 sec(5000 milli sec)
    )
    meter_provider = MeterProvider(
        resource= resource,
        metric_readers= [metric_reader]
    )
    metrics.set_meter_provider(meter_provider)
    FastAPIInstrumentor.instrument_app(app, excluded_urls= "/docs,/openapi.json")
    LoggingInstrumentor().instrument(set_logging_format= True)
    logging.info(f"OpenTelemetry initialized for {service_name}")
    return tracer_provider, meter_provider