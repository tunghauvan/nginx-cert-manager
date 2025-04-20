import pika
import json
import logging
import os

from dotenv import load_dotenv
load_dotenv()

def send_rabbitmq_message(
    queue: str,
    message: dict,
    host: str = None,
    port: int = None,
    durable: bool = True
):
    """
    Send a message to a RabbitMQ queue.

    Args:
        queue (str): Queue name.
        message (dict): Message to send (will be JSON-encoded).
        host (str): RabbitMQ host (overrides env if set).
        port (int): RabbitMQ port (overrides env if set).
        durable (bool): Whether the queue/message should be durable.
    """
    logger = logging.getLogger("nginx-cert-manager.rabbitmq")
    # Get config from environment or arguments
    rabbitmq_host = host or os.environ.get("RABBITMQ_HOST", "localhost")
    rabbitmq_port = port or int(os.environ.get("RABBITMQ_PORT", 5672))
    rabbitmq_user = os.environ.get("RABBITMQ_DEFAULT_USER", "user")
    rabbitmq_pass = os.environ.get("RABBITMQ_DEFAULT_PASS", "password")

    try:
        credentials = pika.PlainCredentials(rabbitmq_user, rabbitmq_pass)
        connection = pika.BlockingConnection(
            pika.ConnectionParameters(
                host=rabbitmq_host,
                port=rabbitmq_port,
                credentials=credentials
            )
        )
        channel = connection.channel()
        channel.queue_declare(queue=queue, durable=durable)
        channel.basic_publish(
            exchange='',
            routing_key=queue,
            body=json.dumps(message),
            properties=pika.BasicProperties(
                delivery_mode=2 if durable else 1,
            )
        )
        logger.info(f"Sent message to RabbitMQ queue '{queue}': {message}")
        connection.close()
        return True
    except Exception as e:
        logger.error(f"Failed to send message to RabbitMQ: {e}")
        return False

def setup_delay_queue(channel, queue_name, retry_delay_ms, logger: logging.Logger):
    """
    Set up the queues and exchanges needed for delayed message processing
    """
    # Create the retry exchange
    retry_exchange_name = f"{queue_name}_retry_exchange"
    channel.exchange_declare(
        exchange=retry_exchange_name,
        exchange_type='direct',
        durable=True
    )

    # Create the delay queue with the specified TTL (time-to-live)
    delay_queue_name = f"{queue_name}_delay_queue"
    arguments = {
        'x-dead-letter-exchange': '',  # Default exchange
        'x-dead-letter-routing-key': queue_name,  # Route back to the original queue
        'x-message-ttl': retry_delay_ms,  # Delay time in milliseconds
    }
    channel.queue_declare(
        queue=delay_queue_name,
        durable=True,
        arguments=arguments
    )

    # Bind the delay queue to the retry exchange
    channel.queue_bind(
        queue=delay_queue_name,
        exchange=retry_exchange_name,
        routing_key=delay_queue_name
    )

    logger.info(f"Configured delay queue: {delay_queue_name} with TTL: {retry_delay_ms}ms")
    return retry_exchange_name, delay_queue_name
