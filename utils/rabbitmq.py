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
