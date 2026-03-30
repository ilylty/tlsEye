import subprocess
import json
import base64
import argparse
import sys

try:
    from kafka import KafkaProducer
except ImportError:
    print("Please install kafka-python: pip install kafka-python")
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(
        description="Read PCAP and send TLS Client Hello to Kafka"
    )
    pcap_file = r"xxxx"
    parser.add_argument("--brokers", default="127.0.0.1:9092", help="Kafka brokers")
    parser.add_argument("--topic", default="tls_client_hello", help="Kafka topic")
    args = parser.parse_args()

    print(f"Connecting to Kafka at {args.brokers}...")
    producer = KafkaProducer(
        bootstrap_servers=args.brokers,
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
    )

    tshark_cmd = [
        "tshark",
        "-r",
        pcap_file,
        "-Y",
        "tls.handshake.type == 1",  # Filter only Client Hello
        "-T",
        "fields",
        "-e",
        "ip.src",
        "-e",
        "ip.dst",
        "-e",
        "tcp.payload",
    ]

    print(f"Running tshark on {pcap_file}...")
    try:
        process = subprocess.Popen(
            tshark_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
    except FileNotFoundError:
        print(
            "Error: tshark is not installed or not in PATH. Please install Wireshark/tshark."
        )
        sys.exit(1)

    count = 0
    for line in process.stdout:
        line = line.strip()
        if not line:
            continue

        parts = line.split("\t")
        if len(parts) >= 3:
            src_ip = parts[0]
            dst_ip = parts[1]
            tcp_payload_hex = parts[2]

            # The payload might be empty or multiple payloads separated by commas
            # We take the first one or clean it up
            tcp_payload_hex = tcp_payload_hex.split(",")[0].replace(":", "")
            if not tcp_payload_hex:
                continue

            try:
                # Convert hex string to raw bytes
                raw_bytes = bytes.fromhex(tcp_payload_hex)
                # Convert to base64
                payload_base64 = base64.b64encode(raw_bytes).decode("utf-8")

                msg = {
                    "ori_ip": src_ip,
                    "dst_ip": dst_ip,
                    "payload_base64": payload_base64,
                }

                producer.send(args.topic, value=msg)
                count += 1

                if count % 100 == 0:
                    print(f"Sent {count} messages...")
            except Exception as e:
                print(f"Error processing packet: {e}")

    producer.flush()
    print(
        f"Done! Successfully sent {count} Client Hello messages to Kafka topic '{args.topic}'."
    )


if __name__ == "__main__":
    main()
