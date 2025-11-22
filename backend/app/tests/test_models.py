from datetime import datetime

from app.models import FlowRecord


def test_flowrecord_basic():
    now = datetime.utcnow()
    fr = FlowRecord(
        id="1",
        src_ip="10.0.0.1",
        src_port=1234,
        dst_ip="10.0.0.2",
        dst_port=80,
        transport_proto="TCP",
        app_proto="HTTP",
        start_time=now,
        end_time=now,
        duration_sec=0.0,
        bytes_from_src=10,
        bytes_from_dst=20,
        packets_from_src=1,
        packets_from_dst=2,
    )
    assert fr.src_ip == "10.0.0.1"

