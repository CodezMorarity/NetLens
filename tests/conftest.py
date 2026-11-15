import pytest
from scapy.all import wrpcap

from examples.generate_demo import demo_packets


@pytest.fixture
def packets():
    return demo_packets()


@pytest.fixture
def pcap(tmp_path, packets):
    path = tmp_path / "sample.pcap"
    wrpcap(str(path), packets)
    return path
