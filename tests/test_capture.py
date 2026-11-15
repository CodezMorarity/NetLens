import signal
import threading

import pytest
from scapy.all import IP, TCP, AsyncSniffer, Ether, PcapNgWriter, rdpcap
from scapy.automaton import ObjectPipe

from netlens.capture import NetLens, PCAPWriter


def test_pcap_streams_before_close_and_rotates_in_directory(tmp_path, packets):
    path = tmp_path / "nested" / "capture.pcap"
    path.parent.mkdir()
    writer = PCAPWriter(path, max_size_mb=150 / 1024**2)
    writer.write(packets[0])
    assert len(rdpcap(str(path))) == 1
    writer.write(packets[1])
    writer.close()
    writer.close()
    assert len(writer.files) == 2
    assert (path.parent / "capture_1.pcap").exists()
    assert sum(len(rdpcap(name)) for name in writer.files) == 2
    with pytest.raises(ValueError, match="closed"):
        writer.write(packets[0])


def test_pcap_refuses_overwrite(tmp_path):
    path = tmp_path / "existing.pcap"
    path.write_bytes(b"keep")
    with pytest.raises(FileExistsError):
        PCAPWriter(path)
    assert path.read_bytes() == b"keep"


def test_rotation_collision_propagates_error(tmp_path, packets):
    path = tmp_path / "capture.pcap"
    collision = tmp_path / "capture_1.pcap"
    collision.write_bytes(b"keep")
    with PCAPWriter(path, max_size_mb=100 / 1024**2) as writer:
        writer.write(packets[0])
        with pytest.raises(FileExistsError):
            writer.write(packets[1])
    assert collision.read_bytes() == b"keep"


def test_empty_capture_is_readable(tmp_path):
    path = tmp_path / "empty.pcap"
    with PCAPWriter(path):
        pass
    assert len(rdpcap(str(path))) == 0
    assert NetLens().analyze(path)["total_packets"] == 0


def test_mixed_linktypes_rotate(tmp_path):
    with PCAPWriter(tmp_path / "mixed.pcap") as writer:
        writer.write(Ether() / IP() / TCP())
        writer.write(IP() / TCP())
    assert len(writer.files) == 2
    assert isinstance(rdpcap(writer.files[0])[0], Ether)
    assert isinstance(rdpcap(writer.files[1])[0], IP)


def test_offline_stream_count_and_bounded_store(pcap, tmp_path):
    sniffer = NetLens(count=5, store_limit=2, pcap_out=tmp_path / "copy.pcap")
    data = sniffer.analyze(pcap)
    assert data["total_packets"] == 5
    assert len(data["stored_packets"]) == 2
    assert [p["number"] for p in data["stored_packets"]] == [4, 5]
    assert len(rdpcap(data["pcap_files"][0])) == 5


def test_pcapng_supported(tmp_path, packets):
    path = tmp_path / "capture.pcapng"
    with PcapNgWriter(str(path)) as writer:
        for packet in packets:
            writer.write(packet)
    assert NetLens().analyze(path)["total_packets"] == len(packets)


@pytest.mark.parametrize("remove_bytes", [1, 10, 30])
def test_truncated_pcap_is_not_silently_accepted(pcap, remove_bytes):
    pcap.write_bytes(pcap.read_bytes()[:-remove_bytes])
    with pytest.raises(ValueError, match="Truncated"):
        NetLens().analyze(pcap)


def test_truncated_pcap_header(pcap):
    pcap.write_bytes(pcap.read_bytes() + b"incomplete")
    with pytest.raises(ValueError, match="header"):
        NetLens().analyze(pcap)


def test_truncated_pcapng_is_not_silently_accepted(tmp_path, packets):
    path = tmp_path / "truncated.pcapng"
    with PcapNgWriter(str(path)) as writer:
        writer.write(packets[0])
    path.write_bytes(path.read_bytes()[:-1])
    with pytest.raises(ValueError, match="Truncated"):
        NetLens().analyze(path)


def fake_socket_capture(monkeypatch, action=None):
    """Exercise real AsyncSniffer on a local in-memory pipe, without raw sockets."""
    pipe = ObjectPipe()

    def factory(**kwargs):
        kwargs.pop("iface")
        kwargs.pop("filter")
        started = kwargs["started_callback"]

        def ready():
            started()
            if action:
                action(pipe)

        kwargs["started_callback"] = ready
        return AsyncSniffer(opened_socket=pipe, **kwargs)

    monkeypatch.setattr("netlens.capture.AsyncSniffer", factory)
    return pipe


def test_live_capture_count_and_signal_restoration(monkeypatch, packets):
    previous = signal.getsignal(signal.SIGINT)
    pipe = fake_socket_capture(monkeypatch, lambda pipe: [pipe.send(p) for p in packets[:3]])
    try:
        data = NetLens(count=3).start()
    finally:
        pipe.close()
    assert data["total_packets"] == 3
    assert signal.getsignal(signal.SIGINT) == previous


def test_stop_while_idle_does_not_need_another_packet(monkeypatch):
    sniffer = NetLens()
    timer = threading.Timer(0.1, sniffer.stop)
    pipe = fake_socket_capture(monkeypatch, lambda _: timer.start())
    try:
        data = sniffer.start()
    finally:
        pipe.close()
        timer.join()
    assert data["total_packets"] == 0
    assert data["wall_seconds"] < 2
    assert not sniffer.capture.thread.is_alive()
    sniffer.stop()


def test_live_timeout_on_idle_socket(monkeypatch):
    pipe = fake_socket_capture(monkeypatch)
    try:
        assert NetLens(timeout=0.1).start()["total_packets"] == 0
    finally:
        pipe.close()


def test_callback_errors_propagate_and_close_writer(monkeypatch, tmp_path, packets):
    def fail(_):
        raise OSError("disk failure")

    pipe = fake_socket_capture(monkeypatch, lambda pipe: pipe.send(packets[0]))
    sniffer = NetLens(on_packet=fail, pcap_out=tmp_path / "failed.pcap")
    try:
        with pytest.raises(OSError, match="disk failure"):
            sniffer.start()
    finally:
        pipe.close()
    assert sniffer.pcap_writer.closed
    assert not sniffer.capture.thread.is_alive()


def test_startup_error_is_reported(monkeypatch, tmp_path):
    def fail(**kwargs):
        raise PermissionError("no capture access")

    monkeypatch.setattr("netlens.capture.AsyncSniffer", fail)
    sniffer = NetLens(pcap_out=tmp_path / "failed.pcap")
    with pytest.raises(PermissionError):
        sniffer.start()
    assert sniffer.pcap_writer.closed
