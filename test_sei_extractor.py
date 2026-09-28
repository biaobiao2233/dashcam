import io
import struct
import sys
import types
import unittest

# The focused parser tests do not require generated protobuf bindings.
sys.modules.setdefault("dashcam_pb2", types.SimpleNamespace())

import sei_extractor


def length_prefixed(*nals):
    return b"".join(struct.pack(">I", len(nal)) + nal for nal in nals)


class SeiNalTests(unittest.TestCase):
    def test_extracts_h264_user_data_unregistered(self):
        nal = bytes([0x06, 0x05, 0x08, 0x42, 0x42, 0x69, 0x08, 0x01, 0x80])
        self.assertEqual(sei_extractor.extract_proto_payload(nal), b"\x08\x01")

    def test_extracts_h265_prefix_sei(self):
        nal = bytes([39 << 1, 0x01, 0x05, 0x08, 0x42, 0x42, 0x69, 0x08, 0x01, 0x80])
        self.assertEqual(sei_extractor.extract_proto_payload(nal), b"\x08\x01")

    def test_extracts_h265_suffix_sei(self):
        nal = bytes([40 << 1, 0x01, 0x05, 0x08, 0x42, 0x42, 0x69, 0x08, 0x01, 0x80])
        self.assertEqual(sei_extractor.extract_proto_payload(nal), b"\x08\x01")

    def test_rejects_non_user_data_sei(self):
        nal = bytes([39 << 1, 0x01, 0x04, 0x08, 0x42, 0x42, 0x69, 0x08, 0x01, 0x80])
        self.assertIsNone(sei_extractor.extract_proto_payload(nal))

    def test_iter_nals_keeps_h264_and_h265_sei_only(self):
        h264 = bytes([0x06, 0x05, 0x01, 0x80])
        h265 = bytes([39 << 1, 0x01, 0x05, 0x01, 0x80])
        slice_nal = bytes([0x01, 0x00, 0x00])
        stream = length_prefixed(slice_nal, h264, h265)
        self.assertEqual(
            list(sei_extractor.iter_nals(io.BytesIO(stream), 0, len(stream))),
            [h264, h265],
        )


if __name__ == "__main__":
    unittest.main()
