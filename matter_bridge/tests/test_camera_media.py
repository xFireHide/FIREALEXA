"""Camera source and signaling boundaries; no physical camera is required."""
import json
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock
import xml.etree.ElementTree as ET

from aiohttp import web

from matter_bridge.adapters.onvif_adapter import OnvifAdapter
from matter_bridge.core.api import LocalAPI
from matter_bridge.core.base_adapter import DeviceInfo, DeviceType


class CameraSignalingTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.adapter = OnvifAdapter({"cam": {"username": "user@name", "password": "s/e:cret"}})
        self.device = DeviceInfo("onvif", "cam", "192.168.1.173", 5000,
                                 device_type=DeviceType.CAMERA,
                                 raw_metadata={"onvif_authenticated": True})
        self.adapter._devices["cam"] = self.device
        self.adapter._profiles["cam"] = [{"token": "main", "rtsp_uri": "rtsp://192.168.1.173:554/live"}]
        registry = SimpleNamespace(get=lambda brand, device_id: self.device if device_id == "cam" else None)
        self.api = LocalAPI(registry, [self.adapter])

    def request(self, body=None, **kwargs):
        values = dict(remote="127.0.0.1", host="127.0.0.1:8765", scheme="http",
                      headers={}, content_type="application/json", match_info={"device_id": "cam"},
                      json=AsyncMock(return_value=body))
        values.update(kwargs)
        return SimpleNamespace(**values)

    def test_source_encodes_credentials_without_modifying_public_profile(self):
        source = self.adapter.media_source("cam", "main")
        self.assertEqual(source["uri"], "rtsp://user%40name:s%2Fe%3Acret@192.168.1.173:554/live")
        self.assertNotIn("@", self.adapter._profiles["cam"][0]["rtsp_uri"])
        self.assertFalse(source["audio"])
        self.adapter._profiles["cam"][0]["rtsp_uri"] = "rtsp://192.168.1.174/live"
        with self.assertRaises(ValueError):
            self.adapter.media_source("cam", "main")

    def test_audio_is_available_only_for_profile_with_audio_encoder(self):
        profiles = OnvifAdapter._profile_tokens(ET.fromstring('''
          <ProfilesResponse xmlns:t="urn:onvif:test">
            <t:Profiles token="silent"><t:VideoEncoderConfiguration /></t:Profiles>
            <t:Profiles token="with-audio"><t:VideoEncoderConfiguration />
              <t:AudioEncoderConfiguration /></t:Profiles>
          </ProfilesResponse>'''))
        self.assertEqual([p["audio"] for p in profiles], [False, True])
        self.adapter._profiles["cam"][0]["audio"] = True
        self.assertTrue(self.adapter.media_source("cam", "main")["audio"])

    async def test_offer_returns_only_signaling_data(self):
        expected = {"session_id": "opaque", "type": "answer", "sdp": "answer"}
        self.api._camera_media.create = AsyncMock(return_value=expected)
        response = await self.api.create_camera_session(self.request({"profile": "main", "sdp": "offer"}))
        self.assertEqual(response.status, 201)
        self.assertEqual(json.loads(response.body), expected)
        source, _ = self.api._camera_media.create.call_args.args
        self.assertIn("s%2Fe%3Acret", source["uri"])
        self.assertNotIn("s%2Fe%3Acret", response.text)

    async def test_unauthenticated_or_unknown_profile_never_starts_worker(self):
        self.api._camera_media.create = AsyncMock()
        for profile in ("unknown", "main"):
            if profile == "main":
                self.device.raw_metadata["onvif_authenticated"] = False
            with self.assertRaises(web.HTTPConflict):
                await self.api.create_camera_session(self.request({"profile": profile, "sdp": "offer"}))
        self.api._camera_media.create.assert_not_called()

    async def test_camera_can_initiate_offer_and_receive_answer(self):
        expected = {"session_id": "opaque", "type": "offer", "sdp": "offer"}
        self.api._camera_media.create = AsyncMock(return_value=expected)
        response = await self.api.create_camera_session(self.request({"profile": "main"}))
        self.assertEqual(json.loads(response.body), expected)
        self.assertIsNone(self.api._camera_media.create.call_args.args[1])
        self.api._camera_media.answer = AsyncMock()
        response = await self.api.camera_answer(self.request(
            {"sdp": "answer"}, match_info={"session_id": "opaque"}))
        self.assertEqual(response.status, 204)
        self.api._camera_media.answer.assert_awaited_once_with("opaque", "answer")

    async def test_invalid_answer_is_rejected_before_worker(self):
        self.api._camera_media.answer = AsyncMock()
        for body in ({"sdp": None}, {"sdp": ""}, {"sdp": "x" * 65537}):
            with self.assertRaises(web.HTTPBadRequest):
                await self.api.camera_answer(self.request(body, match_info={"session_id": "opaque"}))
        self.api._camera_media.answer.assert_not_called()

    async def test_explicit_audio_selection_cannot_enable_missing_audio(self):
        self.api._camera_media.create = AsyncMock(return_value={"sdp": "offer"})
        with self.assertRaises(web.HTTPConflict):
            await self.api.create_camera_session(self.request({"profile": "main", "audio": True}))
        self.api._camera_media.create.assert_not_called()
        self.adapter._profiles["cam"][0]["audio"] = True
        await self.api.create_camera_session(self.request({"profile": "main", "audio": False}))
        self.assertFalse(self.api._camera_media.create.call_args.args[0]["audio"])

    def test_rejects_remote_rebinding_and_cross_origin_clients(self):
        for kwargs in ({"remote": "192.168.1.22"}, {"host": "attacker.example:8765"},
                       {"headers": {"Origin": "https://attacker.example"}}):
            with self.assertRaises(web.HTTPForbidden):
                self.api._check_camera_client(self.request(**kwargs))

    async def test_worker_error_does_not_leak_source_details(self):
        self.api._camera_media.create = AsyncMock(side_effect=RuntimeError("rtsp://secret"))
        with self.assertRaises(web.HTTPBadGateway) as error:
            await self.api.create_camera_session(self.request({"profile": "main", "sdp": "offer"}))
        self.assertNotIn("secret", error.exception.text)
