"""Encrypted Wan 2.2 Animate Runpod Serverless bridge for Text to Image Studio.
Opaque RSA-OAEP/AES-256-GCM requests are decrypted only in this GPU process.
No plaintext prompt, media content, data URL, or crypto key is logged.
The bundled ComfyUI Wan Animate 14B workflows are reused unchanged.
"""
import base64
import binascii
import copy
import json
import os
import pathlib
import secrets
import subprocess
import tempfile
import time
import uuid
from typing import Any

import requests
import runpod
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

AAD = b"studio-video-v1"
INPUT_LIMIT = 12_000_000
VIDEO_LIMIT = 4 * 1024 * 1024
IMAGE_LIMIT = 2 * 1024 * 1024
OUTPUT_LIMIT = 8 * 1024 * 1024
BASE = "http://127.0.0.1:8188"
KID = secrets.token_hex(12)
PRIVATE_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
PUBLIC_KEY_PEM = PRIVATE_KEY.public_key().public_bytes(
    serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
).decode("ascii")

def _decode64url(data: str) -> bytes:
    if not isinstance(data, str) or not data or len(data) > 18_000_000:
        raise ValueError("Invalid encrypted packet")
    if any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_" for c in data):
        raise ValueError("Invalid encrypted packet")
    return base64.urlsafe_b64decode(data + "=" * (-len(data) % 4))

def _encode64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")

def _decrypt(packet: dict) -> tuple[dict, bytes]:
    if packet.get("v") != 1 or packet.get("kid") != KID:
        raise ValueError("Expired GPU encryption key. Retry with a fresh job.")
    if len(packet.get("c", "")) > INPUT_LIMIT:
        raise ValueError("Encrypted request too large")
    wrapped = _decode64url(packet["w"])
    key = PRIVATE_KEY.decrypt(wrapped, padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(), label=None
    ))
    if len(key) != 32:
        raise ValueError("Incorrect AES key")
    iv = _decode64url(packet["n"])
    if len(iv) != 12:
        raise ValueError("Invalid nonce")
    plaintext = AESGCM(key).decrypt(iv, _decode64url(packet["c"]), AAD)
    if len(plaintext) > 10_000_000:
        raise ValueError("Decrypted request too large")
    value = json.loads(plaintext)
    if not isinstance(value, dict) or value.get("protocol") != "studio-wan-animate-v1":
        raise ValueError("Unknown Studio video format")
    return value, key

def _encrypt(value: dict, key: bytes) -> dict:
    iv = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(iv, json.dumps(value, separators=(",", ":")).encode("utf-8"), AAD)
    return {"v": 1, "n": _encode64url(iv), "c": _encode64url(ciphertext)}

def _parse_data_url(data: str, allowed_types: tuple[str, ...], limit: int) -> tuple[bytes, str]:
    if not isinstance(data, str) or not data.startswith("data:") or len(data) > limit * 2:
        raise ValueError("Invalid uploaded media")
    meta, sep, raw = data.partition(",")
    if sep != "," or not meta.endswith(";base64"):
        raise ValueError("Expected base64 data URL")
    mime = meta[5:-7].lower()
    if mime not in allowed_types:
        raise ValueError("Unsupported media format")
    try:
        content = base64.b64decode(raw, validate=True)
    except (binascii.Error, ValueError):
        raise ValueError("Damaged uploaded media") from None
    if not content or len(content) > limit:
        raise ValueError("Media size exceeds private limit")
    return content, mime

def _run_ffmpeg(source: pathlib.Path, output: pathlib.Path, *, fps: int = 16) -> None:
    # ffmpeg decodes only local, decrypted ephemeral content on the GPU worker.
    command = [
        "ffmpeg", "-nostdin", "-hide_banner", "-loglevel", "error", "-y",
        "-i", str(source), "-an",
        "-t", "5", "-vf", f"fps={fps},scale='min(512,iw)':'min(512,ih)':force_original_aspect_ratio=decrease,pad=ceil(iw/16)*16:ceil(ih/16)*16",
        "-c:v", "libx264", "-pix_fmt", "yuv420p", "-preset", "veryfast",
        "-crf", "28", "-movflags", "+faststart", str(output),
    ]
    subprocess.run(command, timeout=50, check=True, capture_output=True)

def _workflow(mode: str, image: pathlib.Path, video: pathlib.Path, settings: dict, description: str) -> dict:
    workflow_file = "/newWanAnimate_noSAM_animate_api.json" if mode == "animation" else "/newWanAnimate_noSAM_api.json"
    with open(workflow_file, "r", encoding="utf-8") as f:
        prompt = json.load(f)
    # Validate all dynamically supplied nodes and keep the GPU workflow fixed.
    width = max(256, min(768, int(settings.get("width", 512))))
    height = max(256, min(768, int(settings.get("height", 512))))
    width, height = (max(256, width // 16 * 16), max(256, height // 16 * 16))
    prompt["57"]["inputs"]["image"] = str(image)
    prompt["63"]["inputs"]["video"] = str(video)
    prompt["63"]["inputs"]["force_rate"] = 16
    prompt["30"]["inputs"]["frame_rate"] = 16
    prompt["65"]["inputs"]["positive_prompt"] = description[:2000] or "A realistic moving person."
    prompt["27"]["inputs"]["seed"] = secrets.randbelow(2**31)
    prompt["27"]["inputs"]["cfg"] = 1.0
    prompt["27"]["inputs"]["steps"] = 4
    prompt["150"]["inputs"]["value"] = width
    prompt["151"]["inputs"]["value"] = height
    return prompt

def _generate(prompt: dict) -> bytes:
    client_id = uuid.uuid4().hex
    result = requests.post(f"{BASE}/prompt", json={"prompt": prompt, "client_id": client_id}, timeout=45)
    result.raise_for_status()
    data = result.json()
    job_id = data.get("prompt_id")
    if not job_id:
        # Do not expose ComfyUI's full validation response: it can contain private paths/prompts.
        raise RuntimeError("Wan workflow could not be queued")
    end = time.monotonic() + 1200
    while time.monotonic() < end:
        response = requests.get(f"{BASE}/history/{job_id}", timeout=25)
        response.raise_for_status()
        record = response.json().get(job_id)
        if record:
            if record.get("status", {}).get("status_str") == "error":
                raise RuntimeError("Wan video workflow failed")
            for node in record.get("outputs", {}).values():
                for video in node.get("gifs", []) + node.get("videos", []):
                    root = pathlib.Path("/ComfyUI/output").resolve()
                    file_path = video.get("fullpath")
                    candidate = pathlib.Path(file_path).resolve() if file_path else (root / video.get("subfolder", "") / video.get("filename", "")).resolve()
                    if candidate.is_file() and (candidate == root or root in candidate.parents):
                        if candidate.stat().st_size > 80 * 1024 * 1024:
                            raise ValueError("GPU output too large")
                        return candidate.read_bytes()
            raise RuntimeError("Wan returned no video")
        time.sleep(3)
    raise TimeoutError("Wan rendering exceeded the GPU timeout")

def _run_video(data: dict, key: bytes) -> dict:
    mode = data.get("mode")
    if mode not in ("replacement", "animation"):
        raise ValueError("Choose replacement or animation")
    settings = data.get("settings") or {}
    if not isinstance(settings, dict):
        raise ValueError("Invalid video settings")
    driving = data.get("drivingVideo") or {}
    character = data.get("characterImage") or {}
    video_bytes, video_mime = _parse_data_url(driving.get("data", ""), ("video/mp4", "video/webm"), VIDEO_LIMIT)
    image_bytes, _ = _parse_data_url(character.get("data", ""), ("image/jpeg",), IMAGE_LIMIT)
    description = data.get("prompt", "")
    if not isinstance(description, str):
        raise ValueError("Prompt must be text")
    with tempfile.TemporaryDirectory(prefix="private-wan-") as tmp:
        work = pathlib.Path(tmp)
        source = work / ("motion.webm" if video_mime == "video/webm" else "motion.mp4")
        source.write_bytes(video_bytes)
        image = work / "character.jpg"
        image.write_bytes(image_bytes)
        motion = work / "source.mp4"
        _run_ffmpeg(source, motion)
        if not motion.is_file() or motion.stat().st_size == 0:
            raise RuntimeError("Video conversion failed")
        workflow = _workflow(mode, image, motion, settings, description)
        rendered = _generate(workflow)
        temp_output = work / "generated.mp4"
        temp_output.write_bytes(rendered)
        final_video = work / "final.mp4"
        # Re-encode to bound the encrypted response size and normalize mp4 container.
        subprocess.run([
            "ffmpeg", "-nostdin", "-hide_banner", "-loglevel", "error", "-y",
            "-i", str(temp_output), "-t", "5", "-an", "-c:v", "libx264",
            "-pix_fmt", "yuv420p", "-preset", "veryfast", "-crf", "29",
            "-movflags", "+faststart", str(final_video),
        ], check=True, timeout=120, capture_output=True)
        output_bytes = final_video.read_bytes()
        if not output_bytes or len(output_bytes) > OUTPUT_LIMIT:
            raise ValueError("Rendered MP4 exceeds private response limit")
        return {"encrypted_v1": _encrypt({
            "videoBase64": base64.b64encode(output_bytes).decode("ascii"),
            "mimeType": "video/mp4",
        }, key)}

def handler(job: dict) -> dict:
    payload = job.get("input") or {}
    if not isinstance(payload, dict):
        return {"error": "Invalid video job"}
    if payload.get("task") == "get_public_key":
        return {"v": 1, "kid": KID, "public_key": PUBLIC_KEY_PEM}
    if payload.get("task") != "animate_encrypted_v1":
        return {"error": "Encrypted Wan job required"}
    try:
        data, key = _decrypt(payload.get("envelope") or {})
        return _run_video(data, key)
    except Exception as error:
        # No stack traces, media, prompts, or worker keys in Runpod job output.
        return {"error": "Private Wan rendering failed", "reason": type(error).__name__}

if __name__ == "__main__":
    runpod.serverless.start({"handler": handler})
