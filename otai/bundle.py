# -*- coding: utf-8 -*-
"""오프라인 지식 번들 (FR-SRC-006, NFR-OFF-001, 14.1 `bundle.export import`).

폐쇄망은 이 제품의 핵심 요구다. 외부에서 만든 서명 번들을 매체로 반입해
검증·미리보기·**원자 적용·롤백**한다.

서명 (ADR-018): Ed25519. 매니페스트에 `sig_alg` 를 두어 나중에 다른 방식을
추가해도 기존 번들이 계속 검증되게 한다 — 일방통행 문이 아니다.

검증 순서 — 세 번째가 흔히 빠진다:
  1. 서명 검증 (매니페스트 정규 바이트)
  2. 파일별 sha256 대조
  3. **매니페스트에 없는 멤버가 zip 에 있는지** ← 서명을 위조 못 해도 파일은 끼워넣을 수 있다

번들은 결정적이다 — 같은 입력이면 바이트 동일 (mtime 고정).
wall-clock 을 읽지 않는다. `created_as_of` 는 CLI 의 `--as-of` 다.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from .safeio import (UnsafeInput, bounded_json_load, bounded_json_loads,
                     inspect_zip, safe_extract)

BUNDLE_VERSION = "1"
SIG_ALG = "ed25519"
MANIFEST_NAME = "manifest.json"
SIG_NAME = "manifest.sig"

# 결정적 zip: 모든 멤버에 같은 타임스탬프를 준다 (zip 은 mtime 을 기록한다)
FIXED_DATE = (1980, 1, 1, 0, 0, 0)


class BundleError(Exception):
    pass


def _canonical(manifest: dict) -> bytes:
    """서명 대상 바이트. input_hash 와 같은 정규화를 쓴다."""
    return json.dumps(manifest, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# --------------------------------------------------------------------------
# 키
# --------------------------------------------------------------------------
def generate_keypair(out_dir) -> Tuple[Path, Path]:
    """서명 키쌍 생성. **비밀키는 저장소에 두지 않는다** (.gitignore: *.key)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    priv = ed25519.Ed25519PrivateKey.generate()

    key_path = out_dir / "signing.key"
    pub_path = out_dir / "signing.pub"
    key_path.write_bytes(priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    pub_path.write_bytes(priv.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    ))
    try:
        os.chmod(key_path, 0o600)
    except OSError:
        pass
    return key_path, pub_path


def _sign(data: bytes, key_path) -> bytes:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    priv = ed25519.Ed25519PrivateKey.from_private_bytes(Path(key_path).read_bytes())
    return priv.sign(data)


def _verify_sig(data: bytes, signature: bytes, pub_path) -> bool:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric import ed25519
    pub = ed25519.Ed25519PublicKey.from_public_bytes(Path(pub_path).read_bytes())
    try:
        pub.verify(signature, data)
        return True
    except InvalidSignature:
        return False


# --------------------------------------------------------------------------
# 내보내기
# --------------------------------------------------------------------------
def export_bundle(files: Sequence[Tuple[str, Path]], out_path, *, as_of: str,
                  key_path) -> dict:
    """(번들내 경로, 원본 파일) 목록을 서명된 zip 으로 만든다."""
    entries = []
    for rel, src in sorted(files, key=lambda t: t[0]):
        src = Path(src)
        if not src.is_file():
            raise BundleError("번들에 넣을 파일이 없습니다: %s" % src)
        entries.append({"path": rel, "sha256": _sha256(src),
                        "bytes": src.stat().st_size})

    manifest = {
        "bundle_version": BUNDLE_VERSION,
        "sig_alg": SIG_ALG,
        "created_as_of": as_of,
        "files": entries,
    }
    canonical = _canonical(manifest)
    signature = _sign(canonical, key_path)

    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(out_path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        def add(name: str, data: bytes):
            info = zipfile.ZipInfo(name, date_time=FIXED_DATE)
            info.external_attr = 0o644 << 16
            info.create_system = 3
            info.compress_type = zipfile.ZIP_DEFLATED
            zf.writestr(info, data)

        add(MANIFEST_NAME, canonical)
        add(SIG_NAME, signature)
        for rel, src in sorted(files, key=lambda t: t[0]):
            add(rel, Path(src).read_bytes())

    return manifest


# --------------------------------------------------------------------------
# 검증
# --------------------------------------------------------------------------
@dataclass
class VerifyResult:
    ok: bool
    manifest: Optional[dict]
    manifest_sha256: Optional[str]
    reason: str = ""
    files: Tuple[dict, ...] = ()

    @property
    def bundle_id(self) -> Optional[str]:
        return self.manifest_sha256[:12] if self.manifest_sha256 else None


def verify_bundle(zip_path, pub_path) -> VerifyResult:
    """서명 → 파일 해시 → 미신고 멤버 순으로 검증한다."""
    zip_path = Path(zip_path)
    try:
        infos = inspect_zip(zip_path)
    except UnsafeInput as exc:
        return VerifyResult(False, None, None, "안전하지 않은 아카이브: %s" % exc)

    names = {i.filename for i in infos if not i.filename.endswith("/")}
    if MANIFEST_NAME not in names or SIG_NAME not in names:
        return VerifyResult(False, None, None, "매니페스트 또는 서명이 없습니다")

    with zipfile.ZipFile(zip_path) as zf:
        canonical = zf.read(MANIFEST_NAME)
        signature = zf.read(SIG_NAME)

        # 1) 서명
        if not _verify_sig(canonical, signature, pub_path):
            return VerifyResult(False, None, None, "서명 검증 실패")

        try:
            # 서명이 통과했어도 **한계는 본다.** 서명은 보낸 이를 증명할 뿐
            # 잘 만들어졌음을 증명하지 않는다 (ADR-041). 서명 키를 쥔 쪽이
            # 실수로든 고의로든 64MB·깊이 100의 매니페스트를 보낼 수 있다.
            manifest = bounded_json_loads(canonical, name=SIG_NAME)
        except Exception as exc:
            return VerifyResult(False, None, None, "매니페스트 파싱 실패: %s" % exc)

        if manifest.get("sig_alg") != SIG_ALG:
            return VerifyResult(False, manifest, None,
                                "지원하지 않는 서명 방식: %r" % manifest.get("sig_alg"))

        msha = hashlib.sha256(canonical).hexdigest()
        declared = {f["path"] for f in manifest.get("files", ())}

        # 2) 파일별 해시
        for f in manifest.get("files", ()):
            if f["path"] not in names:
                return VerifyResult(False, manifest, msha,
                                    "매니페스트가 선언한 파일이 없습니다: %s" % f["path"])
            digest = hashlib.sha256(zf.read(f["path"])).hexdigest()
            if digest != f["sha256"]:
                return VerifyResult(False, manifest, msha,
                                    "해시 불일치: %s" % f["path"])

        # 3) 미신고 멤버 — 서명을 위조 못 해도 파일은 끼워넣을 수 있다
        extra = names - declared - {MANIFEST_NAME, SIG_NAME}
        if extra:
            return VerifyResult(False, manifest, msha,
                                "매니페스트에 없는 멤버: %s" % ", ".join(sorted(extra)))

    return VerifyResult(True, manifest, msha, "검증 통과",
                        tuple(manifest.get("files", ())))


# --------------------------------------------------------------------------
# 원자 적용과 롤백
# --------------------------------------------------------------------------
CURRENT_FILE = "current"


def _root(data_dir) -> Path:
    return Path(data_dir) / "bundles"


def read_current(data_dir) -> Optional[str]:
    p = Path(data_dir) / CURRENT_FILE
    if not p.exists():
        return None
    value = p.read_text(encoding="utf-8").strip()
    return value or None


def _write_current(data_dir, value: str) -> None:
    """단일 os.replace 로 원자적으로 전환한다."""
    data_dir = Path(data_dir)
    data_dir.mkdir(parents=True, exist_ok=True)
    tmp = data_dir / (CURRENT_FILE + ".tmp")
    tmp.write_text(value + "\n", encoding="utf-8")
    os.replace(tmp, data_dir / CURRENT_FILE)


@dataclass
class ApplyResult:
    ok: bool
    bundle_id: Optional[str]
    previous: Optional[str]
    reason: str


def apply_bundle(zip_path, pub_path, data_dir) -> ApplyResult:
    """검증 → 스테이징 전개 → current 포인터 전환.

    검증이 실패하면 **아무것도 바뀌지 않는다.** 스테이징도 지운다.
    """
    previous = read_current(data_dir)
    res = verify_bundle(zip_path, pub_path)
    if not res.ok:
        return ApplyResult(False, res.bundle_id, previous, res.reason)

    staging = _root(data_dir) / res.bundle_id
    if staging.exists():
        shutil.rmtree(staging)
    try:
        safe_extract(zip_path, staging)
    except UnsafeInput as exc:
        shutil.rmtree(staging, ignore_errors=True)
        return ApplyResult(False, res.bundle_id, previous, "전개 거부: %s" % exc)

    _write_current(data_dir, res.bundle_id)
    return ApplyResult(True, res.bundle_id, previous, "적용 완료")


def rollback(data_dir, to_bundle_id: Optional[str]) -> ApplyResult:
    previous = read_current(data_dir)
    if to_bundle_id is None:
        return ApplyResult(False, None, previous, "되돌릴 번들이 지정되지 않았습니다")
    if not (_root(data_dir) / to_bundle_id).exists():
        return ApplyResult(False, to_bundle_id, previous,
                           "해당 번들이 로컬에 없습니다: %s" % to_bundle_id)
    _write_current(data_dir, to_bundle_id)
    return ApplyResult(True, to_bundle_id, previous, "롤백 완료")


def active_dir(data_dir) -> Optional[Path]:
    cur = read_current(data_dir)
    if cur is None:
        return None
    d = _root(data_dir) / cur
    return d if d.exists() else None
