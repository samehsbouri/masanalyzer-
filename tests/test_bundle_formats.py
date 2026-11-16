"""Feature 7: .apks (APK-Set) and .aab (App Bundle) container support."""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from masanalyzer.packaging import prepare_target  # noqa: E402
from masanalyzer.testing import build_apks, build_aab  # noqa: E402


class ApksContainer(unittest.TestCase):
    """APK-Set: base APK is primary, split payloads merged into the tree."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="masan_apks_")
        cls.path = build_apks(os.path.join(cls.tmp, "app.apks"))
        cls.target = prepare_target(cls.path)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_container_meta(self):
        self.assertEqual(self.target.meta.get("container"), "apks")
        self.assertEqual(self.target.meta.get("base_apk"), "base.apk")
        splits = self.target.meta.get("splits") or []
        self.assertEqual(len(splits), 2)
        entries = {s["apk"]: s["entries"] for s in splits}
        self.assertEqual(entries.get("split_config.arm64_v8a.apk"), 2)
        self.assertEqual(entries.get("split_assets.apk"), 1)

    def test_base_apk_identity_comes_from_primary(self):
        self.assertEqual(self.target.platform, "android")
        pkg = self.target.package or ""
        self.assertEqual(pkg, "com.example.splitset")

    def test_split_files_merged_with_prefix(self):
        rels = {sf.relpath for sf in self.target.files}
        self.assertIn(
            "split_config.arm64_v8a/lib/arm64-v8a/libsplit.so", rels
        )
        self.assertIn(
            "split_config.arm64_v8a/assets/split_extra.json", rels
        )
        self.assertIn(
            "split_assets/res/values/stub.xml", rels
        )

    def test_base_dex_parsed(self):
        dex_files = self.target.meta.get("dex_files") or []
        self.assertTrue(dex_files, "base APK dex must be parsed")
        paths = self.target.meta.get("dex") or []
        self.assertEqual(paths[0]["path"], "classes.dex")


class AabContainer(unittest.TestCase):
    """App Bundle: flattened bundle tree scan; protobuf manifest skipped."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="masan_aab_")
        cls.path = build_aab(os.path.join(cls.tmp, "app.aab"))
        cls.target = prepare_target(cls.path)

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_container_meta(self):
        self.assertEqual(self.target.meta.get("container"), "aab")

    def test_protobuf_manifest_skipped_with_warning(self):
        self.assertIsNone(self.target.manifest, "AXML parser must not consume .pb")
        rels = self.target.meta.get("aab_proto_manifests") or []
        self.assertEqual(
            rels, ["base/manifest/AndroidManifest.xml"]
        )
        warnings = " ".join(self.target.meta.get("warnings") or [])
        self.assertIn("protobuf manifest", warnings)

    def test_bundle_dex_parsed(self):
        dex_files = self.target.meta.get("dex_files") or []
        self.assertTrue(dex_files)
        paths = self.target.meta.get("dex") or []
        self.assertEqual(paths[0]["path"], "base/dex/classes.dex")

    def test_bundle_tree_files_classified(self):
        rels = {sf.relpath: sf.kind for sf in self.target.files}
        self.assertEqual(
            rels.get("base/lib/arm64-v8a/libbundle.so"), "native"
        )
        self.assertEqual(rels.get("resources.pb"), "binary")
        self.assertEqual(rels.get("BUNDLE-METADATA/"
                                  "com.android.tools/proguard.map"),
                         "resource")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
