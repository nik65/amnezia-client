import hashlib
import json
from pathlib import Path
import pytest
from deploy.release_lab import prepare_windows_payload_lab as generator


@pytest.fixture
def inputs(tmp_path, monkeypatch):
    source = tmp_path / 'source'
    files = {}
    for name in ('deploy/release_lab/lab.py', 'deploy/release_lab/windows_host/hyperv_adapter.ps1',
                 'deploy/selfhosted_updates/extra.dat'):
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(name.encode())
        files['source:' + name] = path
    fragment = tmp_path / 'fragment.ps1'
    fragment.write_bytes(b'fixture')
    files['fixture:static.dat'] = fragment
    files['overlay:windows_host/installed_payload_action.ps1'] = fragment
    # Use a small exact closure; production enumeration remains separately tested.
    monkeypatch.setattr(generator, 'input_paths', lambda source: dict(files))
    monkeypatch.setattr(generator, 'BASE_CONTROLLER_SHA', generator.file_record(files['source:deploy/release_lab/lab.py'])['sha256'])
    monkeypatch.setattr(generator, 'BASE_ADAPTER_SHA', generator.file_record(files['source:deploy/release_lab/windows_host/hyperv_adapter.ps1'])['sha256'])
    monkeypatch.setattr(generator, 'patch_controller', lambda text: text + '# overlay')
    monkeypatch.setattr(generator, 'patch_adapter', lambda text, action: text + '# overlay')
    manifest = tmp_path / 'inputs.json'
    manifest.write_text(json.dumps(dict(schema=1, scope='ordinary-payload-generator-inputs',
        files={key: generator.file_record(path) for key, path in files.items()})))
    return source, files, manifest, hashlib.sha256(manifest.read_bytes()).hexdigest(), tmp_path / 'out'


def test_complete_closure_and_output_binding(inputs):
    source, files, manifest, sha, output = inputs
    result, _ = generator.prepare(source, output, manifest, sha)
    assert json.loads(result.read_text())['input_manifest_sha256'] == sha
    assert (output / 'dist/release-lab-fixtures/static.dat').read_bytes() == b'fixture'


@pytest.mark.parametrize('key', ['source:deploy/selfhosted_updates/extra.dat', 'fixture:static.dat'])
@pytest.mark.parametrize('mutation', ['drift', 'missing'])
def test_drift_or_missing_refused_before_output(inputs, key, mutation):
    source, files, manifest, sha, output = inputs
    if mutation == 'drift': files[key].write_bytes(b'changed')
    else: files[key].unlink()
    with pytest.raises(ValueError): generator.prepare(source, output, manifest, sha)
    assert not output.exists()


def test_unlisted_input_refused_before_output(inputs):
    source, files, manifest, sha, output = inputs
    files['fixture:extra'] = manifest
    with pytest.raises(ValueError, match='exact full input set'):
        generator.prepare(source, output, manifest, sha)
    assert not output.exists()


def test_wrong_manifest_hash_refused_before_output(inputs):
    source, files, manifest, sha, output = inputs
    with pytest.raises(ValueError, match='SHA256'):
        generator.prepare(source, output, manifest, '0' * 64)
    assert not output.exists()


def test_copy_corruption_refused_without_freeze(inputs, monkeypatch):
    source, files, manifest, sha, output = inputs
    original = generator.shutil.copyfile
    def corrupt(src, dst):
        original(src, dst)
        if str(dst).endswith('static.dat'): Path(dst).write_bytes(b'corrupt')
    monkeypatch.setattr(generator.shutil, 'copyfile', corrupt)
    with pytest.raises(ValueError, match='copied output'):
        generator.prepare(source, output, manifest, sha)
    assert not (output / 'LAB_TOOLING_FREEZE.json').exists()


def test_production_enumeration_covers_both_trees_overlays_and_fixtures(tmp_path):
    for directory in generator.COPY_TREES:
        root = tmp_path / directory
        root.mkdir(parents=True)
        (root / 'arbitrary.dat').write_bytes(b'input')
    paths = generator.input_paths(tmp_path)
    assert 'source:deploy/release_lab/arbitrary.dat' in paths
    assert 'source:deploy/selfhosted_updates/arbitrary.dat' in paths
    assert 'overlay:windows_installed_payload_contract.py' in paths
    assert 'overlay:windows_host/installed_payload_action.ps1' in paths
    assert 'fixture:android-cvd-vulkan-noble-amd64-20260913.tar.gz' in paths
    assert len([key for key in paths if key.startswith('fixture:')]) == 18


@pytest.mark.parametrize('mutation', ['schema_bool', 'schema_float', 'top_extra', 'record_extra',
                                     'size_bool', 'size_float', 'size_negative', 'sha_upper', 'sha_short', 'sha_number'])
def test_malformed_manifest_refused_before_output(inputs, mutation):
    source, files, manifest, sha, output = inputs
    value = json.loads(manifest.read_text())
    record = value['files'][next(iter(value['files']))]
    if mutation == 'schema_bool': value['schema'] = True
    elif mutation == 'schema_float': value['schema'] = 1.0
    elif mutation == 'top_extra': value['extra'] = 1
    elif mutation == 'record_extra': record['extra'] = 1
    elif mutation == 'size_bool': record['size'] = True
    elif mutation == 'size_float': record['size'] = float(record['size'])
    elif mutation == 'size_negative': record['size'] = -1
    elif mutation == 'sha_upper': record['sha256'] = record['sha256'].upper()
    elif mutation == 'sha_short': record['sha256'] = 'a' * 63
    elif mutation == 'sha_number': record['sha256'] = 1
    manifest.write_text(json.dumps(value))
    sha = hashlib.sha256(manifest.read_bytes()).hexdigest()
    with pytest.raises(ValueError): generator.prepare(source, output, manifest, sha)
    assert not output.exists()
