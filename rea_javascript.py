"""Recover JavaScript ASTs using explicit external build tools; never certifies an app."""
import hashlib
import json
import subprocess
from pathlib import Path


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def recover_javascript(original, directory, toolchain, node='node', timeout=180):
    original, directory, toolchain = (Path(p).resolve() for p in (original, directory, toolchain))
    if original == directory or original in directory.parents or directory in original.parents:
        raise ValueError('INPUT_AND_OUTPUT_MUST_BE_DISJOINT')
    directory.mkdir(parents=True, exist_ok=True)
    report_path = directory / 'recovery.json'
    summary = {'status': 'INCOMPLETE', 'application_entry_executed': False,
               'ui_verified': False, 'api_verified': False,
               'reason': 'JAVASCRIPT_RECOVERY_IS_NOT_FULL_APPLICATION_VERIFICATION', 'files': []}
    def save():
        report_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2))
    save()
    helper = Path(__file__).with_name('rea_js_recover.cjs')
    summary['recovery_tool_sha256'] = digest(helper)
    summary['toolchain_lock_sha256'] = digest(toolchain / 'package-lock.json')
    inputs = sorted(original.rglob('*.js')) if original.is_dir() else [original]
    for index, source in enumerate(inputs):
        relative = source.relative_to(original) if original.is_dir() else Path(source.name)
        destination = directory / 'generated' / relative
        metadata = directory / 'metadata' / (str(relative) + '.json')
        metadata.parent.mkdir(parents=True, exist_ok=True)
        before = digest(source)
        entry = {'path': str(relative), 'original_sha256': before, 'status': 'INCOMPLETE'}
        try:
            with metadata.with_suffix('.log').open('wb') as log:
                run = subprocess.run([str(node), '--max-old-space-size=2600', str(helper),
                                      str(source), str(destination), str(metadata), str(toolchain)],
                                     stdin=subprocess.DEVNULL, stdout=log, stderr=log, timeout=timeout)
            if run.returncode:
                raise ValueError('RECOVERY_PROCESS_EXIT_' + str(run.returncode))
            recovered = json.loads(metadata.read_text())
            if digest(source) != before or recovered.get('original_sha256') != before:
                raise ValueError('ORIGINAL_CHANGED_DURING_RECOVERY')
            if digest(destination) != recovered.get('generated_sha256'):
                raise ValueError('GENERATED_HASH_MISMATCH')
            with metadata.with_suffix('.syntax.log').open('wb') as log:
                checked = subprocess.run([str(node), '--check', str(destination)],
                                         stdin=subprocess.DEVNULL, stdout=log, stderr=log, timeout=timeout)
            if checked.returncode:
                raise ValueError('REGENERATED_SYNTAX_INVALID')
            entry.update(recovered, syntax_checked=True)
        except (OSError, ValueError, subprocess.TimeoutExpired) as error:
            entry.update(status='INCOMPLETE', reason=str(error))
        summary['files'].append(entry)
        summary['processed_files'] = index + 1
        summary['total_files'] = len(inputs)
        summary['generated_files'] = sum(f['status'] == 'GENERATED_UNVERIFIED' for f in summary['files'])
        summary['folded_decoder_calls'] = sum(f.get('folded_decoder_calls', 0) for f in summary['files'])
        save()
    if digest(helper) != summary['recovery_tool_sha256'] or digest(toolchain / 'package-lock.json') != summary['toolchain_lock_sha256']:
        summary['reason'] = 'RECOVERY_TOOL_CHANGED_DURING_RUN'
    save()
    return summary
