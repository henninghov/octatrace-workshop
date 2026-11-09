#!/usr/bin/env python3
"""C5.3 UI gate/native build and deliberate faults. No service/device operations."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
SDK=Path(os.environ.get('FLUTTER_SDK','/Users/henninghov/Sites/sdk/flutter'))


def inputs():
    folders=['lib','test','tools','assets','macos','vendor']
    paths=[p for folder in folders for p in (ROOT/folder).rglob('*') if p.is_file() and p.name != '.DS_Store' and not any(x in p.parts for x in ['__pycache__','ephemeral'])]
    paths += [p for p in ROOT.glob('*.lock.json')]+[ROOT/n for n in ['pubspec.yaml','pubspec.lock','analysis_options.yaml','design/factory-qr-ui.json']]
    return {str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(set(paths))}


def run(config):
    frozen=inputs()
    out=ROOT/'build/factory-ui'/datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    out.mkdir(parents=True)
    (out/'inputs.json').write_text(json.dumps(frozen,sort_keys=True,indent=2)+'\n')
    def command(args,name,cwd=ROOT):
        with (out/name).open('w') as stream:
            result=subprocess.run(args,cwd=cwd,stdout=stream,stderr=subprocess.STDOUT)
        if result.returncode:raise RuntimeError('Failed check: '+str(out/name))
    command(['bash','tools/quality_gate.sh'],'gate.log')
    coverage=json.loads((ROOT/'coverage/result.json').read_text())
    args=[str(SDK/'bin/flutter'),'build','macos','--debug','--no-pub','--dart-define-from-file='+str(config)]
    command(args,'native-build.log')
    app=ROOT/'build/macos/Build/Products/Debug/Octatrace Workshop.app'
    command(['/usr/bin/codesign','--verify','--deep','--strict','--verbose=2',str(app)],'signature.log')
    controls=[('ignore-cancel-generation','lib/domain/factory_controller.dart','generation == _generation &&',''),
              ('ignore-qr-device-binding','lib/domain/factory_enrollment.dart','uuid != deviceId ||','')]
    for name,path,before,after in controls:
        with tempfile.TemporaryDirectory(prefix='workshop-c53-fault-') as folder:
            target=Path(folder)
            for sub in ['lib','test','assets','vendor']:
                shutil.copytree(ROOT/sub,target/sub)
            for file in ['pubspec.yaml','pubspec.lock','analysis_options.yaml']:
                shutil.copy2(ROOT/file,target/file)
            (target/'.dart_tool').mkdir()
            for metadata in ['package_config.json','package_graph.json']:
                shutil.copy2(ROOT/'.dart_tool'/metadata,target/'.dart_tool'/metadata)
            source=target/path;text=source.read_text()
            if text.count(before)!=1:raise RuntimeError('Fault anchor drift: '+name)
            source.write_text(text.replace(before,after))
            with (out/(name+'.log')).open('w') as stream:
                result=subprocess.run([str(SDK/'bin/flutter'),'test','--no-pub','test/factory_controller_test.dart'],cwd=target,stdout=stream,stderr=subprocess.STDOUT)
            text=(out/(name+'.log')).read_text()
            if result.returncode==0 or 'Some tests failed' not in text or 'Expected:' not in text:
                raise RuntimeError('Deliberate security fault not detected: '+name)
    if inputs()!=frozen:raise RuntimeError('Qualification inputs changed during execution')
    def file_hash(path):
        digest=hashlib.sha256()
        with path.open('rb') as stream:
            for chunk in iter(lambda:stream.read(1024*1024),b''):digest.update(chunk)
        return digest.hexdigest()
    bundle_files={str(p.relative_to(app)):file_hash(p) for p in sorted(app.rglob('*')) if p.is_file()}
    bundle_links={str(p.relative_to(app)):os.readlink(p) for p in sorted(app.rglob('*')) if p.is_symlink()}
    receipt={'checkpoint':'C5.3','status':'passed','validation':'software UI/HTTP adapter/real-file persistence/native build; no hosted or physical pass',
      'source_sha256':hashlib.sha256(json.dumps(frozen,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
      'inputs':frozen,'coverage':coverage,'negative_controls':[x[0] for x in controls],
      'artifact':str(app),'artifact_launcher_sha256':bundle_files['Contents/MacOS/Octatrace Workshop'],
      'artifact_bundle_files':bundle_files,'artifact_bundle_links':bundle_links,
      'artifact_bundle_sha256':hashlib.sha256(json.dumps({'files':bundle_files,'links':bundle_links},sort_keys=True,separators=(',',':')).encode()).hexdigest(),
      'logs_sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in out.glob('*.log')},
      'limits':['No hosted C5 backend/key activation','No real device QR/enrollment/scan','No Git publication or app installation/launch']}
    (out/'results.json').write_text(json.dumps(receipt,indent=2)+'\n')
    print(json.dumps({'report':str(out/'results.json'),'source':receipt['source_sha256'],'coverage':coverage,'negative_controls':receipt['negative_controls']},indent=2))


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config',type=Path,required=True,help='Existing ignored development configuration (never printed)')
    run(parser.parse_args().config.resolve())
